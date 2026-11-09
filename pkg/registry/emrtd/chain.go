package emrtd

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/asn1"
	"fmt"
	"strings"
	"time"

	"github.com/sirosfoundation/go-trust/pkg/authzen"
)

var oidKeyUsage = asn1.ObjectIdentifier{2, 5, 29, 15}

// maxChainLen bounds DSC -> link certs -> CSCA, inclusive.
const maxChainLen = 5

// maxSearchSteps bounds the total number of signature checks one evaluation
// may spend building paths (across the claimed state and the wrong-country
// probe). Exhaustion is an explicit denial, never a silent truncation.
const maxSearchSteps = 2000

// search carries the work budget and cancellation state for one evaluation.
type search struct {
	ctx       context.Context
	steps     int
	exhausted bool
	canceled  bool
}

func newSearch(ctx context.Context) *search {
	return &search{ctx: ctx, steps: maxSearchSteps}
}

// stopped reports whether the search must abandon work, latching the reason.
func (s *search) stopped() bool {
	if s.exhausted || s.canceled {
		return true
	}
	if s.ctx.Err() != nil {
		s.canceled = true
		return true
	}
	if s.steps <= 0 {
		s.exhausted = true
		return true
	}
	return false
}

// issuedBy reports whether child names parent as its issuer and carries a
// valid signature by parent's key. The second result reports a name match
// regardless of signature validity (used to choose between the no_anchor and
// chain_invalid deny codes).
//
// Leniencies (ICAO 9303 Part 12 PKI is not web PKI):
//   - Issuer/subject are compared byte-for-byte first, then by rendered string
//     case-insensitively: CSCAs and DSCs in the wild differ in string type
//     (PrintableString vs UTF8String) for the same name.
//   - AuthorityKeyIdentifier/SubjectKeyIdentifier are NOT required to match.
//     They are lookup hints; the signature check below is what binds the
//     certificates, and some states issue DSCs with absent or stale AKIs.
func (r *Registry) issuedBy(child, parent *x509.Certificate) (signed, named bool) {
	if !namesEqual(child.RawIssuer, parent.RawSubject, child.Issuer.String(), parent.Subject.String()) {
		return false, false
	}
	if weakSigAlg(child.SignatureAlgorithm) {
		return false, true
	}
	err := r.ext.CheckSignature(parent, child.SignatureAlgorithm, child.RawTBSCertificate, child.Signature)
	return err == nil, true
}

// namesEqual compares DER names byte-for-byte, then by rendered string
// case-insensitively (see the leniencies above).
func namesEqual(rawA, rawB []byte, strA, strB string) bool {
	return bytes.Equal(rawA, rawB) || strings.EqualFold(strA, strB)
}

// weakSigAlg reports signature algorithms that are refused outright: a
// correct SHA-1 or MD5 signature still must not form a trusted path.
func weakSigAlg(a x509.SignatureAlgorithm) bool {
	switch a {
	case x509.MD2WithRSA, x509.MD5WithRSA, x509.SHA1WithRSA, x509.DSAWithSHA1, x509.ECDSAWithSHA1:
		return true
	}
	return false
}

// canIssue is the constraint applied to UNTRUSTED link certificates taken from
// the request: they must be CA certificates whose keyUsage asserts keyCertSign
// (a missing keyUsage extension is not enough).
// Anchors are exempt: they are human-reviewed, and some legacy CSCAs lack
// basicConstraints. pathLenConstraint is not enforced by default (see
// pathLenPolicy); chain length is bounded by maxChainLen instead.
func canIssue(c *x509.Certificate) bool {
	if !c.BasicConstraintsValid || !c.IsCA {
		return false
	}
	return c.KeyUsage&x509.KeyUsageCertSign != 0
}

// buildPaths walks every structurally valid signature path
// DSC -> [link...] -> anchor, calling accept on each as it is found; the walk
// stops as soon as accept returns true. Only anchors terminate a path; extras
// are intermediates only. found reports whether any structural path existed;
// the search budget and cancellation are tracked in s.
func (r *Registry) buildPaths(s *search, dsc *x509.Certificate, extras []*x509.Certificate, anchors []*anchor, accept func([]*x509.Certificate) bool) (found, nameMatched bool) {
	isAnchor := func(c *x509.Certificate) bool {
		for _, a := range anchors {
			if bytes.Equal(a.cert.Raw, c.Raw) {
				return true
			}
		}
		return false
	}
	inPath := func(path []*x509.Certificate, c *x509.Certificate) bool {
		for _, p := range path {
			if bytes.Equal(p.Raw, c.Raw) {
				return true
			}
		}
		return false
	}
	check := func(child, parent *x509.Certificate) (bool, bool) {
		s.steps--
		return r.issuedBy(child, parent)
	}

	done := false
	var walk func(path []*x509.Certificate)
	walk = func(path []*x509.Certificate) {
		cur := path[len(path)-1]
		for _, a := range anchors {
			if done || s.stopped() {
				return
			}
			if inPath(path, a.cert) {
				continue // a certificate cannot vouch for itself
			}
			signed, named := check(cur, a.cert)
			nameMatched = nameMatched || named
			if signed {
				found = true
				if accept(append(append([]*x509.Certificate{}, path...), a.cert)) {
					done = true
					return
				}
			}
		}
		if len(path) >= maxChainLen-1 {
			return
		}
		for _, e := range extras {
			if done || s.stopped() {
				return
			}
			if inPath(path, e) || isAnchor(e) {
				continue
			}
			signed, named := check(cur, e)
			if !signed {
				// A supplied link that names the issuer but does not verify
				// is an invalid chain, not a missing issuer.
				nameMatched = nameMatched || named
				continue
			}
			if !canIssue(e) {
				// Validly signed link that may not act as a CA: a
				// structural violation, reported as chain_invalid.
				nameMatched = true
				continue
			}
			walk(append(append([]*x509.Certificate{}, path...), e))
		}
	}
	walk([]*x509.Certificate{dsc})
	return found, nameMatched
}

// hasKeyUsageExt reports whether the certificate carries a keyUsage extension,
// including one whose bit string is all zero (which parses as KeyUsage == 0).
func hasKeyUsageExt(c *x509.Certificate) bool {
	for _, e := range c.Extensions {
		if e.Id.Equal(oidKeyUsage) {
			return true
		}
	}
	return false
}

// checkPath applies path-length, time, key-usage and revocation checks to a
// candidate path. It returns nil when the path is acceptable.
func (r *Registry) checkPath(path []*x509.Certificate, at time.Time, crls []*crlData, anchors []*anchor, pl pathLenPolicy, cp crlPolicy, now time.Time, vc crlVerdicts) *authzen.EvaluationResponse {
	if d := r.checkPathLen(path, pl); d != nil {
		return d
	}

	// Validity is evaluated at document signing time, not wall clock, per
	// ICAO 9303 Part 12 (the DSC of an old passport is long expired at now).
	// Every certificate on the path is checked, CSCA and link certificates too.
	for _, c := range path {
		if at.Before(c.NotBefore) {
			return r.deny(CodeNotYetValid, fmt.Sprintf("%q is not valid before %s (evaluated at %s)",
				c.Subject.String(), c.NotBefore.Format(time.RFC3339Nano), at.Format(time.RFC3339Nano)))
		}
		if at.After(c.NotAfter) {
			return r.deny(CodeExpired, fmt.Sprintf("%q expired %s (evaluated at %s)",
				c.Subject.String(), c.NotAfter.Format(time.RFC3339Nano), at.Format(time.RFC3339Nano)))
		}
	}

	// Key usage: a DSC must be allowed to make digital signatures. ICAO 9303
	// Part 12 mandates the extension; a DSC with NO keyUsage extension is
	// tolerated because some older issuers omitted it. One that is present
	// but lacks digitalSignature is refused, which also keeps a CSCA
	// (keyCertSign/cRLSign only) from being presented as a DSC.
	dsc := path[0]
	// A document signer is an end-entity certificate: a CA (e.g. a link
	// certificate that also carries digitalSignature) must not be accepted
	// as a DSC, whatever its key usage says.
	if dsc.BasicConstraintsValid && dsc.IsCA {
		return r.deny(CodeBadKeyUsage, "DSC is a CA certificate (basicConstraints cA=true)")
	}
	if hasKeyUsageExt(dsc) && dsc.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		return r.deny(CodeBadKeyUsage, "DSC keyUsage does not include digitalSignature")
	}

	// Revocation. A certificate listed on any verified CRL of its issuer is
	// revoked, regardless of the revocation date relative to signing time
	// (fail closed: we cannot tell when the key was actually compromised).
	// A CRL whose signature does not verify against the issuer is ignored,
	// not believed. A CRL past nextUpdate still counts for positive hits:
	// staleness never un-revokes a certificate. No CRL for an issuer means
	// no revocation information, which is not a denial.
	//
	// With crl_mode require-current, each issuer must in addition have a
	// verified, current CRL. That is checked after every revocation hit, so a
	// revoked certificate is always reported as revoked, never as a feed
	// problem.
	var covered []crlCoverage
	for i := 0; i < len(path)-1; i++ {
		cert, issuer := path[i], path[i+1]
		cov := crlCoverage{issuer: issuer}
		for _, crl := range crls {
			// The CRL must be issued under the name of the certificate's issuer.
			if !namesEqual(crl.RawIssuer, cert.RawIssuer, crl.Issuer.String(), cert.Issuer.String()) {
				continue
			}
			if weakSigAlg(crl.SignatureAlgorithm) {
				continue
			}
			if !r.crlAuthentic(vc, crl, issuer, anchors) {
				continue
			}
			if crl.isRevoked(cert.SerialNumber) {
				return r.deny(CodeRevoked, fmt.Sprintf("%q (serial %s) is revoked by CRL", cert.Subject.String(), cert.SerialNumber))
			}
			cov.verified++
			if cp.current(crl, now) {
				cov.current = true
			}
		}
		covered = append(covered, cov)
	}
	if !cp.require {
		return nil
	}
	for _, cov := range covered {
		switch {
		case cov.current:
		case cov.verified == 0:
			return r.crlDeny(CodeCRLUnavailable, cov.issuer, "no verified CRL for issuer %q")
		default:
			return r.crlDeny(CodeCRLStale, cov.issuer, "no current CRL for issuer %q (checked against nextUpdate and crl_max_age)")
		}
	}
	return nil
}

// crlCoverage is what the loaded CRLs say about one issuer on a path: how many
// verified CRLs apply to the certificate it issued and whether one is current.
type crlCoverage struct {
	issuer   *x509.Certificate
	verified int
	current  bool
}

func (r *Registry) crlDeny(code string, issuer *x509.Certificate, format string) *authzen.EvaluationResponse {
	detail := fmt.Sprintf(format, issuer.Subject.String())
	r.log.Warn("emrtd: CRL requirement not met", "code", code, "issuer", issuer.Subject.String())
	return r.deny(code, detail)
}

// Context keys through which the manager hands the policy's CRL setting to the
// registry. Like the path-length keys they are server-controlled and written
// only from the matching policy's `emrtd` block.
const (
	ctxCRLMode            = "emrtd_crl_mode"
	ctxCRLMaxAge          = "emrtd_crl_max_age"
	ctxCRLCountries       = "emrtd_crl_countries"
	ctxCRLExemptCountries = "emrtd_crl_exempt_countries"
	CRLModeBestEffort     = "best-effort"
	CRLModeRequireCurrent = "require-current"
)

// crlPolicy is the resolved CRL requirement for one evaluation. The zero value
// is best-effort, which is the default behaviour.
type crlPolicy struct {
	require bool
	maxAge  time.Duration
}

// current reports whether a CRL is current for the policy: nextUpdate is set
// and not past, and, with a max age, thisUpdate is not older than that.
// A CRL without nextUpdate is never current (RFC 5280 requires the field, so
// its absence is treated as not vouching for any period).
func (p crlPolicy) current(crl *crlData, now time.Time) bool {
	if crl.NextUpdate.IsZero() || now.After(crl.NextUpdate) || now.Before(crl.ThisUpdate) {
		return false
	}
	return p.maxAge == 0 || now.Sub(crl.ThisUpdate) <= p.maxAge
}

// crlPolicyFromContext reads the policy-derived CRL setting for the claimed
// state. Anything it cannot interpret is an error, so the caller denies: a
// malformed control never silently degrades to best-effort.
func crlPolicyFromContext(ctx map[string]interface{}, country string) (crlPolicy, error) {
	var p crlPolicy
	raw, ok := ctx[ctxCRLMode]
	if !ok || raw == nil {
		return p, nil
	}
	mode, isStr := raw.(string)
	switch {
	case !isStr:
		return p, fmt.Errorf("context.%s must be a string", ctxCRLMode)
	case mode == CRLModeRequireCurrent:
		p.require = true
	case mode == CRLModeBestEffort || mode == "":
	default:
		return p, fmt.Errorf("context.%s %q is not %q or %q", ctxCRLMode, mode, CRLModeBestEffort, CRLModeRequireCurrent)
	}
	if raw, ok := ctx[ctxCRLMaxAge]; ok && raw != nil {
		s, isStr := raw.(string)
		if !isStr {
			return p, fmt.Errorf("context.%s must be a duration string", ctxCRLMaxAge)
		}
		d, err := time.ParseDuration(s)
		if err != nil || d < 0 {
			return p, fmt.Errorf("context.%s %q is not a non-negative duration", ctxCRLMaxAge, s)
		}
		p.maxAge = d
	}
	only, err := countryList(ctx, ctxCRLCountries)
	if err != nil {
		return p, err
	}
	exempt, err := countryList(ctx, ctxCRLExemptCountries)
	if err != nil {
		return p, err
	}
	if p.require && (len(only) > 0 && !only[country] || exempt[country]) {
		p.require = false
	}
	return p, nil
}

// countryList reads a list of alpha-3 codes from the context as a set.
func countryList(ctx map[string]interface{}, key string) (map[string]bool, error) {
	raw, ok := ctx[key]
	if !ok || raw == nil {
		return nil, nil
	}
	var items []string
	switch v := raw.(type) {
	case []string:
		items = v
	case []interface{}:
		for _, e := range v {
			s, ok := e.(string)
			if !ok {
				return nil, fmt.Errorf("context.%s must be a list of strings", key)
			}
			items = append(items, s)
		}
	default:
		return nil, fmt.Errorf("context.%s must be a list of strings", key)
	}
	set := make(map[string]bool, len(items))
	for _, s := range items {
		set[s] = true
	}
	return set, nil
}

// Context keys through which the manager hands the policy's path-length
// setting to the registry. They are server-controlled: the manager strips
// client-supplied values (they are not in clientSuppliableContextKeys) and
// writes them only from the matching policy's `emrtd` block.
const (
	ctxPathLenMode     = "emrtd_path_len_mode"
	ctxPathLenOverride = "emrtd_path_len_override"
)

// Values of the path_len_mode policy setting.
const (
	PathLenIgnore  = "ignore"
	PathLenEnforce = "enforce"
)

// pathLenPolicy is the resolved path-length setting for one evaluation. The
// zero value ignores pathLenConstraint, which is the default behaviour.
type pathLenPolicy struct {
	enforce  bool
	override int // used when hasOver
	hasOver  bool
}

// pathLenFromContext reads the policy-derived setting from the request
// context. Anything it cannot interpret is an error, so the caller denies: a
// malformed control never silently degrades to "ignore".
func pathLenFromContext(ctx map[string]interface{}) (pathLenPolicy, error) {
	var pl pathLenPolicy
	if raw, ok := ctx[ctxPathLenMode]; ok && raw != nil {
		mode, isStr := raw.(string)
		switch {
		case !isStr:
			return pl, fmt.Errorf("context.%s must be a string", ctxPathLenMode)
		case mode == PathLenEnforce:
			pl.enforce = true
		case mode == PathLenIgnore || mode == "":
		default:
			return pl, fmt.Errorf("context.%s %q is not %q or %q", ctxPathLenMode, mode, PathLenIgnore, PathLenEnforce)
		}
	}
	if raw, ok := ctx[ctxPathLenOverride]; ok && raw != nil {
		var n int
		switch v := raw.(type) {
		case int:
			n = v
		case int64:
			n = int(v)
		case float64:
			n = int(v)
			if float64(n) != v {
				return pl, fmt.Errorf("context.%s must be an integer", ctxPathLenOverride)
			}
		default:
			return pl, fmt.Errorf("context.%s must be an integer", ctxPathLenOverride)
		}
		if n < 0 {
			return pl, fmt.Errorf("context.%s must not be negative", ctxPathLenOverride)
		}
		pl.override, pl.hasOver, pl.enforce = n, true, true
	}
	return pl, nil
}

// selfIssued reports whether a certificate's issuer and subject names are the
// same (RFC 5280 section 3.3), as for a link certificate that re-certifies a
// CSCA's new key under its unchanged name.
func selfIssued(c *x509.Certificate) bool {
	return namesEqual(c.RawIssuer, c.RawSubject, c.Issuer.String(), c.Subject.String())
}

// ownPathLen returns a certificate's pathLenConstraint, or -1 when it has none.
func ownPathLen(c *x509.Certificate) int {
	if !c.BasicConstraintsValid {
		return -1
	}
	if c.MaxPathLen > 0 || (c.MaxPathLen == 0 && c.MaxPathLenZero) {
		return c.MaxPathLen
	}
	return -1
}

// checkPathLen enforces pathLenConstraint on the issuers of a path
// DSC -> [link...] -> anchor when the policy asks for it (RFC 5280 6.1.4).
//
// For the issuer at path[i] the constraint limits the number of
// non-self-issued intermediate CAs below it, i.e. path[1..i-1]; the DSC is the
// end-entity and never counts, and self-issued certificates do not count. The
// limit is the policy override when set, otherwise the certificate's own
// pathLenConstraint (absent means unlimited). The anchor is checked like any
// other issuer.
func (r *Registry) checkPathLen(path []*x509.Certificate, pl pathLenPolicy) *authzen.EvaluationResponse {
	if !pl.enforce {
		return nil
	}
	below := 0 // non-self-issued intermediates strictly between the DSC and path[i]
	for i := 1; i < len(path); i++ {
		limit := ownPathLen(path[i])
		if pl.hasOver {
			limit = pl.override
		}
		if limit >= 0 && below > limit {
			src := "its pathLenConstraint"
			if pl.hasOver {
				src = "the path_len_override"
			}
			return r.deny(CodeChainInvalid, fmt.Sprintf("%q allows %d non-self-issued intermediate CA(s) below it by %s, but the path has %d",
				path[i].Subject.String(), limit, src, below))
		}
		if !selfIssued(path[i]) {
			below++
		}
	}
	return nil
}

// crlKey identifies one CRL/issuer-certificate pair within an evaluation.
type crlKey struct {
	crl    *crlData
	issuer string // issuer certificate DER
}

// crlVerdicts memoizes CRL signature verification for ONE evaluation. A
// request with many candidate paths would otherwise verify the same CRL
// against the same issuer once per path, spending CPU outside the
// maxSearchSteps budget. It is deliberately not shared across evaluations:
// issuers can be client-supplied link certificates, so a long-lived cache
// would grow with attacker-chosen keys.
type crlVerdicts map[crlKey]bool

// crlAuthentic reports whether the CRL is signed by a key that speaks for the
// CRL's issuer name. After a CSCA key rollover a state signs ONE CRL with its
// current key that also lists DSCs issued under earlier keys (ICAO 9303 Part
// 12), so the signer need not be the issuer on this path. Accepted signers:
//   - the issuer certificate on the validated path (as before), and
//   - any REVIEWED anchor of the claimed country whose subject name equals the
//     CRL's issuer name, i.e. every key of that CSCA name.
//
// Never accepted: another country's anchor (anchors is the claimed country's
// list), an anchor with a different name, or a certificate that is not on the
// validated path (request-supplied extras that did not chain). The caller has
// already checked that the CRL issuer name equals the revoked certificate's
// issuer name.
func (r *Registry) crlAuthentic(vc crlVerdicts, crl *crlData, pathIssuer *x509.Certificate, anchors []*anchor) bool {
	if r.crlSignatureOK(vc, crl, pathIssuer) {
		return true
	}
	for _, a := range anchors {
		if !namesEqual(crl.RawIssuer, a.cert.RawSubject, crl.Issuer.String(), a.cert.Subject.String()) {
			continue
		}
		if r.crlSignatureOK(vc, crl, a.cert) {
			return true
		}
	}
	return false
}

func (r *Registry) crlSignatureOK(vc crlVerdicts, crl *crlData, issuer *x509.Certificate) bool {
	k := crlKey{crl: crl, issuer: string(issuer.Raw)}
	if ok, seen := vc[k]; seen {
		return ok
	}
	ok := r.ext.CheckSignature(issuer, crl.SignatureAlgorithm, crl.RawTBSRevocationList, crl.Signature) == nil
	vc[k] = ok
	return ok
}
