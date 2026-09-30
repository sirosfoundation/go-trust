package emrtd

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"strings"
	"time"

	"github.com/sirosfoundation/go-trust/pkg/authzen"
)

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

func pemDecode(data []byte) ([]byte, []byte) {
	blk, rest := pem.Decode(data)
	if blk == nil {
		return nil, rest
	}
	return blk.Bytes, rest
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
// the request: they must be CA certificates allowed to sign certificates.
// Anchors are exempt: they are human-reviewed, and some legacy CSCAs lack
// basicConstraints. pathLenConstraint is deliberately not enforced; chain
// length is bounded by maxChainLen instead.
func canIssue(c *x509.Certificate) bool {
	if !c.BasicConstraintsValid || !c.IsCA {
		return false
	}
	return c.KeyUsage == 0 || c.KeyUsage&x509.KeyUsageCertSign != 0
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
			signed, _ := check(cur, e)
			if !signed {
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

// checkPath applies time, key-usage and revocation checks to a candidate path.
// It returns nil when the path is acceptable.
func (r *Registry) checkPath(path []*x509.Certificate, at time.Time, crls []*x509.RevocationList) *authzen.EvaluationResponse {
	// Validity is evaluated at document signing time, not wall clock, per
	// ICAO 9303 Part 12 (the DSC of an old passport is long expired at now).
	// Every certificate on the path is checked, CSCA and link certificates too.
	for _, c := range path {
		if at.Before(c.NotBefore) {
			return r.deny(CodeNotYetValid, fmt.Sprintf("%q is not valid before %s (evaluated at %s)",
				c.Subject.String(), c.NotBefore.Format(time.RFC3339), at.Format(time.RFC3339)))
		}
		if at.After(c.NotAfter) {
			return r.deny(CodeExpired, fmt.Sprintf("%q expired %s (evaluated at %s)",
				c.Subject.String(), c.NotAfter.Format(time.RFC3339), at.Format(time.RFC3339)))
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
	if dsc.KeyUsage != 0 && dsc.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		return r.deny(CodeBadKeyUsage, "DSC keyUsage does not include digitalSignature")
	}

	// Revocation. A certificate listed on any verified CRL of its issuer is
	// revoked, regardless of the revocation date relative to signing time
	// (fail closed: we cannot tell when the key was actually compromised).
	// A CRL whose signature does not verify against the issuer is ignored,
	// not believed. A CRL past nextUpdate still counts for positive hits:
	// staleness never un-revokes a certificate. No CRL for an issuer means
	// no revocation information, which is not a denial.
	for i := 0; i < len(path)-1; i++ {
		cert, issuer := path[i], path[i+1]
		for _, crl := range crls {
			if !namesEqual(crl.RawIssuer, issuer.RawSubject, crl.Issuer.String(), issuer.Subject.String()) {
				continue
			}
			if weakSigAlg(crl.SignatureAlgorithm) {
				continue
			}
			if r.ext.CheckSignature(issuer, crl.SignatureAlgorithm, crl.RawTBSRevocationList, crl.Signature) != nil {
				continue
			}
			for _, e := range crl.RevokedCertificateEntries {
				if e.SerialNumber.Cmp(cert.SerialNumber) == 0 {
					return r.deny(CodeRevoked, fmt.Sprintf("%q (serial %s) is revoked by CRL", cert.Subject.String(), cert.SerialNumber))
				}
			}
		}
	}
	return nil
}
