package emrtd

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"strings"
	"time"

	"github.com/sirosfoundation/go-trust/pkg/authzen"
)

// maxChainLen bounds DSC -> link certs -> CSCA, inclusive.
const maxChainLen = 5

// maxPaths bounds the number of candidate paths explored.
const maxPaths = 16

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
	if !bytes.Equal(child.RawIssuer, parent.RawSubject) &&
		!strings.EqualFold(child.Issuer.String(), parent.Subject.String()) {
		return false, false
	}
	err := r.ext.CheckSignature(parent, child.SignatureAlgorithm, child.RawTBSCertificate, child.Signature)
	return err == nil, true
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

// buildPaths returns every structurally valid signature path
// DSC -> [link...] -> anchor. Only anchors terminate a path; extras are
// intermediates only.
func (r *Registry) buildPaths(dsc *x509.Certificate, extras []*x509.Certificate, anchors []*anchor) (paths [][]*x509.Certificate, nameMatched bool) {
	anchorRaw := make([][]byte, len(anchors))
	for i, a := range anchors {
		anchorRaw[i] = a.cert.Raw
	}
	isAnchor := func(c *x509.Certificate) bool {
		for _, raw := range anchorRaw {
			if bytes.Equal(raw, c.Raw) {
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

	var walk func(path []*x509.Certificate)
	walk = func(path []*x509.Certificate) {
		if len(paths) >= maxPaths {
			return
		}
		cur := path[len(path)-1]
		for _, a := range anchors {
			if inPath(path, a.cert) {
				continue // a certificate cannot vouch for itself
			}
			signed, named := r.issuedBy(cur, a.cert)
			nameMatched = nameMatched || named
			if signed {
				paths = append(paths, append(append([]*x509.Certificate{}, path...), a.cert))
			}
		}
		if len(path) >= maxChainLen-1 {
			return
		}
		for _, e := range extras {
			if inPath(path, e) || isAnchor(e) {
				continue
			}
			signed, _ := r.issuedBy(cur, e)
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
	return paths, nameMatched
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
			if !bytes.Equal(crl.RawIssuer, issuer.RawSubject) {
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
