package mdocrical

import (
	"crypto/x509"
	"encoding/asn1"
)

// oidExtKeyUsage is the id-ce-extKeyUsage extension.
var oidExtKeyUsage = asn1.ObjectIdentifier{2, 5, 29, 37}

// constraints returns the entry's TrustConstraints, from either spelling of the
// key.
func (i *RICALCertificateInfo) constraints() []TrustConstraint {
	if len(i.MisspeltTrustConstraints) == 0 {
		return i.TrustConstraints
	}
	return append(append([]TrustConstraint(nil), i.TrustConstraints...), i.MisspeltTrustConstraints...)
}

// intermediatesBelow is the number of certificates between the leaf and the
// certificate at index k of a leaf-first verified chain: the path length
// measured from that CA.
func intermediatesBelow(k int) int {
	if k < 1 {
		return 0
	}
	return k - 1
}

// trustConstraintsSatisfied applies F.3.2.6: the end-entity certificate is
// trusted only if at least one TrustConstraint of the governing CertificateInfo
// is fully satisfied. Constraints are evaluated independently and never
// combined.
func trustConstraintsSatisfied(constraints []TrustConstraint, leaf *x509.Certificate, intermediates int) bool {
	for _, c := range constraints {
		if constraintSatisfied(c, leaf, intermediates) {
			return true
		}
	}
	return false
}

// constraintSatisfied reports whether one TrustConstraint holds. Fail closed:
//   - extensions: constraint types this registry does not understand, so the
//     constraint is not satisfied;
//   - certificateProfiles: the registry cannot tell which profile a reader
//     certificate follows, so the constraint is not satisfied;
//   - policies: every listed OID must be a policy of the leaf;
//   - eku: the leaf must carry at least one EKU and every one must be listed;
//   - pathLen: at most that many intermediate CAs between the CA and the leaf.
func constraintSatisfied(c TrustConstraint, leaf *x509.Certificate, intermediates int) bool {
	if len(c.Extensions) > 0 || c.CertificateProfiles != nil {
		return false
	}
	if len(c.Policies) > 0 {
		have := make(map[string]bool, len(leaf.Policies))
		for _, p := range leaf.Policies {
			have[p.String()] = true
		}
		for _, want := range c.Policies {
			if !have[want] {
				return false
			}
		}
	}
	if c.EKU != nil {
		ekus, ok := leafEKUs(leaf)
		if !ok || len(ekus) == 0 {
			return false
		}
		allowed := make(map[string]bool, len(c.EKU))
		for _, o := range c.EKU {
			allowed[o] = true
		}
		for _, o := range ekus {
			if !allowed[o] {
				return false
			}
		}
	}
	if c.PathLen != nil && uint64(intermediates) > *c.PathLen {
		return false
	}
	return true
}

// leafEKUs returns the OIDs of the leaf's extended key usage extension.
func leafEKUs(leaf *x509.Certificate) ([]string, bool) {
	for _, e := range leaf.Extensions {
		if !e.Id.Equal(oidExtKeyUsage) {
			continue
		}
		var oids []asn1.ObjectIdentifier
		if rest, err := asn1.Unmarshal(e.Value, &oids); err != nil || len(rest) != 0 {
			return nil, false
		}
		out := make([]string, len(oids))
		for i, o := range oids {
			out[i] = o.String()
		}
		return out, true
	}
	return nil, true
}
