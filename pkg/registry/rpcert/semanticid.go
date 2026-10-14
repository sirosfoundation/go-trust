package rpcert

import (
	"crypto/x509"
	"regexp"
)

// SubjectKind classifies a WRPAC subject as a natural or legal person.
type SubjectKind int

const (
	// SubjectKindUnknown means the certificate carries no (or contradictory)
	// WRPAC policy OIDs, so its kind cannot be told from the policy.
	SubjectKindUnknown SubjectKind = iota
	// SubjectKindNaturalPerson is a certificate under NCP-n-eudiwrp or QCP-n-eudiwrp.
	SubjectKindNaturalPerson
	// SubjectKindLegalPerson is a certificate under NCP-l-eudiwrp or QCP-l-eudiwrp.
	SubjectKindLegalPerson
)

// SubjectKindFromPolicies classifies cert by its WRPAC certificate policy OIDs
// (ETSI TS 119 411-8: the -n and -l policies are what distinguish natural from
// legal person certificates). A certificate carrying both kinds, or neither,
// is SubjectKindUnknown.
func SubjectKindFromPolicies(cert *x509.Certificate) SubjectKind {
	if cert == nil {
		return SubjectKindUnknown
	}
	var natural, legal bool
	for _, oid := range CertPolicyOIDStrings(cert) {
		switch oid {
		case OIDNCPNaturalPerson, OIDQCPNaturalPerson:
			natural = true
		case OIDNCPLegalPerson, OIDQCPLegalPerson:
			legal = true
		}
	}
	switch {
	case natural && !legal:
		return SubjectKindNaturalPerson
	case legal && !natural:
		return SubjectKindLegalPerson
	}
	return SubjectKindUnknown
}

// semanticIDPattern is the EN 319 412-1 clause 5.1.3 semantics identifier
// syntax: a 3-letter identifier type, a 2-letter country code, a hyphen-minus
// and a non-empty value without leading or trailing whitespace.
var semanticIDPattern = regexp.MustCompile(`^[A-Z]{3}[A-Z]{2}-[\x21-\x7E]([\x20-\x7E]*[\x21-\x7E])?$`)

// naturalPersonSemanticTypes are the identifier types EN 319 412-1 5.1.3 defines
// for natural persons: passport, identity card, personal number, tax and
// taxpayer identification number. Every other type names a legal person.
var naturalPersonSemanticTypes = map[string]bool{
	"PAS": true, "IDC": true, "PNO": true, "TAX": true, "TIN": true,
}

// IsSemanticIdentifier reports whether s matches the semantic identifier
// syntax (3-letter type, 2-letter country, hyphen, value).
func IsSemanticIdentifier(s string) bool {
	return semanticIDPattern.MatchString(s)
}

// realOrganizationIdentifier returns only the organizationIdentifier attribute
// (2.5.4.97), without the serialNumber fallback of SubjectOrganizationIdentifier.
func realOrganizationIdentifier(cert *x509.Certificate) string {
	for _, atv := range cert.Subject.Names {
		if atv.Type.Equal(oidOrganizationIdentifier) {
			if v, ok := atv.Value.(string); ok && v != "" {
				return v
			}
		}
	}
	return ""
}

// SemanticIdentifier returns the ETSI semantic identifier of the certificate's
// subject, and false when there is none that can be trusted as one.
//
// Where it lives depends on the subject (ETSI TS 119 475 5.1.3 and 5.1.5, which
// refer to EN 319 412-1 5.1.3):
//   - legal person: organizationIdentifier (2.5.4.97), per EN 319 412-3 4.2.1.
//     The serialNumber fallback exists for older certificates and fixtures that
//     put it there.
//   - natural person: Subject serialNumber (2.5.4.5), never
//     organizationIdentifier, which would name an affiliated organization.
//
// The value must match the semantic identifier syntax, and its type must fit
// the subject: a natural-person type (PNO, IDC, PAS, TAX, TIN) is refused for a
// legal-person certificate and any other type for a natural-person one, when the
// policy OIDs tell the two apart. A serialNumber that is merely a certificate
// serial (or anything else non-semantic) is therefore never returned. An
// organizationIdentifier that is present but not valid is not papered over by
// falling back to serialNumber.
func SemanticIdentifier(cert *x509.Certificate) (string, bool) {
	if cert == nil {
		return "", false
	}
	kind := SubjectKindFromPolicies(cert)

	var candidate string
	if kind == SubjectKindNaturalPerson {
		candidate = cert.Subject.SerialNumber
	} else {
		candidate = realOrganizationIdentifier(cert)
		if candidate == "" {
			candidate = cert.Subject.SerialNumber
		}
	}

	if !IsSemanticIdentifier(candidate) {
		return "", false
	}
	isNaturalType := naturalPersonSemanticTypes[candidate[:3]]
	switch kind {
	case SubjectKindNaturalPerson:
		if !isNaturalType {
			return "", false
		}
	case SubjectKindLegalPerson:
		if isNaturalType {
			return "", false
		}
	}
	return candidate, true
}
