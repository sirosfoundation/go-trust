package rpcert

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"testing"
)

// orgIDName builds a Subject carrying organizationIdentifier (2.5.4.97), which
// pkix.Name has no field for, so it goes in ExtraNames.
func orgIDName(orgID, serial string) pkix.Name {
	n := pkix.Name{Country: []string{"SE"}, Organization: []string{"Test AB"}, SerialNumber: serial}
	if orgID != "" {
		n.ExtraNames = []pkix.AttributeTypeAndValue{{Type: oidOrganizationIdentifier, Value: orgID}}
	}
	return n
}

func TestSemanticIdentifier(t *testing.T) {
	legal := []asn1.ObjectIdentifier{parseOID(OIDNCPLegalPerson)}
	natural := []asn1.ObjectIdentifier{parseOID(OIDNCPNaturalPerson)}

	tests := []struct {
		name     string
		subject  pkix.Name
		policies []asn1.ObjectIdentifier
		want     string
		wantOK   bool
	}{
		{"legal person, organizationIdentifier (5.1.3)", orgIDName("VATSE-556000000101", ""), legal, "VATSE-556000000101", true},
		{"legal person, legacy serialNumber fallback", orgIDName("", "NTRSE-5560000001"), legal, "NTRSE-5560000001", true},
		{"no policy OIDs, organizationIdentifier", orgIDName("LEIXG-529900T8BM49AURSDO55", ""), nil, "LEIXG-529900T8BM49AURSDO55", true},
		{"value with an internal space", orgIDName("NTRDE-HRB 12345", ""), legal, "NTRDE-HRB 12345", true},
		// ETSI TS 119 475 5.1.5: a natural person's identifier is in serialNumber.
		{"natural person, serialNumber (5.1.5)", orgIDName("", "PNOSE-196001010101"), natural, "PNOSE-196001010101", true},
		{"natural person, passport", orgIDName("", "PASFR-12AB34567"), natural, "PASFR-12AB34567", true},
		{
			"natural person, organizationIdentifier is the affiliation, not the person",
			orgIDName("VATSE-556000000101", "PNOSE-196001010101"), natural, "PNOSE-196001010101", true,
		},
		{"natural person with only an affiliation", orgIDName("VATSE-556000000101", ""), natural, "", false},
		{"natural person, legal-person type in serialNumber", orgIDName("", "VATSE-556000000101"), natural, "", false},
		{"legal person, natural-person type", orgIDName("PNOSE-196001010101", ""), legal, "", false},
		// A serialNumber that is not a semantic identifier must not be emitted.
		{"serialNumber is a plain number", orgIDName("", "123456"), legal, "", false},
		{"serialNumber is a plain number, no policy", orgIDName("", "123456"), nil, "", false},
		{"lower-case type", orgIDName("vatse-556000000101", ""), legal, "", false},
		{"three-letter country", orgIDName("VATSWE-556000000101", ""), legal, "", false},
		{"missing hyphen", orgIDName("VATSE556000000101", ""), legal, "", false},
		{"empty value", orgIDName("VATSE-", ""), legal, "", false},
		{"trailing space", orgIDName("VATSE-5560 ", ""), legal, "", false},
		{"control character", orgIDName("VATSE-55\x01", ""), legal, "", false},
		{"nothing at all", orgIDName("", ""), legal, "", false},
		// An invalid organizationIdentifier is not papered over by serialNumber.
		{"invalid organizationIdentifier does not fall back", orgIDName("garbage", "VATSE-556000000101"), legal, "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cert := makeCert(t, certOpts{subject: tt.subject, policyOIDs: tt.policies})
			got, ok := SemanticIdentifier(cert)
			if ok != tt.wantOK || got != tt.want {
				t.Fatalf("SemanticIdentifier() = (%q, %v), want (%q, %v)", got, ok, tt.want, tt.wantOK)
			}
		})
	}

	if got, ok := SemanticIdentifier(nil); ok || got != "" {
		t.Fatalf("nil cert: got (%q, %v)", got, ok)
	}
}

func TestSubjectKindFromPolicies(t *testing.T) {
	cases := []struct {
		name     string
		policies []string
		want     SubjectKind
	}{
		{"none", nil, SubjectKindUnknown},
		{"NCP-n", []string{OIDNCPNaturalPerson}, SubjectKindNaturalPerson},
		{"QCP-n", []string{OIDQCPNaturalPerson}, SubjectKindNaturalPerson},
		{"NCP-l", []string{OIDNCPLegalPerson}, SubjectKindLegalPerson},
		{"QCP-l", []string{OIDQCPLegalPerson}, SubjectKindLegalPerson},
		{"both is contradictory", []string{OIDNCPNaturalPerson, OIDNCPLegalPerson}, SubjectKindUnknown},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var oids []asn1.ObjectIdentifier
			for _, p := range c.policies {
				oids = append(oids, parseOID(p))
			}
			cert := makeCert(t, certOpts{subject: pkix.Name{CommonName: "x"}, policyOIDs: oids})
			if got := SubjectKindFromPolicies(cert); got != c.want {
				t.Fatalf("got %v, want %v", got, c.want)
			}
		})
	}
	if SubjectKindFromPolicies(nil) != SubjectKindUnknown {
		t.Fatal("nil cert must be unknown")
	}
}

// TestWRPACProfile_ExtractIdentity_NaturalPersonSerialNumber pins the narrow
// fix to ExtractIdentity: a natural-person certificate's serialNumber is the
// person's semantic identifier (TS 119 475 5.1.5), not an organisation
// identifier, and a natural person affiliated with an organisation is still a
// natural person.
func TestWRPACProfile_ExtractIdentity_NaturalPersonSerialNumber(t *testing.T) {
	p := NewWRPACProfile()
	cert := makeCert(t, certOpts{
		subject:    orgIDName("", "PNOSE-196001010101"), // Organization is set: an affiliation
		keyUsage:   x509.KeyUsageContentCommitment,
		policyOIDs: []asn1.ObjectIdentifier{parseOID(OIDNCPNaturalPerson)},
		emails:     []string{"alice@example.test"},
	})
	identity, err := p.ExtractIdentity(cert)
	if err != nil {
		t.Fatal(err)
	}
	if identity["subject_type"] != "natural_person" {
		t.Errorf("subject_type = %v, want natural_person", identity["subject_type"])
	}
	if _, has := identity["organization_identifier"]; has {
		t.Errorf("serialNumber must not be relabelled organization_identifier: %v", identity["organization_identifier"])
	}
	if identity["serial_number"] != "PNOSE-196001010101" {
		t.Errorf("serial_number = %v, want the person's identifier kept", identity["serial_number"])
	}
}
