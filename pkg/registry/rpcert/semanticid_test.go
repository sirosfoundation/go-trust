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
		// Unclassified: organizationIdentifier could be a natural person's affiliation.
		{"no policy OIDs, organizationIdentifier", orgIDName("LEIXG-529900T8BM49AURSDO55", ""), nil, "", false},
		{"no policy OIDs, serialNumber", orgIDName("", "PNOSE-196001010101"), nil, "", false},
		{"no policy OIDs, natural person with affiliation", orgIDName("VATSE-556000000101", "PNOSE-196001010101"), nil, "", false},
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

// Neither a contradictory nor a missing classification yields a semantic
// identifier; only a certificate that is clearly one kind does.
func TestSemanticIdentifier_ContradictoryPoliciesFailClosed(t *testing.T) {
	both := []asn1.ObjectIdentifier{parseOID(OIDNCPNaturalPerson), parseOID(OIDNCPLegalPerson)}
	for _, subject := range []pkix.Name{
		orgIDName("VATSE-556000000101", ""),
		orgIDName("", "PNOSE-196001010101"),
		orgIDName("", "VATSE-556000000101"),
	} {
		cert := makeCert(t, certOpts{subject: subject, policyOIDs: both})
		if got, ok := SemanticIdentifier(cert); ok || got != "" {
			t.Fatalf("contradictory policies must not yield a semantic id, got (%q, %v)", got, ok)
		}
		if got, ok := SemanticIdentifier(makeCert(t, certOpts{subject: subject})); ok || got != "" {
			t.Fatalf("policy-less certificate with %v must not yield one, got (%q, %v)", subject, got, ok)
		}
	}
}

// An organizationIdentifier that is present but empty or not a string is
// malformed, not absent: it must not be papered over by a valid serialNumber.
func TestSemanticIdentifier_MalformedOrganizationIdentifierDoesNotFallBack(t *testing.T) {
	for name, value := range map[string]interface{}{"empty string": "", "non-string value": 42} {
		for _, policies := range [][]asn1.ObjectIdentifier{nil, {parseOID(OIDNCPLegalPerson)}} {
			subject := pkix.Name{
				Country: []string{"SE"}, Organization: []string{"Test AB"}, SerialNumber: "VATSE-556000000101",
				ExtraNames: []pkix.AttributeTypeAndValue{{Type: oidOrganizationIdentifier, Value: value}},
			}
			cert := makeCert(t, certOpts{subject: subject, policyOIDs: policies})
			if _, present := organizationIdentifierAttr(cert); !present {
				t.Fatalf("%s: fixture must carry the attribute", name)
			}
			if got, ok := SemanticIdentifier(cert); ok || got != "" {
				t.Fatalf("%s (policies %v): got (%q, %v), want none", name, policies, got, ok)
			}
		}
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
		{"both is contradictory", []string{OIDNCPNaturalPerson, OIDNCPLegalPerson}, SubjectKindContradictory},
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
func TestWRPACProfile_ExtractIdentity_NaturalPersonWithAffiliationID(t *testing.T) {
	p := NewWRPACProfile()
	cert := makeCert(t, certOpts{
		// serialNumber is the person's identifier; 2.5.4.97 names the affiliated organisation.
		subject:    orgIDName("VATSE-556000000101", "PNOSE-196001010101"),
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
	if identity["serial_number"] != "PNOSE-196001010101" {
		t.Errorf("serial_number = %v, want the person's identifier preserved", identity["serial_number"])
	}
	if identity["organization_identifier"] != "VATSE-556000000101" {
		t.Errorf("organization_identifier = %v, want the real organisation identifier exposed", identity["organization_identifier"])
	}
}

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
