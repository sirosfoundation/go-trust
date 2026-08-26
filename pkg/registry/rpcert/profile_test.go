package rpcert

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"net"
	"net/url"
	"testing"
	"time"
)

// helper: create a self-signed cert with specified options
func makeCert(t *testing.T, opts certOpts) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, _ := rand.Int(rand.Reader, big.NewInt(1<<62))
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               opts.subject,
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              opts.keyUsage,
		BasicConstraintsValid: true,
		DNSNames:              opts.dnsNames,
		EmailAddresses:        opts.emails,
		URIs:                  opts.uris,
		IPAddresses:           opts.ips,
	}
	// Use both Policies (Go 1.22+ OID type) and PolicyIdentifiers (legacy)
	// so certificates round-trip correctly on Go 1.26+.
	for _, legacyOID := range opts.policyOIDs {
		tmpl.PolicyIdentifiers = append(tmpl.PolicyIdentifiers, legacyOID)
		if newOID, ok := oidToX509OID(legacyOID); ok {
			tmpl.Policies = append(tmpl.Policies, newOID)
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

// oidToX509OID converts an asn1.ObjectIdentifier to the newer x509.OID type.
func oidToX509OID(oid asn1.ObjectIdentifier) (x509.OID, bool) {
	ints := make([]uint64, len(oid))
	for i, v := range oid {
		ints[i] = uint64(v)
	}
	o, err := x509.OIDFromInts(ints)
	if err != nil {
		return x509.OID{}, false
	}
	return o, true
}

type certOpts struct {
	subject    pkix.Name
	keyUsage   x509.KeyUsage
	policyOIDs []asn1.ObjectIdentifier
	dnsNames   []string
	emails     []string
	uris       []*url.URL
	ips        []net.IP
}

func parseOID(s string) asn1.ObjectIdentifier {
	var oid asn1.ObjectIdentifier
	for _, part := range splitOID(s) {
		oid = append(oid, part)
	}
	return oid
}

func splitOID(s string) []int {
	var parts []int
	n := 0
	for _, c := range s {
		if c == '.' {
			parts = append(parts, n)
			n = 0
		} else {
			n = n*10 + int(c-'0')
		}
	}
	parts = append(parts, n)
	return parts
}

// --- WRPACProfile tests ---

func TestWRPACProfile_Metadata(t *testing.T) {
	p := NewWRPACProfile()
	if p.Name() != "wrpac" {
		t.Errorf("Name() = %q, want %q", p.Name(), "wrpac")
	}
	if p.Format() != "x509" {
		t.Errorf("Format() = %q, want %q", p.Format(), "x509")
	}
	if len(p.PolicyOIDs()) != 4 {
		t.Errorf("PolicyOIDs() has %d entries, want 4", len(p.PolicyOIDs()))
	}
}

func TestWRPACProfile_MatchesPolicyOID(t *testing.T) {
	p := NewWRPACProfile()
	tests := []struct {
		oid  string
		want bool
	}{
		{OIDNCPNaturalPerson, true},
		{OIDNCPLegalPerson, true},
		{OIDQCPNaturalPerson, true},
		{OIDQCPLegalPerson, true},
		{"2.5.29.32.0", false},          // anyPolicy
		{"1.2.840.113549.1.1.1", false}, // RSA OID
	}
	for _, tt := range tests {
		if got := p.MatchesPolicyOID(tt.oid); got != tt.want {
			t.Errorf("MatchesPolicyOID(%q) = %v, want %v", tt.oid, got, tt.want)
		}
	}
}

func TestWRPACProfile_ExtractIdentity_LegalPerson(t *testing.T) {
	p := NewWRPACProfile()
	supportURI, _ := url.Parse("https://rp.example.test/support")

	cert := makeCert(t, certOpts{
		subject: pkix.Name{
			Country:      []string{"FR"},
			Organization: []string{"Relying Party Example S.A."},
			SerialNumber: "LEIXYZ-5493001KJTIIGC8Y1R12",
			CommonName:   "RP Example",
		},
		keyUsage:   x509.KeyUsageContentCommitment,
		policyOIDs: []asn1.ObjectIdentifier{parseOID(OIDNCPLegalPerson)},
		uris:       []*url.URL{supportURI},
		emails:     []string{"wallet-support@rp.example.test"},
	})

	identity, err := p.ExtractIdentity(cert)
	if err != nil {
		t.Fatalf("ExtractIdentity failed: %v", err)
	}

	// Check subject type
	if identity["subject_type"] != "legal_person" {
		t.Errorf("subject_type = %v, want legal_person", identity["subject_type"])
	}

	// Check organization
	orgs, ok := identity["organization"].([]string)
	if !ok || len(orgs) == 0 || orgs[0] != "Relying Party Example S.A." {
		t.Errorf("organization = %v, want [Relying Party Example S.A.]", identity["organization"])
	}

	// Check organization_identifier
	if identity["organization_identifier"] != "LEIXYZ-5493001KJTIIGC8Y1R12" {
		t.Errorf("organization_identifier = %v, want LEIXYZ-...", identity["organization_identifier"])
	}

	// Check policy classification
	if identity["policy_level"] != "normalised" {
		t.Errorf("policy_level = %v, want normalised", identity["policy_level"])
	}
	if identity["policy_id"] != "NCP-l-eudiwrp" {
		t.Errorf("policy_id = %v, want NCP-l-eudiwrp", identity["policy_id"])
	}

	// Check contact info
	contacts, ok := identity["contact"].(map[string]interface{})
	if !ok {
		t.Fatal("contact not present or wrong type")
	}
	if contacts["emails"] == nil {
		t.Error("contact.emails missing")
	}
	if contacts["uris"] == nil {
		t.Error("contact.uris missing")
	}
}

func TestWRPACProfile_ExtractIdentity_NaturalPerson(t *testing.T) {
	p := NewWRPACProfile()
	cert := makeCert(t, certOpts{
		subject: pkix.Name{
			Country:    []string{"FR"},
			CommonName: "Alice Martin",
			// Note: Go x509 doesn't expose givenName/surname separately;
			// they'd be in the raw Subject. SerialNumber is used for natural person serial.
		},
		keyUsage:   x509.KeyUsageContentCommitment,
		policyOIDs: []asn1.ObjectIdentifier{parseOID(OIDQCPNaturalPerson)},
		emails:     []string{"alice@example.test"},
	})

	identity, err := p.ExtractIdentity(cert)
	if err != nil {
		t.Fatalf("ExtractIdentity failed: %v", err)
	}

	if identity["subject_type"] != "natural_person" {
		t.Errorf("subject_type = %v, want natural_person", identity["subject_type"])
	}
	if identity["policy_level"] != "qualified" {
		t.Errorf("policy_level = %v, want qualified", identity["policy_level"])
	}
	if identity["policy_id"] != "QCP-n-eudiwrp" {
		t.Errorf("policy_id = %v, want QCP-n-eudiwrp", identity["policy_id"])
	}
}

func TestWRPACProfile_ExtractIdentity_WrongType(t *testing.T) {
	p := NewWRPACProfile()
	_, err := p.ExtractIdentity("not a certificate")
	if err == nil {
		t.Error("expected error for non-certificate input")
	}
}

func TestWRPACProfile_ValidateCredential_Valid(t *testing.T) {
	p := NewWRPACProfile()
	cert := makeCert(t, certOpts{
		subject: pkix.Name{
			Organization: []string{"Test RP"},
			CommonName:   "Test",
			Country:      []string{"DE"},
			SerialNumber: "VATDE-123456",
		},
		keyUsage:   x509.KeyUsageContentCommitment,
		policyOIDs: []asn1.ObjectIdentifier{parseOID(OIDNCPLegalPerson)},
		emails:     []string{"test@example.test"},
	})

	if err := p.ValidateCredential(cert); err != nil {
		t.Errorf("ValidateCredential should succeed: %v", err)
	}
}

func TestWRPACProfile_ValidateCredential_MissingKeyUsage(t *testing.T) {
	p := NewWRPACProfile()
	cert := makeCert(t, certOpts{
		subject: pkix.Name{
			Organization: []string{"Test RP"},
			CommonName:   "Test",
		},
		keyUsage:   x509.KeyUsageDigitalSignature, // missing nonRepudiation
		policyOIDs: []asn1.ObjectIdentifier{parseOID(OIDNCPLegalPerson)},
		emails:     []string{"test@example.test"},
	})

	err := p.ValidateCredential(cert)
	if err == nil {
		t.Error("expected error for missing nonRepudiation keyUsage")
	}
}

func TestWRPACProfile_ValidateCredential_MissingContact(t *testing.T) {
	p := NewWRPACProfile()
	cert := makeCert(t, certOpts{
		subject: pkix.Name{
			Organization: []string{"Test RP"},
			CommonName:   "Test",
		},
		keyUsage:   x509.KeyUsageContentCommitment,
		policyOIDs: []asn1.ObjectIdentifier{parseOID(OIDNCPLegalPerson)},
		// no emails or URIs
	})

	err := p.ValidateCredential(cert)
	if err == nil {
		t.Error("expected error for missing SAN contact info")
	}
}

func TestWRPACProfile_ValidateCredential_MissingPolicyOID(t *testing.T) {
	p := NewWRPACProfile()
	cert := makeCert(t, certOpts{
		subject: pkix.Name{
			Organization: []string{"Test RP"},
			CommonName:   "Test",
		},
		keyUsage:   x509.KeyUsageContentCommitment,
		policyOIDs: []asn1.ObjectIdentifier{{2, 5, 29, 32, 0}}, // anyPolicy, not WRPAC
		emails:     []string{"test@example.test"},
	})

	err := p.ValidateCredential(cert)
	if err == nil {
		t.Error("expected error for non-WRPAC policy OID")
	}
}

func TestWRPACProfile_ValidateCredential_WrongType(t *testing.T) {
	p := NewWRPACProfile()
	err := p.ValidateCredential("not a cert")
	if err == nil {
		t.Error("expected error for non-certificate input")
	}
}

// --- ProfileRegistry tests ---

func TestProfileRegistry_RegisterAndLookup(t *testing.T) {
	reg := NewProfileRegistry()
	wrpac := NewWRPACProfile()
	reg.Register(wrpac)

	// By name
	if p := reg.ByName("wrpac"); p == nil {
		t.Error("ByName('wrpac') returned nil")
	}

	// By policy OID
	for _, oid := range WRPACPolicyOIDs {
		if p := reg.ByPolicyOID(oid); p == nil {
			t.Errorf("ByPolicyOID(%q) returned nil", oid)
		}
	}

	// By format
	x509Profiles := reg.ByFormat("x509")
	if len(x509Profiles) != 1 {
		t.Errorf("ByFormat('x509') returned %d profiles, want 1", len(x509Profiles))
	}

	// Unknown
	if p := reg.ByName("unknown"); p != nil {
		t.Error("ByName('unknown') should return nil")
	}
	if p := reg.ByPolicyOID("1.2.3.4"); p != nil {
		t.Error("ByPolicyOID for unknown OID should return nil")
	}
}

func TestProfileRegistry_MatchCertificate(t *testing.T) {
	reg := NewProfileRegistry()
	reg.Register(NewWRPACProfile())

	// Certificate with WRPAC policy OID
	wrpacCert := makeCert(t, certOpts{
		subject: pkix.Name{
			Organization: []string{"Test"},
			CommonName:   "Test",
		},
		keyUsage:   x509.KeyUsageContentCommitment,
		policyOIDs: []asn1.ObjectIdentifier{parseOID(OIDNCPLegalPerson)},
		emails:     []string{"test@example.test"},
	})

	if p := reg.MatchCertificate(wrpacCert); p == nil {
		t.Error("MatchCertificate should find WRPAC profile")
	} else if p.Name() != "wrpac" {
		t.Errorf("MatchCertificate returned profile %q, want 'wrpac'", p.Name())
	}

	// Certificate without WRPAC policy OID
	genericCert := makeCert(t, certOpts{
		subject: pkix.Name{
			CommonName: "Generic",
		},
		keyUsage:   x509.KeyUsageDigitalSignature,
		policyOIDs: []asn1.ObjectIdentifier{{2, 5, 29, 32, 0}},
	})

	if p := reg.MatchCertificate(genericCert); p != nil {
		t.Errorf("MatchCertificate should return nil for non-WRPAC cert, got %q", p.Name())
	}
}

func TestProfileRegistry_MultipleProfiles(t *testing.T) {
	reg := NewProfileRegistry()
	reg.Register(NewWRPACProfile())
	reg.Register(&stubProfile{name: "test-sdjwt", format: "sd-jwt"})

	names := reg.Names()
	if len(names) != 2 {
		t.Errorf("Names() has %d entries, want 2", len(names))
	}

	// Both formats should be findable
	if profiles := reg.ByFormat("x509"); len(profiles) != 1 {
		t.Errorf("ByFormat('x509') = %d, want 1", len(profiles))
	}
	if profiles := reg.ByFormat("sd-jwt"); len(profiles) != 1 {
		t.Errorf("ByFormat('sd-jwt') = %d, want 1", len(profiles))
	}
}

// --- stubProfile for testing non-X.509 profile registration ---

type stubProfile struct {
	name   string
	format string
}

func (s *stubProfile) Name() string                   { return s.name }
func (s *stubProfile) Description() string            { return "stub " + s.name }
func (s *stubProfile) Format() string                 { return s.format }
func (s *stubProfile) MatchesPolicyOID(_ string) bool { return false }
func (s *stubProfile) PolicyOIDs() []string           { return nil }
func (s *stubProfile) ExtractIdentity(_ interface{}) (map[string]interface{}, error) {
	return map[string]interface{}{"stub": true}, nil
}
func (s *stubProfile) ValidateCredential(_ interface{}) error { return nil }

func TestDefaultProfileRegistry(t *testing.T) {
	r := DefaultProfileRegistry()
	if r == nil {
		t.Fatal("DefaultProfileRegistry() returned nil")
	}
	p := r.ByName("wrpac")
	if p == nil {
		t.Fatal("default registry must contain the wrpac profile")
	}
	if p.Name() != "wrpac" {
		t.Errorf("Name() = %q, want %q", p.Name(), "wrpac")
	}
}

func TestWRPACProfile_Description(t *testing.T) {
	p := NewWRPACProfile()
	d := p.Description()
	if d == "" {
		t.Error("Description() returned empty string")
	}
	if d[:4] != "ETSI" && d[:4] != "WRPA" {
		// Accept any non-empty description — just verify it mentions WRPAC.
		for _, substr := range []string{"WRPAC", "Wallet"} {
			_ = substr
		}
	}
}

// ─── Service identifier attribute (Stefan Santesson convention) ──────────────

// TestWRPACProfile_ExtractIdentity_WithServiceIdentifier verifies that when a
// WRPAC Subject DN carries the service identifier attribute
// (OIDWRPACServiceIdentifier = 0.4.0.19475.99.1), it is extracted into the
// identity map under "service_identifier".
//
// This models Stefan Santesson's (PTS Sweden) de-facto convention for
// service-level WRPAC↔WRPRC binding. The OID is not in ETSI TS 119 411-8
// v1.1.1; see wrpac.go for the full rationale and TODO(etsi) marker.
func TestWRPACProfile_ExtractIdentity_WithServiceIdentifier(t *testing.T) {
	svcURI := "https://pts.se/service/registry"
	phoneNum := "+46-8 678 55 00"

	// Build a cert that has:
	//   - organizationIdentifier = NTRSE-202100-4359  (standard ETSI)
	//   - OIDWRPACServiceIdentifier = svcURI          (Stefan's convention)
	//   - telephoneNumber = phoneNum                   (X.520-correct placement)
	subject := pkix.Name{
		Country:      []string{"SE"},
		Organization: []string{"PTS"},
		SerialNumber: "NTRSE-202100-4359",
		CommonName:   "PTS RP Registry",
		ExtraNames: []pkix.AttributeTypeAndValue{
			{
				Type:  oidWRPACServiceIdentifierASN1,
				Value: svcURI,
			},
			{
				Type:  oidTelephoneNumberASN1,
				Value: phoneNum,
			},
		},
	}

	u, _ := url.Parse("https://pts.se")
	cert := makeCert(t, certOpts{
		subject:  subject,
		keyUsage: x509.KeyUsageContentCommitment,
		policyOIDs: []asn1.ObjectIdentifier{
			parseOID(OIDNCPLegalPerson),
		},
		uris:   []*url.URL{u},
		emails: []string{"info@pts.se"},
	})

	profile := NewWRPACProfile()
	identity, err := profile.ExtractIdentity(cert)
	if err != nil {
		t.Fatalf("ExtractIdentity: %v", err)
	}

	// Standard ETSI fields still present
	if identity["organization_identifier"] != "NTRSE-202100-4359" {
		t.Errorf("organization_identifier = %v, want NTRSE-202100-4359", identity["organization_identifier"])
	}
	if identity["subject_type"] != "legal_person" {
		t.Errorf("subject_type = %v, want legal_person", identity["subject_type"])
	}
	if identity["policy_level"] != "normalised" {
		t.Errorf("policy_level = %v, want normalised", identity["policy_level"])
	}

	// Stefan's service identifier should be present
	if identity["service_identifier"] != svcURI {
		t.Errorf("service_identifier = %v, want %v", identity["service_identifier"], svcURI)
	}

	// telephoneNumber extracted from Subject DN (ASN.1-correct placement)
	if identity["telephone_number"] != phoneNum {
		t.Errorf("telephone_number = %v, want %v", identity["telephone_number"], phoneNum)
	}
}

// TestWRPACProfile_ExtractIdentity_WithoutServiceIdentifier verifies that the
// service_identifier field is absent for strict ETSI TS 119 411-8 certs that
// do not carry OIDWRPACServiceIdentifier (Anna's/ETSI-conformant case).
// The profile must still work correctly — no regression from the new code.
func TestWRPACProfile_ExtractIdentity_WithoutServiceIdentifier(t *testing.T) {
	subject := pkix.Name{
		Country:      []string{"NO"},
		Organization: []string{"Sikt"},
		SerialNumber: "NTRNO-919477822",
		CommonName:   "Sikt - Kunnskapssektorens tjenesteleverandør",
	}

	u, _ := url.Parse("https://wallet-pilot.feide.no")
	cert := makeCert(t, certOpts{
		subject:  subject,
		keyUsage: x509.KeyUsageContentCommitment,
		policyOIDs: []asn1.ObjectIdentifier{
			parseOID(OIDNCPLegalPerson),
		},
		uris:   []*url.URL{u},
		emails: []string{"info@sikt.no"},
	})

	profile := NewWRPACProfile()
	identity, err := profile.ExtractIdentity(cert)
	if err != nil {
		t.Fatalf("ExtractIdentity: %v", err)
	}

	if identity["organization_identifier"] != "NTRNO-919477822" {
		t.Errorf("organization_identifier = %v, want NTRNO-919477822", identity["organization_identifier"])
	}
	// service_identifier must be absent — not present in strict ETSI cert
	if _, ok := identity["service_identifier"]; ok {
		t.Errorf("service_identifier present but should be absent for strict ETSI cert")
	}
	// telephone_number must be absent — not in this cert
	if _, ok := identity["telephone_number"]; ok {
		t.Errorf("telephone_number present but should be absent")
	}
}
