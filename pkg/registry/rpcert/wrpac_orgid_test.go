package rpcert

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newSubjectCert mints a certificate whose subject DN carries exactly the
// attributes given, so each test controls which of the two the value lives in.
func newSubjectCert(t *testing.T, serialNumber string, extra []pkix.AttributeTypeAndValue) *x509.Certificate {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   "rp.example.com",
			Organization: []string{"Example RP"},
			SerialNumber: serialNumber,
			ExtraNames:   extra,
		},
		NotBefore: time.Now().Add(-time.Hour),
		NotAfter:  time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return cert
}

func orgIDAttr(v string) []pkix.AttributeTypeAndValue {
	return []pkix.AttributeTypeAndValue{{
		Type:  asn1.ObjectIdentifier{2, 5, 4, 97},
		Value: v,
	}}
}

// TestSubjectOrganizationIdentifier covers where the value may live.
//
// EN 319 412-3 clause 4.2.1 requires organizationIdentifier (2.5.4.97) for a
// legal person. Go's pkix.Name has no field for it, so it surfaces only in
// Subject.Names — reading Subject.SerialNumber instead returns nothing for a
// conformant certificate while still appearing to work against fixtures that
// put the value in serialNumber.
func TestSubjectOrganizationIdentifier(t *testing.T) {
	t.Run("reads organizationIdentifier 2.5.4.97", func(t *testing.T) {
		cert := newSubjectCert(t, "", orgIDAttr("VATSE-5560000000"))
		assert.Equal(t, "VATSE-5560000000", SubjectOrganizationIdentifier(cert))
	})

	t.Run("falls back to serialNumber when 2.5.4.97 is absent", func(t *testing.T) {
		cert := newSubjectCert(t, "NTRSE-1234567890", nil)
		assert.Equal(t, "NTRSE-1234567890", SubjectOrganizationIdentifier(cert))
	})

	t.Run("prefers organizationIdentifier when both are present", func(t *testing.T) {
		// siros-wrpac-tool currently writes both so the two readings agree.
		// Once this ships, the conformant attribute is authoritative and that
		// dual write can be dropped.
		cert := newSubjectCert(t, "serial-value", orgIDAttr("orgid-value"))
		assert.Equal(t, "orgid-value", SubjectOrganizationIdentifier(cert))
	})

	t.Run("neither present", func(t *testing.T) {
		assert.Empty(t, SubjectOrganizationIdentifier(newSubjectCert(t, "", nil)))
	})

	t.Run("nil certificate", func(t *testing.T) {
		assert.Empty(t, SubjectOrganizationIdentifier(nil))
	})
}

// TestExtractIdentity_OrganizationIdentifier is the regression that matters:
// a conformant WRPAC must yield an organization_identifier, because the
// WRPAC-to-WRPRC binding check (ARF RPRC_16) compares against it. Reading the
// wrong attribute made a valid certificate look like one carrying no
// identifier at all.
func TestExtractIdentity_OrganizationIdentifier(t *testing.T) {
	profile := NewWRPACProfile()

	t.Run("conformant certificate yields the identifier", func(t *testing.T) {
		cert := newSubjectCert(t, "", orgIDAttr("VATSE-5560000000"))
		identity, err := profile.ExtractIdentity(cert)
		require.NoError(t, err)
		assert.Equal(t, "VATSE-5560000000", identity["organization_identifier"])
		assert.NotContains(t, identity, "serial_number",
			"the identifier is reported once, under its own name")
	})

	t.Run("legacy serialNumber-only certificate still resolves", func(t *testing.T) {
		cert := newSubjectCert(t, "NTRSE-1234567890", nil)
		identity, err := profile.ExtractIdentity(cert)
		require.NoError(t, err)
		assert.Equal(t, "NTRSE-1234567890", identity["organization_identifier"])
	})

	t.Run("subject_type is legal_person when an organisation is present", func(t *testing.T) {
		cert := newSubjectCert(t, "", orgIDAttr("VATSE-5560000000"))
		identity, err := profile.ExtractIdentity(cert)
		require.NoError(t, err)
		assert.Equal(t, "legal_person", identity["subject_type"])
	})
}
