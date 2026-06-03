package rpcert

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// RPEntitlements
// ---------------------------------------------------------------------------

func TestRPEntitlements_IsValid(t *testing.T) {
	now := time.Now()
	past := now.Add(-time.Hour)
	future := now.Add(time.Hour)
	farFuture := now.Add(24 * time.Hour)

	tests := []struct {
		name  string
		ent   RPEntitlements
		valid bool
	}{
		{
			name:  "registered with valid period",
			ent:   RPEntitlements{RegistrationStatus: StatusRegistered, ValidFrom: &past, ValidUntil: &future},
			valid: true,
		},
		{
			name:  "registered without period",
			ent:   RPEntitlements{RegistrationStatus: StatusRegistered},
			valid: true,
		},
		{
			name:  "suspended",
			ent:   RPEntitlements{RegistrationStatus: StatusSuspended},
			valid: false,
		},
		{
			name:  "revoked",
			ent:   RPEntitlements{RegistrationStatus: StatusRevoked},
			valid: false,
		},
		{
			name:  "not found",
			ent:   RPEntitlements{RegistrationStatus: StatusNotFound},
			valid: false,
		},
		{
			name:  "not yet valid",
			ent:   RPEntitlements{RegistrationStatus: StatusRegistered, ValidFrom: &future, ValidUntil: &farFuture},
			valid: false,
		},
		{
			name:  "expired",
			ent:   RPEntitlements{RegistrationStatus: StatusRegistered, ValidFrom: &past, ValidUntil: &past},
			valid: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.valid, tt.ent.IsValid())
		})
	}
}

// ---------------------------------------------------------------------------
// DetectOverRequest
// ---------------------------------------------------------------------------

func TestDetectOverRequest(t *testing.T) {
	tests := []struct {
		name      string
		ent       *RPEntitlements
		requested []string
		overReq   bool
		overAttrs []string
	}{
		{
			name:      "no over-request",
			ent:       &RPEntitlements{AllowedAttributes: []string{"family_name", "given_name", "birth_date"}},
			requested: []string{"family_name", "given_name"},
			overReq:   false,
		},
		{
			name:      "over-request detected",
			ent:       &RPEntitlements{AllowedAttributes: []string{"family_name"}},
			requested: []string{"family_name", "birth_date", "address"},
			overReq:   true,
			overAttrs: []string{"birth_date", "address"},
		},
		{
			name:      "nil entitlements",
			ent:       nil,
			requested: []string{"family_name"},
			overReq:   false,
		},
		{
			name:      "empty allowed attributes",
			ent:       &RPEntitlements{AllowedAttributes: []string{}},
			requested: []string{"family_name"},
			overReq:   false,
		},
		{
			name:      "exact match",
			ent:       &RPEntitlements{AllowedAttributes: []string{"a", "b"}},
			requested: []string{"a", "b"},
			overReq:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := DetectOverRequest(tt.ent, tt.requested)
			assert.Equal(t, tt.overReq, result.IsOverRequest)
			if tt.overAttrs != nil {
				assert.Equal(t, tt.overAttrs, result.OverRequested)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// ValidatorRegistry
// ---------------------------------------------------------------------------

func TestValidatorRegistry(t *testing.T) {
	reg := NewValidatorRegistry()

	// Get unregistered
	_, err := reg.Get("x509")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no registration certificate validator")

	// Register
	v := NewX509RegistrationCertValidator(nil)
	reg.Register("x509", v)

	// Get registered
	got, err := reg.Get("x509")
	require.NoError(t, err)
	assert.Equal(t, "x509", got.Format())

	// Formats
	formats := reg.Formats()
	assert.Contains(t, formats, "x509")
}

// ---------------------------------------------------------------------------
// DefaultConfig
// ---------------------------------------------------------------------------

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()
	assert.Equal(t, "x509", cfg.CertFormat)
	assert.False(t, cfg.StrictEntitlementCheck)
	assert.True(t, cfg.AllowWithoutWRPRC)
	assert.Equal(t, 10*time.Second, cfg.Timeout)
}

// ---------------------------------------------------------------------------
// X509RegistrationCertValidator
// ---------------------------------------------------------------------------

func generateTestCert(t *testing.T) (*x509.Certificate, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Test RP Corp"},
			CommonName:   "test-rp.example.com",
			Country:      []string{"SE"},
			SerialNumber: "RP-12345",
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		IsCA:                  true,
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)

	pemData := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	return cert, pemData
}

func TestX509Validator_ValidateSuccess(t *testing.T) {
	cert, pemData := generateTestCert(t)

	// Create a pool with the self-signed cert as root
	pool := x509.NewCertPool()
	pool.AddCert(cert)

	v := NewX509RegistrationCertValidator(pool)
	assert.Equal(t, "x509", v.Format())

	ent, err := v.Validate(context.Background(), pemData)
	require.NoError(t, err)
	require.NotNil(t, ent)

	assert.Equal(t, StatusRegistered, ent.RegistrationStatus)
	assert.Equal(t, "RP-12345", ent.RPIdentifier)
	assert.True(t, ent.IsValid())
	assert.NotNil(t, ent.ValidFrom)
	assert.NotNil(t, ent.ValidUntil)
}

func TestX509Validator_ValidateNoRoots(t *testing.T) {
	_, pemData := generateTestCert(t)

	// nil roots = error (no trust anchors configured)
	v := NewX509RegistrationCertValidator(nil)
	_, err := v.Validate(context.Background(), pemData)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no trust anchors configured")
}

func TestX509Validator_ValidateUntrustedChain(t *testing.T) {
	_, pemData := generateTestCert(t)

	// Empty pool = no trusted roots
	pool := x509.NewCertPool()
	v := NewX509RegistrationCertValidator(pool)

	_, err := v.Validate(context.Background(), pemData)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "chain validation failed")
}

func TestX509Validator_ValidateInvalidPEM(t *testing.T) {
	v := NewX509RegistrationCertValidator(x509.NewCertPool())

	_, err := v.Validate(context.Background(), []byte("not pem data"))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no CERTIFICATE PEM block")
}

func TestX509Validator_ValidateInvalidCert(t *testing.T) {
	v := NewX509RegistrationCertValidator(x509.NewCertPool())

	badPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("not a cert")})
	_, err := v.Validate(context.Background(), badPEM)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse")
}

// ---------------------------------------------------------------------------
// StubRegisterClient
// ---------------------------------------------------------------------------

func TestStubRegisterClient(t *testing.T) {
	c := NewStubRegisterClient("https://register.example.com")
	assert.True(t, c.Healthy())

	_, err := c.LookupRP(context.Background(), "RP-12345")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not implemented")

	empty := NewStubRegisterClient("")
	assert.False(t, empty.Healthy())
}

// ---------------------------------------------------------------------------
// PEM bundle and non-CERTIFICATE block handling
// ---------------------------------------------------------------------------

func TestX509Validator_ValidatePEMBundle(t *testing.T) {
	cert, pemData := generateTestCert(t)

	// Create a bundle with the cert repeated (simulating leaf + intermediate)
	bundle := append([]byte{}, pemData...)
	bundle = append(bundle, pemData...)

	pool := x509.NewCertPool()
	pool.AddCert(cert)

	v := NewX509RegistrationCertValidator(pool)
	ent, err := v.Validate(context.Background(), bundle)
	require.NoError(t, err)
	assert.Equal(t, "RP-12345", ent.RPIdentifier)
}

func TestX509Validator_SkipsNonCertificateBlocks(t *testing.T) {
	cert, certPEM := generateTestCert(t)

	// Prepend a non-CERTIFICATE PEM block
	privKeyBlock := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("fake")})
	bundle := append([]byte{}, privKeyBlock...)
	bundle = append(bundle, certPEM...)

	pool := x509.NewCertPool()
	pool.AddCert(cert)
	v := NewX509RegistrationCertValidator(pool)
	ent, err := v.Validate(context.Background(), bundle)
	require.NoError(t, err)
	assert.Equal(t, "RP-12345", ent.RPIdentifier)
}

func TestX509Validator_OnlyNonCertBlocks(t *testing.T) {
	privKeyBlock := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("fake")})
	v := NewX509RegistrationCertValidator(x509.NewCertPool())
	_, err := v.Validate(context.Background(), privKeyBlock)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no CERTIFICATE PEM block")
}

// ---------------------------------------------------------------------------
// ValidatorRegistry nil guard
// ---------------------------------------------------------------------------

func TestValidatorRegistry_NilValidator(t *testing.T) {
	reg := NewValidatorRegistry()
	reg.Register("broken", nil)

	_, err := reg.Get("broken")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "is nil")
}
