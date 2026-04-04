package lote

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/sirosfoundation/g119612/pkg/etsi119602"
	"github.com/sirosfoundation/go-trust/pkg/authzen"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func writeLoTE(t *testing.T, dir, name string, lote *etsi119602.ListOfTrustedEntities) string {
	t.Helper()
	data, err := json.Marshal(lote)
	require.NoError(t, err)
	path := filepath.Join(dir, name)
	require.NoError(t, os.WriteFile(path, data, 0644))
	return path
}

func testLoTE() *etsi119602.ListOfTrustedEntities {
	return &etsi119602.ListOfTrustedEntities{
		Version: "1.0",
		SchemeInformation: etsi119602.SchemeInformation{
			Territory: "SE",
			SchemeOperator: etsi119602.NameSet{
				{Language: "en", Value: "Test Operator"},
			},
		},
		TrustedEntities: []etsi119602.TrustedEntity{
			{
				EntityID:     "https://issuer.example.com",
				EntityStatus: etsi119602.StatusGranted,
				EntityName: etsi119602.NameSet{
					{Language: "en", Value: "Test Issuer"},
				},
				DigitalIdentities: []etsi119602.DigitalIdentity{
					{
						Type: "jwk",
						JWK: map[string]interface{}{
							"kty": "EC",
							"crv": "P-256",
							"x":   "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
							"y":   "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0",
						},
					},
				},
			},
			{
				EntityID:     "https://withdrawn.example.com",
				EntityStatus: etsi119602.StatusWithdrawn,
				EntityName: etsi119602.NameSet{
					{Language: "en", Value: "Withdrawn Entity"},
				},
			},
		},
	}
}

func TestNew_Basic(t *testing.T) {
	dir := t.TempDir()
	path := writeLoTE(t, dir, "lote.json", testLoTE())

	reg, err := New(Config{Sources: []string{path}})
	require.NoError(t, err)
	assert.True(t, reg.Healthy())

	info := reg.Info()
	assert.Equal(t, "LoTE", info.Name)
	assert.Equal(t, "lote", info.Type)
	assert.True(t, info.Healthy)
}

func TestNew_NoSources(t *testing.T) {
	_, err := New(Config{})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "at least one source")
}

func TestNew_BadSource(t *testing.T) {
	_, err := New(Config{Sources: []string{"/nonexistent/path.json"}})
	assert.Error(t, err)
}

func TestEvaluate_GrantedEntity_JWKMatch(t *testing.T) {
	dir := t.TempDir()
	path := writeLoTE(t, dir, "lote.json", testLoTE())

	reg, err := New(Config{Sources: []string{path}})
	require.NoError(t, err)

	resp, err := reg.Evaluate(context.Background(), &authzen.EvaluationRequest{
		Subject: authzen.Subject{Type: "key", ID: "https://issuer.example.com"},
		Resource: authzen.Resource{
			Type: "jwk",
			ID:   "https://issuer.example.com",
			Key: []interface{}{
				map[string]interface{}{
					"kty": "EC",
					"crv": "P-256",
					"x":   "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
					"y":   "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0",
				},
			},
		},
	})
	require.NoError(t, err)
	assert.True(t, resp.Decision)
}

func TestEvaluate_WithdrawnEntity(t *testing.T) {
	dir := t.TempDir()
	path := writeLoTE(t, dir, "lote.json", testLoTE())

	reg, err := New(Config{Sources: []string{path}})
	require.NoError(t, err)

	resp, err := reg.Evaluate(context.Background(), &authzen.EvaluationRequest{
		Subject:  authzen.Subject{Type: "key", ID: "https://withdrawn.example.com"},
		Resource: authzen.Resource{Type: "jwk", ID: "https://withdrawn.example.com"},
	})
	require.NoError(t, err)
	assert.False(t, resp.Decision)
	assert.Contains(t, resp.Context.Reason["admin"].(string), "withdrawn")
}

func TestEvaluate_UnknownEntity(t *testing.T) {
	dir := t.TempDir()
	path := writeLoTE(t, dir, "lote.json", testLoTE())

	reg, err := New(Config{Sources: []string{path}})
	require.NoError(t, err)

	resp, err := reg.Evaluate(context.Background(), &authzen.EvaluationRequest{
		Subject:  authzen.Subject{Type: "key", ID: "https://unknown.example.com"},
		Resource: authzen.Resource{Type: "jwk", ID: "https://unknown.example.com"},
	})
	require.NoError(t, err)
	assert.False(t, resp.Decision)
	assert.Contains(t, resp.Context.Reason["admin"].(string), "not found")
}

func TestEvaluate_ResolutionOnly(t *testing.T) {
	dir := t.TempDir()
	path := writeLoTE(t, dir, "lote.json", testLoTE())

	reg, err := New(Config{Sources: []string{path}})
	require.NoError(t, err)

	// Resolution only: no resource type or key
	resp, err := reg.Evaluate(context.Background(), &authzen.EvaluationRequest{
		Subject:  authzen.Subject{Type: "key", ID: "https://issuer.example.com"},
		Resource: authzen.Resource{ID: "https://issuer.example.com"},
	})
	require.NoError(t, err)
	assert.True(t, resp.Decision)
	assert.NotNil(t, resp.Context.TrustMetadata)
}

func TestEvaluate_KeyMismatch(t *testing.T) {
	dir := t.TempDir()
	path := writeLoTE(t, dir, "lote.json", testLoTE())

	reg, err := New(Config{Sources: []string{path}})
	require.NoError(t, err)

	resp, err := reg.Evaluate(context.Background(), &authzen.EvaluationRequest{
		Subject: authzen.Subject{Type: "key", ID: "https://issuer.example.com"},
		Resource: authzen.Resource{
			Type: "jwk",
			ID:   "https://issuer.example.com",
			Key: []interface{}{
				map[string]interface{}{
					"kty": "EC",
					"crv": "P-256",
					"x":   "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
					"y":   "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB",
				},
			},
		},
	})
	require.NoError(t, err)
	assert.False(t, resp.Decision)
	assert.Contains(t, resp.Context.Reason["admin"].(string), "does not match")
}

func TestSupportedResourceTypes(t *testing.T) {
	dir := t.TempDir()
	path := writeLoTE(t, dir, "lote.json", testLoTE())

	reg, err := New(Config{Sources: []string{path}})
	require.NoError(t, err)

	types := reg.SupportedResourceTypes()
	assert.Contains(t, types, "jwk")
	assert.Contains(t, types, "x5c")
}

func TestSupportsResolutionOnly(t *testing.T) {
	dir := t.TempDir()
	path := writeLoTE(t, dir, "lote.json", testLoTE())

	reg, err := New(Config{Sources: []string{path}})
	require.NoError(t, err)
	assert.True(t, reg.SupportsResolutionOnly())
}

func TestRefresh(t *testing.T) {
	dir := t.TempDir()
	path := writeLoTE(t, dir, "lote.json", testLoTE())

	reg, err := New(Config{Sources: []string{path}})
	require.NoError(t, err)

	// Update the file with an additional entity
	updated := testLoTE()
	updated.TrustedEntities = append(updated.TrustedEntities, etsi119602.TrustedEntity{
		EntityID:     "https://new.example.com",
		EntityStatus: etsi119602.StatusGranted,
	})
	data, err := json.Marshal(updated)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(path, data, 0644))

	// Refresh
	require.NoError(t, reg.Refresh(context.Background()))

	// Should now find the new entity
	resp, err := reg.Evaluate(context.Background(), &authzen.EvaluationRequest{
		Subject:  authzen.Subject{Type: "key", ID: "https://new.example.com"},
		Resource: authzen.Resource{ID: "https://new.example.com"},
	})
	require.NoError(t, err)
	assert.True(t, resp.Decision)
}

func TestMultipleSources(t *testing.T) {
	dir := t.TempDir()

	lote1 := &etsi119602.ListOfTrustedEntities{
		Version:           "1.0",
		SchemeInformation: etsi119602.SchemeInformation{Territory: "SE"},
		TrustedEntities: []etsi119602.TrustedEntity{
			{EntityID: "https://se.example.com", EntityStatus: etsi119602.StatusGranted},
		},
	}
	lote2 := &etsi119602.ListOfTrustedEntities{
		Version:           "1.0",
		SchemeInformation: etsi119602.SchemeInformation{Territory: "NO"},
		TrustedEntities: []etsi119602.TrustedEntity{
			{EntityID: "https://no.example.com", EntityStatus: etsi119602.StatusGranted},
		},
	}

	path1 := writeLoTE(t, dir, "se.json", lote1)
	path2 := writeLoTE(t, dir, "no.json", lote2)

	reg, err := New(Config{Sources: []string{path1, path2}})
	require.NoError(t, err)

	// Both entities should be findable
	for _, id := range []string{"https://se.example.com", "https://no.example.com"} {
		resp, err := reg.Evaluate(context.Background(), &authzen.EvaluationRequest{
			Subject:  authzen.Subject{Type: "key", ID: id},
			Resource: authzen.Resource{ID: id},
		})
		require.NoError(t, err)
		assert.True(t, resp.Decision, "should find %s", id)
	}
}

// --- X.509 trust anchor / PKIX path validation tests ---

// generateTestCA creates a self-signed CA certificate and key.
func generateTestCA(t *testing.T) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	require.NoError(t, err)

	caCert, err := x509.ParseCertificate(caDER)
	require.NoError(t, err)
	return caCert, caKey
}

// generateLeafCert creates a leaf certificate signed by the given CA.
func generateLeafCert(t *testing.T, caCert *x509.Certificate, caKey *ecdsa.PrivateKey) *x509.Certificate {
	t.Helper()
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "Leaf Cert"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, caCert, &leafKey.PublicKey, caKey)
	require.NoError(t, err)

	leafCert, err := x509.ParseCertificate(leafDER)
	require.NoError(t, err)
	return leafCert
}

func TestEvaluate_X5C_TrustAnchor_PathValidation(t *testing.T) {
	// Create a CA and a leaf cert signed by that CA
	caCert, caKey := generateTestCA(t)
	leafCert := generateLeafCert(t, caCert, caKey)

	// Build a LoTE with the CA cert as a trust anchor
	lote := &etsi119602.ListOfTrustedEntities{
		Version:           "1.0",
		SchemeInformation: etsi119602.SchemeInformation{Territory: "SE"},
		TrustedEntities: []etsi119602.TrustedEntity{
			{
				EntityID:     "https://ca.example.com",
				EntityStatus: etsi119602.StatusGranted,
				DigitalIdentities: []etsi119602.DigitalIdentity{
					{
						Type:            "x509",
						X509Certificate: base64.StdEncoding.EncodeToString(caCert.Raw),
					},
				},
			},
		},
	}

	dir := t.TempDir()
	path := writeLoTE(t, dir, "lote.json", lote)
	reg, err := New(Config{Sources: []string{path}})
	require.NoError(t, err)

	// Present the LEAF cert (not the CA cert) — should validate via PKIX path
	resp, err := reg.Evaluate(context.Background(), &authzen.EvaluationRequest{
		Subject: authzen.Subject{Type: "key", ID: "https://ca.example.com"},
		Resource: authzen.Resource{
			Type: "x5c",
			ID:   "https://ca.example.com",
			Key: []interface{}{
				base64.StdEncoding.EncodeToString(leafCert.Raw),
				base64.StdEncoding.EncodeToString(caCert.Raw),
			},
		},
	})
	require.NoError(t, err)
	assert.True(t, resp.Decision)
	assert.Contains(t, resp.Context.Reason["admin"].(string), "trust anchor")
}

func TestEvaluate_X5C_DirectMatch_SameCert(t *testing.T) {
	// When the presented cert IS the entity's cert — direct key match
	caCert, _ := generateTestCA(t)

	lote := &etsi119602.ListOfTrustedEntities{
		Version:           "1.0",
		SchemeInformation: etsi119602.SchemeInformation{Territory: "SE"},
		TrustedEntities: []etsi119602.TrustedEntity{
			{
				EntityID:     "https://ca.example.com",
				EntityStatus: etsi119602.StatusGranted,
				DigitalIdentities: []etsi119602.DigitalIdentity{
					{
						Type:            "x509",
						X509Certificate: base64.StdEncoding.EncodeToString(caCert.Raw),
					},
				},
			},
		},
	}

	dir := t.TempDir()
	path := writeLoTE(t, dir, "lote.json", lote)
	reg, err := New(Config{Sources: []string{path}})
	require.NoError(t, err)

	// Present the SAME cert (the CA cert) — should match via direct key hash
	resp, err := reg.Evaluate(context.Background(), &authzen.EvaluationRequest{
		Subject: authzen.Subject{Type: "key", ID: "https://ca.example.com"},
		Resource: authzen.Resource{
			Type: "x5c",
			ID:   "https://ca.example.com",
			Key: []interface{}{
				base64.StdEncoding.EncodeToString(caCert.Raw),
			},
		},
	})
	require.NoError(t, err)
	assert.True(t, resp.Decision)
	// Should match via direct key hash, not path validation
	assert.Contains(t, resp.Context.Reason["admin"].(string), "key matches")
}

func TestEvaluate_X5C_UntrustedChain(t *testing.T) {
	// CA in the LoTE, but leaf signed by a DIFFERENT CA
	caCert, _ := generateTestCA(t)
	otherCA, otherCAKey := generateTestCA(t)
	leafFromOther := generateLeafCert(t, otherCA, otherCAKey)

	lote := &etsi119602.ListOfTrustedEntities{
		Version:           "1.0",
		SchemeInformation: etsi119602.SchemeInformation{Territory: "SE"},
		TrustedEntities: []etsi119602.TrustedEntity{
			{
				EntityID:     "https://ca.example.com",
				EntityStatus: etsi119602.StatusGranted,
				DigitalIdentities: []etsi119602.DigitalIdentity{
					{
						Type:            "x509",
						X509Certificate: base64.StdEncoding.EncodeToString(caCert.Raw),
					},
				},
			},
		},
	}

	dir := t.TempDir()
	path := writeLoTE(t, dir, "lote.json", lote)
	reg, err := New(Config{Sources: []string{path}})
	require.NoError(t, err)

	// Leaf signed by otherCA, but only caCert is in the LoTE
	resp, err := reg.Evaluate(context.Background(), &authzen.EvaluationRequest{
		Subject: authzen.Subject{Type: "key", ID: "https://ca.example.com"},
		Resource: authzen.Resource{
			Type: "x5c",
			ID:   "https://ca.example.com",
			Key: []interface{}{
				base64.StdEncoding.EncodeToString(leafFromOther.Raw),
			},
		},
	})
	require.NoError(t, err)
	assert.False(t, resp.Decision)
	assert.Contains(t, resp.Context.Reason["admin"].(string), "does not match")
}

func TestEvaluate_X5C_JWKEntity_NoPathValidation(t *testing.T) {
	// Entity with only JWK identity — x5c request should fail (no cert pool)
	dir := t.TempDir()
	path := writeLoTE(t, dir, "lote.json", testLoTE())
	reg, err := New(Config{Sources: []string{path}})
	require.NoError(t, err)

	// Use a random cert for the x5c key
	caCert, _ := generateTestCA(t)

	resp, err := reg.Evaluate(context.Background(), &authzen.EvaluationRequest{
		Subject: authzen.Subject{Type: "key", ID: "https://issuer.example.com"},
		Resource: authzen.Resource{
			Type: "x5c",
			ID:   "https://issuer.example.com",
			Key: []interface{}{
				base64.StdEncoding.EncodeToString(caCert.Raw),
			},
		},
	})
	require.NoError(t, err)
	assert.False(t, resp.Decision)
}

// Tests for extractStringSlice helper function

func TestExtractStringSlice_NilContext(t *testing.T) {
	result := extractStringSlice(nil, "credential_types")
	assert.Nil(t, result)
}

func TestExtractStringSlice_MissingKey(t *testing.T) {
	ctx := map[string]interface{}{"other_key": "value"}
	result := extractStringSlice(ctx, "credential_types")
	assert.Nil(t, result)
}

func TestExtractStringSlice_StringSlice(t *testing.T) {
	ctx := map[string]interface{}{
		"credential_types": []string{"eu.europa.ec.eudi.pid.1", "eu.europa.ec.eudi.mdl.1"},
	}
	result := extractStringSlice(ctx, "credential_types")
	assert.Equal(t, []string{"eu.europa.ec.eudi.pid.1", "eu.europa.ec.eudi.mdl.1"}, result)
}

func TestExtractStringSlice_InterfaceSlice(t *testing.T) {
	// Simulates JSON-unmarshaled data where []string becomes []interface{}
	ctx := map[string]interface{}{
		"credential_types": []interface{}{"eu.europa.ec.eudi.pid.1", "eu.europa.ec.eudi.mdl.1"},
	}
	result := extractStringSlice(ctx, "credential_types")
	assert.Equal(t, []string{"eu.europa.ec.eudi.pid.1", "eu.europa.ec.eudi.mdl.1"}, result)
}

func TestExtractStringSlice_MixedInterfaceSlice(t *testing.T) {
	// Filters out non-string values
	ctx := map[string]interface{}{
		"credential_types": []interface{}{"eu.europa.ec.eudi.pid.1", 123, "eu.europa.ec.eudi.mdl.1", nil},
	}
	result := extractStringSlice(ctx, "credential_types")
	assert.Equal(t, []string{"eu.europa.ec.eudi.pid.1", "eu.europa.ec.eudi.mdl.1"}, result)
}

func TestExtractStringSlice_WrongType(t *testing.T) {
	ctx := map[string]interface{}{"credential_types": "single-string"}
	result := extractStringSlice(ctx, "credential_types")
	assert.Nil(t, result)
}

// Tests for credential_types in response

func TestEvaluate_CredentialTypesInResponse(t *testing.T) {
	dir := t.TempDir()
	path := writeLoTE(t, dir, "lote.json", testLoTE())
	reg, err := New(Config{Sources: []string{path}})
	require.NoError(t, err)

	// Request with credential_types in context (as would be injected by manager)
	resp, err := reg.Evaluate(context.Background(), &authzen.EvaluationRequest{
		Subject: authzen.Subject{Type: "key", ID: "https://issuer.example.com"},
		Resource: authzen.Resource{
			Type: "jwk",
			ID:   "https://issuer.example.com",
			Key: []interface{}{
				map[string]interface{}{
					"kty": "EC",
					"crv": "P-256",
					"x":   "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
					"y":   "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0",
				},
			},
		},
		Context: map[string]interface{}{
			"credential_types": []string{"eu.europa.ec.eudi.pid.1"},
		},
	})
	require.NoError(t, err)
	assert.True(t, resp.Decision)
	assert.NotNil(t, resp.Context)
	assert.NotNil(t, resp.Context.Reason)
	assert.Equal(t, []string{"eu.europa.ec.eudi.pid.1"}, resp.Context.Reason["requested_credential_types"])
}

func TestEvaluate_NoCredentialTypesInContext(t *testing.T) {
	dir := t.TempDir()
	path := writeLoTE(t, dir, "lote.json", testLoTE())
	reg, err := New(Config{Sources: []string{path}})
	require.NoError(t, err)

	// Request without credential_types in context
	resp, err := reg.Evaluate(context.Background(), &authzen.EvaluationRequest{
		Subject: authzen.Subject{Type: "key", ID: "https://issuer.example.com"},
		Resource: authzen.Resource{
			Type: "jwk",
			ID:   "https://issuer.example.com",
			Key: []interface{}{
				map[string]interface{}{
					"kty": "EC",
					"crv": "P-256",
					"x":   "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
					"y":   "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0",
				},
			},
		},
	})
	require.NoError(t, err)
	assert.True(t, resp.Decision)
	assert.NotNil(t, resp.Context)
	assert.NotNil(t, resp.Context.Reason)
	// Should not have requested_credential_types when not provided
	_, hasCredTypes := resp.Context.Reason["requested_credential_types"]
	assert.False(t, hasCredTypes)
}
