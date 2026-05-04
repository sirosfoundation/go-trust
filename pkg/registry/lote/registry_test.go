package lote

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
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

// writeLoTE writes a LoTE as JSON with the {"LoTE": ...} envelope required by ParseLoTE.
func writeLoTE(t *testing.T, dir, name string, lote *etsi119602.ListOfTrustedEntities) string {
	t.Helper()
	data, err := lote.Marshal()
	require.NoError(t, err)
	path := filepath.Join(dir, name)
	require.NoError(t, os.WriteFile(path, data, 0644))
	return path
}

// testLoTE builds a standard LoTE fixture using ETSI TS 119 602-1 types.
func testLoTE() *etsi119602.ListOfTrustedEntities {
	return &etsi119602.ListOfTrustedEntities{
		ListAndSchemeInformation: etsi119602.ListAndSchemeInformation{
			LoTEVersionIdentifier: 1,
			LoTESequenceNumber:    1,
			SchemeTerritory:       "SE",
			SchemeOperatorName: etsi119602.NameSet{
				{Lang: "en", Value: "Test Operator"},
			},
			ListIssueDateTime: "2026-01-01T00:00:00Z",
			NextUpdate:        "2027-01-01T00:00:00Z",
		},
		TrustedEntitiesList: []etsi119602.TrustedEntity{
			{
				TrustedEntityInformation: etsi119602.TrustedEntityInformation{
					TEName: etsi119602.NameSet{
						{Lang: "en", Value: "Test Issuer"},
					},
					TEInformationURI: []etsi119602.NonEmptyMultiLangURI{
						{Lang: "en", URIValue: "https://issuer.example.com"},
					},
				},
				TrustedEntityServices: []etsi119602.TrustedEntityService{
					{
						ServiceInformation: etsi119602.ServiceInformation{
							ServiceName: etsi119602.NameSet{
								{Lang: "en", Value: "PID Issuance"},
							},
							ServiceDigitalIdentity: etsi119602.ServiceDigitalIdentity{
								PublicKeyValues: []map[string]any{
									{
										"kty": "EC",
										"crv": "P-256",
										"x":   "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
										"y":   "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0",
									},
								},
							},
						},
					},
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
	assert.Contains(t, err.Error(), "at least one source or lotl_sources")
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

func TestEvaluate_WithdrawnService(t *testing.T) {
	// Pub-EAA profile: entity present in list but service has withdrawn status.
	// Per ETSI TS 119 602-1: withdrawn services' digital identities are NOT trusted.
	lote := &etsi119602.ListOfTrustedEntities{
		ListAndSchemeInformation: etsi119602.ListAndSchemeInformation{
			LoTEVersionIdentifier: 1,
			LoTESequenceNumber:    1,
			SchemeTerritory:       "SE",
			SchemeOperatorName:    etsi119602.NameSet{{Lang: "en", Value: "Op"}},
			ListIssueDateTime:     "2026-01-01T00:00:00Z",
			NextUpdate:            "2027-01-01T00:00:00Z",
		},
		TrustedEntitiesList: []etsi119602.TrustedEntity{
			{
				TrustedEntityInformation: etsi119602.TrustedEntityInformation{
					TEName: etsi119602.NameSet{{Lang: "en", Value: "Pub-EAA Provider"}},
					TEInformationURI: []etsi119602.NonEmptyMultiLangURI{
						{Lang: "en", URIValue: "https://withdrawn-svc.example.com"},
					},
				},
				TrustedEntityServices: []etsi119602.TrustedEntityService{
					{
						ServiceInformation: etsi119602.ServiceInformation{
							ServiceName:   etsi119602.NameSet{{Lang: "en", Value: "Attestation Issuance"}},
							ServiceStatus: "http://uri.etsi.org/19602/PubEAAProvidersList/SvcStatus/withdrawn",
							ServiceDigitalIdentity: etsi119602.ServiceDigitalIdentity{
								PublicKeyValues: []map[string]any{
									{
										"kty": "EC",
										"crv": "P-256",
										"x":   "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
										"y":   "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0",
									},
								},
							},
						},
					},
				},
			},
		},
	}

	dir := t.TempDir()
	path := writeLoTE(t, dir, "lote.json", lote)
	reg, err := New(Config{Sources: []string{path}})
	require.NoError(t, err)

	// Entity IS in the list, so resolution-only should succeed
	resp, err := reg.Evaluate(context.Background(), &authzen.EvaluationRequest{
		Subject:  authzen.Subject{Type: "key", ID: "https://withdrawn-svc.example.com"},
		Resource: authzen.Resource{ID: "https://withdrawn-svc.example.com"},
	})
	require.NoError(t, err)
	assert.True(t, resp.Decision, "entity should be resolvable even with withdrawn service")

	// But key matching should fail — withdrawn service's keys are not indexed
	resp, err = reg.Evaluate(context.Background(), &authzen.EvaluationRequest{
		Subject: authzen.Subject{Type: "key", ID: "https://withdrawn-svc.example.com"},
		Resource: authzen.Resource{
			Type: "jwk",
			ID:   "https://withdrawn-svc.example.com",
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
	assert.False(t, resp.Decision, "withdrawn service's key should not match")
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
	updated.TrustedEntitiesList = append(updated.TrustedEntitiesList, etsi119602.TrustedEntity{
		TrustedEntityInformation: etsi119602.TrustedEntityInformation{
			TEInformationURI: []etsi119602.NonEmptyMultiLangURI{
				{Lang: "en", URIValue: "https://new.example.com"},
			},
		},
	})
	data, err := updated.Marshal()
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(path, data, 0644))

	require.NoError(t, reg.Refresh(context.Background()))

	resp, err := reg.Evaluate(context.Background(), &authzen.EvaluationRequest{
		Subject:  authzen.Subject{Type: "key", ID: "https://new.example.com"},
		Resource: authzen.Resource{ID: "https://new.example.com"},
	})
	require.NoError(t, err)
	assert.True(t, resp.Decision)
}

func TestInfo_LastUpdated(t *testing.T) {
	dir := t.TempDir()
	path := writeLoTE(t, dir, "lote.json", testLoTE())

	reg, err := New(Config{Sources: []string{path}})
	require.NoError(t, err)

	info := reg.Info()
	require.NotNil(t, info.LastUpdated, "expected LastUpdated to be set")
	assert.False(t, info.LastUpdated.IsZero())

	before := *info.LastUpdated
	time.Sleep(10 * time.Millisecond)

	require.NoError(t, reg.Refresh(context.Background()))

	info = reg.Info()
	assert.True(t, info.LastUpdated.After(before), "expected LastUpdated to advance after refresh")
}

func TestMultipleSources(t *testing.T) {
	dir := t.TempDir()

	lote1 := minimalLoTE("SE", simpleEntity("https://se.example.com"))
	lote2 := minimalLoTE("NO", simpleEntity("https://no.example.com"))

	path1 := writeLoTE(t, dir, "se.json", lote1)
	path2 := writeLoTE(t, dir, "no.json", lote2)

	reg, err := New(Config{Sources: []string{path1, path2}})
	require.NoError(t, err)

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

// x509Entity builds a TrustedEntity with an X.509 certificate as the service's digital identity.
func x509Entity(id string, caCert *x509.Certificate) etsi119602.TrustedEntity {
	return etsi119602.TrustedEntity{
		TrustedEntityInformation: etsi119602.TrustedEntityInformation{
			TEInformationURI: []etsi119602.NonEmptyMultiLangURI{
				{Lang: "en", URIValue: id},
			},
		},
		TrustedEntityServices: []etsi119602.TrustedEntityService{
			{
				ServiceInformation: etsi119602.ServiceInformation{
					ServiceName: etsi119602.NameSet{{Lang: "en", Value: "CA Service"}},
					ServiceDigitalIdentity: etsi119602.ServiceDigitalIdentity{
						X509Certificates: []etsi119602.PKIOb{
							{Val: base64.StdEncoding.EncodeToString(caCert.Raw)},
						},
					},
				},
			},
		},
	}
}

// minimalLoTE builds a minimal valid LoTE with the given territory and entities.
func minimalLoTE(territory string, entities ...etsi119602.TrustedEntity) *etsi119602.ListOfTrustedEntities {
	return &etsi119602.ListOfTrustedEntities{
		ListAndSchemeInformation: etsi119602.ListAndSchemeInformation{
			LoTEVersionIdentifier: 1,
			SchemeTerritory:       territory,
			SchemeOperatorName:    etsi119602.NameSet{{Lang: "en", Value: territory + " Op"}},
			ListIssueDateTime:     "2026-01-01T00:00:00Z",
			NextUpdate:            "2027-01-01T00:00:00Z",
		},
		TrustedEntitiesList: entities,
	}
}

// simpleEntity builds a TrustedEntity with only a TEInformationURI (no services).
func simpleEntity(id string) etsi119602.TrustedEntity {
	return etsi119602.TrustedEntity{
		TrustedEntityInformation: etsi119602.TrustedEntityInformation{
			TEInformationURI: []etsi119602.NonEmptyMultiLangURI{
				{Lang: "en", URIValue: id},
			},
		},
	}
}

func TestEvaluate_X5C_TrustAnchor_PathValidation(t *testing.T) {
	caCert, caKey := generateTestCA(t)
	leafCert := generateLeafCert(t, caCert, caKey)

	lote := minimalLoTE("SE", x509Entity("https://ca.example.com", caCert))

	dir := t.TempDir()
	path := writeLoTE(t, dir, "lote.json", lote)
	reg, err := New(Config{Sources: []string{path}})
	require.NoError(t, err)

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
	caCert, _ := generateTestCA(t)

	lote := minimalLoTE("SE", x509Entity("https://ca.example.com", caCert))

	dir := t.TempDir()
	path := writeLoTE(t, dir, "lote.json", lote)
	reg, err := New(Config{Sources: []string{path}})
	require.NoError(t, err)

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
	assert.Contains(t, resp.Context.Reason["admin"].(string), "key matches")
}

func TestEvaluate_X5C_UntrustedChain(t *testing.T) {
	caCert, _ := generateTestCA(t)
	otherCA, otherCAKey := generateTestCA(t)
	leafFromOther := generateLeafCert(t, otherCA, otherCAKey)

	lote := minimalLoTE("SE", x509Entity("https://ca.example.com", caCert))

	dir := t.TempDir()
	path := writeLoTE(t, dir, "lote.json", lote)
	reg, err := New(Config{Sources: []string{path}})
	require.NoError(t, err)

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
	dir := t.TempDir()
	path := writeLoTE(t, dir, "lote.json", testLoTE())
	reg, err := New(Config{Sources: []string{path}})
	require.NoError(t, err)

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
	ctx := map[string]interface{}{
		"credential_types": []interface{}{"eu.europa.ec.eudi.pid.1", "eu.europa.ec.eudi.mdl.1"},
	}
	result := extractStringSlice(ctx, "credential_types")
	assert.Equal(t, []string{"eu.europa.ec.eudi.pid.1", "eu.europa.ec.eudi.mdl.1"}, result)
}

func TestExtractStringSlice_MixedInterfaceSlice(t *testing.T) {
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

func TestEvaluate_CredentialTypesInResponse(t *testing.T) {
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
	_, hasCredTypes := resp.Context.Reason["requested_credential_types"]
	assert.False(t, hasCredTypes)
}

// --- XML LoTE format tests ---

func writeLoTEXML(t *testing.T, dir, name string, lote *etsi119602.ListOfTrustedEntities) string {
	t.Helper()
	path := filepath.Join(dir, name)
	require.NoError(t, lote.EncodeXMLToFile(path))
	return path
}

func TestNew_XMLSource(t *testing.T) {
	dir := t.TempDir()
	path := writeLoTEXML(t, dir, "lote.xml", testLoTE())

	reg, err := New(Config{Sources: []string{path}})
	require.NoError(t, err)
	assert.True(t, reg.Healthy())

	resp, err := reg.Evaluate(context.Background(), &authzen.EvaluationRequest{
		Subject:  authzen.Subject{Type: "key", ID: "https://issuer.example.com"},
		Resource: authzen.Resource{ID: "https://issuer.example.com"},
	})
	require.NoError(t, err)
	assert.True(t, resp.Decision)
}

func TestNew_XMLSource_JWKMatch(t *testing.T) {
	dir := t.TempDir()
	path := writeLoTEXML(t, dir, "lote.xml", testLoTE())

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

func TestNew_MixedJSONAndXMLSources(t *testing.T) {
	dir := t.TempDir()

	lote1 := minimalLoTE("SE", simpleEntity("https://se.example.com"))
	lote2 := minimalLoTE("NO", simpleEntity("https://no.example.com"))

	jsonPath := writeLoTE(t, dir, "se.json", lote1)
	xmlPath := writeLoTEXML(t, dir, "no.xml", lote2)

	reg, err := New(Config{Sources: []string{jsonPath, xmlPath}})
	require.NoError(t, err)

	for _, id := range []string{"https://se.example.com", "https://no.example.com"} {
		resp, err := reg.Evaluate(context.Background(), &authzen.EvaluationRequest{
			Subject:  authzen.Subject{Type: "key", ID: id},
			Resource: authzen.Resource{ID: id},
		})
		require.NoError(t, err)
		assert.True(t, resp.Decision, "should find %s", id)
	}
}

// --- LoTL resolution tests ---

func writeLoTL(t *testing.T, dir, name string, lotl *etsi119602.ListOfTrustedLists) string {
	t.Helper()
	data, err := lotl.MarshalLoTL()
	require.NoError(t, err)
	path := filepath.Join(dir, name)
	require.NoError(t, os.WriteFile(path, data, 0644))
	return path
}

// lotlPointer builds an OtherLoTEPointer with the given location and qualifier type.
func lotlPointer(location, schemeType, territory string) etsi119602.OtherLoTEPointer {
	return etsi119602.OtherLoTEPointer{
		LoTELocation: location,
		LoTEQualifiers: []etsi119602.LoTEQualifier{
			{
				LoTEType:        schemeType,
				SchemeTerritory: territory,
			},
		},
	}
}

func TestNew_LoTLSource(t *testing.T) {
	dir := t.TempDir()

	lote1 := minimalLoTE("SE", simpleEntity("https://se-pid.example.com"))
	lote2 := minimalLoTE("DE", simpleEntity("https://de-pid.example.com"))
	path1 := writeLoTE(t, dir, "se-pid.json", lote1)
	path2 := writeLoTE(t, dir, "de-pid.json", lote2)

	lotl := &etsi119602.ListOfTrustedLists{
		ListAndSchemeInformation: etsi119602.ListAndSchemeInformation{
			LoTEVersionIdentifier: 1,
			SchemeTerritory:       "EU",
			LoTEType:              etsi119602.LoTLTypeEU,
			SchemeOperatorName:    etsi119602.NameSet{{Lang: "en", Value: "EU Commission"}},
			ListIssueDateTime:     "2026-01-01T00:00:00Z",
			NextUpdate:            "2027-01-01T00:00:00Z",
			PointersToOtherLoTE: []etsi119602.OtherLoTEPointer{
				lotlPointer(path1, etsi119602.LoTETypePIDProviders, "SE"),
				lotlPointer(path2, etsi119602.LoTETypePIDProviders, "DE"),
			},
		},
	}
	lotlPath := writeLoTL(t, dir, "eu-lotl.json", lotl)

	reg, err := New(Config{LoTLSources: []string{lotlPath}})
	require.NoError(t, err)
	assert.True(t, reg.Healthy())

	for _, id := range []string{"https://se-pid.example.com", "https://de-pid.example.com"} {
		resp, err := reg.Evaluate(context.Background(), &authzen.EvaluationRequest{
			Subject:  authzen.Subject{Type: "key", ID: id},
			Resource: authzen.Resource{ID: id},
		})
		require.NoError(t, err)
		assert.True(t, resp.Decision, "should find %s via LoTL", id)
	}
}

func TestNew_LoTLAndDirectSources(t *testing.T) {
	dir := t.TempDir()

	directLoTE := minimalLoTE("SE", simpleEntity("https://direct.example.com"))
	directPath := writeLoTE(t, dir, "direct.json", directLoTE)

	lotlLoTE := minimalLoTE("DE", simpleEntity("https://via-lotl.example.com"))
	lotlLotePath := writeLoTE(t, dir, "via-lotl.json", lotlLoTE)

	lotl := &etsi119602.ListOfTrustedLists{
		ListAndSchemeInformation: etsi119602.ListAndSchemeInformation{
			LoTEVersionIdentifier: 1,
			SchemeTerritory:       "EU",
			LoTEType:              etsi119602.LoTLTypeEU,
			SchemeOperatorName:    etsi119602.NameSet{{Lang: "en", Value: "EU"}},
			ListIssueDateTime:     "2026-01-01T00:00:00Z",
			NextUpdate:            "2027-01-01T00:00:00Z",
			PointersToOtherLoTE: []etsi119602.OtherLoTEPointer{
				lotlPointer(lotlLotePath, etsi119602.LoTETypePIDProviders, "DE"),
			},
		},
	}
	lotlPath := writeLoTL(t, dir, "lotl.json", lotl)

	reg, err := New(Config{
		Sources:     []string{directPath},
		LoTLSources: []string{lotlPath},
	})
	require.NoError(t, err)

	for _, id := range []string{"https://direct.example.com", "https://via-lotl.example.com"} {
		resp, err := reg.Evaluate(context.Background(), &authzen.EvaluationRequest{
			Subject:  authzen.Subject{Type: "key", ID: id},
			Resource: authzen.Resource{ID: id},
		})
		require.NoError(t, err)
		assert.True(t, resp.Decision, "should find %s", id)
	}
}

func TestNew_NestedLoTL(t *testing.T) {
	dir := t.TempDir()

	lote := minimalLoTE("SE", simpleEntity("https://nested.example.com"))
	lotePath := writeLoTE(t, dir, "lote.json", lote)

	innerLoTL := &etsi119602.ListOfTrustedLists{
		ListAndSchemeInformation: etsi119602.ListAndSchemeInformation{
			LoTEVersionIdentifier: 1,
			SchemeTerritory:       "SE",
			LoTEType:              etsi119602.LoTLTypeEU,
			SchemeOperatorName:    etsi119602.NameSet{{Lang: "en", Value: "SE"}},
			ListIssueDateTime:     "2026-01-01T00:00:00Z",
			NextUpdate:            "2027-01-01T00:00:00Z",
			PointersToOtherLoTE: []etsi119602.OtherLoTEPointer{
				lotlPointer(lotePath, etsi119602.LoTETypePIDProviders, "SE"),
			},
		},
	}
	innerPath := writeLoTL(t, dir, "inner-lotl.json", innerLoTL)

	outerLoTL := &etsi119602.ListOfTrustedLists{
		ListAndSchemeInformation: etsi119602.ListAndSchemeInformation{
			LoTEVersionIdentifier: 1,
			SchemeTerritory:       "EU",
			LoTEType:              etsi119602.LoTLTypeEU,
			SchemeOperatorName:    etsi119602.NameSet{{Lang: "en", Value: "EU"}},
			ListIssueDateTime:     "2026-01-01T00:00:00Z",
			NextUpdate:            "2027-01-01T00:00:00Z",
			PointersToOtherLoTE: []etsi119602.OtherLoTEPointer{
				lotlPointer(innerPath, etsi119602.LoTLTypeEU, "SE"),
			},
		},
	}
	outerPath := writeLoTL(t, dir, "outer-lotl.json", outerLoTL)

	reg, err := New(Config{LoTLSources: []string{outerPath}})
	require.NoError(t, err)

	resp, err := reg.Evaluate(context.Background(), &authzen.EvaluationRequest{
		Subject:  authzen.Subject{Type: "key", ID: "https://nested.example.com"},
		Resource: authzen.Resource{ID: "https://nested.example.com"},
	})
	require.NoError(t, err)
	assert.True(t, resp.Decision, "should find entity discovered via nested LoTL")
}

func TestNew_LoTLDepthLimit(t *testing.T) {
	dir := t.TempDir()

	lote := minimalLoTE("SE", simpleEntity("https://deep.example.com"))
	lotePath := writeLoTE(t, dir, "lote.json", lote)

	depth1 := &etsi119602.ListOfTrustedLists{
		ListAndSchemeInformation: etsi119602.ListAndSchemeInformation{
			LoTEVersionIdentifier: 1,
			SchemeTerritory:       "SE",
			LoTEType:              etsi119602.LoTLTypeEU,
			SchemeOperatorName:    etsi119602.NameSet{{Lang: "en", Value: "SE"}},
			ListIssueDateTime:     "2026-01-01T00:00:00Z",
			NextUpdate:            "2027-01-01T00:00:00Z",
			PointersToOtherLoTE: []etsi119602.OtherLoTEPointer{
				lotlPointer(lotePath, etsi119602.LoTETypePIDProviders, "SE"),
			},
		},
	}
	depth1Path := writeLoTL(t, dir, "depth1.json", depth1)

	depth2 := &etsi119602.ListOfTrustedLists{
		ListAndSchemeInformation: etsi119602.ListAndSchemeInformation{
			LoTEVersionIdentifier: 1,
			SchemeTerritory:       "EU",
			LoTEType:              etsi119602.LoTLTypeEU,
			SchemeOperatorName:    etsi119602.NameSet{{Lang: "en", Value: "EU"}},
			ListIssueDateTime:     "2026-01-01T00:00:00Z",
			NextUpdate:            "2027-01-01T00:00:00Z",
			PointersToOtherLoTE: []etsi119602.OtherLoTEPointer{
				lotlPointer(depth1Path, etsi119602.LoTLTypeEU, "SE"),
			},
		},
	}
	depth2Path := writeLoTL(t, dir, "depth2.json", depth2)

	reg, err := New(Config{
		LoTLSources:         []string{depth2Path},
		MaxDereferenceDepth: 1,
	})
	require.NoError(t, err)

	resp, err := reg.Evaluate(context.Background(), &authzen.EvaluationRequest{
		Subject:  authzen.Subject{Type: "key", ID: "https://deep.example.com"},
		Resource: authzen.Resource{ID: "https://deep.example.com"},
	})
	require.NoError(t, err)
	assert.False(t, resp.Decision, "should NOT find entity beyond depth limit")
}

func TestNew_LoTLWithEmptyPointer(t *testing.T) {
	dir := t.TempDir()

	lotl := &etsi119602.ListOfTrustedLists{
		ListAndSchemeInformation: etsi119602.ListAndSchemeInformation{
			LoTEVersionIdentifier: 1,
			SchemeTerritory:       "EU",
			LoTEType:              etsi119602.LoTLTypeEU,
			SchemeOperatorName:    etsi119602.NameSet{{Lang: "en", Value: "EU"}},
			ListIssueDateTime:     "2026-01-01T00:00:00Z",
			NextUpdate:            "2027-01-01T00:00:00Z",
			PointersToOtherLoTE: []etsi119602.OtherLoTEPointer{
				{LoTELocation: ""},                  // empty location — should be skipped
				{LoTELocation: "/nonexistent.json"}, // bad path — should warn and continue
			},
		},
	}
	lotlPath := writeLoTL(t, dir, "lotl.json", lotl)

	reg, err := New(Config{LoTLSources: []string{lotlPath}})
	require.NoError(t, err)
	assert.True(t, reg.Healthy())
}

func TestNew_LoTLOnlyNoDirectSources(t *testing.T) {
	dir := t.TempDir()

	lote := minimalLoTE("SE", simpleEntity("https://lotl-only.example.com"))
	lotePath := writeLoTE(t, dir, "lote.json", lote)

	lotl := &etsi119602.ListOfTrustedLists{
		ListAndSchemeInformation: etsi119602.ListAndSchemeInformation{
			LoTEVersionIdentifier: 1,
			SchemeTerritory:       "EU",
			LoTEType:              etsi119602.LoTLTypeEU,
			SchemeOperatorName:    etsi119602.NameSet{{Lang: "en", Value: "EU"}},
			ListIssueDateTime:     "2026-01-01T00:00:00Z",
			NextUpdate:            "2027-01-01T00:00:00Z",
			PointersToOtherLoTE: []etsi119602.OtherLoTEPointer{
				lotlPointer(lotePath, etsi119602.LoTETypePIDProviders, "SE"),
			},
		},
	}
	lotlPath := writeLoTL(t, dir, "lotl.json", lotl)

	reg, err := New(Config{LoTLSources: []string{lotlPath}})
	require.NoError(t, err)
	assert.True(t, reg.Healthy())

	resp, err := reg.Evaluate(context.Background(), &authzen.EvaluationRequest{
		Subject:  authzen.Subject{Type: "key", ID: "https://lotl-only.example.com"},
		Resource: authzen.Resource{ID: "https://lotl-only.example.com"},
	})
	require.NoError(t, err)
	assert.True(t, resp.Decision)
}

func TestNew_LoTLCycleDetection(t *testing.T) {
	dir := t.TempDir()

	lote := minimalLoTE("SE", simpleEntity("https://cycle.example.com"))
	lotePath := writeLoTE(t, dir, "lote.json", lote)

	lotlAPath := filepath.Join(dir, "lotl-a.json")
	lotlBPath := filepath.Join(dir, "lotl-b.json")

	lotlA := &etsi119602.ListOfTrustedLists{
		ListAndSchemeInformation: etsi119602.ListAndSchemeInformation{
			LoTEVersionIdentifier: 1,
			SchemeTerritory:       "EU",
			LoTEType:              etsi119602.LoTLTypeEU,
			SchemeOperatorName:    etsi119602.NameSet{{Lang: "en", Value: "EU"}},
			ListIssueDateTime:     "2026-01-01T00:00:00Z",
			NextUpdate:            "2027-01-01T00:00:00Z",
			PointersToOtherLoTE: []etsi119602.OtherLoTEPointer{
				lotlPointer(lotePath, etsi119602.LoTETypePIDProviders, "SE"),
				lotlPointer(lotlBPath, etsi119602.LoTLTypeEU, "EU"),
			},
		},
	}
	lotlB := &etsi119602.ListOfTrustedLists{
		ListAndSchemeInformation: etsi119602.ListAndSchemeInformation{
			LoTEVersionIdentifier: 1,
			SchemeTerritory:       "EU",
			LoTEType:              etsi119602.LoTLTypeEU,
			SchemeOperatorName:    etsi119602.NameSet{{Lang: "en", Value: "EU B"}},
			ListIssueDateTime:     "2026-01-01T00:00:00Z",
			NextUpdate:            "2027-01-01T00:00:00Z",
			PointersToOtherLoTE: []etsi119602.OtherLoTEPointer{
				lotlPointer(lotlAPath, etsi119602.LoTLTypeEU, "EU"),
			},
		},
	}

	dataA, _ := lotlA.MarshalLoTL()
	dataB, _ := lotlB.MarshalLoTL()
	require.NoError(t, os.WriteFile(lotlAPath, dataA, 0644))
	require.NoError(t, os.WriteFile(lotlBPath, dataB, 0644))

	reg, err := New(Config{LoTLSources: []string{lotlAPath}})
	require.NoError(t, err)
	assert.True(t, reg.Healthy())

	resp, err := reg.Evaluate(context.Background(), &authzen.EvaluationRequest{
		Subject:  authzen.Subject{Type: "key", ID: "https://cycle.example.com"},
		Resource: authzen.Resource{ID: "https://cycle.example.com"},
	})
	require.NoError(t, err)
	assert.True(t, resp.Decision, "should find entity despite LoTL cycle")
}

// --- Entity ID derivation tests ---

func TestEntityID_FromTEInformationURI(t *testing.T) {
	ent := etsi119602.TrustedEntity{
		TrustedEntityInformation: etsi119602.TrustedEntityInformation{
			TEName: etsi119602.NameSet{{Lang: "en", Value: "Some Name"}},
			TEInformationURI: []etsi119602.NonEmptyMultiLangURI{
				{Lang: "en", URIValue: "https://entity.example.com"},
			},
		},
	}
	assert.Equal(t, "https://entity.example.com", entityID(ent))
}

func TestEntityID_FallbackToName(t *testing.T) {
	ent := etsi119602.TrustedEntity{
		TrustedEntityInformation: etsi119602.TrustedEntityInformation{
			TEName: etsi119602.NameSet{{Lang: "en", Value: "Fallback Name"}},
		},
	}
	assert.Equal(t, "Fallback Name", entityID(ent))
}

func TestEntityID_Empty(t *testing.T) {
	ent := etsi119602.TrustedEntity{}
	assert.Equal(t, "", entityID(ent))
}

func TestIsWithdrawnStatus(t *testing.T) {
	assert.False(t, isWithdrawnStatus(""))
	assert.False(t, isWithdrawnStatus("http://uri.etsi.org/19602/PubEAAProvidersList/SvcStatus/notified"))
	assert.True(t, isWithdrawnStatus("http://uri.etsi.org/19602/PubEAAProvidersList/SvcStatus/withdrawn"))
	assert.True(t, isWithdrawnStatus("http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/withdrawn"))
	assert.True(t, isWithdrawnStatus(etsi119602.StatusWithdrawn))
}

// TestBuildIndex_ImplicitTrust verifies that entities/services without an explicit
// ServiceStatus (the "presence = trusted" model per ETSI TS 119 602 Annexes D-I
// for non-Pub-EAA profiles) are correctly indexed and trusted.
func TestBuildIndex_ImplicitTrust(t *testing.T) {
	lote := &etsi119602.ListOfTrustedEntities{
		ListAndSchemeInformation: etsi119602.ListAndSchemeInformation{
			LoTEVersionIdentifier: 1,
			LoTEType:              etsi119602.LoTETypePIDProviders,
			SchemeTerritory:       "SE",
			SchemeOperatorName:    etsi119602.NameSet{{Lang: "en", Value: "Test"}},
			ListIssueDateTime:     "2026-01-01T00:00:00Z",
			NextUpdate:            "2027-01-01T00:00:00Z",
		},
		TrustedEntitiesList: []etsi119602.TrustedEntity{
			{
				TrustedEntityInformation: etsi119602.TrustedEntityInformation{
					TEName:           etsi119602.NameSet{{Lang: "en", Value: "Implicit Trust Entity"}},
					TEInformationURI: []etsi119602.NonEmptyMultiLangURI{{Lang: "en", URIValue: "https://implicit.example.com"}},
				},
				TrustedEntityServices: []etsi119602.TrustedEntityService{
					{
						ServiceInformation: etsi119602.ServiceInformation{
							ServiceName: etsi119602.NameSet{{Lang: "en", Value: "PID Service"}},
							// ServiceStatus intentionally absent — implicit trust
							ServiceDigitalIdentity: etsi119602.ServiceDigitalIdentity{
								PublicKeyValues: []map[string]any{
									{"kty": "EC", "crv": "P-256", "x": "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU", "y": "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"},
								},
							},
						},
					},
				},
			},
		},
	}

	idx := buildIndex([]*etsi119602.ListOfTrustedEntities{lote}, nil)

	// Entity should be indexed (presence = trusted)
	assert.Len(t, idx.byID, 1, "entity with no ServiceStatus should be indexed")

	// Service key should be indexed
	assert.NotEmpty(t, idx.byKeyHash, "service keys should be indexed when ServiceStatus is absent")
}
