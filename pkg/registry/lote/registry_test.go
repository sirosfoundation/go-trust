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
	"strings"
	"testing"
	"time"

	"github.com/sirosfoundation/g119612/pkg/etsi119602"
	"github.com/sirosfoundation/go-trust/pkg/authzen"
	"github.com/sirosfoundation/go-trust/pkg/registry/rpcert"
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

// TestEvaluate_X5C_CAAnchored_SubjectIDNotListed is a regression test for
// issue #90: when subject.id is a relying party that is NOT listed as an entity
// in the LoTE (only its issuing CA is listed), chain validation should still
// succeed by matching against the global CA pool.
func TestEvaluate_X5C_CAAnchored_SubjectIDNotListed(t *testing.T) {
	caCert, caKey := generateTestCA(t)

	// Leaf with clientAuth-only EKU, simulating a WRPAC.
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(42),
		Subject:      pkix.Name{CommonName: "RP Leaf"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, caCert, &leafKey.PublicKey, caKey)
	require.NoError(t, err)
	leafCert, err := x509.ParseCertificate(leafDER)
	require.NoError(t, err)

	// LoTE lists only the CA entity — the RP ("https://rp.example.com") is NOT listed.
	caEntityID := "https://access-ca.example.com"
	lote := minimalLoTE("SE", x509Entity(caEntityID, caCert))
	path := writeLoTE(t, t.TempDir(), "lote.json", lote)

	reg, err := New(Config{
		Name:    "ca-anchored-test",
		Sources: []string{path},
	})
	require.NoError(t, err)

	resp, err := reg.Evaluate(context.Background(), &authzen.EvaluationRequest{
		Subject: authzen.Subject{Type: "key", ID: "https://rp.example.com"},
		Resource: authzen.Resource{
			Type: "x5c",
			ID:   "https://rp.example.com",
			Key: []interface{}{
				base64.StdEncoding.EncodeToString(leafCert.Raw),
				base64.StdEncoding.EncodeToString(caCert.Raw),
			},
		},
	})
	require.NoError(t, err)

	if !resp.Decision {
		t.Errorf("expected true decision (issue #90): RP not listed but leaf chains to listed CA; got false. Reason: %v", resp.Context.Reason)
	}

	// Verify the admin reason string does not contain the doubled "in LoTE" phrasing.
	if admin, ok := resp.Context.Reason["admin"].(string); ok {
		if strings.Contains(admin, "in LoTE\"") {
			t.Errorf("admin reason has doubled 'in LoTE' phrasing: %s", admin)
		}
	}
}

// TestEvaluate_X5C_CAAnchored_ClientIDSchemeBindingMismatch proves the CA-anchored
// fallback no longer grants trust on chain-validity alone when the caller uses
// an OpenID4VP certificate-binding client_id_scheme: chaining to a listed CA is
// necessary but not sufficient - the leaf must also be bound to the claimed
// identity. Without this check, any certificate issued by a listed CA could
// impersonate ANY x509_san_dns/x509_san_uri/x509_hash identity, regardless of
// what the certificate itself actually says.
func TestEvaluate_X5C_CAAnchored_ClientIDSchemeBindingMismatch(t *testing.T) {
	caCert, caKey := generateTestCA(t)

	// Leaf legitimately issued by the listed CA, but for a DIFFERENT DNS name
	// than the one the caller claims via the x509_san_dns client_id_scheme.
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(43),
		Subject:      pkix.Name{CommonName: "unrelated.example.com"},
		DNSNames:     []string{"unrelated.example.com"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, caCert, &leafKey.PublicKey, caKey)
	require.NoError(t, err)
	leafCert, err := x509.ParseCertificate(leafDER)
	require.NoError(t, err)

	caEntityID := "https://access-ca-binding.example.com"
	lote := minimalLoTE("SE", x509Entity(caEntityID, caCert))
	path := writeLoTE(t, t.TempDir(), "lote.json", lote)

	reg, err := New(Config{Name: "ca-anchored-binding-test", Sources: []string{path}})
	require.NoError(t, err)

	resp, err := reg.Evaluate(context.Background(), &authzen.EvaluationRequest{
		Subject: authzen.Subject{Type: "key", ID: "x509_san_dns:rp.example.com"},
		Resource: authzen.Resource{
			Type: "x5c",
			ID:   "x509_san_dns:rp.example.com",
			Key: []interface{}{
				base64.StdEncoding.EncodeToString(leafCert.Raw),
				base64.StdEncoding.EncodeToString(caCert.Raw),
			},
		},
	})
	require.NoError(t, err)
	assert.False(t, resp.Decision, "leaf chains to a listed CA but is not bound to the claimed x509_san_dns identity - must be denied")
	admin, _ := resp.Context.Reason["admin"].(string)
	assert.Contains(t, admin, "certificate binding check failed", "expected a certificate-binding deny reason, got: %s", admin)
}

// TestEvaluate_X5C_CAAnchored_ClientIDSchemeBindingSuccess proves the CA-anchored
// fallback still grants trust when the leaf IS bound to the claimed identity.
func TestEvaluate_X5C_CAAnchored_ClientIDSchemeBindingSuccess(t *testing.T) {
	caCert, caKey := generateTestCA(t)

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(44),
		Subject:      pkix.Name{CommonName: "rp.example.com"},
		DNSNames:     []string{"rp.example.com"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, caCert, &leafKey.PublicKey, caKey)
	require.NoError(t, err)
	leafCert, err := x509.ParseCertificate(leafDER)
	require.NoError(t, err)

	caEntityID := "https://access-ca-binding-ok.example.com"
	lote := minimalLoTE("SE", x509Entity(caEntityID, caCert))
	path := writeLoTE(t, t.TempDir(), "lote.json", lote)

	reg, err := New(Config{Name: "ca-anchored-binding-ok-test", Sources: []string{path}})
	require.NoError(t, err)

	resp, err := reg.Evaluate(context.Background(), &authzen.EvaluationRequest{
		Subject: authzen.Subject{Type: "key", ID: "x509_san_dns:rp.example.com"},
		Resource: authzen.Resource{
			Type: "x5c",
			ID:   "x509_san_dns:rp.example.com",
			Key: []interface{}{
				base64.StdEncoding.EncodeToString(leafCert.Raw),
				base64.StdEncoding.EncodeToString(caCert.Raw),
			},
		},
	})
	require.NoError(t, err)
	assert.True(t, resp.Decision, "leaf chains to a listed CA and is bound to the claimed x509_san_dns identity - should be trusted, got reason: %v", resp.Context.Reason)
}

// TestEvaluate_X5C_CAAnchored_UntrustedLeafRejected ensures that the global CA
// pool fallback does not grant access to a leaf issued by an unknown CA.
func TestEvaluate_X5C_CAAnchored_UntrustedLeafRejected(t *testing.T) {
	caCert, _ := generateTestCA(t)
	otherCA, otherKey := generateTestCA(t)

	// Leaf issued by otherCA (NOT listed in the LoTE).
	leafCert := generateLeafCert(t, otherCA, otherKey)

	lote := minimalLoTE("SE", x509Entity("https://access-ca.example.com", caCert))
	path := writeLoTE(t, t.TempDir(), "lote.json", lote)

	reg, err := New(Config{
		Name:    "ca-anchored-reject-test",
		Sources: []string{path},
	})
	require.NoError(t, err)

	resp, err := reg.Evaluate(context.Background(), &authzen.EvaluationRequest{
		Subject: authzen.Subject{Type: "key", ID: "https://rp.example.com"},
		Resource: authzen.Resource{
			Type: "x5c",
			ID:   "https://rp.example.com",
			Key:  []interface{}{base64.StdEncoding.EncodeToString(leafCert.Raw)},
		},
	})
	require.NoError(t, err)
	assert.False(t, resp.Decision, "leaf issued by unlisted CA must be rejected")
}

func TestRegistry_SetProfiles(t *testing.T) {
	lote := minimalLoTE("SE", simpleEntity("https://entity.example.com"))
	path := writeLoTE(t, t.TempDir(), "lote.json", lote)

	reg, err := New(Config{
		Name:    "set-profiles-test",
		Sources: []string{path},
	})
	require.NoError(t, err)

	pr := rpcert.NewProfileRegistry()
	// SetProfiles must not panic and must be accepted without error.
	reg.SetProfiles(pr)
}

// TestEvaluate_PubEAA_NotifiedService verifies that Pub-EAA entities with
// a "notified" service status are trusted.
func TestEvaluate_PubEAA_NotifiedService(t *testing.T) {
	lote := &etsi119602.ListOfTrustedEntities{
		ListAndSchemeInformation: etsi119602.ListAndSchemeInformation{
			LoTEVersionIdentifier: 1,
			LoTEType:              etsi119602.LoTETypePubEAAProviders, // Pub-EAA profile
			SchemeTerritory:       "SE",
			SchemeOperatorName:    etsi119602.NameSet{{Lang: "en", Value: "Test"}},
			ListIssueDateTime:     "2026-01-01T00:00:00Z",
			NextUpdate:            "2027-01-01T00:00:00Z",
		},
		TrustedEntitiesList: []etsi119602.TrustedEntity{
			{
				TrustedEntityInformation: etsi119602.TrustedEntityInformation{
					TEName:           etsi119602.NameSet{{Lang: "en", Value: "Pub-EAA Provider"}},
					TEInformationURI: []etsi119602.NonEmptyMultiLangURI{{Lang: "en", URIValue: "https://pubeaa-notified.example.com"}},
				},
				TrustedEntityServices: []etsi119602.TrustedEntityService{
					{
						ServiceInformation: etsi119602.ServiceInformation{
							ServiceName:           etsi119602.NameSet{{Lang: "en", Value: "PubEAA Issuance"}},
							ServiceTypeIdentifier: "http://uri.etsi.org/19602/SvcType/PubEAA/Issuance",
							ServiceStatus:         "http://uri.etsi.org/19602/PubEAAProvidersList/SvcStatus/notified",
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

	dir := t.TempDir()
	path := writeLoTE(t, dir, "lote.json", lote)
	reg, err := New(Config{Sources: []string{path}})
	require.NoError(t, err)

	// Resolution-only should succeed for notified Pub-EAA entity
	resp, err := reg.Evaluate(context.Background(), &authzen.EvaluationRequest{
		Subject:  authzen.Subject{Type: "key", ID: "https://pubeaa-notified.example.com"},
		Resource: authzen.Resource{ID: "https://pubeaa-notified.example.com"},
	})
	require.NoError(t, err)
	assert.True(t, resp.Decision, "Pub-EAA entity with notified service should be trusted")
}

// TestEvaluate_PubEAA_NoNotifiedService verifies that Pub-EAA entities without
// any "notified" service status are NOT trusted (per ETSI TS 119 602 Annex H).
func TestEvaluate_PubEAA_NoNotifiedService(t *testing.T) {
	lote := &etsi119602.ListOfTrustedEntities{
		ListAndSchemeInformation: etsi119602.ListAndSchemeInformation{
			LoTEVersionIdentifier: 1,
			LoTEType:              etsi119602.LoTETypePubEAAProviders, // Pub-EAA profile
			SchemeTerritory:       "SE",
			SchemeOperatorName:    etsi119602.NameSet{{Lang: "en", Value: "Test"}},
			ListIssueDateTime:     "2026-01-01T00:00:00Z",
			NextUpdate:            "2027-01-01T00:00:00Z",
		},
		TrustedEntitiesList: []etsi119602.TrustedEntity{
			{
				TrustedEntityInformation: etsi119602.TrustedEntityInformation{
					TEName:           etsi119602.NameSet{{Lang: "en", Value: "Pub-EAA Provider No Status"}},
					TEInformationURI: []etsi119602.NonEmptyMultiLangURI{{Lang: "en", URIValue: "https://pubeaa-nostatus.example.com"}},
				},
				TrustedEntityServices: []etsi119602.TrustedEntityService{
					{
						ServiceInformation: etsi119602.ServiceInformation{
							ServiceName:           etsi119602.NameSet{{Lang: "en", Value: "PubEAA Issuance"}},
							ServiceTypeIdentifier: "http://uri.etsi.org/19602/SvcType/PubEAA/Issuance",
							// ServiceStatus intentionally absent - per Annex H this should NOT be trusted
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

	dir := t.TempDir()
	path := writeLoTE(t, dir, "lote.json", lote)
	reg, err := New(Config{Sources: []string{path}})
	require.NoError(t, err)

	// Resolution-only should FAIL for Pub-EAA entity without notified status
	resp, err := reg.Evaluate(context.Background(), &authzen.EvaluationRequest{
		Subject:  authzen.Subject{Type: "key", ID: "https://pubeaa-nostatus.example.com"},
		Resource: authzen.Resource{ID: "https://pubeaa-nostatus.example.com"},
	})
	require.NoError(t, err)
	assert.False(t, resp.Decision, "Pub-EAA entity without notified service should NOT be trusted")
	// The entity has a service with absent status: allServicesWithdrawnOrAbsent returns true,
	// so the reason should mention "no active services".
	assert.Contains(t, resp.Context.Reason["admin"], "no active services")
}

// TestEvaluate_PubEAA_WithdrawnOnlyService verifies that Pub-EAA entities with
// only withdrawn services are NOT trusted.
func TestEvaluate_PubEAA_WithdrawnOnlyService(t *testing.T) {
	lote := &etsi119602.ListOfTrustedEntities{
		ListAndSchemeInformation: etsi119602.ListAndSchemeInformation{
			LoTEVersionIdentifier: 1,
			LoTEType:              etsi119602.LoTETypePubEAAProviders, // Pub-EAA profile
			SchemeTerritory:       "SE",
			SchemeOperatorName:    etsi119602.NameSet{{Lang: "en", Value: "Test"}},
			ListIssueDateTime:     "2026-01-01T00:00:00Z",
			NextUpdate:            "2027-01-01T00:00:00Z",
		},
		TrustedEntitiesList: []etsi119602.TrustedEntity{
			{
				TrustedEntityInformation: etsi119602.TrustedEntityInformation{
					TEName:           etsi119602.NameSet{{Lang: "en", Value: "Pub-EAA Provider Withdrawn"}},
					TEInformationURI: []etsi119602.NonEmptyMultiLangURI{{Lang: "en", URIValue: "https://pubeaa-withdrawn.example.com"}},
				},
				TrustedEntityServices: []etsi119602.TrustedEntityService{
					{
						ServiceInformation: etsi119602.ServiceInformation{
							ServiceName:           etsi119602.NameSet{{Lang: "en", Value: "PubEAA Issuance"}},
							ServiceTypeIdentifier: "http://uri.etsi.org/19602/SvcType/PubEAA/Issuance",
							ServiceStatus:         "http://uri.etsi.org/19602/PubEAAProvidersList/SvcStatus/withdrawn",
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

	dir := t.TempDir()
	path := writeLoTE(t, dir, "lote.json", lote)
	reg, err := New(Config{Sources: []string{path}})
	require.NoError(t, err)

	// Resolution-only should FAIL for Pub-EAA entity with only withdrawn services
	resp, err := reg.Evaluate(context.Background(), &authzen.EvaluationRequest{
		Subject:  authzen.Subject{Type: "key", ID: "https://pubeaa-withdrawn.example.com"},
		Resource: authzen.Resource{ID: "https://pubeaa-withdrawn.example.com"},
	})
	require.NoError(t, err)
	assert.False(t, resp.Decision, "Pub-EAA entity with only withdrawn service should NOT be trusted")
}

func TestHasNotifiedService(t *testing.T) {
	// Entity with notified service
	entNotified := etsi119602.TrustedEntity{
		TrustedEntityServices: []etsi119602.TrustedEntityService{
			{
				ServiceInformation: etsi119602.ServiceInformation{
					ServiceStatus: "http://uri.etsi.org/19602/PubEAAProvidersList/SvcStatus/notified",
				},
			},
		},
	}
	assert.True(t, hasNotifiedService(entNotified), "should detect notified service")

	// Entity with withdrawn service only
	entWithdrawn := etsi119602.TrustedEntity{
		TrustedEntityServices: []etsi119602.TrustedEntityService{
			{
				ServiceInformation: etsi119602.ServiceInformation{
					ServiceStatus: "http://uri.etsi.org/19602/PubEAAProvidersList/SvcStatus/withdrawn",
				},
			},
		},
	}
	assert.False(t, hasNotifiedService(entWithdrawn), "should not detect withdrawn as notified")

	// Entity with no status
	entNoStatus := etsi119602.TrustedEntity{
		TrustedEntityServices: []etsi119602.TrustedEntityService{
			{
				ServiceInformation: etsi119602.ServiceInformation{},
			},
		},
	}
	assert.False(t, hasNotifiedService(entNoStatus), "should not detect empty status as notified")

	// Entity with no services
	entNoServices := etsi119602.TrustedEntity{}
	assert.False(t, hasNotifiedService(entNoServices), "should not detect notified with no services")
}

// minimalPubEAALoTE builds a Pub-EAA LoTE (LoTETypePubEAAProviders) with the
// given entities. The LoTEType distinguishes it from generic LoTEs and triggers
// the service-status check in Evaluate().
func minimalPubEAALoTE(territory string, entities ...etsi119602.TrustedEntity) *etsi119602.ListOfTrustedEntities {
	return &etsi119602.ListOfTrustedEntities{
		ListAndSchemeInformation: etsi119602.ListAndSchemeInformation{
			LoTEVersionIdentifier: 1,
			LoTEType:              etsi119602.LoTETypePubEAAProviders,
			SchemeTerritory:       territory,
			SchemeOperatorName:    etsi119602.NameSet{{Lang: "en", Value: territory + " PubEAA Op"}},
			ListIssueDateTime:     "2026-01-01T00:00:00Z",
			NextUpdate:            "2027-01-01T00:00:00Z",
		},
		TrustedEntitiesList: entities,
	}
}

// pubEAAEntity builds a Pub-EAA entity with a single service of the given status.
// Pass "" for status to simulate a missing ServiceStatus field.
func pubEAAEntity(id, serviceStatus string) etsi119602.TrustedEntity {
	svc := etsi119602.TrustedEntityService{
		ServiceInformation: etsi119602.ServiceInformation{
			ServiceName:           etsi119602.NameSet{{Lang: "en", Value: "PubEAA Issuance"}},
			ServiceTypeIdentifier: "http://uri.etsi.org/19602/SvcType/PubEAA/Issuance",
			ServiceStatus:         serviceStatus,
			ServiceDigitalIdentity: etsi119602.ServiceDigitalIdentity{
				PublicKeyValues: []map[string]any{
					{"kty": "EC", "crv": "P-256",
						"x": "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
						"y": "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"},
				},
			},
		},
	}
	return etsi119602.TrustedEntity{
		TrustedEntityInformation: etsi119602.TrustedEntityInformation{
			TEInformationURI: []etsi119602.NonEmptyMultiLangURI{{Lang: "en", URIValue: id}},
		},
		TrustedEntityServices: []etsi119602.TrustedEntityService{svc},
	}
}

// TestEvaluate_PubEAA_WithdrawnErrorReason verifies that the error reason
// distinguishes "all services withdrawn" from "no notified service" (gap #1).
func TestEvaluate_PubEAA_WithdrawnErrorReason(t *testing.T) {
	entityID := "https://pubeaa-withdrawn-reason.example.com"
	lote := minimalPubEAALoTE("SE", pubEAAEntity(entityID, pubEAAStatusWithdrawn))
	path := writeLoTE(t, t.TempDir(), "lote.json", lote)
	reg, err := New(Config{Sources: []string{path}})
	require.NoError(t, err)

	resp, err := reg.Evaluate(context.Background(), &authzen.EvaluationRequest{
		Subject:  authzen.Subject{Type: "key", ID: entityID},
		Resource: authzen.Resource{ID: entityID},
	})
	require.NoError(t, err)
	require.False(t, resp.Decision)
	admin, _ := resp.Context.Reason["admin"].(string)
	assert.Contains(t, admin, "no active services", "reason should say 'no active services' when all are withdrawn, got: %s", admin)
}

// TestEvaluate_PubEAA_X5C_NotifiedService verifies that x5c path validation
// works for a Pub-EAA entity whose CA has notified status (gap #4).
func TestEvaluate_PubEAA_X5C_NotifiedService(t *testing.T) {
	caCert, caKey := generateTestCA(t)
	leafCert := generateLeafCert(t, caCert, caKey)

	caEntityID := "https://pubeaa-ca-notified.example.com"
	ent := etsi119602.TrustedEntity{
		TrustedEntityInformation: etsi119602.TrustedEntityInformation{
			TEInformationURI: []etsi119602.NonEmptyMultiLangURI{{Lang: "en", URIValue: caEntityID}},
		},
		TrustedEntityServices: []etsi119602.TrustedEntityService{{
			ServiceInformation: etsi119602.ServiceInformation{
				ServiceName:           etsi119602.NameSet{{Lang: "en", Value: "PubEAA Issuance"}},
				ServiceTypeIdentifier: "http://uri.etsi.org/19602/SvcType/PubEAA/Issuance",
				ServiceStatus:         pubEAAStatusNotified,
				ServiceDigitalIdentity: etsi119602.ServiceDigitalIdentity{
					X509Certificates: []etsi119602.PKIOb{{Val: base64.StdEncoding.EncodeToString(caCert.Raw)}},
				},
			},
		}},
	}
	lote := minimalPubEAALoTE("SE", ent)
	path := writeLoTE(t, t.TempDir(), "lote.json", lote)
	reg, err := New(Config{Sources: []string{path}})
	require.NoError(t, err)

	// Direct subject match — x5c key validation against the CA pool.
	resp, err := reg.Evaluate(context.Background(), &authzen.EvaluationRequest{
		Subject: authzen.Subject{Type: "key", ID: caEntityID},
		Resource: authzen.Resource{
			Type: "x5c",
			ID:   caEntityID,
			Key: []interface{}{
				base64.StdEncoding.EncodeToString(leafCert.Raw),
				base64.StdEncoding.EncodeToString(caCert.Raw),
			},
		},
	})
	require.NoError(t, err)
	assert.True(t, resp.Decision, "Pub-EAA entity with notified service + valid x5c chain should be trusted")
}

// TestEvaluate_PubEAA_X5C_WithdrawnService verifies that a Pub-EAA entity
// with a withdrawn service rejects x5c requests (gap #4).
func TestEvaluate_PubEAA_X5C_WithdrawnService(t *testing.T) {
	caCert, caKey := generateTestCA(t)
	leafCert := generateLeafCert(t, caCert, caKey)

	caEntityID := "https://pubeaa-ca-withdrawn.example.com"
	ent := etsi119602.TrustedEntity{
		TrustedEntityInformation: etsi119602.TrustedEntityInformation{
			TEInformationURI: []etsi119602.NonEmptyMultiLangURI{{Lang: "en", URIValue: caEntityID}},
		},
		TrustedEntityServices: []etsi119602.TrustedEntityService{{
			ServiceInformation: etsi119602.ServiceInformation{
				ServiceName:           etsi119602.NameSet{{Lang: "en", Value: "PubEAA Issuance"}},
				ServiceTypeIdentifier: "http://uri.etsi.org/19602/SvcType/PubEAA/Issuance",
				ServiceStatus:         pubEAAStatusWithdrawn,
				ServiceDigitalIdentity: etsi119602.ServiceDigitalIdentity{
					X509Certificates: []etsi119602.PKIOb{{Val: base64.StdEncoding.EncodeToString(caCert.Raw)}},
				},
			},
		}},
	}
	lote := minimalPubEAALoTE("SE", ent)
	path := writeLoTE(t, t.TempDir(), "lote.json", lote)
	reg, err := New(Config{Sources: []string{path}})
	require.NoError(t, err)

	resp, err := reg.Evaluate(context.Background(), &authzen.EvaluationRequest{
		Subject: authzen.Subject{Type: "key", ID: caEntityID},
		Resource: authzen.Resource{
			Type: "x5c",
			ID:   caEntityID,
			Key: []interface{}{
				base64.StdEncoding.EncodeToString(leafCert.Raw),
				base64.StdEncoding.EncodeToString(caCert.Raw),
			},
		},
	})
	require.NoError(t, err)
	assert.False(t, resp.Decision, "Pub-EAA entity with only withdrawn service must be rejected for x5c")
}

// TestEvaluate_PubEAA_CAAnchored_WithdrawnCABlocked verifies that the CA-anchored
// x5c fallback (issue #90) is blocked for Pub-EAA CAs whose services are not
// notified — preventing the status check from being bypassed (gap #2).
func TestEvaluate_PubEAA_CAAnchored_WithdrawnCABlocked(t *testing.T) {
	caCert, caKey := generateTestCA(t)
	leafCert := generateLeafCert(t, caCert, caKey)

	caEntityID := "https://pubeaa-ca-withdrawn-anchor.example.com"
	ent := etsi119602.TrustedEntity{
		TrustedEntityInformation: etsi119602.TrustedEntityInformation{
			TEInformationURI: []etsi119602.NonEmptyMultiLangURI{{Lang: "en", URIValue: caEntityID}},
		},
		TrustedEntityServices: []etsi119602.TrustedEntityService{{
			ServiceInformation: etsi119602.ServiceInformation{
				ServiceName:           etsi119602.NameSet{{Lang: "en", Value: "PubEAA Issuance"}},
				ServiceTypeIdentifier: "http://uri.etsi.org/19602/SvcType/PubEAA/Issuance",
				ServiceStatus:         pubEAAStatusWithdrawn,
				ServiceDigitalIdentity: etsi119602.ServiceDigitalIdentity{
					X509Certificates: []etsi119602.PKIOb{{Val: base64.StdEncoding.EncodeToString(caCert.Raw)}},
				},
			},
		}},
	}
	lote := minimalPubEAALoTE("SE", ent)
	path := writeLoTE(t, t.TempDir(), "lote.json", lote)
	reg, err := New(Config{Sources: []string{path}})
	require.NoError(t, err)

	// Subject is "rp.example.com" — NOT listed in the LoTE, so the CA-anchored
	// fallback fires. The CA has only a withdrawn service, so the request must
	// be rejected even though the chain is cryptographically valid.
	resp, err := reg.Evaluate(context.Background(), &authzen.EvaluationRequest{
		Subject: authzen.Subject{Type: "key", ID: "https://rp.example.com"},
		Resource: authzen.Resource{
			Type: "x5c",
			ID:   "https://rp.example.com",
			Key: []interface{}{
				base64.StdEncoding.EncodeToString(leafCert.Raw),
				base64.StdEncoding.EncodeToString(caCert.Raw),
			},
		},
	})
	require.NoError(t, err)
	assert.False(t, resp.Decision, "CA-anchored fallback must be blocked when Pub-EAA CA has no notified service")
}

// TestBuildIndex_SchemeTypePropagation verifies that the LoTEType from the
// list-level metadata is correctly stored on each indexed entity, so that
// Pub-EAA status checking fires correctly at evaluation time (gap #6).
func TestBuildIndex_SchemeTypePropagation(t *testing.T) {
	entityID := "https://pubeaa-propagation.example.com"
	lote := minimalPubEAALoTE("SE", pubEAAEntity(entityID, pubEAAStatusNotified))
	path := writeLoTE(t, t.TempDir(), "lote.json", lote)

	reg, err := New(Config{Sources: []string{path}})
	require.NoError(t, err)

	reg.mu.RLock()
	ent, ok := reg.index.byID[entityID]
	reg.mu.RUnlock()

	require.True(t, ok, "entity must be indexed")
	assert.Equal(t, etsi119602.LoTETypePubEAAProviders, ent.schemeType,
		"schemeType must be propagated from LoTEType during buildIndex")
}

// TestEvaluate_PubEAA_MixedServices_OnlyNotifiedKeyAccepted verifies that for a
// Pub-EAA entity with two services — one notified and one with absent status —
// only the notified service's key is accepted. The key from the absent-status
// service must be rejected even though the entity has a notified service.
// This addresses the Copilot review finding that buildIndex previously indexed
// keys from all non-withdrawn services regardless of Pub-EAA status.
func TestEvaluate_PubEAA_MixedServices_OnlyNotifiedKeyAccepted(t *testing.T) {
	entityID := "https://pubeaa-mixed.example.com"

	// Two distinct EC P-256 public keys. Key A belongs to the notified service,
	// key B to the absent-status service.
	keyNotified := map[string]any{
		"kty": "EC", "crv": "P-256",
		"x": "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
		"y": "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0",
	}
	keyAbsent := map[string]any{
		"kty": "EC", "crv": "P-256",
		"x": "MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
		"y": "4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM",
	}

	ent := etsi119602.TrustedEntity{
		TrustedEntityInformation: etsi119602.TrustedEntityInformation{
			TEInformationURI: []etsi119602.NonEmptyMultiLangURI{{Lang: "en", URIValue: entityID}},
		},
		TrustedEntityServices: []etsi119602.TrustedEntityService{
			{
				ServiceInformation: etsi119602.ServiceInformation{
					ServiceName:           etsi119602.NameSet{{Lang: "en", Value: "Notified Issuance"}},
					ServiceTypeIdentifier: "http://uri.etsi.org/19602/SvcType/PubEAA/Issuance",
					ServiceStatus:         pubEAAStatusNotified,
					ServiceDigitalIdentity: etsi119602.ServiceDigitalIdentity{
						PublicKeyValues: []map[string]any{keyNotified},
					},
				},
			},
			{
				ServiceInformation: etsi119602.ServiceInformation{
					ServiceName:           etsi119602.NameSet{{Lang: "en", Value: "Absent-Status Issuance"}},
					ServiceTypeIdentifier: "http://uri.etsi.org/19602/SvcType/PubEAA/Issuance",
					// ServiceStatus intentionally absent — must NOT be indexed
					ServiceDigitalIdentity: etsi119602.ServiceDigitalIdentity{
						PublicKeyValues: []map[string]any{keyAbsent},
					},
				},
			},
		},
	}
	lote := minimalPubEAALoTE("SE", ent)
	path := writeLoTE(t, t.TempDir(), "lote.json", lote)
	reg, err := New(Config{Sources: []string{path}})
	require.NoError(t, err)

	makeReq := func(key map[string]any) *authzen.EvaluationRequest {
		return &authzen.EvaluationRequest{
			Subject: authzen.Subject{Type: "key", ID: entityID},
			Resource: authzen.Resource{
				Type: "jwk",
				ID:   entityID,
				Key:  []interface{}{key},
			},
		}
	}

	// The notified service's key must be accepted.
	respOK, err := reg.Evaluate(context.Background(), makeReq(keyNotified))
	require.NoError(t, err)
	assert.True(t, respOK.Decision, "notified service key must be trusted")

	// The absent-status service's key must be rejected, even though the entity
	// has another service that is notified.
	respDeny, err := reg.Evaluate(context.Background(), makeReq(keyAbsent))
	require.NoError(t, err)
	assert.False(t, respDeny.Decision, "absent-status service key must NOT be trusted")
}
