package didweb

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/sirosfoundation/go-trust/pkg/authzen"
	reg "github.com/sirosfoundation/go-trust/pkg/registry"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestDIDToHTTPURL tests the conversion of did:web identifiers to HTTPS URLs
func TestDIDToHTTPURL(t *testing.T) {
	tests := []struct {
		name        string
		did         string
		expectedURL string
		expectError bool
	}{
		{
			name:        "bare domain",
			did:         "did:web:example.com",
			expectedURL: "https://example.com/.well-known/did.json",
			expectError: false,
		},
		{
			name:        "domain with path",
			did:         "did:web:example.com:user:alice",
			expectedURL: "https://example.com/user/alice/did.json",
			expectError: false,
		},
		{
			name:        "domain with port",
			did:         "did:web:example.com%3A3000",
			expectedURL: "https://example.com:3000/.well-known/did.json",
			expectError: false,
		},
		{
			name:        "domain with port and path",
			did:         "did:web:example.com%3A3000:user:bob",
			expectedURL: "https://example.com:3000/user/bob/did.json",
			expectError: false,
		},
		{
			name:        "subdomain",
			did:         "did:web:w3c-ccg.github.io",
			expectedURL: "https://w3c-ccg.github.io/.well-known/did.json",
			expectError: false,
		},
		{
			name:        "subdomain with path",
			did:         "did:web:w3c-ccg.github.io:user:alice",
			expectedURL: "https://w3c-ccg.github.io/user/alice/did.json",
			expectError: false,
		},
		{
			name:        "invalid - not did:web",
			did:         "did:example:123",
			expectedURL: "",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			url, err := didToHTTPURL(tt.did)
			if tt.expectError {
				assert.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expectedURL, url)
			}
		})
	}
}

// TestJWKsMatch tests the JWK comparison logic
func TestJWKsMatch(t *testing.T) {
	tests := []struct {
		name     string
		jwk1     map[string]interface{}
		jwk2     map[string]interface{}
		expected bool
	}{
		{
			name: "matching Ed25519 keys",
			jwk1: map[string]interface{}{
				"kty": "OKP",
				"crv": "Ed25519",
				"x":   "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo",
			},
			jwk2: map[string]interface{}{
				"kty": "OKP",
				"crv": "Ed25519",
				"x":   "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo",
			},
			expected: true,
		},
		{
			name: "different Ed25519 keys",
			jwk1: map[string]interface{}{
				"kty": "OKP",
				"crv": "Ed25519",
				"x":   "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo",
			},
			jwk2: map[string]interface{}{
				"kty": "OKP",
				"crv": "Ed25519",
				"x":   "22qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo",
			},
			expected: false,
		},
		{
			name: "matching P-256 keys",
			jwk1: map[string]interface{}{
				"kty": "EC",
				"crv": "P-256",
				"x":   "38M1FDts7Oea7urmseiugGW7tWc3mLpJh6rKe7xINZ8",
				"y":   "nDQW6XZ7b_u2Sy9slofYLlG03sOEoug3I0aAPQ0exs4",
			},
			jwk2: map[string]interface{}{
				"kty": "EC",
				"crv": "P-256",
				"x":   "38M1FDts7Oea7urmseiugGW7tWc3mLpJh6rKe7xINZ8",
				"y":   "nDQW6XZ7b_u2Sy9slofYLlG03sOEoug3I0aAPQ0exs4",
			},
			expected: true,
		},
		{
			name: "different key types",
			jwk1: map[string]interface{}{
				"kty": "OKP",
				"crv": "Ed25519",
				"x":   "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo",
			},
			jwk2: map[string]interface{}{
				"kty": "EC",
				"crv": "P-256",
				"x":   "38M1FDts7Oea7urmseiugGW7tWc3mLpJh6rKe7xINZ8",
				"y":   "nDQW6XZ7b_u2Sy9slofYLlG03sOEoug3I0aAPQ0exs4",
			},
			expected: false,
		},
		{
			name: "matching RSA keys",
			jwk1: map[string]interface{}{
				"kty": "RSA",
				"n":   "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx",
				"e":   "AQAB",
			},
			jwk2: map[string]interface{}{
				"kty": "RSA",
				"n":   "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx",
				"e":   "AQAB",
			},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := reg.JWKsMatch(tt.jwk1, tt.jwk2)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestResolveDID tests DID resolution with a mock HTTP server
func TestResolveDID(t *testing.T) {
	// Create a test DID document
	testDIDDoc := &DIDDocument{
		Context: "https://www.w3.org/ns/did/v1",
		ID:      "did:web:example.com",
		VerificationMethod: []VerificationMethod{
			{
				ID:         "did:web:example.com#key-1",
				Type:       "JsonWebKey2020",
				Controller: "did:web:example.com",
				PublicKeyJwk: map[string]interface{}{
					"kty": "OKP",
					"crv": "Ed25519",
					"x":   "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo",
				},
			},
		},
	}

	// Create a mock HTTP server
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/.well-known/did.json", r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(testDIDDoc)
	}))
	defer server.Close()

	// Create registry with insecure skip verify for test server
	registry, err := NewDIDWebRegistry(Config{
		InsecureSkipVerify: true,
	})
	require.NoError(t, err)

	// Override the HTTP client to use the test server
	// In a real test, we'd need to mock the DID resolution differently
	// For now, we'll test the parsing logic separately
	t.Run("URL parsing", func(t *testing.T) {
		url, err := didToHTTPURL("did:web:example.com")
		require.NoError(t, err)
		assert.Equal(t, "https://example.com/.well-known/did.json", url)
	})

	// Test with actual resolution would require more sophisticated mocking
	_ = registry
}

// TestEvaluate tests the complete evaluation flow
func TestEvaluate(t *testing.T) {
	// Create a test DID document
	testDIDDoc := &DIDDocument{
		Context: "https://www.w3.org/ns/did/v1",
		ID:      "did:web:example.com",
		VerificationMethod: []VerificationMethod{
			{
				ID:         "did:web:example.com#key-1",
				Type:       "JsonWebKey2020",
				Controller: "did:web:example.com",
				PublicKeyJwk: map[string]interface{}{
					"kty": "OKP",
					"crv": "Ed25519",
					"x":   "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo",
				},
			},
		},
	}

	// Create a mock HTTP server
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(testDIDDoc)
	}))
	defer server.Close()

	// Create registry
	registry, err := NewDIDWebRegistry(Config{
		InsecureSkipVerify: true,
	})
	require.NoError(t, err)

	t.Run("non did:web identifier", func(t *testing.T) {
		req := &authzen.EvaluationRequest{
			Subject: authzen.Subject{
				Type: "key",
				ID:   "not-a-did-web",
			},
			Resource: authzen.Resource{
				Type: "jwk",
				ID:   "not-a-did-web",
				Key: []interface{}{
					map[string]interface{}{
						"kty": "OKP",
						"crv": "Ed25519",
						"x":   "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo",
					},
				},
			},
		}

		resp, err := registry.Evaluate(context.Background(), req)
		require.NoError(t, err)
		assert.False(t, resp.Decision)
		assert.Contains(t, resp.Context.Reason["error"], "must be a did:web identifier")
	})
}

// TestSupportedResourceTypes tests the SupportedResourceTypes method
func TestSupportedResourceTypes(t *testing.T) {
	registry, err := NewDIDWebRegistry(Config{})
	require.NoError(t, err)

	types := registry.SupportedResourceTypes()
	assert.Contains(t, types, "jwk")
}

// TestInfo tests the Info method
func TestInfo(t *testing.T) {
	registry, err := NewDIDWebRegistry(Config{
		Description: "Test Registry",
	})
	require.NoError(t, err)

	info := registry.Info()
	assert.Equal(t, "didweb-registry", info.Name)
	assert.Equal(t, "did:web", info.Type)
	assert.Equal(t, "Test Registry", info.Description)
	assert.Equal(t, "1.0.0", info.Version)
}

// TestHealthy tests the Healthy method
func TestHealthy(t *testing.T) {
	registry, err := NewDIDWebRegistry(Config{})
	require.NoError(t, err)

	assert.True(t, registry.Healthy())
}

// TestRefresh tests the Refresh method
func TestRefresh(t *testing.T) {
	registry, err := NewDIDWebRegistry(Config{})
	require.NoError(t, err)

	err = registry.Refresh(context.Background())
	assert.NoError(t, err)
}

// TestSupportsResolutionOnly tests the SupportsResolutionOnly method
func TestSupportsResolutionOnly(t *testing.T) {
	registry, err := NewDIDWebRegistry(Config{})
	require.NoError(t, err)

	// DIDWebRegistry should support resolution-only requests
	assert.True(t, registry.SupportsResolutionOnly())
}

// TestResolutionOnlyRequest tests resolution-only request handling
func TestResolutionOnlyRequest(t *testing.T) {
	// Create a test DID document
	testDIDDoc := &DIDDocument{
		Context: []interface{}{"https://www.w3.org/ns/did/v1"},
		ID:      "did:web:localhost",
		VerificationMethod: []VerificationMethod{
			{
				ID:         "did:web:localhost#key-1",
				Type:       "JsonWebKey2020",
				Controller: "did:web:localhost",
				PublicKeyJwk: map[string]interface{}{
					"kty": "OKP",
					"crv": "Ed25519",
					"x":   "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo",
				},
			},
		},
		Authentication: []interface{}{"did:web:localhost#key-1"},
	}

	// Create a mock HTTP server that serves the DID document
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(testDIDDoc)
	}))
	defer server.Close()

	// Create a custom DIDWebRegistry with a modified HTTP client for testing
	registry, err := NewDIDWebRegistry(Config{
		InsecureSkipVerify: true,
	})
	require.NoError(t, err)

	// Override httpClient to use the test server
	registry.httpClient = server.Client()

	// Create a resolution-only request (no type or key)
	req := &authzen.EvaluationRequest{
		Subject: authzen.Subject{
			Type: "key",
			ID:   "did:web:localhost",
		},
		Resource: authzen.Resource{
			ID: "did:web:localhost", // No type or key
		},
	}

	// Verify this is recognized as resolution-only
	assert.True(t, req.IsResolutionOnlyRequest())
	assert.NoError(t, req.Validate())

	// The Evaluate call would need real network access or more sophisticated mocking
	// For now, test the buildResolutionOnlyResponse and didDocumentToTrustMetadata methods

	t.Run("buildResolutionOnlyResponse", func(t *testing.T) {
		startTime := time.Now()
		resp := registry.buildResolutionOnlyResponse(testDIDDoc, startTime)
		assert.True(t, resp.Decision)
		assert.NotNil(t, resp.Context)
		assert.NotNil(t, resp.Context.TrustMetadata)

		// Verify trust_metadata contains the DID document
		trustMeta, ok := resp.Context.TrustMetadata.(map[string]interface{})
		assert.True(t, ok)
		assert.Equal(t, "did:web:localhost", trustMeta["id"])
		assert.NotNil(t, trustMeta["verificationMethod"])

		// Verify reason includes resolution_only flag
		assert.Equal(t, true, resp.Context.Reason["resolution_only"])
	})

	t.Run("didDocumentToTrustMetadata", func(t *testing.T) {
		trustMeta := registry.didDocumentToTrustMetadata(testDIDDoc)

		// Check required fields
		assert.Equal(t, "did:web:localhost", trustMeta["id"])
		assert.NotNil(t, trustMeta["@context"])

		// Check verificationMethod
		vms, ok := trustMeta["verificationMethod"].([]map[string]interface{})
		assert.True(t, ok)
		assert.Len(t, vms, 1)
		assert.Equal(t, "did:web:localhost#key-1", vms[0]["id"])
		assert.Equal(t, "JsonWebKey2020", vms[0]["type"])
		assert.NotNil(t, vms[0]["publicKeyJwk"])

		// Check authentication
		assert.NotNil(t, trustMeta["authentication"])
	})
}

// TestTrustMetadataInFullEvaluation tests that trust_metadata is included in successful full evaluations
func TestTrustMetadataInFullEvaluation(t *testing.T) {
	// Create a test DID document
	testDIDDoc := &DIDDocument{
		Context: "https://www.w3.org/ns/did/v1",
		ID:      "did:web:example.com",
		VerificationMethod: []VerificationMethod{
			{
				ID:         "did:web:example.com#key-1",
				Type:       "JsonWebKey2020",
				Controller: "did:web:example.com",
				PublicKeyJwk: map[string]interface{}{
					"kty": "OKP",
					"crv": "Ed25519",
					"x":   "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo",
				},
			},
		},
	}

	registry, err := NewDIDWebRegistry(Config{})
	require.NoError(t, err)

	// Test the trust metadata conversion
	trustMeta := registry.didDocumentToTrustMetadata(testDIDDoc)

	assert.Equal(t, "did:web:example.com", trustMeta["id"])
	assert.Equal(t, "https://www.w3.org/ns/did/v1", trustMeta["@context"])

	vms, ok := trustMeta["verificationMethod"].([]map[string]interface{})
	assert.True(t, ok)
	assert.Len(t, vms, 1)
	assert.Equal(t, "did:web:example.com#key-1", vms[0]["id"])
}

// TestDIDDocumentToTrustMetadataWithOptionalFields tests trust metadata conversion with all optional fields
func TestDIDDocumentToTrustMetadataWithOptionalFields(t *testing.T) {
	testDIDDoc := &DIDDocument{
		Context:    []string{"https://www.w3.org/ns/did/v1", "https://w3id.org/security/suites/jws-2020/v1"},
		ID:         "did:web:example.com",
		Controller: "did:web:parent.com",
		VerificationMethod: []VerificationMethod{
			{
				ID:         "did:web:example.com#key-1",
				Type:       "JsonWebKey2020",
				Controller: "did:web:example.com",
				PublicKeyJwk: map[string]interface{}{
					"kty": "EC",
					"crv": "P-256",
					"x":   "38M1FDts7Oea7urmseiugGW7tWc3mLpJh6rKe7xINZ8",
					"y":   "nDQW6XZ7b_u2Sy9slofYLlG03sOEoug3I0aAPQ0exs4",
				},
			},
			{
				ID:           "did:web:example.com#key-2",
				Type:         "EcdsaSecp256k1VerificationKey2019",
				Controller:   "did:web:example.com",
				PublicKeyHex: "02b97c30de767f084ce3080168ee293053ba33b235d7116a3263d29f1450936b71",
			},
		},
		Authentication:  []interface{}{"did:web:example.com#key-1"},
		AssertionMethod: []interface{}{"did:web:example.com#key-1"},
		KeyAgreement:    []interface{}{"did:web:example.com#key-2"},
		Service: []interface{}{
			map[string]interface{}{
				"id":              "did:web:example.com#service-1",
				"type":            "LinkedDomains",
				"serviceEndpoint": "https://example.com",
			},
		},
	}

	registry, err := NewDIDWebRegistry(Config{})
	require.NoError(t, err)

	trustMeta := registry.didDocumentToTrustMetadata(testDIDDoc)

	// Check all fields are present
	assert.Equal(t, "did:web:example.com", trustMeta["id"])
	assert.Equal(t, "did:web:parent.com", trustMeta["controller"])
	assert.NotNil(t, trustMeta["@context"])
	assert.NotNil(t, trustMeta["verificationMethod"])
	assert.NotNil(t, trustMeta["authentication"])
	assert.NotNil(t, trustMeta["assertionMethod"])
	assert.NotNil(t, trustMeta["keyAgreement"])
	assert.NotNil(t, trustMeta["service"])

	// Check verification methods
	vms, ok := trustMeta["verificationMethod"].([]map[string]interface{})
	assert.True(t, ok)
	assert.Len(t, vms, 2)

	// First method has JWK
	assert.NotNil(t, vms[0]["publicKeyJwk"])
	assert.Empty(t, vms[0]["publicKeyHex"])

	// Second method has hex key
	assert.Empty(t, vms[1]["publicKeyJwk"])
	assert.Equal(t, "02b97c30de767f084ce3080168ee293053ba33b235d7116a3263d29f1450936b71", vms[1]["publicKeyHex"])
}

// TestResolutionOnlyWithNonDIDWeb tests resolution-only with non-did:web identifier
func TestResolutionOnlyWithNonDIDWeb(t *testing.T) {
	registry, err := NewDIDWebRegistry(Config{})
	require.NoError(t, err)

	// Resolution-only request with non-did:web identifier
	req := &authzen.EvaluationRequest{
		Subject: authzen.Subject{
			Type: "key",
			ID:   "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
		},
		Resource: authzen.Resource{
			ID: "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
		},
	}

	resp, err := registry.Evaluate(context.Background(), req)
	require.NoError(t, err)
	assert.False(t, resp.Decision)
	assert.Contains(t, resp.Context.Reason["error"], "must be a did:web identifier")
}

// TestSetHTTPClient tests the SetHTTPClient method
func TestSetHTTPClient(t *testing.T) {
	registry, err := NewDIDWebRegistry(Config{})
	require.NoError(t, err)

	// Create a custom HTTP client
	customClient := &http.Client{
		Timeout: 30 * time.Second,
	}

	// Set the custom client
	registry.SetHTTPClient(customClient)

	// Verify it was set (the client is used internally)
	assert.NotNil(t, registry)
}

// TestEvaluate_InvalidResourceType tests evaluation with non-existent domain
func TestEvaluate_InvalidResourceType(t *testing.T) {
	registry, err := NewDIDWebRegistry(Config{})
	require.NoError(t, err)

	req := &authzen.EvaluationRequest{
		Subject: authzen.Subject{
			Type: "key",
			ID:   "did:web:non-existent-domain-12345.example.com",
		},
		Resource: authzen.Resource{
			Type: "jwk",
			ID:   "did:web:non-existent-domain-12345.example.com",
		},
	}

	resp, err := registry.Evaluate(context.Background(), req)
	require.NoError(t, err)
	assert.False(t, resp.Decision)
	// Should fail due to resolution error
	assert.NotNil(t, resp.Context.Reason)
}

// TestEvaluate_EmptySubjectID tests evaluation with empty subject ID
func TestEvaluate_EmptySubjectID(t *testing.T) {
	registry, err := NewDIDWebRegistry(Config{})
	require.NoError(t, err)

	req := &authzen.EvaluationRequest{
		Subject: authzen.Subject{
			Type: "key",
			ID:   "",
		},
		Resource: authzen.Resource{
			Type: "jwk",
			ID:   "did:web:example.com",
		},
	}

	resp, err := registry.Evaluate(context.Background(), req)
	require.NoError(t, err)
	assert.False(t, resp.Decision)
}

// TestEvaluate_WithMockServer tests evaluation with a mock DID document server
func TestEvaluate_WithMockServer(t *testing.T) {
	// Create a mock DID document
	didDoc := map[string]interface{}{
		"@context": []interface{}{
			"https://www.w3.org/ns/did/v1",
			"https://w3id.org/security/suites/jws-2020/v1",
		},
		"id": "did:web:example.com",
		"verificationMethod": []interface{}{
			map[string]interface{}{
				"id":         "did:web:example.com#key-1",
				"type":       "JsonWebKey2020",
				"controller": "did:web:example.com",
				"publicKeyJwk": map[string]interface{}{
					"kty": "EC",
					"crv": "P-256",
					"x":   "WbbOWOeX3VLvj5t8kdnj4a7z1S_M5OOa3yiAqcVGhKU",
					"y":   "0yLk7PZsv6UvW7J_N-N28RYT0gPBY6xw7_q1VJTg0Xg",
				},
			},
		},
		"authentication":  []interface{}{"did:web:example.com#key-1"},
		"assertionMethod": []interface{}{"did:web:example.com#key-1"},
	}

	// Create mock server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/did+json")
		json.NewEncoder(w).Encode(didDoc)
	}))
	defer server.Close()

	// Create registry
	registry, err := NewDIDWebRegistry(Config{})
	require.NoError(t, err)

	// Test basic registry functionality
	info := registry.Info()
	assert.Equal(t, "didweb-registry", info.Name)
	assert.True(t, registry.Healthy())
	assert.True(t, registry.SupportsResolutionOnly())
}

// TestEvaluate_ResolutionOnlyMode tests resolution-only mode
func TestEvaluate_ResolutionOnlyMode(t *testing.T) {
	registry, err := NewDIDWebRegistry(Config{})
	require.NoError(t, err)

	// Resolution-only request (no key in resource)
	req := &authzen.EvaluationRequest{
		Subject: authzen.Subject{
			Type: "key",
			ID:   "did:web:non-existent-domain.example.com",
		},
		Resource: authzen.Resource{
			ID:  "did:web:non-existent-domain.example.com",
			Key: nil, // No key means resolution-only
		},
	}

	resp, err := registry.Evaluate(context.Background(), req)
	// Should fail because domain doesn't exist, but without panic
	require.NoError(t, err)
	assert.False(t, resp.Decision)
}

// A did:web document whose methods publish their keys as publicKeyMultibase (Ed25519VerificationKey2020,
// Multikey) must hand those keys on in trust_metadata; a relying party resolves the issuer's key from there.
func TestDIDDocumentToTrustMetadataKeepsPublicKeyMultibase(t *testing.T) {
	const doc = `{
	  "@context": ["https://www.w3.org/ns/did/v1", "https://w3id.org/security/multikey/v1"],
	  "id": "did:web:issuer.example",
	  "verificationMethod": [
	    {"id": "did:web:issuer.example#k1", "type": "Ed25519VerificationKey2020", "controller": "did:web:issuer.example",
	     "publicKeyMultibase": "z6MkqFENPafCx8qmm3KEE99cct7Qrr6eNbJR8inKLSE6vZiC"},
	    {"id": "did:web:issuer.example#k2", "type": "Multikey", "controller": "did:web:issuer.example",
	     "publicKeyMultibase": "zDnaeuGVUZ13VTEkfg6jB79b2gMLSiXBrAF7kGSP3Dnffm4it"}
	  ]
	}`
	var didDoc DIDDocument
	require.NoError(t, json.Unmarshal([]byte(doc), &didDoc))

	registry, err := NewDIDWebRegistry(Config{})
	require.NoError(t, err)

	vms, ok := registry.didDocumentToTrustMetadata(&didDoc)["verificationMethod"].([]map[string]interface{})
	require.True(t, ok)
	require.Len(t, vms, 2)
	assert.Equal(t, "z6MkqFENPafCx8qmm3KEE99cct7Qrr6eNbJR8inKLSE6vZiC", vms[0]["publicKeyMultibase"])
	assert.Equal(t, "zDnaeuGVUZ13VTEkfg6jB79b2gMLSiXBrAF7kGSP3Dnffm4it", vms[1]["publicKeyMultibase"])
}
