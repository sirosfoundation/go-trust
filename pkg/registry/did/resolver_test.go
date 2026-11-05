package did

import (
	"context"
	"encoding/base64"
	"testing"

	"github.com/sirosfoundation/go-trust/pkg/authzen"
	reg "github.com/sirosfoundation/go-trust/pkg/registry"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestExtractDIDMethod tests the DID method extraction
func TestExtractDIDMethod(t *testing.T) {
	tests := []struct {
		name        string
		did         string
		expected    string
		expectError bool
	}{
		{
			name:     "did:web",
			did:      "did:web:example.com",
			expected: "web",
		},
		{
			name:     "did:key",
			did:      "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
			expected: "key",
		},
		{
			name:     "did:ethr",
			did:      "did:ethr:0xb9c5714089478a327f09197987f16f9e5d936e8a",
			expected: "ethr",
		},
		{
			name:        "invalid - no prefix",
			did:         "example:123",
			expectError: true,
		},
		{
			name:        "invalid - no method",
			did:         "did:",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			method, err := extractDIDMethod(tt.did)
			if tt.expectError {
				assert.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expected, method)
			}
		})
	}
}

// TestBase58Decode tests the base58btc decoder
func TestBase58Decode(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		expectError bool
	}{
		{
			name:  "simple decode",
			input: "3mJr7AoUCHxNqd",
		},
		{
			name:  "Ed25519 key prefix",
			input: "6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
		},
		{
			name:        "invalid character",
			input:       "0OIl", // Contains invalid chars
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := base58Decode(tt.input)
			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// TestDIDKeyResolverMethod tests the Method() function
func TestDIDKeyResolverMethod(t *testing.T) {
	resolver := NewDIDKeyResolver()
	assert.Equal(t, "key", resolver.Method())
}

// TestDIDKeyResolverResolve tests did:key resolution
func TestDIDKeyResolverResolve(t *testing.T) {
	resolver := NewDIDKeyResolver()
	ctx := context.Background()

	tests := []struct {
		name        string
		did         string
		expectError bool
		errorMsg    string
	}{
		{
			name: "valid Ed25519 did:key",
			did:  "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
		},
		{
			name:        "invalid prefix",
			did:         "did:web:example.com",
			expectError: true,
			errorMsg:    "must start with 'did:key:'",
		},
		{
			name:        "empty key material",
			did:         "did:key:",
			expectError: true,
			errorMsg:    "missing key material",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			doc, err := resolver.Resolve(ctx, tt.did)
			if tt.expectError {
				assert.Error(t, err)
				if tt.errorMsg != "" {
					assert.Contains(t, err.Error(), tt.errorMsg)
				}
			} else {
				require.NoError(t, err)
				assert.NotNil(t, doc)
				assert.Equal(t, tt.did, doc.ID)
				assert.NotEmpty(t, doc.VerificationMethod)
			}
		})
	}
}

// TestDIDKeyResolverEd25519 tests Ed25519 key resolution
func TestDIDKeyResolverEd25519(t *testing.T) {
	resolver := NewDIDKeyResolver()
	ctx := context.Background()

	// This is a known Ed25519 did:key
	did := "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"

	doc, err := resolver.Resolve(ctx, did)
	require.NoError(t, err)
	require.NotNil(t, doc)

	// Check DID document structure
	assert.Equal(t, did, doc.ID)
	assert.Len(t, doc.VerificationMethod, 1)

	vm := doc.VerificationMethod[0]
	assert.Contains(t, vm.ID, did)
	assert.Equal(t, "Ed25519VerificationKey2020", vm.Type)
	assert.Equal(t, did, vm.Controller)
	assert.NotNil(t, vm.PublicKeyJwk)

	// Check JWK
	jwk := vm.PublicKeyJwk
	assert.Equal(t, "OKP", jwk["kty"])
	assert.Equal(t, "Ed25519", jwk["crv"])
	assert.NotEmpty(t, jwk["x"])

	// Check other properties
	assert.NotEmpty(t, doc.Authentication)
	assert.NotEmpty(t, doc.AssertionMethod)
}

// TestGenericDIDRegistryBasic tests basic GenericDIDRegistry functionality
func TestGenericDIDRegistryBasic(t *testing.T) {
	registry := NewGenericDIDRegistry(GenericDIDRegistryConfig{
		Description: "Test Registry",
	})

	// Test Info()
	info := registry.Info()
	assert.Equal(t, "generic-did-registry", info.Name)
	assert.Equal(t, "did", info.Type)
	assert.Equal(t, "Test Registry", info.Description)

	// Test Healthy() - should be false with no resolvers
	assert.False(t, registry.Healthy())

	// Register did:key resolver
	registry.RegisterResolver(NewDIDKeyResolver())

	// Test Healthy() - should be true now
	assert.True(t, registry.Healthy())

	// Test SupportedResourceTypes()
	types := registry.SupportedResourceTypes()
	assert.Contains(t, types, "jwk")

	// Test SupportsResolutionOnly()
	assert.True(t, registry.SupportsResolutionOnly())
}

// TestGenericDIDRegistryResolutionOnly tests resolution-only requests
func TestGenericDIDRegistryResolutionOnly(t *testing.T) {
	registry := NewGenericDIDRegistryWithKeyMethod(GenericDIDRegistryConfig{})
	ctx := context.Background()

	// Create a resolution-only request
	req := &authzen.EvaluationRequest{
		Subject: authzen.Subject{
			Type: "key",
			ID:   "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
		},
		Resource: authzen.Resource{
			ID: "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
		},
	}

	assert.True(t, req.IsResolutionOnlyRequest())

	resp, err := registry.Evaluate(ctx, req)
	require.NoError(t, err)
	assert.True(t, resp.Decision)
	assert.NotNil(t, resp.Context)
	assert.NotNil(t, resp.Context.TrustMetadata)

	// Check trust_metadata contains DID document
	trustMeta, ok := resp.Context.TrustMetadata.(map[string]interface{})
	assert.True(t, ok)
	assert.Equal(t, "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK", trustMeta["id"])

	// Check reason
	assert.Equal(t, true, resp.Context.Reason["resolution_only"])
}

// TestGenericDIDRegistryUnsupportedMethod tests handling of unsupported DID methods
func TestGenericDIDRegistryUnsupportedMethod(t *testing.T) {
	registry := NewGenericDIDRegistryWithKeyMethod(GenericDIDRegistryConfig{})
	ctx := context.Background()

	// Request with unsupported DID method
	req := &authzen.EvaluationRequest{
		Subject: authzen.Subject{
			Type: "key",
			ID:   "did:web:example.com",
		},
		Resource: authzen.Resource{
			ID: "did:web:example.com",
		},
	}

	resp, err := registry.Evaluate(ctx, req)
	require.NoError(t, err)
	assert.False(t, resp.Decision)
	assert.Contains(t, resp.Context.Reason["error"], "no resolver registered")
}

// TestGenericDIDRegistryInvalidDID tests handling of invalid DIDs
func TestGenericDIDRegistryInvalidDID(t *testing.T) {
	registry := NewGenericDIDRegistryWithKeyMethod(GenericDIDRegistryConfig{})
	ctx := context.Background()

	// Request with invalid DID
	req := &authzen.EvaluationRequest{
		Subject: authzen.Subject{
			Type: "key",
			ID:   "not-a-did",
		},
		Resource: authzen.Resource{
			ID: "not-a-did",
		},
	}

	resp, err := registry.Evaluate(ctx, req)
	require.NoError(t, err)
	assert.False(t, resp.Decision)
	assert.Contains(t, resp.Context.Reason["error"], "invalid DID format")
}

// TestGenericDIDRegistryRefresh tests the Refresh method
func TestGenericDIDRegistryRefresh(t *testing.T) {
	registry := NewGenericDIDRegistryWithKeyMethod(GenericDIDRegistryConfig{})
	err := registry.Refresh(context.Background())
	assert.NoError(t, err)
}

// TestDIDDocumentToTrustMetadata tests trust metadata conversion
func TestDIDDocumentToTrustMetadata(t *testing.T) {
	doc := &DIDDocument{
		Context: []string{"https://www.w3.org/ns/did/v1"},
		ID:      "did:key:z6Mktest",
		VerificationMethod: []VerificationMethod{
			{
				ID:         "did:key:z6Mktest#key-1",
				Type:       "Ed25519VerificationKey2020",
				Controller: "did:key:z6Mktest",
				PublicKeyJwk: map[string]interface{}{
					"kty": "OKP",
					"crv": "Ed25519",
					"x":   "testkey",
				},
			},
		},
		Authentication:  []interface{}{"did:key:z6Mktest#key-1"},
		AssertionMethod: []interface{}{"did:key:z6Mktest#key-1"},
	}

	trustMeta := didDocumentToTrustMetadata(doc)

	assert.Equal(t, "did:key:z6Mktest", trustMeta["id"])
	assert.NotNil(t, trustMeta["@context"])
	assert.NotNil(t, trustMeta["verificationMethod"])
	assert.NotNil(t, trustMeta["authentication"])
	assert.NotNil(t, trustMeta["assertionMethod"])

	vms, ok := trustMeta["verificationMethod"].([]map[string]interface{})
	assert.True(t, ok)
	assert.Len(t, vms, 1)
	assert.Equal(t, "did:key:z6Mktest#key-1", vms[0]["id"])
}

// TestJWKsMatch tests JWK comparison
func TestJWKsMatch(t *testing.T) {
	tests := []struct {
		name     string
		jwk1     map[string]interface{}
		jwk2     map[string]interface{}
		expected bool
	}{
		{
			name:     "matching Ed25519",
			jwk1:     map[string]interface{}{"kty": "OKP", "crv": "Ed25519", "x": "abc123"},
			jwk2:     map[string]interface{}{"kty": "OKP", "crv": "Ed25519", "x": "abc123"},
			expected: true,
		},
		{
			name:     "non-matching Ed25519",
			jwk1:     map[string]interface{}{"kty": "OKP", "crv": "Ed25519", "x": "abc123"},
			jwk2:     map[string]interface{}{"kty": "OKP", "crv": "Ed25519", "x": "xyz789"},
			expected: false,
		},
		{
			name:     "matching EC",
			jwk1:     map[string]interface{}{"kty": "EC", "crv": "P-256", "x": "abc", "y": "def"},
			jwk2:     map[string]interface{}{"kty": "EC", "crv": "P-256", "x": "abc", "y": "def"},
			expected: true,
		},
		{
			name:     "different kty",
			jwk1:     map[string]interface{}{"kty": "OKP", "crv": "Ed25519", "x": "abc123"},
			jwk2:     map[string]interface{}{"kty": "EC", "crv": "P-256", "x": "abc", "y": "def"},
			expected: false,
		},
		{
			name:     "matching RSA",
			jwk1:     map[string]interface{}{"kty": "RSA", "n": "modulus", "e": "AQAB"},
			jwk2:     map[string]interface{}{"kty": "RSA", "n": "modulus", "e": "AQAB"},
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

// TestDecodeMultibaseKey tests multibase key decoding
func TestDecodeMultibaseKey(t *testing.T) {
	tests := []struct {
		name         string
		multibaseKey string
		expectType   string
		expectError  bool
		errorMsg     string
	}{
		{
			name:         "key too short",
			multibaseKey: "z",
			expectError:  true,
			errorMsg:     "multibase key too short",
		},
		{
			name:         "empty string",
			multibaseKey: "",
			expectError:  true,
			errorMsg:     "multibase key too short",
		},
		{
			name:         "unsupported encoding",
			multibaseKey: "m0123456789", // 'm' is base64 but not supported
			expectError:  true,
			errorMsg:     "unsupported multibase encoding",
		},
		{
			name:         "valid Ed25519 key",
			multibaseKey: "z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
			expectType:   "Ed25519VerificationKey2020",
			expectError:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			keyType, jwk, err := decodeMultibaseKey(tt.multibaseKey)
			if tt.expectError {
				assert.Error(t, err)
				if tt.errorMsg != "" {
					assert.Contains(t, err.Error(), tt.errorMsg)
				}
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expectType, keyType)
				assert.NotNil(t, jwk)
			}
		})
	}
}

// TestDecompressSecp256k1 tests secp256k1 key decompression
func TestDecompressSecp256k1(t *testing.T) {
	tests := []struct {
		name        string
		compressed  []byte
		expectError bool
		errorMsg    string
	}{
		{
			name:        "invalid length - too short",
			compressed:  []byte{0x02, 0x01, 0x02},
			expectError: true,
			errorMsg:    "invalid compressed key length",
		},
		{
			name:        "invalid length - too long",
			compressed:  make([]byte, 34),
			expectError: true,
			errorMsg:    "invalid compressed key length",
		},
		{
			name:        "bad prefix",
			compressed:  append([]byte{0x04}, make([]byte, 32)...),
			expectError: true,
			errorMsg:    "invalid compressed key prefix",
		},
		{
			// x = 0 gives y^2 = 7, which has no square root modulo p.
			name:        "x not on the curve",
			compressed:  append([]byte{0x02}, make([]byte, 32)...),
			expectError: true,
			errorMsg:    "not on the secp256k1 curve",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			x, y, err := decompressSecp256k1(tt.compressed)
			if tt.expectError {
				assert.Error(t, err)
				if tt.errorMsg != "" {
					assert.Contains(t, err.Error(), tt.errorMsg)
				}
			} else {
				require.NoError(t, err)
				assert.NotNil(t, x)
				assert.NotNil(t, y)
				assert.Len(t, x, 32)
				assert.Len(t, y, 32)
			}
		})
	}
}

// TestDecompressP256 tests P-256 key decompression
func TestDecompressP256(t *testing.T) {
	tests := []struct {
		name        string
		compressed  []byte
		expectError bool
		errorMsg    string
	}{
		{
			name:        "invalid length - too short",
			compressed:  []byte{0x02, 0x01, 0x02},
			expectError: true,
			errorMsg:    "invalid compressed key length",
		},
		{
			name:        "invalid key - wrong prefix",
			compressed:  append([]byte{0x00}, make([]byte, 32)...),
			expectError: true,
			errorMsg:    "failed to decompress P-256 key",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			x, y, err := decompressP256(tt.compressed)
			if tt.expectError {
				assert.Error(t, err)
				if tt.errorMsg != "" {
					assert.Contains(t, err.Error(), tt.errorMsg)
				}
			} else {
				require.NoError(t, err)
				assert.NotNil(t, x)
				assert.NotNil(t, y)
			}
		})
	}
}

// TestDecompressP384 tests P-384 key decompression
func TestDecompressP384(t *testing.T) {
	tests := []struct {
		name        string
		compressed  []byte
		expectError bool
		errorMsg    string
	}{
		{
			name:        "invalid length - too short",
			compressed:  []byte{0x02, 0x01, 0x02},
			expectError: true,
			errorMsg:    "invalid compressed key length",
		},
		{
			name:        "invalid length - wrong size",
			compressed:  make([]byte, 33), // P-384 needs 49 bytes
			expectError: true,
			errorMsg:    "invalid compressed key length",
		},
		{
			name:        "invalid key - wrong prefix",
			compressed:  append([]byte{0x00}, make([]byte, 48)...),
			expectError: true,
			errorMsg:    "failed to decompress P-384 key",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			x, y, err := decompressP384(tt.compressed)
			if tt.expectError {
				assert.Error(t, err)
				if tt.errorMsg != "" {
					assert.Contains(t, err.Error(), tt.errorMsg)
				}
			} else {
				require.NoError(t, err)
				assert.NotNil(t, x)
				assert.NotNil(t, y)
			}
		})
	}
}

// Real secp256k1 points (generated with Python's cryptography package, independent of this decoder): the compressed
// form must decompress to exactly the uncompressed coordinates, for both y parities.
func TestDecompressSecp256k1RealPoints(t *testing.T) {
	for _, tc := range []struct{ x, y string }{
		{"LAxTHydqU13NjFrgTfXB7h9TlSuoB-cxCtOlEJpJIB4", "RwT44IEftOfZ9s1af4lOiah4QrAIeiPW30cGVhKRDQE"},
		{"yMmTu6V5UrICVyBFnq3SgPKuvwfLOodOo-0zjUWpsj0", "RQueaCTANVe-biye2RoCrc19_uMdYBQPsdQDNzQi4go"},
	} {
		wantX, err := base64.RawURLEncoding.DecodeString(tc.x)
		require.NoError(t, err)
		wantY, err := base64.RawURLEncoding.DecodeString(tc.y)
		require.NoError(t, err)
		compressed := append([]byte{0x02 | wantY[31]&1}, wantX...)

		x, y, err := decompressSecp256k1(compressed)
		require.NoError(t, err)
		assert.Equal(t, wantX, x)
		assert.Equal(t, wantY, y)
	}
}
