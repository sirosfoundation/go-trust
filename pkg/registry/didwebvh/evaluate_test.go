package didwebvh

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/sirosfoundation/go-trust/pkg/authzen"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// Evaluate edge cases — these exercise paths at 38.1% coverage
// ---------------------------------------------------------------------------

func TestEvaluate_NonWebVH_Subject(t *testing.T) {
	r, err := NewDIDWebVHRegistry(Config{})
	require.NoError(t, err)

	resp, err := r.Evaluate(context.Background(), &authzen.EvaluationRequest{
		Subject:  authzen.Subject{Type: "key", ID: "did:web:example.com"},
		Resource: authzen.Resource{Type: "jwk", ID: "did:web:example.com", Key: []interface{}{map[string]interface{}{"kty": "EC"}}},
	})
	require.NoError(t, err)
	assert.False(t, resp.Decision)
	assert.Contains(t, resp.Context.Reason["error"], "must be a did:webvh identifier")
}

func TestEvaluate_HTTPFetchError(t *testing.T) {
	// Server that always returns 404
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	// Extract host from test server URL (e.g., "127.0.0.1:PORT")
	host := strings.TrimPrefix(srv.URL, "http://")

	// Percent-encode port colon for did:webvh
	hostEncoded := strings.Replace(host, ":", "%3A", 1)

	scid := "QmWtQnHnZnZnZnZnZnZnZnZnZnZnZnZnZnZnZnZnZnZnZnZ"
	did := fmt.Sprintf("did:webvh:%s:%s", scid, hostEncoded)

	r, err := NewDIDWebVHRegistry(Config{AllowHTTP: true, AllowPrivateIPs: true})
	require.NoError(t, err)

	resp, err := r.Evaluate(context.Background(), &authzen.EvaluationRequest{
		Subject:  authzen.Subject{Type: "key", ID: did},
		Resource: authzen.Resource{Type: "jwk", ID: did, Key: []interface{}{map[string]interface{}{"kty": "EC"}}},
	})
	require.NoError(t, err)
	assert.False(t, resp.Decision)
	assert.Contains(t, resp.Context.Reason["error"], "failed to resolve DID")
}

func TestEvaluate_EmptyDIDLog(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/jsonl")
		w.WriteHeader(http.StatusOK)
		// Empty body
	}))
	defer srv.Close()

	host := strings.TrimPrefix(srv.URL, "http://")
	hostEncoded := strings.Replace(host, ":", "%3A", 1)
	scid := "QmWtQnHnZnZnZnZnZnZnZnZnZnZnZnZnZnZnZnZnZnZnZnZ"
	did := fmt.Sprintf("did:webvh:%s:%s", scid, hostEncoded)

	r, err := NewDIDWebVHRegistry(Config{AllowHTTP: true, AllowPrivateIPs: true})
	require.NoError(t, err)

	resp, err := r.Evaluate(context.Background(), &authzen.EvaluationRequest{
		Subject:  authzen.Subject{Type: "key", ID: did},
		Resource: authzen.Resource{Type: "jwk", ID: did, Key: []interface{}{map[string]interface{}{"kty": "EC"}}},
	})
	require.NoError(t, err)
	assert.False(t, resp.Decision)
	assert.Contains(t, resp.Context.Reason["error"], "failed to resolve DID")
}

func TestEvaluate_InvalidDIDLogJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/jsonl")
		w.WriteHeader(http.StatusOK)
		fmt.Fprintln(w, "not valid json at all")
	}))
	defer srv.Close()

	host := strings.TrimPrefix(srv.URL, "http://")
	hostEncoded := strings.Replace(host, ":", "%3A", 1)
	scid := "QmWtQnHnZnZnZnZnZnZnZnZnZnZnZnZnZnZnZnZnZnZnZnZ"
	did := fmt.Sprintf("did:webvh:%s:%s", scid, hostEncoded)

	r, err := NewDIDWebVHRegistry(Config{AllowHTTP: true, AllowPrivateIPs: true})
	require.NoError(t, err)

	resp, err := r.Evaluate(context.Background(), &authzen.EvaluationRequest{
		Subject:  authzen.Subject{Type: "key", ID: did},
		Resource: authzen.Resource{Type: "jwk", ID: did, Key: []interface{}{map[string]interface{}{"kty": "EC"}}},
	})
	require.NoError(t, err)
	assert.False(t, resp.Decision)
}

func TestEvaluate_ContextTimeout(t *testing.T) {
	// Slow server
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(2 * time.Second)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	host := strings.TrimPrefix(srv.URL, "http://")
	hostEncoded := strings.Replace(host, ":", "%3A", 1)
	scid := "QmWtQnHnZnZnZnZnZnZnZnZnZnZnZnZnZnZnZnZnZnZnZnZ"
	did := fmt.Sprintf("did:webvh:%s:%s", scid, hostEncoded)

	r, err := NewDIDWebVHRegistry(Config{AllowHTTP: true, AllowPrivateIPs: true, Timeout: 100 * time.Millisecond})
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	resp, err := r.Evaluate(ctx, &authzen.EvaluationRequest{
		Subject:  authzen.Subject{Type: "key", ID: did},
		Resource: authzen.Resource{Type: "jwk", ID: did, Key: []interface{}{map[string]interface{}{"kty": "EC"}}},
	})
	require.NoError(t, err)
	assert.False(t, resp.Decision)
}

func TestEvaluate_DIDWithFragment(t *testing.T) {
	// The Evaluate method should strip fragments from subject.id
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	host := strings.TrimPrefix(srv.URL, "http://")
	hostEncoded := strings.Replace(host, ":", "%3A", 1)
	scid := "QmWtQnHnZnZnZnZnZnZnZnZnZnZnZnZnZnZnZnZnZnZnZnZ"
	did := fmt.Sprintf("did:webvh:%s:%s#key-1", scid, hostEncoded)

	r, err := NewDIDWebVHRegistry(Config{AllowHTTP: true, AllowPrivateIPs: true})
	require.NoError(t, err)

	resp, err := r.Evaluate(context.Background(), &authzen.EvaluationRequest{
		Subject:  authzen.Subject{Type: "key", ID: did},
		Resource: authzen.Resource{Type: "jwk", ID: did, Key: []interface{}{map[string]interface{}{"kty": "EC"}}},
	})
	require.NoError(t, err)
	assert.False(t, resp.Decision)
	// Should have attempted resolution (error about DID resolution, not about identifier format)
	assert.Contains(t, resp.Context.Reason["error"], "failed to resolve DID")
}

// ---------------------------------------------------------------------------
// processDIDLog edge cases
// ---------------------------------------------------------------------------

func TestProcessDIDLog_MissingSCID(t *testing.T) {
	r, _ := NewDIDWebVHRegistry(Config{})

	// Entry with no SCID in parameters
	logLine := `{"versionId":"1-abc","versionTime":"2024-01-01T00:00:00Z","parameters":{},"state":{"id":"did:webvh:QmTest:example.com"}}`

	_, _, err := r.processDIDLog(strings.NewReader(logLine), "QmTest", "did:webvh:QmTest:example.com")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "missing SCID")
}

func TestProcessDIDLog_SCIDMismatch(t *testing.T) {
	r, _ := NewDIDWebVHRegistry(Config{})

	logLine := `{"versionId":"1-abc","versionTime":"2024-01-01T00:00:00Z","parameters":{"scid":"QmWrongWrongWrongWrongWrongWrongWrongWrongWrongWrong"},"state":{"id":"did:webvh:QmTest:example.com"}}`

	_, _, err := r.processDIDLog(strings.NewReader(logLine), "QmTestTestTestTestTestTestTestTestTestTestTestTest", "did:webvh:QmTest:example.com")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "SCID mismatch")
}

func TestProcessDIDLog_InvalidVersionPrefix(t *testing.T) {
	r, _ := NewDIDWebVHRegistry(Config{})

	// Version should start with "1-" for first entry, but we give "2-"
	logLine := `{"versionId":"2-abc","versionTime":"2024-01-01T00:00:00Z","parameters":{"scid":"QmTest"},"state":{"id":"did:webvh:QmTest:example.com"}}`

	_, _, err := r.processDIDLog(strings.NewReader(logLine), "QmTest", "did:webvh:QmTest:example.com")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid versionId")
}

// ---------------------------------------------------------------------------
// matchJWK
// ---------------------------------------------------------------------------

func TestMatchJWK(t *testing.T) {
	r, _ := NewDIDWebVHRegistry(Config{})

	tests := []struct {
		name    string
		reqKey  []interface{}
		didDoc  *DIDDocument
		match   bool
		wantErr bool
	}{
		{
			name:   "matching EC keys",
			reqKey: []interface{}{map[string]interface{}{"kty": "EC", "crv": "P-256", "x": "abc", "y": "def"}},
			didDoc: &DIDDocument{
				VerificationMethod: []VerificationMethod{{
					ID:   "#key-1",
					Type: "JsonWebKey2020",
					PublicKeyJwk: map[string]interface{}{"kty": "EC", "crv": "P-256", "x": "abc", "y": "def"},
				}},
			},
			match: true,
		},
		{
			name:   "non-matching keys",
			reqKey: []interface{}{map[string]interface{}{"kty": "EC", "crv": "P-256", "x": "abc", "y": "def"}},
			didDoc: &DIDDocument{
				VerificationMethod: []VerificationMethod{{
					ID:   "#key-1",
					Type: "JsonWebKey2020",
					PublicKeyJwk: map[string]interface{}{"kty": "EC", "crv": "P-256", "x": "xyz", "y": "def"},
				}},
			},
			match: false,
		},
		{
			name:    "empty request key",
			reqKey:  []interface{}{},
			didDoc:  &DIDDocument{},
			match:   false,
			wantErr: true,
		},
		{
			name:    "invalid JWK format",
			reqKey:  []interface{}{"not-a-map"},
			didDoc:  &DIDDocument{},
			match:   false,
			wantErr: true,
		},
		{
			name:   "verification method without JWK",
			reqKey: []interface{}{map[string]interface{}{"kty": "EC"}},
			didDoc: &DIDDocument{
				VerificationMethod: []VerificationMethod{{
					ID:                 "#key-1",
					Type:               "Ed25519VerificationKey2020",
					PublicKeyMultibase: "z6Mk...",
				}},
			},
			match: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matched, _, err := r.matchJWK(tt.reqKey, tt.didDoc)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
			assert.Equal(t, tt.match, matched)
		})
	}
}

// ---------------------------------------------------------------------------
// buildResolutionOnlyResponse
// ---------------------------------------------------------------------------

func TestBuildResolutionOnlyResponse(t *testing.T) {
	r, _ := NewDIDWebVHRegistry(Config{})

	didDoc := &DIDDocument{
		ID: "did:webvh:QmTest:example.com",
		VerificationMethod: []VerificationMethod{
			{ID: "did:webvh:QmTest:example.com#key-1", Type: "Ed25519VerificationKey2020"},
		},
	}
	metadata := &DIDMetadata{
		SCID:      "QmTest",
		VersionID: "1-abc",
	}

	resp := r.buildResolutionOnlyResponse(didDoc, metadata, time.Now())
	assert.True(t, resp.Decision)
	assert.NotNil(t, resp.Context)
	assert.Equal(t, true, resp.Context.Reason["resolution_only"])
	assert.Equal(t, true, resp.Context.Reason["verifiable_history"])
	assert.NotNil(t, resp.Context.TrustMetadata)
}

// ---------------------------------------------------------------------------
// didDocumentToTrustMetadata
// ---------------------------------------------------------------------------

func TestDidDocumentToTrustMetadata(t *testing.T) {
	r, _ := NewDIDWebVHRegistry(Config{})

	didDoc := &DIDDocument{
		Context: "https://www.w3.org/ns/did/v1",
		ID:      "did:webvh:QmTest:example.com",
		VerificationMethod: []VerificationMethod{
			{
				ID:         "did:webvh:QmTest:example.com#key-1",
				Type:       "Ed25519VerificationKey2020",
				Controller: "did:webvh:QmTest:example.com",
			},
		},
	}
	metadata := &DIDMetadata{
		SCID:        "QmTest",
		VersionID:   "2-xyz",
		VersionTime: "2024-06-01T00:00:00Z",
		Created:     "2024-01-01T00:00:00Z",
		Updated:     "2024-06-01T00:00:00Z",
	}

	trustMeta := r.didDocumentToTrustMetadata(didDoc, metadata)
	assert.Equal(t, "did:webvh:QmTest:example.com", trustMeta["id"])
	assert.NotNil(t, trustMeta["verificationMethod"])
	assert.NotNil(t, trustMeta["didResolutionMetadata"])
}

// ---------------------------------------------------------------------------
// Info / SupportedResourceTypes / SupportsResolutionOnly / Healthy / Refresh
// ---------------------------------------------------------------------------

func TestRegistryMetadata(t *testing.T) {
	r, err := NewDIDWebVHRegistry(Config{Description: "Test VH"})
	require.NoError(t, err)

	info := r.Info()
	assert.Equal(t, "didwebvh-registry", info.Name)
	assert.Equal(t, "did:webvh", info.Type)
	assert.Equal(t, "Test VH", info.Description)

	assert.Equal(t, []string{"jwk"}, r.SupportedResourceTypes())
	assert.True(t, r.SupportsResolutionOnly())
	assert.True(t, r.Healthy())
	assert.NoError(t, r.Refresh(context.Background()))
}
