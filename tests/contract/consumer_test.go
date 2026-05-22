// Package contract tests go-trust's public API surface from the perspective
// of its consumers (go-wallet-backend, vc).  These tests exercise the patterns
// that consumer code actually uses, acting as a regression gate against
// accidental contract breakage.
package contract

import (
	"context"
	"encoding/json"
	"sync"
	"testing"

	"github.com/sirosfoundation/go-trust/pkg/authzen"
	"github.com/sirosfoundation/go-trust/pkg/authzenclient"
	"github.com/sirosfoundation/go-trust/pkg/testserver"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// Pattern 1: go-wallet-backend — AuthZEN evaluator via testserver
// go-wallet-backend/pkg/trust/authzen/integration_test.go
// ---------------------------------------------------------------------------

func TestConsumer_WalletBackend_X5CIssuance(t *testing.T) {
	srv := testserver.New(testserver.WithAcceptAll())
	defer srv.Close()

	client := authzenclient.New(srv.URL())
	resp, err := client.EvaluateRaw(context.Background(), &authzen.EvaluationRequest{
		Subject:  authzen.Subject{Type: "key", ID: "https://issuer.example.com"},
		Resource: authzen.Resource{Type: "x5c", ID: "https://issuer.example.com", Key: []interface{}{"MIIBxxx"}},
		Action:   &authzen.Action{Name: "credential-issuer"},
	})
	require.NoError(t, err)
	assert.True(t, resp.Decision)
}

func TestConsumer_WalletBackend_JWKVerification(t *testing.T) {
	srv := testserver.New(testserver.WithAcceptAll())
	defer srv.Close()

	client := authzenclient.New(srv.URL())
	resp, err := client.EvaluateRaw(context.Background(), &authzen.EvaluationRequest{
		Subject: authzen.Subject{Type: "key", ID: "did:web:verifier.example.com"},
		Resource: authzen.Resource{
			Type: "jwk",
			ID:   "did:web:verifier.example.com",
			Key:  []interface{}{map[string]interface{}{"kty": "EC", "crv": "P-256", "x": "f83OJ", "y": "x_FEz"}},
		},
		Action: &authzen.Action{Name: "credential-verifier"},
	})
	require.NoError(t, err)
	assert.True(t, resp.Decision)
}

func TestConsumer_WalletBackend_DecisionCallback(t *testing.T) {
	// go-wallet-backend uses DecisionFunc to capture and validate request shapes
	var captured struct {
		mu  sync.Mutex
		req *authzen.EvaluationRequest
	}

	srv := testserver.New(testserver.WithDecisionFunc(func(req *authzen.EvaluationRequest) (*authzen.EvaluationResponse, error) {
		captured.mu.Lock()
		captured.req = req
		captured.mu.Unlock()
		return &authzen.EvaluationResponse{Decision: true}, nil
	}))
	defer srv.Close()

	client := authzenclient.New(srv.URL())
	_, err := client.EvaluateRaw(context.Background(), &authzen.EvaluationRequest{
		Subject:  authzen.Subject{Type: "key", ID: "https://issuer.example.com"},
		Resource: authzen.Resource{Type: "x5c", ID: "https://issuer.example.com", Key: []interface{}{"MIIBcert"}},
		Action: &authzen.Action{
			Name:       "credential-issuer",
			Parameters: map[string]interface{}{"credential_types": []interface{}{"urn:eu.europa.ec.eudi:pid:1"}},
		},
	})
	require.NoError(t, err)

	captured.mu.Lock()
	got := captured.req
	captured.mu.Unlock()

	require.NotNil(t, got)
	assert.Equal(t, "key", got.Subject.Type)
	assert.Equal(t, "x5c", got.Resource.Type)
	assert.Equal(t, "credential-issuer", got.Action.Name)
	assert.NotNil(t, got.Action.Parameters)
}

// ---------------------------------------------------------------------------
// Pattern 2: vc — GoTrustResolver resolution-only
// vc/pkg/keyresolver/gotrust_adapter.go
// ---------------------------------------------------------------------------

func TestConsumer_VC_ResolutionOnly(t *testing.T) {
	srv := testserver.New(testserver.WithDecisionFunc(func(req *authzen.EvaluationRequest) (*authzen.EvaluationResponse, error) {
		return &authzen.EvaluationResponse{
			Decision: true,
			Context: &authzen.EvaluationResponseContext{
				TrustMetadata: map[string]interface{}{
					"@context": "https://www.w3.org/ns/did/v1",
					"id":       req.Subject.ID,
					"verificationMethod": []interface{}{
						map[string]interface{}{
							"id":                 req.Subject.ID + "#key-1",
							"type":               "JsonWebKey2020",
							"publicKeyJwk":       map[string]interface{}{"kty": "EC", "crv": "P-256"},
						},
					},
				},
			},
		}, nil
	}))
	defer srv.Close()

	client := authzenclient.New(srv.URL())
	resp, err := client.Resolve(context.Background(), "did:web:example.com")
	require.NoError(t, err)
	assert.True(t, resp.Decision)
	require.NotNil(t, resp.Context)
	require.NotNil(t, resp.Context.TrustMetadata)

	// Verify the metadata structure is preserved
	meta, ok := resp.Context.TrustMetadata.(map[string]interface{})
	require.True(t, ok, "trust_metadata should be a map")
	assert.Equal(t, "did:web:example.com", meta["id"])
	assert.NotNil(t, meta["verificationMethod"])
}

// ---------------------------------------------------------------------------
// Pattern 3: vc — GoTrustEvaluator with discovery
// vc/pkg/trust/gotrust.go
// ---------------------------------------------------------------------------

func TestConsumer_VC_DiscoveryAndEvaluate(t *testing.T) {
	srv := testserver.New(testserver.WithAcceptAll())
	defer srv.Close()

	// vc uses Discover() to find the PDP
	client, err := authzenclient.Discover(context.Background(), srv.URL())
	require.NoError(t, err)
	require.NotNil(t, client.Metadata)

	// Then evaluates x5c cert chains
	resp, err := client.EvaluateRaw(context.Background(), &authzen.EvaluationRequest{
		Subject:  authzen.Subject{Type: "key", ID: "https://issuer.example.com"},
		Resource: authzen.Resource{Type: "x5c", ID: "https://issuer.example.com", Key: []interface{}{"MIIBxxx"}},
	})
	require.NoError(t, err)
	assert.True(t, resp.Decision)
}

// ---------------------------------------------------------------------------
// Pattern 4: Wire format stability — consumer JSON shapes
// ---------------------------------------------------------------------------

func TestConsumer_WireFormat_RequestJSON(t *testing.T) {
	// Verify the exact JSON keys consumers rely on
	req := &authzen.EvaluationRequest{
		Subject:  authzen.Subject{Type: "key", ID: "https://issuer.example.com"},
		Resource: authzen.Resource{Type: "x5c", ID: "https://issuer.example.com", Key: []interface{}{"MIIBxxx"}},
		Action:   &authzen.Action{Name: "credential-issuer"},
	}

	data, err := json.Marshal(req)
	require.NoError(t, err)

	var raw map[string]interface{}
	require.NoError(t, json.Unmarshal(data, &raw))

	// These are the keys consumers depend on
	require.Contains(t, raw, "subject")
	require.Contains(t, raw, "resource")
	require.Contains(t, raw, "action")

	subject, ok := raw["subject"].(map[string]interface{})
	require.True(t, ok, "subject should be a map")
	assert.Equal(t, "key", subject["type"])
	assert.Equal(t, "https://issuer.example.com", subject["id"])

	resource, ok := raw["resource"].(map[string]interface{})
	require.True(t, ok, "resource should be a map")
	assert.Equal(t, "x5c", resource["type"])
	assert.NotNil(t, resource["key"])

	action, ok := raw["action"].(map[string]interface{})
	require.True(t, ok, "action should be a map")
	assert.Equal(t, "credential-issuer", action["name"])
}

func TestConsumer_WireFormat_ResponseJSON(t *testing.T) {
	resp := &authzen.EvaluationResponse{
		Decision: true,
		Context: &authzen.EvaluationResponseContext{
			Reason:        map[string]interface{}{"registry": "etsi_tsl"},
			TrustMetadata: map[string]interface{}{"id": "did:web:x"},
		},
	}

	data, err := json.Marshal(resp)
	require.NoError(t, err)

	var raw map[string]interface{}
	require.NoError(t, json.Unmarshal(data, &raw))

	assert.Equal(t, true, raw["decision"])
	require.Contains(t, raw, "context")
	ctx, ok := raw["context"].(map[string]interface{})
	require.True(t, ok, "context should be a map")
	assert.NotNil(t, ctx["reason"])
	assert.NotNil(t, ctx["trust_metadata"])
}

// ---------------------------------------------------------------------------
// Pattern 5: PDPMetadata discovery contract
// ---------------------------------------------------------------------------

func TestConsumer_PDPMetadata_Fields(t *testing.T) {
	srv := testserver.New(testserver.WithAcceptAll())
	defer srv.Close()

	client, err := authzenclient.Discover(context.Background(), srv.URL())
	require.NoError(t, err)

	meta := client.Metadata
	require.NotNil(t, meta)

	// These fields MUST be present per AuthZEN spec
	assert.NotEmpty(t, meta.PolicyDecisionPoint, "policy_decision_point is required")
	assert.NotEmpty(t, meta.AccessEvaluationEndpoint, "access_evaluation_endpoint is required")
}

// ---------------------------------------------------------------------------
// Pattern 6: Reject-all server (go-wallet-backend negative tests)
// ---------------------------------------------------------------------------

func TestConsumer_RejectAll(t *testing.T) {
	srv := testserver.New(testserver.WithRejectAll())
	defer srv.Close()

	client := authzenclient.New(srv.URL())
	resp, err := client.EvaluateRaw(context.Background(), &authzen.EvaluationRequest{
		Subject:  authzen.Subject{Type: "key", ID: "https://issuer.example.com"},
		Resource: authzen.Resource{Type: "x5c", ID: "https://issuer.example.com", Key: []interface{}{"MIIBxxx"}},
	})
	require.NoError(t, err)
	assert.False(t, resp.Decision)
}
