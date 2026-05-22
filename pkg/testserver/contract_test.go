package testserver

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/sirosfoundation/go-trust/pkg/authzen"
	"github.com/sirosfoundation/go-trust/pkg/authzenclient"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestContract_DiscoverThenEvaluate exercises the full consumer workflow:
// discover PDP metadata → evaluate trust → check response shape.
// This is the primary pattern used by go-wallet-backend and vc consumers.
func TestContract_DiscoverThenEvaluate(t *testing.T) {
	srv := New(WithAcceptAll())
	defer srv.Close()

	ctx := context.Background()

	// Step 1: Discover
	client, err := authzenclient.Discover(ctx, srv.URL())
	require.NoError(t, err)
	require.NotNil(t, client.Metadata)
	assert.NotEmpty(t, client.Metadata.AccessEvaluationEndpoint)
	assert.NotEmpty(t, client.Metadata.PolicyDecisionPoint)

	// Step 2: Evaluate x5c
	resp, err := client.EvaluateRaw(ctx, &authzen.EvaluationRequest{
		Subject:  authzen.Subject{Type: "key", ID: "https://issuer.example.com"},
		Resource: authzen.Resource{Type: "x5c", ID: "https://issuer.example.com", Key: []interface{}{"MIIBxxx"}},
		Action:   &authzen.Action{Name: "credential-issuer"},
	})
	require.NoError(t, err)
	assert.True(t, resp.Decision)

	// Step 3: Evaluate jwk
	resp, err = client.EvaluateRaw(ctx, &authzen.EvaluationRequest{
		Subject: authzen.Subject{Type: "key", ID: "did:web:example.com"},
		Resource: authzen.Resource{
			Type: "jwk",
			ID:   "did:web:example.com",
			Key:  []interface{}{map[string]interface{}{"kty": "EC", "crv": "P-256"}},
		},
	})
	require.NoError(t, err)
	assert.True(t, resp.Decision)
}

// TestContract_DecisionFuncCapturesRequest verifies that the DecisionFunc
// receives the exact AuthZEN request shape consumers send.
func TestContract_DecisionFuncCapturesRequest(t *testing.T) {
	var captured atomic.Value

	srv := New(WithDecisionFunc(func(req *authzen.EvaluationRequest) (*authzen.EvaluationResponse, error) {
		captured.Store(req)
		return &authzen.EvaluationResponse{Decision: true}, nil
	}))
	defer srv.Close()

	client := authzenclient.New(srv.URL())
	ctx := context.Background()

	sent := &authzen.EvaluationRequest{
		Subject:  authzen.Subject{Type: "key", ID: "https://issuer.example.com"},
		Resource: authzen.Resource{Type: "x5c", ID: "https://issuer.example.com", Key: []interface{}{"MIIBcert"}},
		Action: &authzen.Action{
			Name:       "credential-issuer",
			Parameters: map[string]interface{}{"credential_types": []interface{}{"urn:eu.europa.ec.eudi:pid:1"}},
		},
	}

	resp, err := client.EvaluateRaw(ctx, sent)
	require.NoError(t, err)
	assert.True(t, resp.Decision)

	loaded := captured.Load()
	require.NotNil(t, loaded, "decision callback should have been invoked")
	got, ok := loaded.(*authzen.EvaluationRequest)
	require.True(t, ok, "captured value should be *EvaluationRequest")
	assert.Equal(t, sent.Subject.Type, got.Subject.Type)
	assert.Equal(t, sent.Subject.ID, got.Subject.ID)
	assert.Equal(t, sent.Resource.Type, got.Resource.Type)
	assert.Equal(t, sent.Action.Name, got.Action.Name)
	assert.NotNil(t, got.Action.Parameters)
}

// TestContract_ResolutionOnly verifies that resolution-only requests
// (no resource.type/key) are handled correctly.
func TestContract_ResolutionOnly(t *testing.T) {
	srv := New(WithDecisionFunc(func(req *authzen.EvaluationRequest) (*authzen.EvaluationResponse, error) {
		return &authzen.EvaluationResponse{
			Decision: true,
			Context: &authzen.EvaluationResponseContext{
				TrustMetadata: map[string]interface{}{
					"id": req.Subject.ID,
				},
			},
		}, nil
	}))
	defer srv.Close()

	client := authzenclient.New(srv.URL())
	resp, err := client.Resolve(context.Background(), "did:web:example.com")
	require.NoError(t, err)
	assert.True(t, resp.Decision)
	assert.NotNil(t, resp.Context)
	assert.NotNil(t, resp.Context.TrustMetadata)
}

// TestContract_ConcurrentEvaluations verifies thread safety under concurrent load.
func TestContract_ConcurrentEvaluations(t *testing.T) {
	var counter atomic.Int64

	srv := New(WithDecisionFunc(func(req *authzen.EvaluationRequest) (*authzen.EvaluationResponse, error) {
		counter.Add(1)
		return &authzen.EvaluationResponse{Decision: true}, nil
	}))
	defer srv.Close()

	client := authzenclient.New(srv.URL())
	ctx := context.Background()

	const numGoroutines = 20
	var wg sync.WaitGroup
	errs := make(chan error, numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			resp, err := client.EvaluateRaw(ctx, &authzen.EvaluationRequest{
				Subject:  authzen.Subject{Type: "key", ID: "test"},
				Resource: authzen.Resource{Type: "x5c", ID: "test", Key: []interface{}{"cert"}},
			})
			if err != nil {
				errs <- err
				return
			}
			if !resp.Decision {
				errs <- assert.AnError
			}
		}()
	}

	wg.Wait()
	close(errs)

	for err := range errs {
		t.Errorf("concurrent evaluation failed: %v", err)
	}
	assert.Equal(t, int64(numGoroutines), counter.Load())
}

// TestContract_InvalidRequest verifies the server returns a structured
// error response (not HTTP error) for invalid AuthZEN requests.
func TestContract_InvalidRequest(t *testing.T) {
	srv := New(WithAcceptAll())
	defer srv.Close()

	client := authzenclient.New(srv.URL())
	ctx := context.Background()

	// Invalid subject type
	resp, err := client.EvaluateRaw(ctx, &authzen.EvaluationRequest{
		Subject:  authzen.Subject{Type: "user", ID: "alice"},
		Resource: authzen.Resource{Type: "x5c", ID: "alice", Key: []interface{}{"cert"}},
	})
	require.NoError(t, err, "server should return a valid JSON response, not an HTTP error")
	assert.False(t, resp.Decision)
}

// TestContract_WithMultipleRegistries tests the server with multiple registries
// configured, mimicking a production-like setup.
func TestContract_WithMultipleRegistries(t *testing.T) {
	srv := New(
		WithMockRegistry("etsi-tsl", false, []string{"x5c"}),
		WithMockRegistry("oidfed", true, []string{"jwk", "x5c"}),
	)
	defer srv.Close()

	client := authzenclient.New(srv.URL())
	ctx := context.Background()

	// JWK request — only oidfed supports it, should get decision=true
	resp, err := client.EvaluateRaw(ctx, &authzen.EvaluationRequest{
		Subject:  authzen.Subject{Type: "key", ID: "did:web:x"},
		Resource: authzen.Resource{Type: "jwk", ID: "did:web:x", Key: []interface{}{map[string]interface{}{"kty": "EC"}}},
	})
	require.NoError(t, err)
	assert.True(t, resp.Decision, "oidfed registry should approve the jwk request")
}
