package did_test

import (
	"context"
	"testing"
	"time"

	"github.com/sirosfoundation/go-trust/pkg/authzen"
	"github.com/sirosfoundation/go-trust/pkg/registry"
	"github.com/sirosfoundation/go-trust/pkg/registry/did"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The verifier client_id from the wallet-backend OID4VP failure this fixes.
const didJwkVerifier = "did:jwk:eyJrdHkiOiJFQyIsImNydiI6IlAtMjU2IiwidXNlIjoic2lnIiwiYWxnIjoiRVMyNTYiLCJ4IjoiY1QtYzVPSnVvWTUzcXpQbEt1S2RHY1FPUHJSSHJET01LTVVLcWNmZGd1YyIsInkiOiJUSmlCWFUtdUhsaGlfMmlXdnJLaEtiMXppX3ZLUHB1VGVTd1ZDNEhKcmVjIn0"

// TestKidBindingThroughManager exercises the path a real request takes --
// RegistryManager.Evaluate, which validates the request and routes it by
// resource type -- rather than calling the registry directly.
//
// Both gates used to reject a kid request before any registry saw it:
// Validate permitted only "jwk"/"x5c", and the DID registry advertised only
// "jwk", so a DID-based client_id could not be evaluated at all.
func TestKidBindingThroughManager(t *testing.T) {
	mgr := registry.NewRegistryManager(registry.FirstMatch, 10*time.Second)
	mgr.Register(did.NewGenericDIDRegistryWithLocalMethods(did.GenericDIDRegistryConfig{}))

	evaluate := func(t *testing.T, resourceType, kid string) *authzen.EvaluationResponse {
		t.Helper()
		resp, err := mgr.Evaluate(context.Background(), &authzen.EvaluationRequest{
			Subject:  authzen.Subject{Type: "key", ID: didJwkVerifier},
			Resource: authzen.Resource{Type: resourceType, ID: didJwkVerifier, Key: []interface{}{kid}},
		})
		require.NoError(t, err)
		return resp
	}

	t.Run("the wallet's request shape is accepted", func(t *testing.T) {
		resp := evaluate(t, "kid", didJwkVerifier+"#0")
		require.True(t, resp.Decision, "reason: %v", resp.Context.Reason)
		assert.Equal(t, didJwkVerifier+"#0", resp.Context.Reason["verification_method"])
	})

	t.Run("a kid the document does not declare is refused", func(t *testing.T) {
		assert.False(t, evaluate(t, "kid", didJwkVerifier+"#nope").Decision)
	})

	t.Run("an unknown resource type is still refused", func(t *testing.T) {
		resp := evaluate(t, "banana", didJwkVerifier+"#0")
		require.False(t, resp.Decision)
		assert.Contains(t, resp.Context.Reason["error"], "resource.type must be")
	})
}
