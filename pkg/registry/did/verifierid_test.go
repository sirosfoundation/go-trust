package did

import (
	"context"
	"testing"

	"github.com/sirosfoundation/go-trust/pkg/authzen"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGenericDIDRegistry_VerifierIDs(t *testing.T) {
	const did = "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
	reg := NewGenericDIDRegistryWithKeyMethod(GenericDIDRegistryConfig{})
	ctx := context.Background()

	doc, err := NewDIDKeyResolver().Resolve(ctx, did)
	require.NoError(t, err)
	require.NotEmpty(t, doc.VerificationMethod)
	jwk := doc.VerificationMethod[0].PublicKeyJwk
	require.NotNil(t, jwk)

	req := func(withKey bool, c map[string]interface{}) *authzen.EvaluationRequest {
		rq := &authzen.EvaluationRequest{
			Subject:  authzen.Subject{Type: "key", ID: did},
			Resource: authzen.Resource{ID: did},
			Context:  c,
		}
		if withKey {
			rq.Resource.Type = "jwk"
			rq.Resource.Key = []interface{}{map[string]interface{}(jwk)}
		}
		return rq
	}
	on := map[string]interface{}{authzen.VerifierIDsPolicyContextKey: []string{"did"}}

	resp, err := reg.Evaluate(ctx, req(true, on))
	require.NoError(t, err)
	require.True(t, resp.Decision, "%v", resp.Context.Reason)
	assert.Equal(t, []authzen.VerifierID{{Type: "did", ID: did, Basis: "did-resolution"}}, resp.Context.VerifierIDs)

	resp, err = reg.Evaluate(ctx, req(true, nil))
	require.NoError(t, err)
	require.True(t, resp.Decision)
	assert.Empty(t, resp.Context.VerifierIDs, "policy off")

	resp, err = reg.Evaluate(ctx, req(false, on))
	require.NoError(t, err)
	require.True(t, resp.Decision)
	assert.Empty(t, resp.Context.VerifierIDs, "resolution-only: no key matched")
}
