package oidfed

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"testing"

	oidfed "github.com/go-oidfed/lib"
	oidfedjwx "github.com/go-oidfed/lib/jwx"
	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/sirosfoundation/go-trust/pkg/authzen"
)

// TestEvaluate_VerifierIDs_OIDFEntity serves a validated trust chain from the
// cache (no network) and checks the entity identifier is returned only for a
// key-bound allow, byte-for-byte, with the policy's say-so.
func TestEvaluate_VerifierIDs_OIDFEntity(t *testing.T) {
	const entityID = "https://rp.example.com"

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	key, err := jwk.Import[jwk.Key](&priv.PublicKey)
	require.NoError(t, err)
	set := jwk.NewSet()
	require.NoError(t, set.AddKey(key))

	reg, err := NewOIDFedRegistry(Config{TrustAnchors: []TrustAnchorConfig{{EntityID: "https://ta.example.com"}}})
	require.NoError(t, err)

	chainFor := func(subject string) oidfed.TrustChain {
		return oidfed.TrustChain{
			&oidfed.EntityStatement{EntityStatementPayload: oidfed.EntityStatementPayload{
				Issuer: subject, Subject: subject, JWKS: oidfedjwx.JWKS{Set: set},
			}},
			&oidfed.EntityStatement{EntityStatementPayload: oidfed.EntityStatementPayload{
				Issuer: "https://ta.example.com", Subject: "https://ta.example.com",
			}},
		}
	}

	keyJSON, err := json.Marshal(key)
	require.NoError(t, err)
	var jwkMap map[string]interface{}
	require.NoError(t, json.Unmarshal(keyJSON, &jwkMap))

	request := func(ctx map[string]interface{}, withKey bool) *authzen.EvaluationRequest {
		rq := &authzen.EvaluationRequest{
			Subject:  authzen.Subject{Type: "key", ID: entityID},
			Resource: authzen.Resource{ID: entityID},
			Context:  ctx,
		}
		if withKey {
			rq.Resource.Type = "jwk"
			rq.Resource.Key = []interface{}{jwkMap}
		}
		return rq
	}
	enabled := map[string]interface{}{authzen.VerifierIDsPolicyContextKey: []string{"oidf_entity"}}

	reg.cache.Set(entityID, nil, nil, []oidfed.TrustChain{chainFor(entityID)}, "https://ta.example.com")

	resp, err := reg.Evaluate(context.Background(), request(enabled, true))
	require.NoError(t, err)
	require.True(t, resp.Decision, "%v", resp.Context.Reason)
	assert.Equal(t, []authzen.VerifierID{{Type: "oidf_entity", ID: entityID, Basis: "oidf-trust-chain"}}, resp.Context.VerifierIDs)

	// Policy off: unchanged.
	resp, err = reg.Evaluate(context.Background(), request(nil, true))
	require.NoError(t, err)
	require.True(t, resp.Decision)
	assert.Empty(t, resp.Context.VerifierIDs)

	// Hint narrowing to another type: nothing.
	hint := map[string]interface{}{authzen.VerifierIDsPolicyContextKey: []string{"oidf_entity"}, authzen.VerifierIDHintContextKey: "did"}
	resp, err = reg.Evaluate(context.Background(), request(hint, true))
	require.NoError(t, err)
	assert.Empty(t, resp.Context.VerifierIDs)

	// Resolution-only: validated chain, but no key bound to the entity.
	resp, err = reg.Evaluate(context.Background(), request(enabled, false))
	require.NoError(t, err)
	require.True(t, resp.Decision)
	assert.Empty(t, resp.Context.VerifierIDs)

	// A chain whose leaf statement is about a different entity is never echoed
	// under the requested entity's name.
	reg.cache.Set(entityID, nil, nil, []oidfed.TrustChain{chainFor("https://other.example.com")}, "https://ta.example.com")
	resp, err = reg.Evaluate(context.Background(), request(enabled, true))
	require.NoError(t, err)
	require.True(t, resp.Decision, "the decision path is unchanged; only the identifier is withheld")
	assert.Empty(t, resp.Context.VerifierIDs)
}
