package didweb

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/sirosfoundation/go-trust/pkg/authzen"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEvaluate_VerifierIDs(t *testing.T) {
	jwk := map[string]interface{}{
		"kty": "EC", "crv": "P-256",
		"x": "WbbOWOeX3VLvj5t8kdnj4a7z1S_M5OOa3yiAqcVGhKU",
		"y": "0yLk7PZsv6UvW7J_N-N28RYT0gPBY6xw7_q1VJTg0Xg",
	}
	var did string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"@context": []interface{}{"https://www.w3.org/ns/did/v1"},
			"id":       did,
			"verificationMethod": []interface{}{map[string]interface{}{
				"id": did + "#key-1", "type": "JsonWebKey2020", "controller": did, "publicKeyJwk": jwk,
			}},
		})
	}))
	defer srv.Close()
	did = "did:web:" + strings.Replace(strings.TrimPrefix(srv.URL, "http://"), ":", "%3A", 1)

	r, err := NewDIDWebRegistry(Config{AllowHTTP: true, AllowPrivateIPs: true})
	require.NoError(t, err)

	req := func(subject string, key interface{}, ctx map[string]interface{}) *authzen.EvaluationRequest {
		rq := &authzen.EvaluationRequest{
			Subject:  authzen.Subject{Type: "key", ID: subject},
			Resource: authzen.Resource{ID: subject},
			Context:  ctx,
		}
		if key != nil {
			rq.Resource.Type = "jwk"
			rq.Resource.Key = []interface{}{key}
		}
		return rq
	}
	enabled := map[string]interface{}{authzen.VerifierIDsPolicyContextKey: []string{"decentralized_identifier"}}

	// Key-bound allow with the policy on: the DID, without the fragment.
	resp, err := r.Evaluate(context.Background(), req(did+"#key-1", jwk, enabled))
	require.NoError(t, err)
	require.True(t, resp.Decision, "%v", resp.Context.Reason)
	assert.Equal(t, []authzen.VerifierID{{Type: "decentralized_identifier", ID: did, Basis: "did-resolution"}}, resp.Context.VerifierIDs)

	// Policy off: unchanged.
	resp, err = r.Evaluate(context.Background(), req(did, jwk, nil))
	require.NoError(t, err)
	require.True(t, resp.Decision)
	assert.Empty(t, resp.Context.VerifierIDs)

	// Hint for another type narrows to nothing.
	hint := map[string]interface{}{authzen.VerifierIDsPolicyContextKey: []string{"decentralized_identifier"}, authzen.VerifierIDHintContextKey: "x509_san_dns"}
	resp, err = r.Evaluate(context.Background(), req(did, jwk, hint))
	require.NoError(t, err)
	assert.Empty(t, resp.Context.VerifierIDs)

	// Resolution only: no key was matched, so no identifier.
	resp, err = r.Evaluate(context.Background(), req(did, nil, enabled))
	require.NoError(t, err)
	require.True(t, resp.Decision)
	assert.Empty(t, resp.Context.VerifierIDs)

	// Key that does not match: deny, nothing.
	other := map[string]interface{}{"kty": "EC", "crv": "P-256", "x": "AAAA", "y": "BBBB"}
	resp, err = r.Evaluate(context.Background(), req(did, other, enabled))
	require.NoError(t, err)
	require.False(t, resp.Decision)
	assert.Empty(t, resp.Context.VerifierIDs)
}
