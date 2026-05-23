package authzen

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestGoldenWireFormat ensures AuthZEN request/response JSON shapes are stable.
// If the golden file does not exist it is created (first run).  On subsequent
// runs the test fails when the serialised form drifts.
func TestGoldenWireFormat(t *testing.T) {
	vectors := []struct {
		name string
		obj  interface{}
	}{
		{
			name: "full_x5c_request",
			obj: EvaluationRequest{
				Subject:  Subject{Type: "key", ID: "https://issuer.example.com"},
				Resource: Resource{Type: "x5c", ID: "https://issuer.example.com", Key: []interface{}{"MIIBxxx"}},
				Action:   &Action{Name: "credential-issuer"},
			},
		},
		{
			name: "full_jwk_request",
			obj: EvaluationRequest{
				Subject: Subject{Type: "key", ID: "did:web:example.com"},
				Resource: Resource{
					Type: "jwk",
					ID:   "did:web:example.com",
					Key: []interface{}{map[string]interface{}{
						"kty": "EC",
						"crv": "P-256",
						"x":   "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
						"y":   "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0",
					}},
				},
				Action: &Action{Name: "credential-verifier"},
			},
		},
		{
			name: "action_with_parameters",
			obj: EvaluationRequest{
				Subject:  Subject{Type: "key", ID: "https://issuer.example.com"},
				Resource: Resource{Type: "x5c", ID: "https://issuer.example.com", Key: []interface{}{"MIIBxxx"}},
				Action: &Action{
					Name: "credential-issuer",
					Parameters: map[string]interface{}{
						"credential_types": []interface{}{"urn:eu.europa.ec.eudi:pid:1"},
					},
				},
			},
		},
		{
			name: "resolution_only_request",
			obj: EvaluationRequest{
				Subject:  Subject{Type: "key", ID: "did:web:example.com"},
				Resource: Resource{ID: "did:web:example.com"},
			},
		},
		{
			name: "url_subject_request",
			obj: EvaluationRequest{
				Subject:  Subject{Type: "url", ID: "https://verifier.example.com"},
				Resource: Resource{ID: "https://verifier.example.com"},
			},
		},
		{
			name: "minimal_request_no_action",
			obj: EvaluationRequest{
				Subject:  Subject{Type: "key", ID: "did:example:123"},
				Resource: Resource{Type: "x5c", ID: "did:example:123", Key: []interface{}{"cert"}},
			},
		},
		{
			name: "request_with_context",
			obj: EvaluationRequest{
				Subject:  Subject{Type: "key", ID: "https://issuer.example.com"},
				Resource: Resource{Type: "x5c", ID: "https://issuer.example.com", Key: []interface{}{"MIIBxxx"}},
				Context:  map[string]interface{}{"tenant": "acme-corp"},
			},
		},
		{
			name: "decision_true_response",
			obj: EvaluationResponse{
				Decision: true,
				Context: &EvaluationResponseContext{
					Reason: map[string]interface{}{
						"registry": "etsi_tsl",
					},
				},
			},
		},
		{
			name: "decision_false_response",
			obj: EvaluationResponse{
				Decision: false,
				Context: &EvaluationResponseContext{
					Reason: map[string]interface{}{
						"error": "no matching trust anchor",
					},
				},
			},
		},
		{
			name: "response_with_trust_metadata",
			obj: EvaluationResponse{
				Decision: true,
				Context: &EvaluationResponseContext{
					TrustMetadata: map[string]interface{}{
						"@context": "https://www.w3.org/ns/did/v1",
						"id":       "did:web:example.com",
					},
				},
			},
		},
		{
			name: "pdp_metadata",
			obj: PDPMetadata{
				PolicyDecisionPoint:      "https://pdp.example.com",
				AccessEvaluationEndpoint: "https://pdp.example.com/evaluation",
			},
		},
	}

	goldenDir := filepath.Join("testdata", "golden")

	for _, v := range vectors {
		t.Run(v.name, func(t *testing.T) {
			got, err := json.MarshalIndent(v.obj, "", "  ")
			require.NoError(t, err)

			goldenPath := filepath.Join(goldenDir, v.name+".json")

			if os.Getenv("UPDATE_GOLDEN") == "1" {
				require.NoError(t, os.MkdirAll(goldenDir, 0o755))
				require.NoError(t, os.WriteFile(goldenPath, got, 0o644))
				t.Logf("updated golden file: %s", goldenPath)
				return
			}

			want, err := os.ReadFile(goldenPath)
			if os.IsNotExist(err) {
				t.Fatalf("golden file missing: %s — run with UPDATE_GOLDEN=1 to create", goldenPath)
			}
			require.NoError(t, err, "failed to read golden file %s", goldenPath)

			assert.JSONEq(t, string(want), string(got),
				"wire format drift detected for %s — run with UPDATE_GOLDEN=1 to update", v.name)
		})
	}
}

// TestGoldenRoundTrip verifies that all golden vectors can be marshaled and
// unmarshaled without loss. This catches silent field drops or type coercion.
func TestGoldenRoundTrip(t *testing.T) {
	t.Run("EvaluationRequest", func(t *testing.T) {
		requests := []EvaluationRequest{
			{
				Subject:  Subject{Type: "key", ID: "did:web:example.com"},
				Resource: Resource{Type: "jwk", ID: "did:web:example.com", Key: []interface{}{map[string]interface{}{"kty": "EC"}}},
				Action:   &Action{Name: "issuer", Parameters: map[string]interface{}{"vct": []interface{}{"pid"}}},
				Context:  map[string]interface{}{"flow": "issuance"},
			},
			{
				Subject:  Subject{Type: "key", ID: "did:web:example.com"},
				Resource: Resource{ID: "did:web:example.com"},
			},
		}

		for i, req := range requests {
			data, err := json.Marshal(req)
			require.NoError(t, err, "marshal request %d", i)

			var got EvaluationRequest
			require.NoError(t, json.Unmarshal(data, &got), "unmarshal request %d", i)

			// Re-marshal for stable comparison
			data2, err := json.Marshal(got)
			require.NoError(t, err)
			assert.JSONEq(t, string(data), string(data2), "round-trip mismatch for request %d", i)
		}
	})

	t.Run("EvaluationResponse", func(t *testing.T) {
		responses := []EvaluationResponse{
			{Decision: true},
			{Decision: false, Context: &EvaluationResponseContext{
				Reason:        map[string]interface{}{"error": "not found"},
				TrustMetadata: map[string]interface{}{"id": "did:web:x"},
			}},
		}

		for i, resp := range responses {
			data, err := json.Marshal(resp)
			require.NoError(t, err, "marshal response %d", i)

			var got EvaluationResponse
			require.NoError(t, json.Unmarshal(data, &got), "unmarshal response %d", i)

			data2, err := json.Marshal(got)
			require.NoError(t, err)
			assert.JSONEq(t, string(data), string(data2), "round-trip mismatch for response %d", i)
		}
	})
}

// TestFieldPresence verifies that omitempty fields behave correctly.
func TestFieldPresence(t *testing.T) {
	t.Run("action omitted when nil", func(t *testing.T) {
		req := EvaluationRequest{
			Subject:  Subject{Type: "key", ID: "x"},
			Resource: Resource{Type: "x5c", ID: "x", Key: []interface{}{"c"}},
		}
		data, err := json.Marshal(req)
		require.NoError(t, err)
		assert.NotContains(t, string(data), `"action"`)
	})

	t.Run("action present when set", func(t *testing.T) {
		req := EvaluationRequest{
			Subject:  Subject{Type: "key", ID: "x"},
			Resource: Resource{Type: "x5c", ID: "x", Key: []interface{}{"c"}},
			Action:   &Action{Name: "issuer"},
		}
		data, err := json.Marshal(req)
		require.NoError(t, err)
		assert.Contains(t, string(data), `"action"`)
	})

	t.Run("context omitted when nil", func(t *testing.T) {
		req := EvaluationRequest{
			Subject:  Subject{Type: "key", ID: "x"},
			Resource: Resource{Type: "x5c", ID: "x", Key: []interface{}{"c"}},
		}
		data, err := json.Marshal(req)
		require.NoError(t, err)
		assert.NotContains(t, string(data), `"context"`)
	})

	t.Run("parameters omitted when nil", func(t *testing.T) {
		action := Action{Name: "issuer"}
		data, err := json.Marshal(action)
		require.NoError(t, err)
		assert.NotContains(t, string(data), `"parameters"`)
	})

	t.Run("response context omitted when nil", func(t *testing.T) {
		resp := EvaluationResponse{Decision: true}
		data, err := json.Marshal(resp)
		require.NoError(t, err)
		assert.NotContains(t, string(data), `"context"`)
	})

	t.Run("response decision false is explicit", func(t *testing.T) {
		resp := EvaluationResponse{Decision: false}
		data, err := json.Marshal(resp)
		require.NoError(t, err)
		assert.Contains(t, string(data), `"decision":false`)
	})
}
