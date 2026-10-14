package authzen

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestVerifierIDsJSONShape(t *testing.T) {
	resp := EvaluationResponse{Decision: true, Context: &EvaluationResponseContext{
		VerifierIDs: []VerifierID{
			{Type: VerifierIDTypeSemantic, ID: "semantic_id:VATSE-556000000101", Basis: VerifierIDBasisX5CChain},
			{Type: VerifierIDTypeDNS, ID: "rp.example.com"},
		},
	}}
	b, err := json.Marshal(resp)
	require.NoError(t, err)
	assert.JSONEq(t, `{"decision":true,"context":{"verifier_ids":[
		{"verifier_id_type":"semantic","verifier_id":"semantic_id:VATSE-556000000101","basis":"x5c-chain"},
		{"verifier_id_type":"dns","verifier_id":"rp.example.com"}]}}`, string(b), "basis is optional")

	// Omitted entirely when empty, so existing responses are byte-identical.
	b, err = json.Marshal(EvaluationResponse{Decision: true, Context: &EvaluationResponseContext{ID: "x"}})
	require.NoError(t, err)
	assert.NotContains(t, string(b), "verifier_ids")

	var back EvaluationResponse
	require.NoError(t, json.Unmarshal([]byte(`{"decision":true,"context":{"verifier_ids":[{"verifier_id_type":"did","verifier_id":"did:web:x"}]}}`), &back))
	assert.Equal(t, []VerifierID{{Type: "did", ID: "did:web:x"}}, back.Context.VerifierIDs)
}

func TestSupportedVerifierIDTypes(t *testing.T) {
	for _, ty := range SupportedVerifierIDTypes() {
		assert.True(t, IsSupportedVerifierIDType(ty), ty)
	}
	for _, ty := range []string{"", "DNS", "did_scid", "service", "spki_sha256", "cert_sha256"} {
		assert.False(t, IsSupportedVerifierIDType(ty), ty)
	}
}
