package testserver_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/sirosfoundation/go-trust/pkg/authzen"
	"github.com/sirosfoundation/go-trust/pkg/authzenclient"
	"github.com/sirosfoundation/go-trust/pkg/testserver"
)

// A DecisionFunc can set verifier_ids, and a Go caller reads them through
// authzenclient after a real HTTP round trip through the typed structs on both
// sides, which is where an unknown member would be dropped.
func TestDecisionFunc_VerifierIDsRoundTrip(t *testing.T) {
	var sawHint interface{}
	srv := testserver.New(testserver.WithDecisionFunc(func(req *authzen.EvaluationRequest) (*authzen.EvaluationResponse, error) {
		sawHint = req.Context[authzen.VerifierIDHintContextKey]
		return &authzen.EvaluationResponse{
			Decision: true,
			Context: &authzen.EvaluationResponseContext{
				VerifierIDs: []authzen.VerifierID{
					{Type: authzen.VerifierIDTypeSemantic, ID: "semantic_id:VATSE-556000000101", Basis: authzen.VerifierIDBasisX5CChain},
					{Type: authzen.VerifierIDTypeDNS, ID: "rp.example.com", Basis: authzen.VerifierIDBasisClientIDBinding},
				},
			},
		}, nil
	}))
	defer srv.Close()

	client := authzenclient.New(srv.URL())
	resp, err := client.Evaluate(context.Background(), &authzen.EvaluationRequest{
		Subject:  authzen.Subject{Type: "key", ID: "https://rp.example.com"},
		Resource: authzen.Resource{Type: "x5c", ID: "https://rp.example.com", Key: []interface{}{"MIIC"}},
		Context:  map[string]interface{}{authzen.VerifierIDHintContextKey: "dns"},
	})
	require.NoError(t, err)
	require.True(t, resp.Decision)
	require.NotNil(t, resp.Context)
	assert.Equal(t, []authzen.VerifierID{
		{Type: "semantic", ID: "semantic_id:VATSE-556000000101", Basis: "x5c-chain"},
		{Type: "dns", ID: "rp.example.com", Basis: "client-id-binding"},
	}, resp.Context.VerifierIDs)
	assert.Equal(t, "dns", sawHint, "the request hint reaches the PDP")
}
