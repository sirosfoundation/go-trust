package registry

import (
	"context"
	"github.com/sirosfoundation/go-trust/pkg/authzen"
	"github.com/stretchr/testify/require"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestPromoteSingleDenyCode(t *testing.T) {
	inner := map[string]interface{}{"code": "expired", "admin": map[string]interface{}{"code": "expired"}}
	details := []map[string]interface{}{{"registry": "r", "reason": inner}}

	reason := map[string]interface{}{"error": "x"}
	promoteSingleDenyCode(reason, details)
	assert.Equal(t, "expired", reason["code"])
	assert.Equal(t, inner["admin"], reason["admin"])

	// code without admin
	reason = map[string]interface{}{}
	promoteSingleDenyCode(reason, []map[string]interface{}{{"reason": map[string]interface{}{"code": "c"}}})
	assert.Equal(t, "c", reason["code"])
	assert.NotContains(t, reason, "admin")

	// more than one registry: ambiguous, nothing promoted
	reason = map[string]interface{}{}
	promoteSingleDenyCode(reason, append(details, details[0]))
	assert.Empty(t, reason)

	// no reason / no code / non-string code: nothing promoted
	for _, d := range [][]map[string]interface{}{
		nil,
		{{"registry": "r"}},
		{{"reason": map[string]interface{}{"error": "e"}}},
		{{"reason": map[string]interface{}{"code": 7}}},
		{{"reason": map[string]interface{}{"code": ""}}},
	} {
		reason = map[string]interface{}{}
		promoteSingleDenyCode(reason, d)
		assert.Empty(t, reason)
	}
}

func TestAllStrategiesPromoteSingleDenyCode(t *testing.T) {
	for _, strat := range []ResolutionStrategy{AllRegistries, BestMatch} {
		mgr := NewRegistryManager(strat, 5*time.Second)
		mgr.Register(&mockRegistry{
			name: "emrtd", resourceTypes: []string{"x5c"}, healthy: true,
			evaluateResponse: &authzen.EvaluationResponse{Decision: false, Context: &authzen.EvaluationResponseContext{
				Reason: map[string]interface{}{"code": "expired", "admin": map[string]interface{}{"code": "expired"}},
			}},
		})
		resp, err := mgr.Evaluate(context.Background(), &authzen.EvaluationRequest{
			Subject: authzen.Subject{Type: "key", ID: "x"}, Resource: authzen.Resource{Type: "x5c", ID: "x"},
		})
		require.NoError(t, err)
		assert.False(t, resp.Decision)
		assert.Equal(t, "expired", resp.Context.Reason["code"], strat)
		assert.NotNil(t, resp.Context.Reason["admin"])
	}
}
