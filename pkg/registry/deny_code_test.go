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

func TestPromoteSingleDenyCode_IgnoresErrorRecords(t *testing.T) {
	inner := map[string]interface{}{"code": "revoked", "admin": map[string]interface{}{"code": "revoked"}}
	details := []map[string]interface{}{
		{"registry": "emrtd", "decision": false, "reason": inner},
		{"registry": "broken", "error": "boom"},
	}
	reason := map[string]interface{}{}
	promoteSingleDenyCode(reason, details)
	assert.Equal(t, "revoked", reason["code"])

	reason = map[string]interface{}{}
	promoteAllResultsDenyCode(reason, details)
	assert.Equal(t, "revoked", reason["code"])
}

func TestAllStrategiesKeepAllowReasonAndAdmin(t *testing.T) {
	admin := map[string]interface{}{"csca_sha256": "abc"}
	mk := func() *mockRegistry {
		return &mockRegistry{
			name: "emrtd", resourceTypes: []string{"x5c"}, healthy: true,
			evaluateResponse: &authzen.EvaluationResponse{Decision: true, Context: &authzen.EvaluationResponseContext{
				Reason: map[string]interface{}{"admin": admin},
			}},
		}
	}
	req := &authzen.EvaluationRequest{
		Subject: authzen.Subject{Type: "key", ID: "x"}, Resource: authzen.Resource{Type: "x5c", ID: "x"},
	}
	for _, strat := range []ResolutionStrategy{AllRegistries, BestMatch} {
		mgr := NewRegistryManager(strat, 5*time.Second)
		mgr.Register(mk())
		resp, err := mgr.Evaluate(context.Background(), req)
		require.NoError(t, err)
		assert.True(t, resp.Decision)
		assert.Equal(t, admin, resp.Context.Reason["admin"], strat)
	}
	// filtered (policy) variant
	mgr := NewRegistryManager(AllRegistries, 5*time.Second)
	reg := mk()
	mgr.Register(reg)
	resp, err := mgr.evaluateAllFiltered(context.Background(), req, []TrustRegistry{reg}, nil)
	require.NoError(t, err)
	assert.Equal(t, admin, resp.Context.Reason["admin"])
	all := resp.Context.Reason["all_results"].([]map[string]interface{})
	assert.NotNil(t, all[0]["reason"])
}

func TestBestMatchPromotesWinnerAdminWithMultipleAllows(t *testing.T) {
	mk := func(name, fp string) *mockRegistry {
		return &mockRegistry{
			name: name, resourceTypes: []string{"x5c"}, healthy: true,
			evaluateResponse: &authzen.EvaluationResponse{Decision: true, Context: &authzen.EvaluationResponseContext{
				Reason: map[string]interface{}{"admin": map[string]interface{}{"csca_sha256": fp}},
			}},
		}
	}
	req := &authzen.EvaluationRequest{
		Subject: authzen.Subject{Type: "key", ID: "x"}, Resource: authzen.Resource{Type: "x5c", ID: "x"},
	}
	mgr := NewRegistryManager(BestMatch, 5*time.Second)
	a, b := mk("a", "fpA"), mk("b", "fpB")
	mgr.Register(a)
	mgr.Register(b)
	resp, err := mgr.Evaluate(context.Background(), req)
	require.NoError(t, err)
	winner := resp.Context.Reason["registry"].(string)
	want := map[string]string{"a": "fpA", "b": "fpB"}[winner]
	admin := resp.Context.Reason["admin"].(map[string]interface{})
	assert.Equal(t, want, admin["csca_sha256"])

	// policy-filtered wrapper
	mgr.strategy = BestMatch
	resp, err = mgr.evaluateBestMatchWithPolicy(context.Background(), req, nil)
	require.NoError(t, err)
	winner = resp.Context.Reason["registry"].(string)
	want = map[string]string{"a": "fpA", "b": "fpB"}[winner]
	admin = resp.Context.Reason["admin"].(map[string]interface{})
	assert.Equal(t, want, admin["csca_sha256"])
}
