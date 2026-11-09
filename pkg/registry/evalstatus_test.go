package registry

import (
	"context"
	"errors"
	"testing"

	"github.com/sirosfoundation/go-trust/pkg/authzen"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var allStrategies = []ResolutionStrategy{FirstMatch, AllRegistries, BestMatch, Sequential}

func evalStatusOf(resp *authzen.EvaluationResponse) interface{} {
	if resp == nil || resp.Context == nil {
		return nil
	}
	return resp.Context.Reason[authzen.ReasonKeyEvaluationStatus]
}

func TestEvaluate_CouldNotEvaluate_RegistryError(t *testing.T) {
	for _, strategy := range allStrategies {
		t.Run(string(strategy), func(t *testing.T) {
			down := &MockRegistry{name: "down", err: errors.New("boom"), types: []string{"x5c"}}
			resp, err := newTrustDataManager(strategy, down).Evaluate(context.Background(), createTestRequest())
			require.NoError(t, err)
			require.False(t, resp.Decision, "still a denial for clients that read only the decision")
			assert.True(t, resp.CouldNotEvaluate())
			assert.Equal(t, authzen.EvaluationStatusError, evalStatusOf(resp))
			errs, _ := resp.Context.Reason[authzen.ReasonKeyEvaluationErrors].([]map[string]interface{})
			require.Len(t, errs, 1)
			assert.Equal(t, "down", errs[0]["registry"])
			assert.Equal(t, "boom", errs[0]["error"])
		})
	}
}

func TestEvaluate_CouldNotEvaluate_FailedAlongsideRealDenial(t *testing.T) {
	// A registry that failed might have trusted the subject, so the denial is
	// not a verdict even though another registry did answer "no".
	for _, strategy := range allStrategies {
		t.Run(string(strategy), func(t *testing.T) {
			down := &MockRegistry{name: "down", err: errors.New("boom"), types: []string{"x5c"}}
			denies := &MockRegistry{name: "up", decision: false, types: []string{"x5c"}}
			resp, err := newTrustDataManager(strategy, down, denies).Evaluate(context.Background(), createTestRequest())
			require.NoError(t, err)
			require.False(t, resp.Decision)
			assert.True(t, resp.CouldNotEvaluate())
		})
	}
}

func TestEvaluate_CouldNotEvaluate_CircuitOpen(t *testing.T) {
	for _, strategy := range allStrategies {
		t.Run(string(strategy), func(t *testing.T) {
			tripped := &MockRegistry{name: "tripped", decision: true, types: []string{"x5c"}}
			m := newTrustDataManager(strategy, tripped)
			for i := 0; i < 10; i++ {
				m.circuitBreakers["tripped"].RecordFailure()
			}
			resp, err := m.Evaluate(context.Background(), createTestRequest())
			require.NoError(t, err)
			require.False(t, resp.Decision)
			assert.True(t, resp.CouldNotEvaluate())
		})
	}
}

func TestEvaluate_CouldNotEvaluate_Panic(t *testing.T) {
	for _, strategy := range allStrategies {
		t.Run(string(strategy), func(t *testing.T) {
			resp, err := newTrustDataManager(strategy, &panicRegistry{&MockRegistry{name: "panics", types: []string{"x5c"}}}).Evaluate(context.Background(), createTestRequest())
			require.NoError(t, err)
			require.False(t, resp.Decision)
			assert.True(t, resp.CouldNotEvaluate())
		})
	}
}

type panicRegistry struct{ *MockRegistry }

func (p *panicRegistry) Evaluate(context.Context, *authzen.EvaluationRequest) (*authzen.EvaluationResponse, error) {
	panic("kaboom")
}

func TestEvaluate_CouldNotEvaluate_CompositeChildFailure(t *testing.T) {
	down := &MockRegistry{name: "down", err: errors.New("boom"), types: []string{"x5c"}}
	denies := &MockRegistry{name: "denies", decision: false, types: []string{"x5c"}}
	resp, err := newTrustDataManager(FirstMatch, NewCompositeRegistry("comp", LogicOR, down, denies)).Evaluate(context.Background(), createTestRequest())
	require.NoError(t, err)
	require.False(t, resp.Decision)
	assert.True(t, resp.CouldNotEvaluate())
}

func TestEvaluate_NotTrusted_IsNotAnEvaluationError(t *testing.T) {
	for _, strategy := range allStrategies {
		t.Run(string(strategy), func(t *testing.T) {
			a := &MockRegistry{name: "a", decision: false, types: []string{"x5c"}}
			b := &MockRegistry{name: "b", decision: false, types: []string{"x5c"}}
			resp, err := newTrustDataManager(strategy, a, b).Evaluate(context.Background(), createTestRequest())
			require.NoError(t, err)
			require.False(t, resp.Decision)
			assert.False(t, resp.CouldNotEvaluate())
			assert.Nil(t, evalStatusOf(resp))
			assert.NotContains(t, resp.Context.Reason, authzen.ReasonKeyEvaluationErrors)
		})
	}
}

func TestEvaluate_Allow_IsNotMarkedWhenAnotherRegistryFailed(t *testing.T) {
	for _, strategy := range allStrategies {
		t.Run(string(strategy), func(t *testing.T) {
			down := &MockRegistry{name: "down", err: errors.New("boom"), types: []string{"x5c"}}
			allows := &MockRegistry{name: "ok", decision: true, types: []string{"x5c"}}
			resp, err := newTrustDataManager(strategy, down, allows).Evaluate(context.Background(), createTestRequest())
			require.NoError(t, err)
			require.True(t, resp.Decision)
			assert.False(t, resp.CouldNotEvaluate())
			assert.Nil(t, evalStatusOf(resp))
		})
	}
}

func TestEvaluate_PolicyDenials_AreNotEvaluationErrors(t *testing.T) {
	// A request the PDP refuses outright (invalid) is a verdict, not an outage.
	m := newTrustDataManager(FirstMatch, &MockRegistry{name: "a", decision: true, types: []string{"x5c"}})
	resp, err := m.Evaluate(context.Background(), &authzen.EvaluationRequest{})
	require.NoError(t, err)
	require.False(t, resp.Decision)
	assert.False(t, resp.CouldNotEvaluate())
}

func TestCouldNotEvaluate_NilSafe(t *testing.T) {
	var r *authzen.EvaluationResponse
	assert.False(t, r.CouldNotEvaluate())
	assert.False(t, (&authzen.EvaluationResponse{}).CouldNotEvaluate())
	assert.False(t, (&authzen.EvaluationResponse{Decision: true, Context: &authzen.EvaluationResponseContext{
		Reason: map[string]interface{}{authzen.ReasonKeyEvaluationStatus: authzen.EvaluationStatusError},
	}}).CouldNotEvaluate(), "an allow is never a failure")
}

type nilRegistry struct{ *MockRegistry }

func (n *nilRegistry) Evaluate(context.Context, *authzen.EvaluationRequest) (*authzen.EvaluationResponse, error) {
	return nil, nil
}

func TestEvaluate_CouldNotEvaluate_NilResponse(t *testing.T) {
	for _, strategy := range allStrategies {
		t.Run(string(strategy), func(t *testing.T) {
			resp, err := newTrustDataManager(strategy, &nilRegistry{&MockRegistry{name: "silent", types: []string{"x5c"}}}).Evaluate(context.Background(), createTestRequest())
			require.NoError(t, err)
			require.False(t, resp.Decision)
			assert.True(t, resp.CouldNotEvaluate(), "no verdict was supplied")
		})
	}
}
