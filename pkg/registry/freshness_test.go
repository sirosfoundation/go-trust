package registry

import (
	"context"
	"testing"
	"time"

	"github.com/sirosfoundation/go-trust/pkg/authzen"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// freshMock is a MockRegistry that also reports freshness.
type freshMock struct {
	*MockRegistry
	f Freshness
}

func (m *freshMock) Freshness() Freshness { return m.f }

func TestParseSourceTime(t *testing.T) {
	want := time.Date(2026, 10, 26, 0, 0, 0, 0, time.UTC)
	assert.True(t, ParseSourceTime("2026-10-26T00:00:00Z").Equal(want))
	assert.True(t, ParseSourceTime("2026-10-26T02:00:00+02:00").Equal(want))
	assert.True(t, ParseSourceTime("2026-10-26T00:00:00.5Z").Equal(want.Add(500*time.Millisecond)))
	// No explicit offset: the zone would have to be guessed, so it is unknown.
	assert.True(t, ParseSourceTime("2026-10-26T00:00:00").IsZero())
	assert.True(t, ParseSourceTime("2026-10-26").IsZero())
	assert.True(t, ParseSourceTime("").IsZero())
	// Unparseable is unknown, never a guess.
	assert.True(t, ParseSourceTime("next tuesday").IsZero())
}

func TestEarliestKnown(t *testing.T) {
	a := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	b := a.Add(time.Hour)
	assert.True(t, EarliestKnown().IsZero())
	assert.True(t, EarliestKnown(b, a).Equal(a))
	// Any unknown makes the whole unknown: a decision may rest on that list.
	assert.True(t, EarliestKnown(b, time.Time{}, a).IsZero())
	assert.True(t, EarliestKnown(time.Time{}, time.Time{}).IsZero())
}

func newTrustDataManager(strategy ResolutionStrategy, regs ...TrustRegistry) *RegistryManager {
	m := NewRegistryManager(strategy, time.Second)
	for _, r := range regs {
		m.Register(r)
	}
	return m
}

func TestEvaluate_TrustData(t *testing.T) {
	asOf := time.Date(2026, 10, 19, 0, 0, 0, 0, time.UTC)
	next := time.Date(2026, 10, 26, 0, 0, 0, 0, time.UTC)

	reporting := &freshMock{
		MockRegistry: &MockRegistry{name: "etsi", decision: true, types: []string{"x5c"}},
		f:            Freshness{AsOf: asOf, NextUpdate: next},
	}
	plain := &MockRegistry{name: "wl", decision: false, types: []string{"x5c"}}

	for _, strategy := range []ResolutionStrategy{FirstMatch, AllRegistries, BestMatch, Sequential} {
		t.Run(string(strategy), func(t *testing.T) {
			m := newTrustDataManager(strategy, reporting, plain)
			resp, err := m.Evaluate(context.Background(), createTestRequest())
			require.NoError(t, err)
			require.NotNil(t, resp.Context)
			assert.NotEmpty(t, resp.Context.ID)

			byName := map[string]authzen.TrustData{}
			for _, td := range resp.Context.TrustData {
				byName[td.Registry] = td
			}
			require.Contains(t, byName, "etsi")
			assert.Equal(t, "2026-10-19T00:00:00Z", byName["etsi"].AsOf)
			assert.Equal(t, "2026-10-26T00:00:00Z", byName["etsi"].NextUpdate)
			// A registry with no notion of freshness is still listed, with
			// nothing to bound the answer: unknown, not omitted.
			require.Contains(t, byName, "wl")
			assert.Empty(t, byName["wl"].AsOf)
			assert.Empty(t, byName["wl"].NextUpdate)
		})
	}
}

func TestEvaluate_TrustDataFlattensComposite(t *testing.T) {
	next := time.Date(2026, 10, 26, 0, 0, 0, 0, time.UTC)
	a := &freshMock{MockRegistry: &MockRegistry{name: "a", decision: true, types: []string{"x5c"}}, f: Freshness{NextUpdate: next}}
	b := &MockRegistry{name: "b", decision: true, types: []string{"x5c"}}
	comp := NewCompositeRegistry("comp", LogicOR, a, b)

	m := newTrustDataManager(FirstMatch, comp)
	resp, err := m.Evaluate(context.Background(), createTestRequest())
	require.NoError(t, err)

	var names []string
	for _, td := range resp.Context.TrustData {
		names = append(names, td.Registry)
	}
	assert.ElementsMatch(t, []string{"a", "b"}, names, "composite contributes its children, not itself")
}

func TestEvaluate_TrustDataOnDeny(t *testing.T) {
	// A denial depends on the data too: it may flip when the list is replaced.
	next := time.Date(2026, 10, 26, 0, 0, 0, 0, time.UTC)
	r := &freshMock{MockRegistry: &MockRegistry{name: "etsi", decision: false, types: []string{"x5c"}}, f: Freshness{NextUpdate: next}}
	resp, err := newTrustDataManager(FirstMatch, r).Evaluate(context.Background(), createTestRequest())
	require.NoError(t, err)
	assert.False(t, resp.Decision)
	require.Len(t, resp.Context.TrustData, 1)
	assert.Equal(t, "2026-10-26T00:00:00Z", resp.Context.TrustData[0].NextUpdate)
}

func TestEvaluate_DecisionIDUniqueAndOnEarlyDeny(t *testing.T) {
	m := newTrustDataManager(FirstMatch, &MockRegistry{name: "r", decision: true, types: []string{"x5c"}})

	r1, err := m.Evaluate(context.Background(), createTestRequest())
	require.NoError(t, err)
	r2, err := m.Evaluate(context.Background(), createTestRequest())
	require.NoError(t, err)
	assert.NotEmpty(t, r1.Context.ID)
	assert.NotEqual(t, r1.Context.ID, r2.Context.ID)

	// An invalid request is denied before any registry is consulted; it still
	// gets an id for audit correlation, and no trust_data.
	bad, err := m.Evaluate(context.Background(), &authzen.EvaluationRequest{})
	require.NoError(t, err)
	assert.False(t, bad.Decision)
	assert.NotEmpty(t, bad.Context.ID)
	assert.Empty(t, bad.Context.TrustData)
}

// sharedResponseRegistry hands back one response object every time, as a
// caching registry might.
type sharedResponseRegistry struct {
	*MockRegistry
	resp *authzen.EvaluationResponse
}

func (s *sharedResponseRegistry) Evaluate(context.Context, *authzen.EvaluationRequest) (*authzen.EvaluationResponse, error) {
	return s.resp, nil
}

func TestEvaluate_DoesNotMutateRegistryResponse(t *testing.T) {
	shared := &authzen.EvaluationResponse{Decision: true, Context: &authzen.EvaluationResponseContext{}}
	r := &sharedResponseRegistry{MockRegistry: &MockRegistry{name: "r", types: []string{"x5c"}}, resp: shared}

	resp, err := newTrustDataManager(FirstMatch, r).Evaluate(context.Background(), createTestRequest())
	require.NoError(t, err)
	assert.NotEmpty(t, resp.Context.ID)
	assert.NotEmpty(t, resp.Context.TrustData)
	assert.Empty(t, shared.Context.ID, "registry's own response must be left untouched")
	assert.Empty(t, shared.Context.TrustData)
}

func TestEvaluate_DecisionIDIgnoresRegistryID(t *testing.T) {
	shared := &authzen.EvaluationResponse{Decision: true, Context: &authzen.EvaluationResponseContext{ID: "from-registry"}}
	r := &sharedResponseRegistry{MockRegistry: &MockRegistry{name: "r", types: []string{"x5c"}}, resp: shared}
	m := newTrustDataManager(FirstMatch, r)

	r1, err := m.Evaluate(context.Background(), createTestRequest())
	require.NoError(t, err)
	r2, err := m.Evaluate(context.Background(), createTestRequest())
	require.NoError(t, err)
	assert.NotEqual(t, "from-registry", r1.Context.ID)
	assert.NotEqual(t, r1.Context.ID, r2.Context.ID, "each decision has its own id")
	assert.Equal(t, "from-registry", shared.Context.ID, "registry's own response is left untouched")
}

// reloadingRegistry replaces its data while it is being evaluated.
type reloadingRegistry struct {
	*MockRegistry
	f *Freshness
}

func (r *reloadingRegistry) Freshness() Freshness { return *r.f }

func (r *reloadingRegistry) Evaluate(ctx context.Context, req *authzen.EvaluationRequest) (*authzen.EvaluationResponse, error) {
	resp, err := r.MockRegistry.Evaluate(ctx, req)
	// A refresh lands after the decision was made from the old list.
	*r.f = Freshness{
		AsOf:       r.f.AsOf.Add(time.Hour),
		NextUpdate: r.f.NextUpdate.Add(24 * time.Hour),
	}
	return resp, err
}

func TestEvaluate_TrustDataUnknownWhenDataChangesDuringEvaluation(t *testing.T) {
	f := &Freshness{
		AsOf:       time.Date(2026, 10, 19, 0, 0, 0, 0, time.UTC),
		NextUpdate: time.Date(2026, 10, 26, 0, 0, 0, 0, time.UTC),
	}
	r := &reloadingRegistry{MockRegistry: &MockRegistry{name: "etsi", decision: true, types: []string{"x5c"}}, f: f}

	resp, err := newTrustDataManager(FirstMatch, r).Evaluate(context.Background(), createTestRequest())
	require.NoError(t, err)
	require.Len(t, resp.Context.TrustData, 1)
	td := resp.Context.TrustData[0]
	assert.Equal(t, "etsi", td.Registry)
	// The newer list's next_update must not be attached to a decision made from
	// the older one.
	assert.Empty(t, td.AsOf)
	assert.Empty(t, td.NextUpdate)

	// Stable data afterwards is reported again.
	resp, err = newTrustDataManager(FirstMatch, &freshMock{MockRegistry: &MockRegistry{name: "etsi", decision: true, types: []string{"x5c"}}, f: *f}).Evaluate(context.Background(), createTestRequest())
	require.NoError(t, err)
	assert.NotEmpty(t, resp.Context.TrustData[0].NextUpdate)
}
