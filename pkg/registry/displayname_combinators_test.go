package registry

import (
	"context"
	"testing"
	"time"

	"github.com/sirosfoundation/go-trust/pkg/authzen"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// dnStub is a registry that answers with a fixed decision and a fixed
// display_name, standing in for any registry that names its trust subject.
type dnStub struct {
	name     string
	decision bool
	display  string
}

func (s *dnStub) Evaluate(context.Context, *authzen.EvaluationRequest) (*authzen.EvaluationResponse, error) {
	return &authzen.EvaluationResponse{
		Decision: s.decision,
		Context: &authzen.EvaluationResponseContext{
			Reason:      map[string]interface{}{"stub": s.name},
			DisplayName: s.display,
		},
	}, nil
}
func (s *dnStub) SupportedResourceTypes() []string { return []string{"x5c"} }
func (s *dnStub) SupportsResolutionOnly() bool     { return false }
func (s *dnStub) Info() RegistryInfo {
	return RegistryInfo{Name: s.name, Type: "stub", Healthy: true}
}
func (s *dnStub) Healthy() bool                 { return true }
func (s *dnStub) Refresh(context.Context) error { return nil }

func dnEval(t *testing.T, strategy ResolutionStrategy, regs ...TrustRegistry) *authzen.EvaluationResponse {
	t.Helper()
	mgr := NewRegistryManager(strategy, 5*time.Second)
	for _, r := range regs {
		mgr.Register(r)
	}
	resp, err := mgr.Evaluate(context.Background(), stubReq())
	require.NoError(t, err)
	require.NotNil(t, resp)
	return resp
}

func dnOf(resp *authzen.EvaluationResponse) string {
	if resp == nil || resp.Context == nil {
		return ""
	}
	return resp.Context.DisplayName
}

// A name one registry established must survive aggregation (#249). The
// combining strategies build a fresh context from the children's results, so
// the field has to be carried deliberately — as verifier_ids already is —
// or the wallet never sees the label the registry went to the trouble of
// resolving.
func TestMergeDisplayName_SurvivesEveryStrategy(t *testing.T) {
	for _, strategy := range []ResolutionStrategy{FirstMatch, AllRegistries, BestMatch, Sequential} {
		t.Run(string(strategy), func(t *testing.T) {
			resp := dnEval(t, strategy,
				&dnStub{name: "named", decision: true, display: "Acme Bank AB"},
			)
			require.True(t, resp.Decision)
			assert.Equal(t, "Acme Bank AB", dnOf(resp))
		})
	}
}

// One named contributor among unnamed ones still delivers its name: most
// registries carry no names, so this is the ordinary multi-registry case.
func TestMergeDisplayName_OneNamedContributorAmongUnnamed(t *testing.T) {
	resp := dnEval(t, AllRegistries,
		&dnStub{name: "unnamed", decision: true},
		&dnStub{name: "named", decision: true, display: "Acme Bank AB"},
	)
	require.True(t, resp.Decision)
	assert.Equal(t, "Acme Bank AB", dnOf(resp))
}

// Two registries that agree on the decision but disagree on the name leave
// the aggregate unnamed: there is no single subject to label, and picking one
// would suppress the other in the wallet's label chain.
func TestMergeDisplayName_ConflictingNamesLeaveItAbsent(t *testing.T) {
	resp := dnEval(t, AllRegistries,
		&dnStub{name: "a", decision: true, display: "Acme Bank AB"},
		&dnStub{name: "b", decision: true, display: "Another Org Ltd"},
	)
	require.True(t, resp.Decision)
	assert.Empty(t, dnOf(resp))
}

// A name carried by a registry that DENIED must never reach the response,
// however the aggregate decides: it describes a subject that registry
// refused to vouch for.
func TestMergeDisplayName_DenyingRegistryNameNeverTravels(t *testing.T) {
	resp := dnEval(t, AllRegistries,
		&dnStub{name: "denier", decision: false, display: "Denied Org"},
		&dnStub{name: "allower", decision: true},
	)
	require.True(t, resp.Decision, "all-registries allows when any registry allows")
	assert.Empty(t, dnOf(resp))
}

// The composite registry aggregates the same way and must carry the name too.
func TestMergeDisplayName_Composite(t *testing.T) {
	for _, op := range []LogicOperator{LogicAND, LogicOR} {
		t.Run(string(op), func(t *testing.T) {
			c := NewCompositeRegistry("composite", op,
				&dnStub{name: "unnamed", decision: true},
				&dnStub{name: "named", decision: true, display: "Acme Bank AB"},
			)
			resp, err := c.Evaluate(context.Background(), stubReq())
			require.NoError(t, err)
			require.True(t, resp.Decision)
			assert.Equal(t, "Acme Bank AB", dnOf(resp))
		})
	}
}

// A composite whose children disagree on the name stays unnamed.
func TestMergeDisplayName_CompositeConflict(t *testing.T) {
	c := NewCompositeRegistry("composite", LogicOR,
		&dnStub{name: "a", decision: true, display: "Acme Bank AB"},
		&dnStub{name: "b", decision: true, display: "Another Org Ltd"},
	)
	resp, err := c.Evaluate(context.Background(), stubReq())
	require.NoError(t, err)
	require.True(t, resp.Decision)
	assert.Empty(t, dnOf(resp))
}
