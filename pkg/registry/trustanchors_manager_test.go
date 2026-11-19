package registry

import (
	"context"
	"testing"
	"time"

	"github.com/sirosfoundation/go-trust/pkg/authzen"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// anchorRegistry stands in for the VICAL registry: it takes part in
// resolution-only requests only as a preload of itself, and answers with anchors.
type anchorRegistry struct {
	*mockRegistry
}

func (a *anchorRegistry) SupportsResolutionOnlyFor(req *authzen.EvaluationRequest) bool {
	return TrustAnchorResolutionTarget(req, a.name, authzen.TrustAnchorTypeVICAL)
}

func (a *anchorRegistry) Evaluate(_ context.Context, req *authzen.EvaluationRequest) (*authzen.EvaluationResponse, error) {
	resp := &authzen.EvaluationResponse{Decision: true}
	AddTrustAnchorSet(resp, req, authzen.TrustAnchorSet{
		Registry: a.name, Type: authzen.TrustAnchorTypeVICAL, TTLSeconds: 60,
		Anchors: []authzen.TrustAnchor{{X5C: "QQ=="}},
	})
	return resp, nil
}

func newAnchorManager(t *testing.T, constraints PolicyConstraints) *RegistryManager {
	t.Helper()
	mgr := NewRegistryManager(FirstMatch, 10*time.Second)
	mgr.Register(&anchorRegistry{&mockRegistry{name: "iaca-vical", resourceTypes: []string{"x5c"}, healthy: true}})
	pm := NewPolicyManager()
	require.NoError(t, pm.RegisterPolicy(&Policy{Name: "proximity", Constraints: constraints}))
	mgr.SetPolicyManager(pm)
	return mgr
}

func preloadRequest(subject string, ctx map[string]interface{}) *authzen.EvaluationRequest {
	return &authzen.EvaluationRequest{
		Subject: authzen.Subject{Type: "key", ID: subject},
		Action:  &authzen.Action{Name: "proximity"},
		Context: ctx,
	}
}

func TestPreload_DeliversAnchorsWhenPolicyEnables(t *testing.T) {
	mgr := newAnchorManager(t, PolicyConstraints{ReturnTrustAnchors: []string{"vical"}})
	resp, err := mgr.Evaluate(context.Background(), preloadRequest("iaca-vical", nil))
	require.NoError(t, err)
	require.True(t, resp.Decision, "%+v", resp.Context)
	require.Len(t, resp.Context.TrustAnchors, 1)
	assert.Equal(t, "iaca-vical", resp.Context.TrustAnchors[0].Registry)
}

func TestPreload_NotEnabledOrNotNamedIsADenial(t *testing.T) {
	off := newAnchorManager(t, PolicyConstraints{})
	resp, err := off.Evaluate(context.Background(), preloadRequest("iaca-vical", nil))
	require.NoError(t, err)
	assert.False(t, resp.Decision)
	assert.Empty(t, resp.Context.TrustAnchors)

	on := newAnchorManager(t, PolicyConstraints{ReturnTrustAnchors: []string{"vical"}})
	resp, err = on.Evaluate(context.Background(), preloadRequest("some-other-list", nil))
	require.NoError(t, err)
	assert.False(t, resp.Decision, "an unknown list is a denial")
	assert.Empty(t, resp.Context.TrustAnchors)
}

// A client cannot switch the member on for itself: the context key is
// server-controlled and stripped from the inbound request.
func TestPreload_ClientCannotEnableAnchors(t *testing.T) {
	mgr := newAnchorManager(t, PolicyConstraints{})
	resp, err := mgr.Evaluate(context.Background(),
		preloadRequest("iaca-vical", map[string]interface{}{authzen.TrustAnchorsPolicyContextKey: []string{"vical"}}))
	require.NoError(t, err)
	assert.False(t, resp.Decision)
	assert.Empty(t, resp.Context.TrustAnchors)
}
