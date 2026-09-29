package registry

import (
	"context"
	"testing"
	"time"

	"github.com/sirosfoundation/go-trust/pkg/authzen"
	"github.com/sirosfoundation/go-trust/pkg/trustapi"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func statusListSignerManager(t *testing.T, failClosed bool) *RegistryManager {
	t.Helper()
	mgr := NewRegistryManager(FirstMatch, 5*time.Second)
	mgr.Register(&MockRegistry{name: "reg", decision: true, types: []string{"*"}})

	pm := NewPolicyManager()
	pm.RegisterPolicy(&Policy{
		Name: string(trustapi.RoleStatusListSigner),
		Constraints: PolicyConstraints{
			RequireKeyBinding: true,
			AllowedKeyTypes:   []string{"x5c", "jwk"},
		},
	})
	pm.SetFailClosedOnUnknownAction(failClosed)
	mgr.SetPolicyManager(pm)
	return mgr
}

func statusListReq(action string, resType string) *authzen.EvaluationRequest {
	return &authzen.EvaluationRequest{
		Subject:  authzen.Subject{Type: "key", ID: "https://status.example.com"},
		Resource: authzen.Resource{Type: resType, ID: "https://status.example.com", Key: []interface{}{"cert"}},
		Action:   &authzen.Action{Name: action},
	}
}

func TestStatusListSignerPolicySelection(t *testing.T) {
	pm := NewPolicyManager()
	pm.RegisterPolicy(&Policy{Name: "status-list-signer"})
	pm.RegisterPolicy(&Policy{Name: "credential-issuer"})

	assert.Equal(t, "status-list-signer", pm.GetPolicy(string(trustapi.RoleStatusListSigner)).Name)
	assert.Equal(t, "credential-issuer", pm.GetPolicy(string(trustapi.RoleCredentialIssuer)).Name)
}

func TestStatusListSignerPolicyEnforced(t *testing.T) {
	mgr := statusListSignerManager(t, false)

	resp, err := mgr.Evaluate(context.Background(), statusListReq("status-list-signer", "x5c"))
	require.NoError(t, err)
	assert.True(t, resp.Decision)

	// key type outside allowed_key_types is refused by the policy
	resp, err = mgr.Evaluate(context.Background(), statusListReq("status-list-signer", "kid"))
	require.NoError(t, err)
	assert.False(t, resp.Decision)
	assert.Equal(t, "status-list-signer", resp.Context.Reason["policy"], "%v", resp.Context.Reason)
}

func TestUnknownActionFailClosed(t *testing.T) {
	mgr := statusListSignerManager(t, true)

	resp, err := mgr.Evaluate(context.Background(), statusListReq("no-such-action", "x5c"))
	require.NoError(t, err)
	assert.False(t, resp.Decision)
	assert.Equal(t, "no policy defined for action", resp.Context.Reason["error"])

	// known action and empty action are unaffected
	resp, err = mgr.Evaluate(context.Background(), statusListReq("status-list-signer", "x5c"))
	require.NoError(t, err)
	assert.True(t, resp.Decision)
	pm := mgr.GetPolicyManager()
	assert.False(t, pm.IsUnknownAction(""))
}

func TestUnknownActionDefaultsToDefaultPolicy(t *testing.T) {
	mgr := statusListSignerManager(t, false)

	resp, err := mgr.Evaluate(context.Background(), statusListReq("no-such-action", "x5c"))
	require.NoError(t, err)
	assert.True(t, resp.Decision, "fail-open remains the default")
}

func TestUnknownActionWarnsOncePerName(t *testing.T) {
	pm := NewPolicyManager()
	assert.True(t, pm.firstUnknownWarning("a"))
	assert.False(t, pm.firstUnknownWarning("a"))
	assert.True(t, pm.firstUnknownWarning("b"))
}
