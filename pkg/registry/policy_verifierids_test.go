package registry

import (
	"testing"

	"github.com/sirosfoundation/go-trust/pkg/authzen"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The public installation path validates, so a library user cannot install a
// policy whose unknown type would silently return nothing.
func TestPolicyManager_RegisterPolicyRejectsUnknownVerifierIDType(t *testing.T) {
	pm := NewPolicyManager()

	bad := &Policy{Name: "bad", Constraints: PolicyConstraints{ReturnVerifierIDs: []string{"semantic", "sematic"}}}
	err := pm.RegisterPolicy(bad)
	require.Error(t, err)
	assert.Contains(t, err.Error(), `"sematic"`)
	assert.Contains(t, err.Error(), `"bad"`)
	assert.Nil(t, pm.GetPolicy("bad"), "a rejected policy is not installed")

	require.NoError(t, pm.RegisterPolicy(&Policy{Name: "ok", Constraints: PolicyConstraints{ReturnVerifierIDs: []string{"dns"}}}))
	assert.NotNil(t, pm.GetPolicy("ok"))

	// SetDefaultPolicy goes through the same check and leaves the default alone on error.
	require.Error(t, pm.SetDefaultPolicy(bad))
	assert.Nil(t, pm.GetPolicy("bad"))
	good := &Policy{Name: "dflt"}
	require.NoError(t, pm.SetDefaultPolicy(good))
	assert.NotNil(t, pm.GetPolicy("dflt"))
}

func TestPolicyConstraintsValidate_VerifierIDs(t *testing.T) {
	assert.NoError(t, PolicyConstraints{}.Validate())
	assert.NoError(t, PolicyConstraints{ReturnVerifierIDs: authzen.SupportedVerifierIDTypes()}.Validate())
	err := PolicyConstraints{ReturnVerifierIDs: []string{"dns", "bogus"}}.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), `"bogus"`)
}
