package registry

import (
	"testing"

	"github.com/sirosfoundation/go-trust/pkg/authzen"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPolicyConstraintsValidate_VerifierIDs(t *testing.T) {
	assert.NoError(t, PolicyConstraints{}.Validate())
	assert.NoError(t, PolicyConstraints{ReturnVerifierIDs: authzen.SupportedVerifierIDTypes()}.Validate())
	err := PolicyConstraints{ReturnVerifierIDs: []string{"dns", "bogus"}}.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), `"bogus"`)
}
