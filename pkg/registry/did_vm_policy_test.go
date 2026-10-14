package registry

import (
	"testing"
	"time"

	"github.com/sirosfoundation/go-trust/pkg/authzen"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type vmStub struct{ Type string }

func vmType(m vmStub) string { return m.Type }

func TestDenyMissingVerificationMethods(t *testing.T) {
	doc := []vmStub{{"JsonWebKey2020"}, {"Multikey"}}
	tests := []struct {
		name     string
		required interface{}
		methods  []vmStub
		allow    bool
	}{
		{"all present", []string{"JsonWebKey2020", "Multikey"}, doc, true},
		{"all present, interface slice", []interface{}{"Multikey"}, doc, true},
		{"missing", []string{"Ed25519VerificationKey2020"}, doc, false},
		{"partially present", []string{"JsonWebKey2020", "Ed25519VerificationKey2020"}, doc, false},
		{"case sensitive", []string{"jsonwebkey2020"}, doc, false},
		{"empty document", []string{"Multikey"}, nil, false},
		{"unset", nil, doc, true},
		{"empty list", []string{}, doc, true},
		{"wrong value type ignored", "Multikey", doc, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctx := map[string]interface{}{}
			if tc.required != nil {
				ctx["required_verification_methods"] = tc.required
			}
			resp := DenyMissingVerificationMethods(ctx, tc.methods, vmType, time.Now())
			if tc.allow {
				assert.Nil(t, resp)
				return
			}
			require.NotNil(t, resp)
			assert.False(t, resp.Decision)
			assert.Contains(t, resp.Context.Reason, "required_verification_methods")
			assert.Contains(t, resp.Context.Reason, "resolution_ms")
		})
	}
	assert.Nil(t, DenyMissingVerificationMethods(nil, []vmStub{}, vmType, time.Now()))
}

func TestCheckRequiredVerificationMethodsEnforcement(t *testing.T) {
	mk := func(typ string) vmStub { return vmStub{Type: typ} }

	// A correct enforcer passes the conformance check.
	good := func(ctx map[string]interface{}, ms []vmStub) *authzen.EvaluationResponse {
		return DenyMissingVerificationMethods(ctx, ms, vmType, time.Now())
	}
	assert.NoError(t, CheckRequiredVerificationMethodsEnforcement(mk, good))

	// A registry that ignores the constraint is detected.
	ignores := func(map[string]interface{}, []vmStub) *authzen.EvaluationResponse { return nil }
	assert.Error(t, CheckRequiredVerificationMethodsEnforcement(mk, ignores))

	// A registry that always denies is detected.
	denies := func(map[string]interface{}, []vmStub) *authzen.EvaluationResponse {
		return &authzen.EvaluationResponse{Decision: false}
	}
	assert.Error(t, CheckRequiredVerificationMethodsEnforcement(mk, denies))
}
