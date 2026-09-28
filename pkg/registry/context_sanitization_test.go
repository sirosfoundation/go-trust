package registry

import (
	"context"
	"testing"
	"time"

	"github.com/sirosfoundation/go-trust/pkg/authzen"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newCapturingManager returns a manager whose single registry records the
// request context as the registries actually see it, i.e. after Evaluate has
// sanitized it and applied policy.
func newCapturingManager(t *testing.T, captured *map[string]interface{}) *RegistryManager {
	t.Helper()

	reg := &captureMockRegistry{
		mockRegistry: &mockRegistry{
			name:             "capture-registry",
			resourceTypes:    []string{"x5c"},
			healthy:          true,
			evaluateResponse: &authzen.EvaluationResponse{Decision: true},
		},
		onEvaluate: func(req *authzen.EvaluationRequest) {
			copied := make(map[string]interface{}, len(req.Context))
			for k, v := range req.Context {
				copied[k] = v
			}
			*captured = copied
		},
	}

	mgr := NewRegistryManager(FirstMatch, 10*time.Second)
	mgr.Register(reg)
	return mgr
}

func x5cRequest(ctx map[string]interface{}) *authzen.EvaluationRequest {
	return &authzen.EvaluationRequest{
		Subject:  authzen.Subject{Type: "key", ID: "https://rp.example.com"},
		Resource: authzen.Resource{Type: "x5c", ID: "https://rp.example.com", Key: []interface{}{"MIIC..."}},
		Context:  ctx,
	}
}

// TestEvaluate_SanitizesClientSuppliedContext is the regression test for the
// hole described in issue #176: the action.parameters allowlist guarded one
// door while request.Context was bound verbatim from the request body and read
// straight off by the enrichment pipeline.
func TestEvaluate_SanitizesClientSuppliedContext(t *testing.T) {
	var captured map[string]interface{}
	mgr := newCapturingManager(t, &captured)

	req := x5cRequest(map[string]interface{}{
		// Data the client legitimately supplies — must survive.
		"requested_attributes": []string{"family_name"},
		"credential_types":     []string{"eu.europa.ec.eudi.pid.1"},
		"purpose":              "age verification",
		"doc_type":             "org.iso.18013.5.1.mDL",
		"intermediary_x5c":     []string{"MIIB..."},

		// Policy controls the client must never be able to set.
		"allow_intermediaries":      true,
		"strict_entitlement_check":  true,
		"extract_rp_identity":       true,
		"allowed_attributes":        []string{"everything"},
		"required_cert_policy_oids": []string{"1.2.3.4"},
		"service_types":             []string{"injected"},
		"service_statuses":          []string{"injected"},
		"countries":                 []string{"XX"},
		"required_trust_marks":      []string{"injected"},
		"allowed_entity_types":      []string{"injected"},
		"credential_type_trust_marks": map[string][]string{
			"eu.europa.ec.eudi.pid.1": {"https://attacker.example/tm"},
		},
		"max_chain_depth":               99,
		"allowed_domains":               []string{"attacker.example"},
		"required_verification_methods": []string{"injected"},
		"required_services":             []string{"injected"},
		"require_verifiable_history":    true,
		"issuer_allowlist":              []string{"https://attacker.example"},
		"require_iaca_endpoint":         true,
		"allowed_aaguids":               []string{"injected"},
		"blocked_aaguids":               []string{"injected"},
		"_policy":                       "attacker-policy",
		"totally_unknown_key":           "junk",
	})

	resp, err := mgr.Evaluate(context.Background(), req)
	require.NoError(t, err)
	require.True(t, resp.Decision)
	require.NotNil(t, captured)

	// Client data survives.
	assert.Equal(t, []string{"family_name"}, captured["requested_attributes"])
	assert.Equal(t, []string{"eu.europa.ec.eudi.pid.1"}, captured["credential_types"])
	assert.Equal(t, "age verification", captured["purpose"])
	assert.Equal(t, "org.iso.18013.5.1.mDL", captured["doc_type"])
	assert.Equal(t, []string{"MIIB..."}, captured["intermediary_x5c"])

	// Every policy control is gone.
	for _, key := range []string{
		"allow_intermediaries", "strict_entitlement_check", "extract_rp_identity",
		"allowed_attributes", "required_cert_policy_oids", "service_types",
		"service_statuses", "countries", "required_trust_marks",
		"allowed_entity_types", "credential_type_trust_marks", "max_chain_depth",
		"allowed_domains", "required_verification_methods", "required_services",
		"require_verifiable_history", "issuer_allowlist", "require_iaca_endpoint",
		"allowed_aaguids", "blocked_aaguids", "_policy", "totally_unknown_key",
	} {
		assert.NotContains(t, captured, key,
			"client-supplied %q must not reach the registries", key)
	}
}

// TestEvaluate_ClientContextCannotOverridePolicy verifies the server's own
// value wins where a policy sets the same key the client tried to set.
func TestEvaluate_ClientContextCannotOverridePolicy(t *testing.T) {
	var captured map[string]interface{}
	mgr := newCapturingManager(t, &captured)

	pm := NewPolicyManager()
	pm.RegisterPolicy(&Policy{
		Name: "verifier",
		ETSI: &ETSIPolicyConstraints{
			AllowedAttributes: []string{"family_name"},
		},
	})
	mgr.SetPolicyManager(pm)

	req := x5cRequest(map[string]interface{}{
		"allowed_attributes":       []string{"family_name", "birthdate", "address"},
		"strict_entitlement_check": true,
	})
	req.Action = &authzen.Action{Name: "verifier"}

	_, err := mgr.Evaluate(context.Background(), req)
	require.NoError(t, err)

	assert.Equal(t, []string{"family_name"}, captured["allowed_attributes"],
		"policy value must win over the client's widened list")
	assert.NotContains(t, captured, "strict_entitlement_check",
		"a control the policy does not set must not be enabled by the client")
	assert.Equal(t, "verifier", captured["_policy"])
}

// TestEvaluate_ClientCannotForgeOriginalSubjectID guards the internal channel
// registries use to recover the pre-normalization client_id claim; whitelist
// system-CA binding decisions are made on it.
func TestEvaluate_ClientCannotForgeOriginalSubjectID(t *testing.T) {
	var capturedOriginal string
	reg := &captureMockRegistry{
		mockRegistry: &mockRegistry{
			name:             "capture-registry",
			resourceTypes:    []string{"x5c"},
			healthy:          true,
			evaluateResponse: &authzen.EvaluationResponse{Decision: true},
		},
		onEvaluate: func(req *authzen.EvaluationRequest) {
			capturedOriginal = OriginalSubjectID(req)
		},
	}
	mgr := NewRegistryManager(FirstMatch, 10*time.Second)
	mgr.Register(reg)

	req := &authzen.EvaluationRequest{
		Subject:  authzen.Subject{Type: "key", ID: "x509_san_dns:rp.example.com"},
		Resource: authzen.Resource{Type: "x5c", ID: "x509_san_dns:rp.example.com", Key: []interface{}{"MIIC..."}},
		Context: map[string]interface{}{
			"_original_subject_id": "x509_san_dns:trusted.example.com",
		},
	}

	_, err := mgr.Evaluate(context.Background(), req)
	require.NoError(t, err)

	assert.Equal(t, "x509_san_dns:rp.example.com", capturedOriginal,
		"the stashed subject ID must come from the request subject, not the client's context")
}

// TestEvaluate_NilContextStaysUsable verifies sanitization of an absent context
// still yields a context registries and policy can write to.
func TestEvaluate_NilContextStaysUsable(t *testing.T) {
	var captured map[string]interface{}
	mgr := newCapturingManager(t, &captured)

	req := x5cRequest(nil)
	_, err := mgr.Evaluate(context.Background(), req)
	require.NoError(t, err)

	require.NotNil(t, req.Context)
	assert.Contains(t, req.Context, "_original_subject_id")
}

// TestEvaluate_RequireKeyBinding covers the constraint that config has carried
// since before it had anywhere to go.
func TestEvaluate_RequireKeyBinding(t *testing.T) {
	newManager := func() *RegistryManager {
		mgr := NewRegistryManager(FirstMatch, 10*time.Second)
		mgr.Register(&mockRegistry{
			name:             "resolver",
			resourceTypes:    []string{"x5c"},
			resolutionOnly:   true,
			healthy:          true,
			evaluateResponse: &authzen.EvaluationResponse{Decision: true},
		})
		pm := NewPolicyManager()
		pm.RegisterPolicy(&Policy{
			Name:        "binding-required",
			Constraints: PolicyConstraints{RequireKeyBinding: true},
		})
		pm.RegisterPolicy(&Policy{Name: "binding-optional"})
		mgr.SetPolicyManager(pm)
		return mgr
	}

	t.Run("resolution-only denied", func(t *testing.T) {
		req := &authzen.EvaluationRequest{
			Subject: authzen.Subject{Type: "key", ID: "did:web:rp.example.com"},
			Action:  &authzen.Action{Name: "binding-required"},
		}
		resp, err := newManager().Evaluate(context.Background(), req)
		require.NoError(t, err)
		assert.False(t, resp.Decision)
		require.NotNil(t, resp.Context)
		assert.Equal(t, "binding-required", resp.Context.Reason["policy"])
	})

	t.Run("request carrying key material allowed", func(t *testing.T) {
		req := x5cRequest(nil)
		req.Action = &authzen.Action{Name: "binding-required"}
		resp, err := newManager().Evaluate(context.Background(), req)
		require.NoError(t, err)
		assert.True(t, resp.Decision)
	})

	t.Run("resolution-only allowed without the constraint", func(t *testing.T) {
		req := &authzen.EvaluationRequest{
			Subject: authzen.Subject{Type: "key", ID: "did:web:rp.example.com"},
			Action:  &authzen.Action{Name: "binding-optional"},
		}
		resp, err := newManager().Evaluate(context.Background(), req)
		require.NoError(t, err)
		assert.True(t, resp.Decision)
	})
}
