package registry

import (
	"testing"
	"time"

	"github.com/sirosfoundation/go-trust/pkg/authzen"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestApplyPolicyToRequest_OIDFedConstraints verifies OIDF constraint injection.
func TestApplyPolicyToRequest_OIDFedConstraints(t *testing.T) {
	mgr := NewRegistryManager(FirstMatch, 10*time.Second)

	policy := &Policy{
		Name: "oidf-test",
		OIDFed: &OIDFedPolicyConstraints{
			RequiredTrustMarks: []string{"https://trust.example.com/tm1"},
			EntityTypes:        []string{"openid_provider"},
			MaxChainDepth:      3,
		},
	}

	req := &authzen.EvaluationRequest{}
	pctx := &PolicyContext{Policy: policy}

	mgr.applyPolicyToRequest(req, pctx)

	require.NotNil(t, req.Context)
	assert.Equal(t, []string{"https://trust.example.com/tm1"}, req.Context["required_trust_marks"])
	assert.Equal(t, []string{"openid_provider"}, req.Context["allowed_entity_types"])
	assert.Equal(t, 3, req.Context["max_chain_depth"])
	assert.Equal(t, "oidf-test", req.Context["_policy"])
}

// TestApplyPolicyToRequest_OIDFedCredentialTypeTrustMarks verifies credential_type_trust_marks injection.
func TestApplyPolicyToRequest_OIDFedCredentialTypeTrustMarks(t *testing.T) {
	mgr := NewRegistryManager(FirstMatch, 10*time.Second)

	policy := &Policy{
		Name: "oidf-credential-types",
		OIDFed: &OIDFedPolicyConstraints{
			CredentialTypeTrustMarks: map[string][]string{
				"eu.europa.ec.eudi.pid.1": {"https://trust.eu/wallet/pid-issuer"},
				"eu.europa.ec.eudi.mdl.1": {"https://trust.eu/wallet/mdl-issuer"},
			},
		},
	}

	req := &authzen.EvaluationRequest{}
	pctx := &PolicyContext{Policy: policy}

	mgr.applyPolicyToRequest(req, pctx)

	require.NotNil(t, req.Context)
	ctTrustMarks, ok := req.Context["credential_type_trust_marks"].(map[string][]string)
	require.True(t, ok, "expected map[string][]string")
	assert.Equal(t, []string{"https://trust.eu/wallet/pid-issuer"}, ctTrustMarks["eu.europa.ec.eudi.pid.1"])
	assert.Equal(t, []string{"https://trust.eu/wallet/mdl-issuer"}, ctTrustMarks["eu.europa.ec.eudi.mdl.1"])
}

// TestApplyPolicyToRequest_ETSIConstraints verifies ETSI constraint injection.
func TestApplyPolicyToRequest_ETSIConstraints(t *testing.T) {
	mgr := NewRegistryManager(FirstMatch, 10*time.Second)

	policy := &Policy{
		Name: "etsi-test",
		ETSI: &ETSIPolicyConstraints{
			ServiceTypes:    []string{"http://uri.etsi.org/TrstSvc/Svctype/CA/QC"},
			ServiceStatuses: []string{"http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted"},
			Countries:       []string{"DE", "FR"},
			CredentialTypes: []string{"eu.europa.ec.eudi.pid.1"},
		},
	}

	req := &authzen.EvaluationRequest{}
	pctx := &PolicyContext{Policy: policy}

	mgr.applyPolicyToRequest(req, pctx)

	require.NotNil(t, req.Context)
	assert.Equal(t, []string{"http://uri.etsi.org/TrstSvc/Svctype/CA/QC"}, req.Context["service_types"])
	assert.Equal(t, []string{"http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted"}, req.Context["service_statuses"])
	assert.Equal(t, []string{"DE", "FR"}, req.Context["countries"])
	assert.Equal(t, []string{"eu.europa.ec.eudi.pid.1"}, req.Context["credential_types"])
	assert.Equal(t, "etsi-test", req.Context["_policy"])
}

// TestApplyPolicyToRequest_DIDConstraints verifies DID constraint injection.
func TestApplyPolicyToRequest_DIDConstraints(t *testing.T) {
	mgr := NewRegistryManager(FirstMatch, 10*time.Second)

	policy := &Policy{
		Name: "did-test",
		DID: &DIDPolicyConstraints{
			AllowedDomains:              []string{"example.com", "*.trusted.org"},
			RequiredVerificationMethods: []string{"Ed25519VerificationKey2020"},
			RequiredServices:            []string{"LinkedDomains"},
			RequireVerifiableHistory:    true,
		},
	}

	req := &authzen.EvaluationRequest{}
	pctx := &PolicyContext{Policy: policy}

	mgr.applyPolicyToRequest(req, pctx)

	require.NotNil(t, req.Context)
	assert.Equal(t, []string{"example.com", "*.trusted.org"}, req.Context["allowed_domains"])
	assert.Equal(t, []string{"Ed25519VerificationKey2020"}, req.Context["required_verification_methods"])
	assert.Equal(t, []string{"LinkedDomains"}, req.Context["required_services"])
	assert.Equal(t, true, req.Context["require_verifiable_history"])
	assert.Equal(t, "did-test", req.Context["_policy"])
}

// TestApplyPolicyToRequest_MDOCIACAConstraints verifies mDOC IACA constraint injection.
func TestApplyPolicyToRequest_MDOCIACAConstraints(t *testing.T) {
	mgr := NewRegistryManager(FirstMatch, 10*time.Second)

	policy := &Policy{
		Name: "mdoc-test",
		MDOCIACA: &MDOCIACAPolicyConstraints{
			IssuerAllowlist:     []string{"https://issuer1.example.com", "https://issuer2.example.com"},
			RequireIACAEndpoint: true,
		},
	}

	req := &authzen.EvaluationRequest{}
	pctx := &PolicyContext{Policy: policy}

	mgr.applyPolicyToRequest(req, pctx)

	require.NotNil(t, req.Context)
	assert.Equal(t, []string{"https://issuer1.example.com", "https://issuer2.example.com"}, req.Context["issuer_allowlist"])
	assert.Equal(t, true, req.Context["require_iaca_endpoint"])
	assert.Equal(t, "mdoc-test", req.Context["_policy"])
}

// TestApplyPolicyToRequest_AllConstraints verifies all constraint types together.
func TestApplyPolicyToRequest_AllConstraints(t *testing.T) {
	mgr := NewRegistryManager(FirstMatch, 10*time.Second)

	policy := &Policy{
		Name: "all-constraints",
		OIDFed: &OIDFedPolicyConstraints{
			RequiredTrustMarks: []string{"tm1"},
		},
		ETSI: &ETSIPolicyConstraints{
			ServiceTypes: []string{"svc-type-1"},
		},
		DID: &DIDPolicyConstraints{
			AllowedDomains: []string{"example.com"},
		},
		MDOCIACA: &MDOCIACAPolicyConstraints{
			IssuerAllowlist: []string{"https://issuer.example.com"},
		},
	}

	req := &authzen.EvaluationRequest{}
	pctx := &PolicyContext{Policy: policy}

	mgr.applyPolicyToRequest(req, pctx)

	require.NotNil(t, req.Context)
	assert.Equal(t, []string{"tm1"}, req.Context["required_trust_marks"])
	assert.Equal(t, []string{"svc-type-1"}, req.Context["service_types"])
	assert.Equal(t, []string{"example.com"}, req.Context["allowed_domains"])
	assert.Equal(t, []string{"https://issuer.example.com"}, req.Context["issuer_allowlist"])
	assert.Equal(t, "all-constraints", req.Context["_policy"])
}

// TestApplyPolicyToRequest_NilPolicy verifies nil policy is handled.
func TestApplyPolicyToRequest_NilPolicy(t *testing.T) {
	mgr := NewRegistryManager(FirstMatch, 10*time.Second)

	req := &authzen.EvaluationRequest{}
	pctx := &PolicyContext{Policy: nil}

	mgr.applyPolicyToRequest(req, pctx)

	// Context is initialized but empty since no policy was applied and no action.parameters
	require.NotNil(t, req.Context)
	assert.Empty(t, req.Context)
}

// TestApplyPolicyToRequest_EmptyConstraints verifies that empty constraint fields
// don't inject context entries.
func TestApplyPolicyToRequest_EmptyConstraints(t *testing.T) {
	mgr := NewRegistryManager(FirstMatch, 10*time.Second)

	policy := &Policy{
		Name:   "empty-constraints",
		OIDFed: &OIDFedPolicyConstraints{},
		ETSI:   &ETSIPolicyConstraints{},
		DID:    &DIDPolicyConstraints{},
		MDOCIACA: &MDOCIACAPolicyConstraints{
			RequireIACAEndpoint: false,
		},
	}

	req := &authzen.EvaluationRequest{}
	pctx := &PolicyContext{Policy: policy}

	mgr.applyPolicyToRequest(req, pctx)

	require.NotNil(t, req.Context)
	// Empty slices should not be injected
	assert.Nil(t, req.Context["required_trust_marks"])
	assert.Nil(t, req.Context["allowed_entity_types"])
	assert.Nil(t, req.Context["service_types"])
	assert.Nil(t, req.Context["service_statuses"])
	assert.Nil(t, req.Context["countries"])
	assert.Nil(t, req.Context["allowed_domains"])
	assert.Nil(t, req.Context["required_services"])
	assert.Nil(t, req.Context["issuer_allowlist"])
	assert.Nil(t, req.Context["require_iaca_endpoint"])
	assert.Nil(t, req.Context["require_verifiable_history"])
	// Only policy name should be set
	assert.Equal(t, "empty-constraints", req.Context["_policy"])
}

// TestApplyPolicyToRequest_PreservesExistingContext verifies that existing context
// fields from the client are preserved when policy constraints are applied.
func TestApplyPolicyToRequest_PreservesExistingContext(t *testing.T) {
	mgr := NewRegistryManager(FirstMatch, 10*time.Second)

	policy := &Policy{
		Name: "preserve-test",
		DID: &DIDPolicyConstraints{
			AllowedDomains: []string{"example.com"},
		},
	}

	req := &authzen.EvaluationRequest{
		Context: map[string]interface{}{
			"client_field": "should-be-preserved",
		},
	}
	pctx := &PolicyContext{Policy: policy}

	mgr.applyPolicyToRequest(req, pctx)

	assert.Equal(t, "should-be-preserved", req.Context["client_field"])
	assert.Equal(t, []string{"example.com"}, req.Context["allowed_domains"])
}

// TestApplyPolicyToRequest_MDOCIACAPartialConstraints verifies that only
// non-empty/non-zero fields are injected.
func TestApplyPolicyToRequest_MDOCIACAPartialConstraints(t *testing.T) {
	mgr := NewRegistryManager(FirstMatch, 10*time.Second)

	// Only require_iaca_endpoint, no allowlist
	policy := &Policy{
		Name: "mdoc-partial",
		MDOCIACA: &MDOCIACAPolicyConstraints{
			RequireIACAEndpoint: true,
		},
	}

	req := &authzen.EvaluationRequest{}
	pctx := &PolicyContext{Policy: policy}

	mgr.applyPolicyToRequest(req, pctx)

	require.NotNil(t, req.Context)
	assert.Nil(t, req.Context["issuer_allowlist"])
	assert.Equal(t, true, req.Context["require_iaca_endpoint"])
}

// TestApplyPolicyToRequest_DIDPartialConstraints verifies partial DID constraints.
func TestApplyPolicyToRequest_DIDPartialConstraints(t *testing.T) {
	mgr := NewRegistryManager(FirstMatch, 10*time.Second)

	policy := &Policy{
		Name: "did-partial",
		DID: &DIDPolicyConstraints{
			RequireVerifiableHistory: true,
			// No AllowedDomains, RequiredServices, RequiredVerificationMethods
		},
	}

	req := &authzen.EvaluationRequest{}
	pctx := &PolicyContext{Policy: policy}

	mgr.applyPolicyToRequest(req, pctx)

	require.NotNil(t, req.Context)
	assert.Nil(t, req.Context["allowed_domains"])
	assert.Nil(t, req.Context["required_services"])
	assert.Nil(t, req.Context["required_verification_methods"])
	assert.Equal(t, true, req.Context["require_verifiable_history"])
}
// TestApplyPolicyToRequest_ActionParameters verifies that action.parameters
// are merged into the request context.
func TestApplyPolicyToRequest_ActionParameters(t *testing.T) {
	mgr := NewRegistryManager(FirstMatch, 10*time.Second)

	req := &authzen.EvaluationRequest{
		Action: &authzen.Action{
			Name: "urn:eudi:credential-issuer",
			Parameters: map[string]interface{}{
				"credential_types": []string{"eu.europa.ec.eudi.pid.1"},
			},
		},
	}
	pctx := &PolicyContext{Policy: nil}

	mgr.applyPolicyToRequest(req, pctx)

	require.NotNil(t, req.Context)
	assert.Equal(t, []string{"eu.europa.ec.eudi.pid.1"}, req.Context["credential_types"])
}

// TestApplyPolicyToRequest_ActionParametersWithPolicy verifies that policy
// constraints take precedence over action parameters for the same key.
func TestApplyPolicyToRequest_ActionParametersWithPolicy(t *testing.T) {
	mgr := NewRegistryManager(FirstMatch, 10*time.Second)

	policy := &Policy{
		Name: "policy-override",
		ETSI: &ETSIPolicyConstraints{
			ServiceTypes: []string{"http://policy.example.com/service-type"},
		},
	}

	req := &authzen.EvaluationRequest{
		Action: &authzen.Action{
			Name: "urn:eudi:credential-issuer",
			Parameters: map[string]interface{}{
				"credential_types": []string{"eu.europa.ec.eudi.pid.1"},
				"service_types":    []string{"http://client.example.com/service-type"}, // Should be overridden
			},
		},
	}
	pctx := &PolicyContext{Policy: policy}

	mgr.applyPolicyToRequest(req, pctx)

	require.NotNil(t, req.Context)
	// client-supplied credential_types should be preserved
	assert.Equal(t, []string{"eu.europa.ec.eudi.pid.1"}, req.Context["credential_types"])
	// policy service_types should override client-supplied value
	assert.Equal(t, []string{"http://policy.example.com/service-type"}, req.Context["service_types"])
	assert.Equal(t, "policy-override", req.Context["_policy"])
}

// TestApplyPolicyToRequest_ActionParametersCannotOverrideInternalKeys verifies
// that action.parameters cannot override internal keys like _policy.
func TestApplyPolicyToRequest_ActionParametersCannotOverrideInternalKeys(t *testing.T) {
	mgr := NewRegistryManager(FirstMatch, 10*time.Second)

	policy := &Policy{
		Name: "real-policy",
	}

	req := &authzen.EvaluationRequest{
		Action: &authzen.Action{
			Name: "test",
			Parameters: map[string]interface{}{
				"_policy": "fake-policy", // Attempt to inject malicious policy name
			},
		},
	}
	pctx := &PolicyContext{Policy: policy}

	mgr.applyPolicyToRequest(req, pctx)

	require.NotNil(t, req.Context)
	// _policy should be set by the policy, not from action.parameters
	assert.Equal(t, "real-policy", req.Context["_policy"])
}

// TestApplyPolicyToRequest_NilActionParameters verifies that nil action.parameters
// does not cause issues.
func TestApplyPolicyToRequest_NilActionParameters(t *testing.T) {
	mgr := NewRegistryManager(FirstMatch, 10*time.Second)

	req := &authzen.EvaluationRequest{
		Action: &authzen.Action{
			Name:       "test",
			Parameters: nil,
		},
	}
	pctx := &PolicyContext{Policy: nil}

	// Should not panic
	mgr.applyPolicyToRequest(req, pctx)

	// Context may be nil or empty since no constraints were applied
}
