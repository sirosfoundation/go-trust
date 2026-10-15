package registry

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"testing"
	"time"

	"github.com/sirosfoundation/go-trust/pkg/authzen"
	"github.com/sirosfoundation/go-trust/pkg/registry/rpcert"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// enrichingRegistry stands in for an x5c registry (etsi/lote): after its own
// chain validation it runs the shared enrichment against a fixed leaf.
type enrichingRegistry struct {
	*mockRegistry
	leaf *x509.Certificate
}

func (e *enrichingRegistry) Evaluate(_ context.Context, req *authzen.EvaluationRequest) (*authzen.EvaluationResponse, error) {
	enrichment := EnrichX5CResponseWithProfiles(req, e.leaf, rpcert.DefaultProfileRegistry())
	resp := &authzen.EvaluationResponse{Decision: enrichment.Decision}
	ApplyEnrichmentToResponse(resp, enrichment)
	return resp, nil
}

func newEnrichingManager(t *testing.T, leaf *x509.Certificate, constraints PolicyConstraints) *RegistryManager {
	t.Helper()
	mgr := NewRegistryManager(FirstMatch, 10*time.Second)
	mgr.Register(&enrichingRegistry{
		mockRegistry: &mockRegistry{name: "etsi-like", resourceTypes: []string{"x5c"}, healthy: true},
		leaf:         leaf,
	})
	pm := NewPolicyManager()
	pm.RegisterPolicy(&Policy{Name: "rp", Constraints: constraints})
	mgr.SetPolicyManager(pm)
	return mgr
}

func vidManagerRequest(ctx map[string]interface{}) *authzen.EvaluationRequest {
	req := x5cRequest(ctx)
	req.Subject.ID = "x509_san_dns:rp.example.com"
	req.Resource.ID = "x509_san_dns:rp.example.com"
	req.Action = &authzen.Action{Name: "rp"}
	return req
}

func TestManager_VerifierIDs_PolicyEnablesAndHintNarrows(t *testing.T) {
	leaf := makeVIDCert(t, vidCertOpts{orgID: "VATSE-556000000101", policy: rpcert.OIDNCPLegalPerson, dns: []string{"rp.example.com"}})
	mgr := newEnrichingManager(t, leaf, PolicyConstraints{ReturnVerifierIDs: []string{"semantic", "x509_san_dns"}})

	// Subject.ID is rewritten by Evaluate ("x509_san_dns:host" -> "https://host");
	// the dns identifier is still derived, from the original claim.
	resp, err := mgr.Evaluate(context.Background(), vidManagerRequest(nil))
	require.NoError(t, err)
	require.True(t, resp.Decision)
	require.NotNil(t, resp.Context)
	got := idsOf(resp.Context.VerifierIDs)
	assert.Equal(t, "semantic_id:VATSE-556000000101", got["semantic"].ID)
	assert.Equal(t, "rp.example.com", got["x509_san_dns"].ID)
	assert.Len(t, resp.Context.VerifierIDs, 2)

	// The client's optional hint narrows to one entry.
	resp, err = mgr.Evaluate(context.Background(),
		vidManagerRequest(map[string]interface{}{authzen.VerifierIDHintContextKey: "semantic"}))
	require.NoError(t, err)
	require.Len(t, resp.Context.VerifierIDs, 1)
	assert.Equal(t, "semantic", resp.Context.VerifierIDs[0].Type)
}

func TestManager_VerifierIDs_DefaultOff(t *testing.T) {
	leaf := makeVIDCert(t, vidCertOpts{orgID: "VATSE-556000000101", policy: rpcert.OIDNCPLegalPerson, dns: []string{"rp.example.com"}})
	mgr := newEnrichingManager(t, leaf, PolicyConstraints{})

	resp, err := mgr.Evaluate(context.Background(), vidManagerRequest(nil))
	require.NoError(t, err)
	require.True(t, resp.Decision)
	assert.Empty(t, resp.Context.VerifierIDs)

	// The member is omitted from the JSON entirely.
	b, err := json.Marshal(resp)
	require.NoError(t, err)
	assert.NotContains(t, string(b), "verifier_ids")
}

// A client cannot turn the feature on, nor widen what the policy enabled: the
// hint only narrows, and return_verifier_ids is a policy control.
func TestManager_VerifierIDs_ClientCannotEnableOrWiden(t *testing.T) {
	leaf := makeVIDCert(t, vidCertOpts{orgID: "VATSE-556000000101", policy: rpcert.OIDNCPLegalPerson, dns: []string{"rp.example.com"}})

	off := newEnrichingManager(t, leaf, PolicyConstraints{})
	resp, err := off.Evaluate(context.Background(), vidManagerRequest(map[string]interface{}{
		authzen.VerifierIDsPolicyContextKey: []string{"semantic", "x509_san_dns"},
		authzen.VerifierIDHintContextKey:    "semantic",
	}))
	require.NoError(t, err)
	assert.Empty(t, resp.Context.VerifierIDs, "client-set return_verifier_ids must be dropped")

	narrow := newEnrichingManager(t, leaf, PolicyConstraints{ReturnVerifierIDs: []string{"semantic"}})
	resp, err = narrow.Evaluate(context.Background(), vidManagerRequest(map[string]interface{}{
		authzen.VerifierIDsPolicyContextKey: []string{"semantic", "x509_san_dns"},
		authzen.VerifierIDHintContextKey:    "x509_san_dns",
	}))
	require.NoError(t, err)
	assert.Empty(t, resp.Context.VerifierIDs, "hint for a type the policy did not enable returns nothing")
}

func TestManager_VerifierIDs_ContextKeys(t *testing.T) {
	assert.False(t, clientSuppliableContextKey(authzen.VerifierIDsPolicyContextKey), "policy control")
	assert.True(t, clientSuppliableContextKey(authzen.VerifierIDHintContextKey), "request hint")
}
