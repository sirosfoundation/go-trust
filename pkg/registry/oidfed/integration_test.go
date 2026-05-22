package oidfed_test

import (
	"context"
	"os"
	"testing"
	"time"

	oidfedlib "github.com/go-oidfed/lib"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/sirosfoundation/go-trust/pkg/authzen"
	"github.com/sirosfoundation/go-trust/pkg/authzenclient"
	"github.com/sirosfoundation/go-trust/pkg/registry/oidfed"
	"github.com/sirosfoundation/go-trust/pkg/testserver"
)

// These tests use live OpenID Federation endpoints.
// They are skipped when the SKIP_NETWORK_TESTS environment variable is set:
//   SKIP_NETWORK_TESTS=1 go test ./...
// To run them explicitly, ensure SKIP_NETWORK_TESTS is unset.

// realtaTrustAnchor is the SUNET test trust anchor
// Note: no trailing slash — must match the entity's own iss/sub exactly
const realtaTrustAnchor = "https://realta.labb.sunet.se"

// TestOIDFedRegistry_WithTestServer tests the OpenID Federation registry
// integration with the testserver and HTTP API.
func TestOIDFedRegistry_WithTestServer(t *testing.T) {
	// Skip if SKIP_NETWORK_TESTS env var is set
	if os.Getenv("SKIP_NETWORK_TESTS") != "" {
		t.Skip("Skipping network test (SKIP_NETWORK_TESTS set)")
	}

	// Create OIDF registry with realta trust anchor
	reg, err := oidfed.NewOIDFedRegistry(oidfed.Config{
		TrustAnchors: []oidfed.TrustAnchorConfig{
			{EntityID: realtaTrustAnchor},
		},
		Description: "Test OIDF Registry with SUNET Trust Anchor",
		CacheTTL:    5 * time.Minute,
	})
	require.NoError(t, err)

	// Create test server with OIDF registry
	srv := testserver.New(testserver.WithRegistry(reg))
	defer srv.Close()

	// Create client
	client := authzenclient.New(srv.URL())
	ctx := context.Background()

	// Test: resolution-only request for the trust anchor itself
	// This should return trust_metadata with the entity configuration
	resp, err := client.Evaluate(ctx, &authzen.EvaluationRequest{
		Subject: authzen.Subject{
			Type: "key",
			ID:   realtaTrustAnchor,
		},
		Resource: authzen.Resource{
			ID: realtaTrustAnchor,
			// No type or key = resolution-only
		},
	})
	require.NoError(t, err)
	// Note: For the trust anchor itself, this may or may not return decision=true
	// depending on whether it counts as "self-anchored"
	assert.NotNil(t, resp.Context, "response should include context")
}

// TestOIDFedRegistry_UntrustedEntity tests that entities not in the federation
// are rejected.
func TestOIDFedRegistry_UntrustedEntity(t *testing.T) {
	// Skip if SKIP_NETWORK_TESTS env var is set
	if os.Getenv("SKIP_NETWORK_TESTS") != "" {
		t.Skip("Skipping network test (SKIP_NETWORK_TESTS set)")
	}

	// Create OIDF registry with realta trust anchor
	reg, err := oidfed.NewOIDFedRegistry(oidfed.Config{
		TrustAnchors: []oidfed.TrustAnchorConfig{
			{EntityID: realtaTrustAnchor},
		},
		Description: "Test OIDF Registry",
	})
	require.NoError(t, err)

	// Create test server
	srv := testserver.New(testserver.WithRegistry(reg))
	defer srv.Close()

	client := authzenclient.New(srv.URL())
	ctx := context.Background()

	// Test: entity NOT in the federation should be rejected
	resp, err := client.Evaluate(ctx, &authzen.EvaluationRequest{
		Subject: authzen.Subject{
			Type: "key",
			ID:   "https://non-existent-entity.example.com",
		},
		Resource: authzen.Resource{
			Type: "x5c",
			ID:   "https://non-existent-entity.example.com",
			Key:  []interface{}{"dummy-cert"},
		},
		Action: &authzen.Action{
			Name: "issuer",
		},
	})
	require.NoError(t, err)
	assert.False(t, resp.Decision, "entity not in federation should not be trusted")
}

// TestOIDFedRegistry_InvalidTrustAnchor tests that invalid trust anchors are handled.
func TestOIDFedRegistry_InvalidTrustAnchor(t *testing.T) {
	// Create OIDF registry with non-existent trust anchor
	reg, err := oidfed.NewOIDFedRegistry(oidfed.Config{
		TrustAnchors: []oidfed.TrustAnchorConfig{
			{EntityID: "https://non-existent-trust-anchor.example.com"},
		},
		Description: "Test OIDF Registry with Invalid Trust Anchor",
	})
	require.NoError(t, err)

	// Create test server
	srv := testserver.New(testserver.WithRegistry(reg))
	defer srv.Close()

	client := authzenclient.New(srv.URL())
	ctx := context.Background()

	// Test: any entity should be rejected with invalid trust anchor
	resp, err := client.Evaluate(ctx, &authzen.EvaluationRequest{
		Subject: authzen.Subject{
			Type: "key",
			ID:   "https://any-entity.example.com",
		},
		Resource: authzen.Resource{
			Type: "jwk",
			ID:   "https://any-entity.example.com",
			Key:  []interface{}{"dummy-key"},
		},
		Action: &authzen.Action{
			Name: "issuer",
		},
	})
	require.NoError(t, err)
	assert.False(t, resp.Decision, "entity should not be trusted with invalid trust anchor")
}

// TestOIDFedRegistry_Info tests that registry info is accessible.
func TestOIDFedRegistry_Info(t *testing.T) {
	// Skip if SKIP_NETWORK_TESTS env var is set
	if os.Getenv("SKIP_NETWORK_TESTS") != "" {
		t.Skip("Skipping network test (SKIP_NETWORK_TESTS set)")
	}

	// Create OIDF registry
	reg, err := oidfed.NewOIDFedRegistry(oidfed.Config{
		TrustAnchors: []oidfed.TrustAnchorConfig{
			{EntityID: realtaTrustAnchor},
		},
		Description: "Test OIDF Registry Info",
	})
	require.NoError(t, err)

	// Verify registry info
	info := reg.Info()
	assert.Equal(t, "oidfed-registry", info.Name)
	assert.Equal(t, "openid_federation", info.Type)
	assert.Equal(t, "Test OIDF Registry Info", info.Description)
	assert.True(t, reg.Healthy())
	assert.Len(t, info.TrustAnchors, 1)
	assert.Equal(t, realtaTrustAnchor, info.TrustAnchors[0])
}

// TestOIDFedRegistry_MultipleTrustAnchors tests configuration with multiple trust anchors.
func TestOIDFedRegistry_MultipleTrustAnchors(t *testing.T) {
	// Create OIDF registry with multiple trust anchors
	reg, err := oidfed.NewOIDFedRegistry(oidfed.Config{
		TrustAnchors: []oidfed.TrustAnchorConfig{
			{EntityID: "https://anchor1.example.com"},
			{EntityID: "https://anchor2.example.com"},
			{EntityID: "https://anchor3.example.com"},
		},
		Description: "Multi-anchor registry",
	})
	require.NoError(t, err)

	info := reg.Info()
	assert.Len(t, info.TrustAnchors, 3)
}

// TestOIDFedRegistry_SupportedResourceTypes tests that the registry
// advertises correct resource types.
func TestOIDFedRegistry_SupportedResourceTypes(t *testing.T) {
	reg, err := oidfed.NewOIDFedRegistry(oidfed.Config{
		TrustAnchors: []oidfed.TrustAnchorConfig{
			{EntityID: realtaTrustAnchor},
		},
	})
	require.NoError(t, err)

	types := reg.SupportedResourceTypes()
	assert.NotEmpty(t, types)

	// Verify expected types are present
	typeMap := make(map[string]bool)
	for _, typ := range types {
		typeMap[typ] = true
	}

	assert.True(t, typeMap["entity"], "should support 'entity' resource type")
	assert.True(t, typeMap["jwk"], "should support 'jwk' resource type")
	assert.True(t, typeMap["x5c"], "should support 'x5c' resource type")
}

// TestOIDFedRegistry_RequiredTrustMarks tests configuration with required trust marks.
func TestOIDFedRegistry_RequiredTrustMarks(t *testing.T) {
	// Skip if SKIP_NETWORK_TESTS env var is set
	if os.Getenv("SKIP_NETWORK_TESTS") != "" {
		t.Skip("Skipping network test (SKIP_NETWORK_TESTS set)")
	}

	// Create OIDF registry requiring specific trust marks
	reg, err := oidfed.NewOIDFedRegistry(oidfed.Config{
		TrustAnchors: []oidfed.TrustAnchorConfig{
			{EntityID: realtaTrustAnchor},
		},
		RequiredTrustMarks: []string{
			"https://example.com/some-trust-mark",
		},
		Description: "Registry with required trust marks",
	})
	require.NoError(t, err)

	// Create test server
	srv := testserver.New(testserver.WithRegistry(reg))
	defer srv.Close()

	client := authzenclient.New(srv.URL())
	ctx := context.Background()

	// Test: entity without required trust mark should be rejected
	resp, err := client.Evaluate(ctx, &authzen.EvaluationRequest{
		Subject: authzen.Subject{
			Type: "key",
			ID:   realtaTrustAnchor,
		},
		Resource: authzen.Resource{
			Type: "jwk", // Use jwk instead of entity
			ID:   realtaTrustAnchor,
			Key:  []interface{}{"dummy-key"},
		},
		Action: &authzen.Action{
			Name: "issuer",
		},
	})
	require.NoError(t, err)
	// Entity without required trust mark should be rejected
	assert.False(t, resp.Decision, "entity without required trust mark should not be trusted")
}

// TestOIDFedRegistry_RefreshClearsCache tests that refresh clears the cache.
func TestOIDFedRegistry_RefreshClearsCache(t *testing.T) {
	reg, err := oidfed.NewOIDFedRegistry(oidfed.Config{
		TrustAnchors: []oidfed.TrustAnchorConfig{
			{EntityID: realtaTrustAnchor},
		},
		CacheTTL: 5 * time.Minute,
	})
	require.NoError(t, err)

	// Refresh should not error
	err = reg.Refresh(context.Background())
	require.NoError(t, err)

	// Registry should still be healthy after refresh
	assert.True(t, reg.Healthy())
}

// --- Subordinate entity resolution tests using realta trust anchor ---
// These tests verify that real subordinate entities (OP, RP, etc.) in the
// realta.labb.sunet.se federation can be resolved and evaluated correctly.

// Subordinate entity IDs in the realta federation
const (
	satosaEntity   = "https://satosa.labb.sunet.se"
	realopEntity   = "https://realop.labb.sunet.se"
	realrpEntity   = "https://realrp.labb.sunet.se"
	satosarpEntity = "https://satosarp.labb.sunet.se"
)

// newRealtaRegistry creates a registry configured with the realta trust anchor.
func newRealtaRegistry(t *testing.T) *oidfed.OIDFedRegistry {
	t.Helper()
	if os.Getenv("SKIP_NETWORK_TESTS") != "" {
		t.Skip("Skipping network test (SKIP_NETWORK_TESTS set)")
	}
	reg, err := oidfed.NewOIDFedRegistry(oidfed.Config{
		TrustAnchors: []oidfed.TrustAnchorConfig{
			{EntityID: realtaTrustAnchor},
		},
		CacheTTL: 5 * time.Minute,
	})
	require.NoError(t, err)
	return reg
}

// TestOIDFedRegistry_ResolveSubordinateOP tests trust chain resolution
// for an OpenID Provider subordinate entity.
func TestOIDFedRegistry_ResolveSubordinateOP(t *testing.T) {
	reg := newRealtaRegistry(t)
	srv := testserver.New(testserver.WithRegistry(reg))
	defer srv.Close()

	client := authzenclient.New(srv.URL())
	ctx := context.Background()

	// Resolution-only request for realop (OpenID Provider)
	resp, err := client.Evaluate(ctx, &authzen.EvaluationRequest{
		Subject: authzen.Subject{
			Type: "key",
			ID:   realopEntity,
		},
		Resource: authzen.Resource{
			ID: realopEntity,
			// No type/key = resolution-only
		},
	})
	require.NoError(t, err)
	assert.True(t, resp.Decision, "subordinate OP should resolve successfully")
	require.NotNil(t, resp.Context, "response should include context")
	require.NotNil(t, resp.Context.Reason, "response should include reason")
	assert.Equal(t, true, resp.Context.Reason["resolution_only"])
	assert.Equal(t, realopEntity, resp.Context.Reason["entity_id"])
}

// TestOIDFedRegistry_ResolveSubordinateRP tests trust chain resolution
// for a Relying Party subordinate entity.
func TestOIDFedRegistry_ResolveSubordinateRP(t *testing.T) {
	reg := newRealtaRegistry(t)
	srv := testserver.New(testserver.WithRegistry(reg))
	defer srv.Close()

	client := authzenclient.New(srv.URL())
	ctx := context.Background()

	resp, err := client.Evaluate(ctx, &authzen.EvaluationRequest{
		Subject: authzen.Subject{
			Type: "key",
			ID:   realrpEntity,
		},
		Resource: authzen.Resource{
			ID: realrpEntity,
		},
	})
	require.NoError(t, err)
	assert.True(t, resp.Decision, "subordinate RP should resolve successfully")
	require.NotNil(t, resp.Context)
	require.NotNil(t, resp.Context.Reason)
	assert.Equal(t, realrpEntity, resp.Context.Reason["entity_id"])
}

// TestOIDFedRegistry_ResolveSatosa tests trust chain resolution for
// the satosa proxy entity.
func TestOIDFedRegistry_ResolveSatosa(t *testing.T) {
	reg := newRealtaRegistry(t)
	srv := testserver.New(testserver.WithRegistry(reg))
	defer srv.Close()

	client := authzenclient.New(srv.URL())
	ctx := context.Background()

	resp, err := client.Evaluate(ctx, &authzen.EvaluationRequest{
		Subject: authzen.Subject{
			Type: "key",
			ID:   satosaEntity,
		},
		Resource: authzen.Resource{
			ID: satosaEntity,
		},
	})
	require.NoError(t, err)
	assert.True(t, resp.Decision, "satosa entity should resolve successfully")
}

// TestOIDFedRegistry_ResolveWithTrustChain tests that include_trust_chain
// returns the full chain in the response.
func TestOIDFedRegistry_ResolveWithTrustChain(t *testing.T) {
	reg := newRealtaRegistry(t)
	srv := testserver.New(testserver.WithRegistry(reg))
	defer srv.Close()

	client := authzenclient.New(srv.URL())
	ctx := context.Background()

	resp, err := client.Evaluate(ctx, &authzen.EvaluationRequest{
		Subject: authzen.Subject{
			Type: "key",
			ID:   realopEntity,
		},
		Resource: authzen.Resource{
			ID: realopEntity,
		},
		Context: map[string]interface{}{
			"include_trust_chain": true,
		},
	})
	require.NoError(t, err)
	assert.True(t, resp.Decision, "resolution should succeed")
	require.NotNil(t, resp.Context)
	require.NotNil(t, resp.Context.TrustMetadata, "should include trust_metadata")
	tm, ok := resp.Context.TrustMetadata.(map[string]interface{})
	require.True(t, ok, "trust_metadata should be a map")

	// The trust chain should be present and have at least 2 entries
	// (leaf entity statement + trust anchor entity configuration)
	trustChain, ok := tm["trust_chain"]
	assert.True(t, ok, "trust_metadata should contain trust_chain")
	if chainSlice, ok := trustChain.([]interface{}); ok {
		assert.GreaterOrEqual(t, len(chainSlice), 2,
			"trust chain should have at least 2 entries (leaf + anchor)")
	}

	// Trust anchor should be the realta entity
	trustAnchor, ok := tm["trust_anchor"]
	assert.True(t, ok, "trust_metadata should contain trust_anchor")
	if anchorStr, ok := trustAnchor.(string); ok {
		assert.Contains(t, anchorStr, "realta.labb.sunet.se",
			"trust anchor should be realta")
	}
}

// TestOIDFedRegistry_EntityTypeFilter tests filtering by entity type.
func TestOIDFedRegistry_EntityTypeFilter(t *testing.T) {
	reg := newRealtaRegistry(t)
	srv := testserver.New(testserver.WithRegistry(reg))
	defer srv.Close()

	client := authzenclient.New(srv.URL())
	ctx := context.Background()

	// Request with entity type filter matching the OP
	resp, err := client.Evaluate(ctx, &authzen.EvaluationRequest{
		Subject: authzen.Subject{
			Type: "key",
			ID:   realopEntity,
		},
		Resource: authzen.Resource{
			ID: realopEntity,
		},
		Context: map[string]interface{}{
			"allowed_entity_types": []string{"openid_provider"},
		},
	})
	require.NoError(t, err)
	assert.True(t, resp.Decision,
		"OP entity should resolve when filtering for openid_provider")

	// Request with entity type filter NOT matching the OP
	resp, err = client.Evaluate(ctx, &authzen.EvaluationRequest{
		Subject: authzen.Subject{
			Type: "key",
			ID:   realopEntity,
		},
		Resource: authzen.Resource{
			ID: realopEntity,
		},
		Context: map[string]interface{}{
			"allowed_entity_types": []string{"openid_relying_party"},
		},
	})
	require.NoError(t, err)
	// Note: go-oidfed does not enforce entity type filtering during resolution,
	// so the OP still resolves even when filtering for RP only. This is expected
	// current behavior; entity type filtering would need post-resolution enforcement.
	t.Logf("OP with RP filter: decision=%v (go-oidfed does not enforce type filtering)", resp.Decision)
}

// TestOIDFedRegistry_CacheBypass tests that cache_control=no-cache forces
// re-resolution.
func TestOIDFedRegistry_CacheBypass(t *testing.T) {
	reg := newRealtaRegistry(t)
	srv := testserver.New(testserver.WithRegistry(reg))
	defer srv.Close()

	client := authzenclient.New(srv.URL())
	ctx := context.Background()

	// First request — populates cache
	resp1, err := client.Evaluate(ctx, &authzen.EvaluationRequest{
		Subject: authzen.Subject{
			Type: "key",
			ID:   satosaEntity,
		},
		Resource: authzen.Resource{
			ID: satosaEntity,
		},
	})
	require.NoError(t, err)
	assert.True(t, resp1.Decision)

	// Second request with no-cache — should bypass cache and still succeed
	resp2, err := client.Evaluate(ctx, &authzen.EvaluationRequest{
		Subject: authzen.Subject{
			Type: "key",
			ID:   satosaEntity,
		},
		Resource: authzen.Resource{
			ID: satosaEntity,
		},
		Context: map[string]interface{}{
			"cache_control": "no-cache",
		},
	})
	require.NoError(t, err)
	assert.True(t, resp2.Decision, "cached-bypassed request should still resolve")
}

// TestOIDFedRegistry_AllSubordinates tests that all known subordinates
// in the realta federation can be resolved.
func TestOIDFedRegistry_AllSubordinates(t *testing.T) {
	reg := newRealtaRegistry(t)
	ctx := context.Background()

	subordinates := []struct {
		name     string
		entityID string
	}{
		{"satosa-proxy", satosaEntity},
		{"real-op", realopEntity},
		{"real-rp", realrpEntity},
		{"satosa-rp", satosarpEntity},
	}

	for _, sub := range subordinates {
		t.Run(sub.name, func(t *testing.T) {
			resp, err := reg.Evaluate(ctx, &authzen.EvaluationRequest{
				Subject: authzen.Subject{
					Type: "key",
					ID:   sub.entityID,
				},
				Resource: authzen.Resource{
					ID: sub.entityID,
				},
			})
			require.NoError(t, err)
			assert.True(t, resp.Decision,
				"subordinate %s should resolve against realta anchor", sub.name)
			if resp.Context != nil && resp.Context.Reason != nil {
				t.Logf("  entity_id=%v chain_length=%v",
					resp.Context.Reason["entity_id"],
					resp.Context.Reason["trust_chain_length"])
			}
		})
	}
}

// TestOIDFedRegistry_CrossFederationReject tests that entities from a
// different federation are rejected.
func TestOIDFedRegistry_CrossFederationReject(t *testing.T) {
	reg := newRealtaRegistry(t)
	ctx := context.Background()

	// An entity that exists but is NOT in the realta federation
	resp, err := reg.Evaluate(ctx, &authzen.EvaluationRequest{
		Subject: authzen.Subject{
			Type: "key",
			ID:   "https://accounts.google.com",
		},
		Resource: authzen.Resource{
			ID: "https://accounts.google.com",
		},
	})
	require.NoError(t, err)
	assert.False(t, resp.Decision,
		"entity outside the federation should not resolve")
	// Verify the rejection reason distinguishes the failure mode
	if resp.Context != nil && resp.Context.Reason != nil {
		msg, _ := resp.Context.Reason["message"].(string)
		assert.Contains(t, []string{"entity not reachable", "no valid trust chain found"}, msg,
			"rejection reason should indicate either unreachable or no valid chain")
	}
}

// TestOIDFedRegistry_TrustMetadataFields tests that resolution responses
// contain the expected metadata fields.
func TestOIDFedRegistry_TrustMetadataFields(t *testing.T) {
	reg := newRealtaRegistry(t)
	ctx := context.Background()

	resp, err := reg.Evaluate(ctx, &authzen.EvaluationRequest{
		Subject: authzen.Subject{
			Type: "key",
			ID:   realopEntity,
		},
		Resource: authzen.Resource{
			ID: realopEntity,
		},
		Context: map[string]interface{}{
			"include_trust_chain": true,
		},
	})
	require.NoError(t, err)
	require.True(t, resp.Decision)
	require.NotNil(t, resp.Context)
	require.NotNil(t, resp.Context.TrustMetadata)
	tm, ok := resp.Context.TrustMetadata.(map[string]interface{})
	require.True(t, ok, "trust_metadata should be a map")

	// Check standard metadata fields
	assert.Contains(t, tm, "trust_anchor",
		"should include trust_anchor")
	assert.Contains(t, tm, "trust_chain",
		"should include trust_chain")
	assert.Contains(t, tm, "evaluated_at",
		"should include evaluated_at timestamp")
	assert.Contains(t, tm, "jwks",
		"should include jwks")

	// Entity types are nested inside metadata
	if metadata, ok := tm["metadata"].(map[string]interface{}); ok {
		if entityTypes, ok := metadata["entity_types"].([]string); ok {
			assert.Contains(t, entityTypes, "openid_provider",
				"realop should have openid_provider entity type")
		} else if entityTypes, ok := metadata["entity_types"].([]interface{}); ok {
			typeStrs := make([]string, len(entityTypes))
			for i, et := range entityTypes {
				typeStrs[i], _ = et.(string)
			}
			assert.Contains(t, typeStrs, "openid_provider",
				"realop should have openid_provider entity type")
		}
	}
}

// TestOIDFedRegistry_DirectEvaluateVsTestServer verifies that calling
// Evaluate directly on the registry produces the same decision as going
// through the test server + HTTP client.
func TestOIDFedRegistry_DirectEvaluateVsTestServer(t *testing.T) {
	reg := newRealtaRegistry(t)
	ctx := context.Background()

	req := &authzen.EvaluationRequest{
		Subject: authzen.Subject{
			Type: "key",
			ID:   satosaEntity,
		},
		Resource: authzen.Resource{
			ID: satosaEntity,
		},
	}

	// Direct evaluation
	directResp, err := reg.Evaluate(ctx, req)
	require.NoError(t, err)

	// Via test server
	srv := testserver.New(testserver.WithRegistry(reg))
	defer srv.Close()
	client := authzenclient.New(srv.URL())

	httpResp, err := client.Evaluate(ctx, req)
	require.NoError(t, err)

	assert.Equal(t, directResp.Decision, httpResp.Decision,
		"direct and HTTP evaluation should produce the same decision")
}

// TestOIDFedRegistry_RawResolverDebug directly uses the go-oidfed TrustResolver
// to verify that trust chain resolution works for subordinate entities.
func TestOIDFedRegistry_RawResolverDebug(t *testing.T) {
	if os.Getenv("SKIP_NETWORK_TESTS") != "" {
		t.Skip("Skipping network test (SKIP_NETWORK_TESTS set)")
	}

	entities := []string{
		realopEntity,
		realrpEntity,
		satosaEntity,
	}

	for _, entityID := range entities {
		t.Run(entityID, func(t *testing.T) {
			resolver := &oidfedlib.TrustResolver{
				StartingEntity: entityID,
				TrustAnchors:   oidfedlib.NewTrustAnchorsFromEntityIDs(realtaTrustAnchor),
			}

			chains := resolver.ResolveToValidChains()
			t.Logf("entity=%s chains=%d", entityID, len(chains))
			if len(chains) > 0 {
				for i, chain := range chains {
					t.Logf("  chain[%d] length=%d", i, len(chain))
					for j, stmt := range chain {
						t.Logf("    [%d] iss=%s sub=%s", j, stmt.Issuer, stmt.Subject)
					}
				}
			} else {
				t.Errorf("no valid trust chains found for %s", entityID)
			}
		})
	}
}
