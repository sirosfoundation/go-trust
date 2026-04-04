package oidfed

import (
	"context"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	oidfed "github.com/go-oidfed/lib"
	oidfedjwx "github.com/go-oidfed/lib/jwx"
	"github.com/go-oidfed/lib/unixtime"
	"github.com/sirosfoundation/go-trust/pkg/authzen"
)

func TestNewOIDFedRegistry(t *testing.T) {
	tests := []struct {
		name    string
		config  Config
		wantErr bool
	}{
		{
			name: "valid config with one trust anchor",
			config: Config{
				TrustAnchors: []TrustAnchorConfig{
					{EntityID: "https://ta.example.com"},
				},
				Description: "Test registry",
			},
			wantErr: false,
		},
		{
			name: "valid config with multiple trust anchors",
			config: Config{
				TrustAnchors: []TrustAnchorConfig{
					{EntityID: "https://ta1.example.com"},
					{EntityID: "https://ta2.example.com"},
				},
			},
			wantErr: false,
		},
		{
			name: "valid config with trust marks",
			config: Config{
				TrustAnchors: []TrustAnchorConfig{
					{EntityID: "https://ta.example.com"},
				},
				RequiredTrustMarks: []string{
					"https://example.com/trustmark/level1",
				},
			},
			wantErr: false,
		},
		{
			name: "no trust anchors - should fail",
			config: Config{
				TrustAnchors: []TrustAnchorConfig{},
			},
			wantErr: true,
		},
		{
			name: "empty entity ID - should fail",
			config: Config{
				TrustAnchors: []TrustAnchorConfig{
					{EntityID: ""},
				},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			registry, err := NewOIDFedRegistry(tt.config)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewOIDFedRegistry() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				if registry == nil {
					t.Error("NewOIDFedRegistry() returned nil registry")
					return
				}
				if len(registry.trustAnchors) != len(tt.config.TrustAnchors) {
					t.Errorf("NewOIDFedRegistry() trust anchors count = %d, want %d",
						len(registry.trustAnchors), len(tt.config.TrustAnchors))
				}
			}
		})
	}
}

func TestOIDFedRegistry_Name(t *testing.T) {
	registry, _ := NewOIDFedRegistry(Config{
		TrustAnchors: []TrustAnchorConfig{{EntityID: "https://ta.example.com"}},
	})

	if name := registry.Name(); name != "oidfed-registry" {
		t.Errorf("Name() = %v, want %v", name, "oidfed-registry")
	}
}

func TestOIDFedRegistry_SupportedResourceTypes(t *testing.T) {
	registry, _ := NewOIDFedRegistry(Config{
		TrustAnchors: []TrustAnchorConfig{{EntityID: "https://ta.example.com"}},
	})

	types := registry.SupportedResourceTypes()
	if len(types) == 0 {
		t.Error("SupportedResourceTypes() returned empty slice")
	}

	expectedTypes := map[string]bool{
		"entity":            true,
		"openid_provider":   true,
		"relying_party":     true,
		"oauth_client":      true,
		"oauth_server":      true,
		"federation_entity": true,
		"jwk":               true,
		"x5c":               true,
	}

	for _, typ := range types {
		if !expectedTypes[typ] {
			t.Errorf("SupportedResourceTypes() contains unexpected type: %s", typ)
		}
	}
}

func TestOIDFedRegistry_Healthy(t *testing.T) {
	registry, _ := NewOIDFedRegistry(Config{
		TrustAnchors: []TrustAnchorConfig{{EntityID: "https://ta.example.com"}},
	})

	if !registry.Healthy() {
		t.Error("Healthy() = false, want true")
	}
}

func TestOIDFedRegistry_Info(t *testing.T) {
	config := Config{
		TrustAnchors: []TrustAnchorConfig{
			{EntityID: "https://ta1.example.com"},
			{EntityID: "https://ta2.example.com"},
		},
		Description: "Test OpenID Federation Registry",
	}

	registry, _ := NewOIDFedRegistry(config)
	info := registry.Info()

	if info.Name != "oidfed-registry" {
		t.Errorf("Info().Name = %v, want %v", info.Name, "oidfed-registry")
	}

	if info.Type != "openid_federation" {
		t.Errorf("Info().Type = %v, want %v", info.Type, "openid_federation")
	}

	if info.Description != config.Description {
		t.Errorf("Info().Description = %v, want %v", info.Description, config.Description)
	}

	if len(info.TrustAnchors) != 2 {
		t.Errorf("Info().TrustAnchors count = %d, want 2", len(info.TrustAnchors))
	}
}

func TestOIDFedRegistry_extractEntityID(t *testing.T) {
	registry, _ := NewOIDFedRegistry(Config{
		TrustAnchors: []TrustAnchorConfig{{EntityID: "https://ta.example.com"}},
	})

	tests := []struct {
		name    string
		req     *authzen.EvaluationRequest
		want    string
		wantErr bool
	}{
		{
			name: "extract from subject.id (https)",
			req: &authzen.EvaluationRequest{
				Subject: authzen.Subject{
					Type: "key",
					ID:   "https://entity.example.com",
				},
				Resource: authzen.Resource{
					Type: "x5c",
					ID:   "https://entity.example.com",
					Key:  []interface{}{"dummy"},
				},
			},
			want:    "https://entity.example.com",
			wantErr: false,
		},
		{
			name: "extract from subject.id (http)",
			req: &authzen.EvaluationRequest{
				Subject: authzen.Subject{
					Type: "key",
					ID:   "http://entity.example.com",
				},
				Resource: authzen.Resource{
					Type: "jwk",
					ID:   "http://entity.example.com",
					Key:  []interface{}{"dummy"},
				},
			},
			want:    "http://entity.example.com",
			wantErr: false,
		},
		{
			name: "extract from resource.id when subject.id is not URL",
			req: &authzen.EvaluationRequest{
				Subject: authzen.Subject{
					Type: "key",
					ID:   "some-identifier",
				},
				Resource: authzen.Resource{
					Type: "x5c",
					ID:   "https://entity.example.com",
					Key:  []interface{}{"dummy"},
				},
			},
			want:    "https://entity.example.com",
			wantErr: false,
		},
		{
			name: "no valid entity ID",
			req: &authzen.EvaluationRequest{
				Subject: authzen.Subject{
					Type: "key",
					ID:   "not-a-url",
				},
				Resource: authzen.Resource{
					Type: "x5c",
					ID:   "also-not-a-url",
					Key:  []interface{}{"dummy"},
				},
			},
			want:    "",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := registry.extractEntityID(tt.req)
			if (err != nil) != tt.wantErr {
				t.Errorf("extractEntityID() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("extractEntityID() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestOIDFedRegistry_Evaluate_NoValidChain(t *testing.T) {
	// This test uses a non-existent entity, so trust chain resolution will fail
	registry, _ := NewOIDFedRegistry(Config{
		TrustAnchors: []TrustAnchorConfig{
			{EntityID: "https://non-existent-ta.example.com"},
		},
	})

	req := &authzen.EvaluationRequest{
		Subject: authzen.Subject{
			Type: "key",
			ID:   "https://non-existent-entity.example.com",
		},
		Resource: authzen.Resource{
			Type: "x5c",
			ID:   "https://non-existent-entity.example.com",
			Key:  []interface{}{"dummy-cert"},
		},
	}

	resp, err := registry.Evaluate(context.Background(), req)
	if err != nil {
		t.Fatalf("Evaluate() error = %v, want nil", err)
	}

	if resp.Decision {
		t.Error("Evaluate() decision = true, want false (no valid chain)")
	}

	if resp.Context == nil || resp.Context.Reason == nil {
		t.Error("Evaluate() response should include context with reason")
	}
}

func TestOIDFedRegistry_Refresh(t *testing.T) {
	registry, _ := NewOIDFedRegistry(Config{
		TrustAnchors: []TrustAnchorConfig{{EntityID: "https://ta.example.com"}},
	})

	// Refresh should not fail (it clears the cache)
	err := registry.Refresh(context.Background())
	if err != nil {
		t.Errorf("Refresh() error = %v, want nil", err)
	}
}

func TestOIDFedRegistry_CacheConfig(t *testing.T) {
	// Test with cache configuration
	registry, _ := NewOIDFedRegistry(Config{
		TrustAnchors: []TrustAnchorConfig{{EntityID: "https://ta.example.com"}},
		CacheTTL:     5 * time.Minute,
		MaxCacheSize: 100,
	})

	stats := registry.GetCacheStats()
	if !stats["enabled"].(bool) {
		t.Error("Cache should be enabled")
	}
	if stats["max_size"].(int) != 100 {
		t.Errorf("Cache max_size = %v, want 100", stats["max_size"])
	}
}

func TestMetadataCache(t *testing.T) {
	cache := NewMetadataCache(1*time.Hour, 10)

	// Test Set and Get
	cache.Set("entity1", []string{"tm1"}, []string{"openid_provider"}, nil, "anchor1")
	entry := cache.Get("entity1", []string{"tm1"}, []string{"openid_provider"})
	if entry == nil {
		t.Error("Cache Get returned nil, expected entry")
	}

	// Test cache miss with different parameters
	entry = cache.Get("entity1", []string{"tm2"}, []string{"openid_provider"})
	if entry != nil {
		t.Error("Cache Get should return nil for different trust marks")
	}

	// Test Clear
	cache.Clear()
	entry = cache.Get("entity1", []string{"tm1"}, []string{"openid_provider"})
	if entry != nil {
		t.Error("Cache Get should return nil after Clear")
	}

	// Test Invalidate
	cache.Set("entity2", nil, nil, nil, "anchor1")
	cache.Invalidate("entity2", nil, nil)
	entry = cache.Get("entity2", nil, nil)
	if entry != nil {
		t.Error("Cache Get should return nil after Invalidate")
	}
}

func TestExtractConstraintsFromContext(t *testing.T) {
	registry, _ := NewOIDFedRegistry(Config{
		TrustAnchors:       []TrustAnchorConfig{{EntityID: "https://ta.example.com"}},
		RequiredTrustMarks: []string{"default-mark"},
		EntityTypes:        []string{"default-type"},
	})

	tests := []struct {
		name             string
		context          map[string]interface{}
		wantTrustMarks   []string
		wantEntityTypes  []string
		wantIncludeChain bool
		wantIncludeCerts bool
	}{
		{
			name:            "nil context uses defaults",
			context:         nil,
			wantTrustMarks:  []string{"default-mark"},
			wantEntityTypes: []string{"default-type"},
		},
		{
			name: "context adds trust marks",
			context: map[string]interface{}{
				"required_trust_marks": []string{"extra-mark"},
			},
			wantTrustMarks:  []string{"default-mark", "extra-mark"},
			wantEntityTypes: []string{"default-type"},
		},
		{
			name: "context replaces entity types",
			context: map[string]interface{}{
				"allowed_entity_types": []string{"new-type"},
			},
			wantTrustMarks:  []string{"default-mark"},
			wantEntityTypes: []string{"new-type"},
		},
		{
			name: "include flags",
			context: map[string]interface{}{
				"include_trust_chain":  true,
				"include_certificates": true,
			},
			wantTrustMarks:   []string{"default-mark"},
			wantEntityTypes:  []string{"default-type"},
			wantIncludeChain: true,
			wantIncludeCerts: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := &authzen.EvaluationRequest{
				Subject:  authzen.Subject{Type: "key", ID: "https://entity.example.com"},
				Resource: authzen.Resource{ID: "https://entity.example.com"},
				Context:  tt.context,
			}

			trustMarks, entityTypes, _, includeChain, includeCerts, _ := registry.extractConstraintsFromContext(req)

			if !equalStringSlices(trustMarks, tt.wantTrustMarks) {
				t.Errorf("trustMarks = %v, want %v", trustMarks, tt.wantTrustMarks)
			}
			if !equalStringSlices(entityTypes, tt.wantEntityTypes) {
				t.Errorf("entityTypes = %v, want %v", entityTypes, tt.wantEntityTypes)
			}
			if includeChain != tt.wantIncludeChain {
				t.Errorf("includeChain = %v, want %v", includeChain, tt.wantIncludeChain)
			}
			if includeCerts != tt.wantIncludeCerts {
				t.Errorf("includeCerts = %v, want %v", includeCerts, tt.wantIncludeCerts)
			}
		})
	}
}

func equalStringSlices(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestTrustAnchorConfig_WithJWKS(t *testing.T) {
	// Test that we can create a registry with explicit JWKS
	jwks := &oidfedjwx.JWKS{}

	config := Config{
		TrustAnchors: []TrustAnchorConfig{
			{
				EntityID: "https://ta.example.com",
				JWKS:     jwks,
			},
		},
	}

	registry, err := NewOIDFedRegistry(config)
	if err != nil {
		t.Fatalf("NewOIDFedRegistry() error = %v, want nil", err)
	}

	if len(registry.trustAnchors) != 1 {
		t.Errorf("trust anchors count = %d, want 1", len(registry.trustAnchors))
	}
}

func TestMetadataCache_TTLExpiration(t *testing.T) {
	// Create cache with very short TTL
	cache := NewMetadataCache(10*time.Millisecond, 10)

	// Add entry
	cache.Set("entity1", []string{"tm1"}, []string{"type1"}, nil, "anchor1")

	// Verify it exists immediately
	entry := cache.Get("entity1", []string{"tm1"}, []string{"type1"})
	if entry == nil {
		t.Error("Cache Get returned nil immediately after Set")
	}

	// Wait for TTL to expire
	time.Sleep(20 * time.Millisecond)

	// Verify entry is expired (Get should return nil)
	entry = cache.Get("entity1", []string{"tm1"}, []string{"type1"})
	if entry != nil {
		t.Error("Cache Get should return nil after TTL expiration")
	}
}

func TestMetadataCache_Eviction(t *testing.T) {
	// Create cache with max size of 3
	cache := NewMetadataCache(1*time.Hour, 3)

	// Add 3 entries
	cache.Set("entity1", nil, nil, nil, "anchor1")
	cache.Set("entity2", nil, nil, nil, "anchor1")
	cache.Set("entity3", nil, nil, nil, "anchor1")

	// Verify all exist
	if cache.Get("entity1", nil, nil) == nil {
		t.Error("entity1 should be in cache")
	}
	if cache.Get("entity2", nil, nil) == nil {
		t.Error("entity2 should be in cache")
	}
	if cache.Get("entity3", nil, nil) == nil {
		t.Error("entity3 should be in cache")
	}

	// Add one more - should evict the oldest
	cache.Set("entity4", nil, nil, nil, "anchor1")

	// entity4 should exist
	if cache.Get("entity4", nil, nil) == nil {
		t.Error("entity4 should be in cache after Set")
	}

	// Cache size should still be 3
	size, _, _ := cache.Stats()
	if size > 3 {
		t.Errorf("Cache size = %d, want <= 3", size)
	}
}

func TestMetadataCache_Stats(t *testing.T) {
	cache := NewMetadataCache(1*time.Hour, 100)

	// Empty cache
	size, hits, misses := cache.Stats()
	if size != 0 {
		t.Errorf("Empty cache size = %d, want 0", size)
	}
	if hits != 0 || misses != 0 {
		t.Errorf("Empty cache hits=%d, misses=%d, want 0,0", hits, misses)
	}

	// Add entries
	cache.Set("entity1", nil, nil, nil, "anchor1")
	cache.Set("entity2", nil, nil, nil, "anchor1")

	size, _, _ = cache.Stats()
	if size != 2 {
		t.Errorf("Cache size = %d, want 2", size)
	}
}

func TestMetadataCache_Invalidate(t *testing.T) {
	cache := NewMetadataCache(1*time.Hour, 10)

	// Add entries with same entity but different constraints
	cache.Set("entity1", []string{"tm1"}, nil, nil, "anchor1")
	cache.Set("entity1", []string{"tm2"}, nil, nil, "anchor1")
	cache.Set("entity2", []string{"tm1"}, nil, nil, "anchor1")

	// Invalidate specific entry (entity1 with tm1)
	cache.Invalidate("entity1", []string{"tm1"}, nil)

	// entity1 with tm1 should be gone
	if cache.Get("entity1", []string{"tm1"}, nil) != nil {
		t.Error("entity1 with tm1 should be invalidated")
	}

	// entity1 with tm2 should still exist (Invalidate is specific to the full key)
	if cache.Get("entity1", []string{"tm2"}, nil) == nil {
		t.Error("entity1 with tm2 should still be in cache")
	}

	// entity2 should still exist
	if cache.Get("entity2", []string{"tm1"}, nil) == nil {
		t.Error("entity2 should still be in cache")
	}
}

func TestCacheKey(t *testing.T) {
	cache := NewMetadataCache(1*time.Hour, 100)

	tests := []struct {
		name        string
		entityID    string
		trustMarks  []string
		entityTypes []string
		wantDiff    bool // should different inputs produce different keys
	}{
		{
			name:        "same entity different trust marks",
			entityID:    "https://entity.example.com",
			trustMarks:  []string{"tm1", "tm2"},
			entityTypes: nil,
			wantDiff:    true,
		},
		{
			name:        "same entity different entity types",
			entityID:    "https://entity.example.com",
			trustMarks:  nil,
			entityTypes: []string{"type1"},
			wantDiff:    true,
		},
		{
			name:        "nil vs empty slices",
			entityID:    "https://entity.example.com",
			trustMarks:  nil,
			entityTypes: nil,
			wantDiff:    false,
		},
	}

	baseKey := cache.cacheKey("https://entity.example.com", nil, nil)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key := cache.cacheKey(tt.entityID, tt.trustMarks, tt.entityTypes)
			isDifferent := key != baseKey
			if tt.wantDiff && !isDifferent {
				t.Errorf("cacheKey() should produce different key for %s", tt.name)
			}
		})
	}
}

func TestShouldBypassCache(t *testing.T) {
	registry, _ := NewOIDFedRegistry(Config{
		TrustAnchors: []TrustAnchorConfig{{EntityID: "https://ta.example.com"}},
	})

	tests := []struct {
		name    string
		context map[string]interface{}
		want    bool
	}{
		{
			name:    "nil context",
			context: nil,
			want:    false,
		},
		{
			name:    "empty context",
			context: map[string]interface{}{},
			want:    false,
		},
		{
			name: "no-cache",
			context: map[string]interface{}{
				"cache_control": "no-cache",
			},
			want: true,
		},
		{
			name: "no-store",
			context: map[string]interface{}{
				"cache_control": "no-store",
			},
			want: true,
		},
		{
			name: "other cache control value",
			context: map[string]interface{}{
				"cache_control": "max-age=300",
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := &authzen.EvaluationRequest{
				Subject:  authzen.Subject{Type: "key", ID: "https://entity.example.com"},
				Resource: authzen.Resource{ID: "https://entity.example.com"},
				Context:  tt.context,
			}
			if got := registry.shouldBypassCache(req); got != tt.want {
				t.Errorf("shouldBypassCache() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestExtractConstraintsFromContext_InterfaceSlices(t *testing.T) {
	registry, _ := NewOIDFedRegistry(Config{
		TrustAnchors: []TrustAnchorConfig{{EntityID: "https://ta.example.com"}},
	})

	tests := []struct {
		name            string
		context         map[string]interface{}
		wantTrustMarks  []string
		wantEntityTypes []string
	}{
		{
			name: "trust marks as []interface{}",
			context: map[string]interface{}{
				"required_trust_marks": []interface{}{"mark1", "mark2"},
			},
			wantTrustMarks:  []string{"mark1", "mark2"},
			wantEntityTypes: nil,
		},
		{
			name: "entity types as []interface{}",
			context: map[string]interface{}{
				"allowed_entity_types": []interface{}{"type1", "type2"},
			},
			wantTrustMarks:  nil,
			wantEntityTypes: []string{"type1", "type2"},
		},
		{
			name: "max chain depth as int",
			context: map[string]interface{}{
				"max_chain_depth": 5,
			},
			wantTrustMarks:  nil,
			wantEntityTypes: nil,
		},
		{
			name: "max chain depth as float64",
			context: map[string]interface{}{
				"max_chain_depth": float64(7),
			},
			wantTrustMarks:  nil,
			wantEntityTypes: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := &authzen.EvaluationRequest{
				Subject:  authzen.Subject{Type: "key", ID: "https://entity.example.com"},
				Resource: authzen.Resource{ID: "https://entity.example.com"},
				Context:  tt.context,
			}
			trustMarks, entityTypes, _, _, _, maxDepth := registry.extractConstraintsFromContext(req)

			if tt.wantTrustMarks != nil && !equalStringSlices(trustMarks, tt.wantTrustMarks) {
				t.Errorf("trustMarks = %v, want %v", trustMarks, tt.wantTrustMarks)
			}
			if tt.wantEntityTypes != nil && !equalStringSlices(entityTypes, tt.wantEntityTypes) {
				t.Errorf("entityTypes = %v, want %v", entityTypes, tt.wantEntityTypes)
			}
			if tt.context["max_chain_depth"] != nil && maxDepth == 10 {
				// maxDepth should be changed from default
				t.Errorf("maxDepth should be changed from default 10")
			}
		})
	}
}

func TestMergeStringSlices(t *testing.T) {
	tests := []struct {
		name string
		a    []string
		b    []string
		want []string
	}{
		{
			name: "no duplicates",
			a:    []string{"a", "b"},
			b:    []string{"c", "d"},
			want: []string{"a", "b", "c", "d"},
		},
		{
			name: "with duplicates",
			a:    []string{"a", "b"},
			b:    []string{"b", "c"},
			want: []string{"a", "b", "c"},
		},
		{
			name: "empty slices",
			a:    []string{},
			b:    []string{},
			want: []string{},
		},
		{
			name: "nil slices",
			a:    nil,
			b:    nil,
			want: []string{},
		},
		{
			name: "one nil",
			a:    []string{"a"},
			b:    nil,
			want: []string{"a"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := mergeStringSlices(tt.a, tt.b)
			if !equalStringSlices(got, tt.want) {
				t.Errorf("mergeStringSlices() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestOIDFedRegistry_Description(t *testing.T) {
	tests := []struct {
		name        string
		description string
		want        string
	}{
		{
			name:        "custom description",
			description: "My Custom Registry",
			want:        "My Custom Registry",
		},
		{
			name:        "empty description gets default",
			description: "",
			want:        "OpenID Federation Registry with 1 trust anchor(s)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			registry, _ := NewOIDFedRegistry(Config{
				TrustAnchors: []TrustAnchorConfig{{EntityID: "https://ta.example.com"}},
				Description:  tt.description,
			})
			if got := registry.Description(); got != tt.want {
				t.Errorf("Description() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestOIDFedRegistry_SupportsResolutionOnly(t *testing.T) {
	registry, _ := NewOIDFedRegistry(Config{
		TrustAnchors: []TrustAnchorConfig{{EntityID: "https://ta.example.com"}},
	})

	if !registry.SupportsResolutionOnly() {
		t.Error("SupportsResolutionOnly() = false, want true")
	}
}

func TestOIDFedRegistry_MaxChainDepth(t *testing.T) {
	tests := []struct {
		name        string
		configDepth int
		wantDepth   int
	}{
		{
			name:        "default depth",
			configDepth: 0,
			wantDepth:   10,
		},
		{
			name:        "custom depth",
			configDepth: 5,
			wantDepth:   5,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			registry, _ := NewOIDFedRegistry(Config{
				TrustAnchors:  []TrustAnchorConfig{{EntityID: "https://ta.example.com"}},
				MaxChainDepth: tt.configDepth,
			})
			if registry.maxChainDepth != tt.wantDepth {
				t.Errorf("maxChainDepth = %d, want %d", registry.maxChainDepth, tt.wantDepth)
			}
		})
	}
}

func TestOIDFedRegistry_GetTrustAnchorEntityIDs(t *testing.T) {
	registry, _ := NewOIDFedRegistry(Config{
		TrustAnchors: []TrustAnchorConfig{
			{EntityID: "https://ta1.example.com"},
			{EntityID: "https://ta2.example.com"},
			{EntityID: "https://ta3.example.com"},
		},
	})

	ids := registry.getTrustAnchorEntityIDs()
	if len(ids) != 3 {
		t.Errorf("getTrustAnchorEntityIDs() returned %d IDs, want 3", len(ids))
	}

	expected := []string{"https://ta1.example.com", "https://ta2.example.com", "https://ta3.example.com"}
	for i, id := range ids {
		if id != expected[i] {
			t.Errorf("getTrustAnchorEntityIDs()[%d] = %s, want %s", i, id, expected[i])
		}
	}
}

func TestOIDFedRegistry_Evaluate_MissingEntityID(t *testing.T) {
	registry, _ := NewOIDFedRegistry(Config{
		TrustAnchors: []TrustAnchorConfig{{EntityID: "https://ta.example.com"}},
	})

	// Request with no valid entity ID
	req := &authzen.EvaluationRequest{
		Subject: authzen.Subject{
			Type: "key",
			ID:   "not-a-url",
		},
		Resource: authzen.Resource{
			Type: "entity",
			ID:   "also-not-a-url",
		},
	}

	resp, err := registry.Evaluate(context.Background(), req)
	if err != nil {
		t.Fatalf("Evaluate() unexpected error: %v", err)
	}

	if resp.Decision {
		t.Error("Evaluate() decision = true, want false for missing entity ID")
	}

	if resp.Context == nil || resp.Context.Reason == nil {
		t.Error("Evaluate() should include error reason in context")
	}
}

func TestOIDFedRegistry_Evaluate_WithCacheBypass(t *testing.T) {
	registry, _ := NewOIDFedRegistry(Config{
		TrustAnchors: []TrustAnchorConfig{
			{EntityID: "https://non-existent-ta.example.com"},
		},
	})

	req := &authzen.EvaluationRequest{
		Subject: authzen.Subject{
			Type: "key",
			ID:   "https://non-existent-entity.example.com",
		},
		Resource: authzen.Resource{
			Type: "entity",
			ID:   "https://non-existent-entity.example.com",
		},
		Context: map[string]interface{}{
			"cache_control": "no-cache",
		},
	}

	resp, err := registry.Evaluate(context.Background(), req)
	if err != nil {
		t.Fatalf("Evaluate() error = %v", err)
	}

	// Should still fail gracefully
	if resp.Decision {
		t.Error("Evaluate() decision = true, want false")
	}
}

func TestContextKeys(t *testing.T) {
	// Verify context key constants are properly defined
	tests := []struct {
		key  string
		want string
	}{
		{ContextKeyRequiredTrustMarks, "required_trust_marks"},
		{ContextKeyAllowedEntityTypes, "allowed_entity_types"},
		{ContextKeyIncludeTrustChain, "include_trust_chain"},
		{ContextKeyIncludeCertificates, "include_certificates"},
		{ContextKeyMaxChainDepth, "max_chain_depth"},
		{ContextKeyCacheControl, "cache_control"},
	}

	for _, tt := range tests {
		if tt.key != tt.want {
			t.Errorf("Context key = %s, want %s", tt.key, tt.want)
		}
	}
}

func TestMetadataKeys(t *testing.T) {
	// Verify metadata key constants are properly defined
	tests := []struct {
		key  string
		want string
	}{
		{MetadataKeyEntityConfiguration, "entity_configuration"},
		{MetadataKeyTrustChain, "trust_chain"},
		{MetadataKeyTrustAnchor, "trust_anchor"},
		{MetadataKeyTrustMarks, "trust_marks"},
		{MetadataKeyEntityTypes, "entity_types"},
		{MetadataKeyJWKS, "jwks"},
		{MetadataKeyResolvedAt, "resolved_at"},
		{MetadataKeyCachedUntil, "cached_until"},
	}

	for _, tt := range tests {
		if tt.key != tt.want {
			t.Errorf("Metadata key = %s, want %s", tt.key, tt.want)
		}
	}
}

// TestExtractEntityID tests the extractEntityID function
func TestExtractEntityID(t *testing.T) {
	registry, _ := NewOIDFedRegistry(Config{
		TrustAnchors: []TrustAnchorConfig{
			{EntityID: "https://ta.example.com"},
		},
	})

	tests := []struct {
		name    string
		req     *authzen.EvaluationRequest
		wantID  string
		wantErr bool
	}{
		{
			name: "entity ID from subject.id with https",
			req: &authzen.EvaluationRequest{
				Subject: authzen.Subject{
					Type: "key",
					ID:   "https://entity.example.com",
				},
				Resource: authzen.Resource{
					Type: "entity",
				},
			},
			wantID:  "https://entity.example.com",
			wantErr: false,
		},
		{
			name: "entity ID from subject.id with http",
			req: &authzen.EvaluationRequest{
				Subject: authzen.Subject{
					Type: "key",
					ID:   "http://entity.example.com",
				},
				Resource: authzen.Resource{
					Type: "entity",
				},
			},
			wantID:  "http://entity.example.com",
			wantErr: false,
		},
		{
			name: "entity ID from resource.id",
			req: &authzen.EvaluationRequest{
				Subject: authzen.Subject{
					Type: "key",
					ID:   "some-non-url-id",
				},
				Resource: authzen.Resource{
					Type: "entity",
					ID:   "https://resource-entity.example.com",
				},
			},
			wantID:  "https://resource-entity.example.com",
			wantErr: false,
		},
		{
			name: "no valid entity ID",
			req: &authzen.EvaluationRequest{
				Subject: authzen.Subject{
					Type: "key",
					ID:   "not-a-url",
				},
				Resource: authzen.Resource{
					Type: "entity",
					ID:   "also-not-a-url",
				},
			},
			wantID:  "",
			wantErr: true,
		},
		{
			name: "empty IDs",
			req: &authzen.EvaluationRequest{
				Subject: authzen.Subject{
					Type: "key",
					ID:   "",
				},
				Resource: authzen.Resource{
					Type: "entity",
					ID:   "",
				},
			},
			wantID:  "",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotID, err := registry.extractEntityID(tt.req)
			if (err != nil) != tt.wantErr {
				t.Errorf("extractEntityID() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if gotID != tt.wantID {
				t.Errorf("extractEntityID() = %v, want %v", gotID, tt.wantID)
			}
		})
	}
}

// TestCacheEviction tests cache eviction when max size is reached
func TestCacheEviction(t *testing.T) {
	cache := NewMetadataCache(1*time.Hour, 5) // Small cache for testing

	// Fill cache beyond capacity
	for i := 0; i < 10; i++ {
		cache.Set(
			"https://entity"+string(rune('0'+i))+".example.com",
			nil, nil,
			nil,
			"https://ta.example.com",
		)
	}

	// Cache size should not exceed maxSize
	size, _, _ := cache.Stats()
	if size > 5 {
		t.Errorf("Cache size = %d, expected <= 5", size)
	}
}

// TestCacheInvalidate tests the cache Invalidate function
func TestCacheInvalidate(t *testing.T) {
	cache := NewMetadataCache(1*time.Hour, 100)

	entityID := "https://entity.example.com"
	trustMarks := []string{"https://tm1.example.com"}
	entityTypes := []string{"openid_relying_party"}

	// Set a cache entry
	cache.Set(entityID, trustMarks, entityTypes, nil, "https://ta.example.com")

	// Verify entry exists
	entry := cache.Get(entityID, trustMarks, entityTypes)
	if entry == nil {
		t.Error("Cache entry should exist before invalidation")
	}

	// Invalidate the entry
	cache.Invalidate(entityID, trustMarks, entityTypes)

	// Verify entry is removed
	entry = cache.Get(entityID, trustMarks, entityTypes)
	if entry != nil {
		t.Error("Cache entry should be nil after invalidation")
	}
}

// TestCacheExpiration tests that expired cache entries are not returned
func TestCacheExpiration(t *testing.T) {
	cache := NewMetadataCache(10*time.Millisecond, 100) // Very short TTL

	entityID := "https://entity.example.com"

	// Set a cache entry
	cache.Set(entityID, nil, nil, nil, "https://ta.example.com")

	// Entry should exist immediately
	entry := cache.Get(entityID, nil, nil)
	if entry == nil {
		t.Error("Cache entry should exist immediately after set")
	}

	// Wait for expiration
	time.Sleep(20 * time.Millisecond)

	// Entry should be expired
	entry = cache.Get(entityID, nil, nil)
	if entry != nil {
		t.Error("Cache entry should be nil after expiration")
	}
}

// TestCacheClear tests the cache Clear function
func TestCacheClear(t *testing.T) {
	cache := NewMetadataCache(1*time.Hour, 100)

	// Add multiple entries
	for i := 0; i < 5; i++ {
		cache.Set(
			"https://entity"+string(rune('0'+i))+".example.com",
			nil, nil,
			nil,
			"https://ta.example.com",
		)
	}

	// Verify entries exist
	size, _, _ := cache.Stats()
	if size != 5 {
		t.Errorf("Cache size = %d, expected 5", size)
	}

	// Clear cache
	cache.Clear()

	// Verify cache is empty
	size, _, _ = cache.Stats()
	if size != 0 {
		t.Errorf("Cache size after clear = %d, expected 0", size)
	}
}

// TestCacheKeyGeneration tests that different parameters generate different keys
func TestCacheKeyGeneration(t *testing.T) {
	cache := NewMetadataCache(1*time.Hour, 100)

	entityID := "https://entity.example.com"

	// Set entries with different trust marks
	cache.Set(entityID, []string{"tm1"}, nil, nil, "ta1")
	cache.Set(entityID, []string{"tm2"}, nil, nil, "ta2")

	// Each should be a separate entry
	entry1 := cache.Get(entityID, []string{"tm1"}, nil)
	entry2 := cache.Get(entityID, []string{"tm2"}, nil)

	if entry1 == nil || entry2 == nil {
		t.Error("Both cache entries should exist")
	}

	if entry1.TrustAnchorID == entry2.TrustAnchorID {
		t.Error("Different trust marks should result in different cache entries")
	}
}

// TestOIDFedRegistry_SupportsResolutionOnly_True tests that SupportsResolutionOnly returns true
func TestOIDFedRegistry_SupportsResolutionOnly_True(t *testing.T) {
	registry, _ := NewOIDFedRegistry(Config{
		TrustAnchors: []TrustAnchorConfig{
			{EntityID: "https://ta.example.com"},
		},
	})

	if !registry.SupportsResolutionOnly() {
		t.Error("SupportsResolutionOnly() = false, want true")
	}
}

// TestOIDFedRegistry_GetCacheStats tests the GetCacheStats method
func TestOIDFedRegistry_GetCacheStats(t *testing.T) {
	registry, _ := NewOIDFedRegistry(Config{
		TrustAnchors: []TrustAnchorConfig{
			{EntityID: "https://ta.example.com"},
		},
		CacheTTL:     5 * time.Minute,
		MaxCacheSize: 100,
	})

	// Initially empty
	stats := registry.GetCacheStats()
	if stats == nil {
		t.Fatal("GetCacheStats() returned nil")
	}

	entries, ok := stats["entries"].(int)
	if !ok || entries != 0 {
		t.Errorf("Initial cache entries = %v, want 0", stats["entries"])
	}

	// Add some entries via the cache
	registry.cache.Set("https://entity1.example.com", nil, nil, nil, "ta1")
	registry.cache.Set("https://entity2.example.com", nil, nil, nil, "ta2")

	stats = registry.GetCacheStats()
	entries, ok = stats["entries"].(int)
	if !ok || entries != 2 {
		t.Errorf("Cache entries after adds = %v, want 2", stats["entries"])
	}

	// Check TTL is reported
	if _, ok := stats["ttl"]; !ok {
		t.Error("GetCacheStats() should include ttl")
	}

	// Check max_size is reported
	if _, ok := stats["max_size"]; !ok {
		t.Error("GetCacheStats() should include max_size")
	}

	// Check enabled is reported
	if enabled, ok := stats["enabled"].(bool); !ok || !enabled {
		t.Error("GetCacheStats() should report enabled = true")
	}
}

// TestOIDFedRegistry_Evaluate_ResolutionOnlyRequest tests resolution-only evaluation
func TestOIDFedRegistry_Evaluate_ResolutionOnlyRequest(t *testing.T) {
	registry, _ := NewOIDFedRegistry(Config{
		TrustAnchors: []TrustAnchorConfig{
			{EntityID: "https://non-existent-ta.example.com"},
		},
	})

	// Resolution-only request (no key in resource)
	req := &authzen.EvaluationRequest{
		Subject: authzen.Subject{
			Type: "key",
			ID:   "https://entity.example.com",
		},
		Resource: authzen.Resource{
			Type: "entity",
			ID:   "https://entity.example.com",
			Key:  nil, // No key = resolution only
		},
	}

	resp, err := registry.Evaluate(context.Background(), req)
	if err != nil {
		t.Fatalf("Evaluate() error = %v", err)
	}

	// Should fail because entity doesn't exist, but no panic
	if resp == nil {
		t.Fatal("Evaluate() returned nil response")
	}
}

// TestOIDFedRegistry_Evaluate_WithTrustMarksContext tests evaluation with trust marks in context
func TestOIDFedRegistry_Evaluate_WithTrustMarksContext(t *testing.T) {
	registry, _ := NewOIDFedRegistry(Config{
		TrustAnchors: []TrustAnchorConfig{
			{EntityID: "https://non-existent-ta.example.com"},
		},
	})

	req := &authzen.EvaluationRequest{
		Subject: authzen.Subject{
			Type: "key",
			ID:   "https://entity.example.com",
		},
		Resource: authzen.Resource{
			Type: "entity",
			ID:   "https://entity.example.com",
		},
		Context: map[string]interface{}{
			"required_trust_marks": []interface{}{"https://example.com/tm1"},
			"allowed_entity_types": []interface{}{"openid_relying_party"},
			"include_trust_chain":  true,
			"include_certificates": true,
		},
	}

	resp, err := registry.Evaluate(context.Background(), req)
	if err != nil {
		t.Fatalf("Evaluate() error = %v", err)
	}

	// Should fail because entity doesn't exist
	if resp == nil {
		t.Fatal("Evaluate() returned nil response")
	}
}

// TestOIDFedRegistry_RefreshClearsCache tests that Refresh clears the cache
func TestOIDFedRegistry_RefreshClearsCache(t *testing.T) {
	registry, _ := NewOIDFedRegistry(Config{
		TrustAnchors: []TrustAnchorConfig{
			{EntityID: "https://ta.example.com"},
		},
	})

	// Add some cache entries
	registry.cache.Set("https://entity1.example.com", nil, nil, nil, "ta1")
	registry.cache.Set("https://entity2.example.com", nil, nil, nil, "ta2")

	size, _, _ := registry.cache.Stats()
	if size != 2 {
		t.Errorf("Cache size before refresh = %d, want 2", size)
	}

	// Refresh should clear the cache
	err := registry.Refresh(context.Background())
	if err != nil {
		t.Errorf("Refresh() error = %v", err)
	}

	size, _, _ = registry.cache.Stats()
	if size != 0 {
		t.Errorf("Cache size after refresh = %d, want 0", size)
	}
}

// TestOIDFedRegistry_MergeStringSlices tests string slice merging with deduplication.
func TestOIDFedRegistry_MergeStringSlices(t *testing.T) {
	tests := []struct {
		name     string
		a        []string
		b        []string
		expected []string
	}{
		{
			name:     "empty slices",
			a:        []string{},
			b:        []string{},
			expected: []string{},
		},
		{
			name:     "first empty",
			a:        []string{},
			b:        []string{"one", "two"},
			expected: []string{"one", "two"},
		},
		{
			name:     "second empty",
			a:        []string{"one", "two"},
			b:        []string{},
			expected: []string{"one", "two"},
		},
		{
			name:     "no overlap",
			a:        []string{"one", "two"},
			b:        []string{"three", "four"},
			expected: []string{"one", "two", "three", "four"},
		},
		{
			name:     "with duplicates",
			a:        []string{"one", "two"},
			b:        []string{"two", "three"},
			expected: []string{"one", "two", "three"},
		},
		{
			name:     "all duplicates",
			a:        []string{"one", "two"},
			b:        []string{"one", "two"},
			expected: []string{"one", "two"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := mergeStringSlices(tt.a, tt.b)
			if len(result) != len(tt.expected) {
				t.Errorf("mergeStringSlices() length = %d, want %d", len(result), len(tt.expected))
			}
			// Check all expected elements are present
			resultMap := make(map[string]bool)
			for _, s := range result {
				resultMap[s] = true
			}
			for _, s := range tt.expected {
				if !resultMap[s] {
					t.Errorf("mergeStringSlices() missing expected element: %s", s)
				}
			}
		})
	}
}

// TestOIDFedRegistry_GetTrustAnchorID tests the getTrustAnchorID helper.
func TestOIDFedRegistry_GetTrustAnchorID(t *testing.T) {
	registry, _ := NewOIDFedRegistry(Config{
		TrustAnchors: []TrustAnchorConfig{
			{EntityID: "https://ta.example.com"},
		},
	})

	tests := []struct {
		name     string
		chain    oidfed.TrustChain
		expected string
	}{
		{
			name:     "empty chain",
			chain:    oidfed.TrustChain{},
			expected: "",
		},
		{
			name: "single element chain",
			chain: oidfed.TrustChain{
				&oidfed.EntityStatement{
					EntityStatementPayload: oidfed.EntityStatementPayload{
						Issuer:  "https://ta.example.com",
						Subject: "https://ta.example.com",
					},
				},
			},
			expected: "https://ta.example.com",
		},
		{
			name: "multi-element chain",
			chain: oidfed.TrustChain{
				&oidfed.EntityStatement{
					EntityStatementPayload: oidfed.EntityStatementPayload{
						Issuer:  "https://entity.example.com",
						Subject: "https://entity.example.com",
					},
				},
				&oidfed.EntityStatement{
					EntityStatementPayload: oidfed.EntityStatementPayload{
						Issuer:  "https://intermediate.example.com",
						Subject: "https://entity.example.com",
					},
				},
				&oidfed.EntityStatement{
					EntityStatementPayload: oidfed.EntityStatementPayload{
						Issuer:  "https://ta.example.com",
						Subject: "https://ta.example.com",
					},
				},
			},
			expected: "https://ta.example.com",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := registry.getTrustAnchorID(tt.chain)
			if result != tt.expected {
				t.Errorf("getTrustAnchorID() = %v, want %v", result, tt.expected)
			}
		})
	}
}

// TestOIDFedRegistry_ExtractMetadata tests the extractMetadata helper.
func TestOIDFedRegistry_ExtractMetadata(t *testing.T) {
	registry, _ := NewOIDFedRegistry(Config{
		TrustAnchors: []TrustAnchorConfig{
			{EntityID: "https://ta.example.com"},
		},
	})

	tests := []struct {
		name             string
		chain            oidfed.TrustChain
		expectIssuer     string
		expectSubject    string
		expectTrustMarks bool
	}{
		{
			name:         "empty chain",
			chain:        oidfed.TrustChain{},
			expectIssuer: "",
		},
		{
			name: "chain without trust marks",
			chain: oidfed.TrustChain{
				&oidfed.EntityStatement{
					EntityStatementPayload: oidfed.EntityStatementPayload{
						Issuer:  "https://entity.example.com",
						Subject: "https://entity.example.com",
					},
				},
			},
			expectIssuer:     "https://entity.example.com",
			expectSubject:    "https://entity.example.com",
			expectTrustMarks: false,
		},
		{
			name: "chain with trust marks",
			chain: oidfed.TrustChain{
				&oidfed.EntityStatement{
					EntityStatementPayload: oidfed.EntityStatementPayload{
						Issuer:  "https://entity.example.com",
						Subject: "https://entity.example.com",
						TrustMarks: oidfed.TrustMarkInfos{
							{TrustMarkType: "https://example.com/tm1"},
							{TrustMarkType: "https://example.com/tm2"},
						},
					},
				},
			},
			expectIssuer:     "https://entity.example.com",
			expectSubject:    "https://entity.example.com",
			expectTrustMarks: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := registry.extractMetadata(tt.chain)
			if len(tt.chain) == 0 {
				if len(result) != 0 {
					t.Errorf("extractMetadata() for empty chain should return empty map")
				}
				return
			}
			if result["issuer"] != tt.expectIssuer {
				t.Errorf("extractMetadata()['issuer'] = %v, want %v", result["issuer"], tt.expectIssuer)
			}
			if result["subject"] != tt.expectSubject {
				t.Errorf("extractMetadata()['subject'] = %v, want %v", result["subject"], tt.expectSubject)
			}
			if tt.expectTrustMarks {
				if result["trust_marks"] == nil {
					t.Errorf("extractMetadata() should include trust_marks")
				}
			}
		})
	}
}

// TestOIDFedRegistry_CheckTrustMarks tests the checkTrustMarks helper.
func TestOIDFedRegistry_CheckTrustMarks(t *testing.T) {
	tests := []struct {
		name               string
		requiredTrustMarks []string
		chain              oidfed.TrustChain
		expected           bool
	}{
		{
			name:               "no required marks - empty chain",
			requiredTrustMarks: []string{},
			chain:              oidfed.TrustChain{},
			expected:           true,
		},
		{
			name:               "no required marks - with chain",
			requiredTrustMarks: []string{},
			chain: oidfed.TrustChain{
				&oidfed.EntityStatement{
					EntityStatementPayload: oidfed.EntityStatementPayload{
						Issuer:  "https://entity.example.com",
						Subject: "https://entity.example.com",
					},
				},
			},
			expected: true,
		},
		{
			name:               "required marks - empty chain",
			requiredTrustMarks: []string{"https://example.com/tm1"},
			chain:              oidfed.TrustChain{},
			expected:           false,
		},
		{
			name:               "required marks - no trust marks in chain",
			requiredTrustMarks: []string{"https://example.com/tm1"},
			chain: oidfed.TrustChain{
				&oidfed.EntityStatement{
					EntityStatementPayload: oidfed.EntityStatementPayload{
						Issuer:  "https://entity.example.com",
						Subject: "https://entity.example.com",
					},
				},
			},
			expected: false,
		},
		{
			name:               "required marks - all present",
			requiredTrustMarks: []string{"https://example.com/tm1"},
			chain: oidfed.TrustChain{
				&oidfed.EntityStatement{
					EntityStatementPayload: oidfed.EntityStatementPayload{
						Issuer:  "https://entity.example.com",
						Subject: "https://entity.example.com",
						TrustMarks: oidfed.TrustMarkInfos{
							{TrustMarkType: "https://example.com/tm1"},
							{TrustMarkType: "https://example.com/tm2"},
						},
					},
				},
			},
			expected: true,
		},
		{
			name:               "required marks - missing one",
			requiredTrustMarks: []string{"https://example.com/tm1", "https://example.com/tm3"},
			chain: oidfed.TrustChain{
				&oidfed.EntityStatement{
					EntityStatementPayload: oidfed.EntityStatementPayload{
						Issuer:  "https://entity.example.com",
						Subject: "https://entity.example.com",
						TrustMarks: oidfed.TrustMarkInfos{
							{TrustMarkType: "https://example.com/tm1"},
							{TrustMarkType: "https://example.com/tm2"},
						},
					},
				},
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			registry, _ := NewOIDFedRegistry(Config{
				TrustAnchors:       []TrustAnchorConfig{{EntityID: "https://ta.example.com"}},
				RequiredTrustMarks: tt.requiredTrustMarks,
			})
			result := registry.checkTrustMarks(tt.chain)
			if result != tt.expected {
				t.Errorf("checkTrustMarks() = %v, want %v", result, tt.expected)
			}
		})
	}
}

// TestOIDFedRegistry_CheckTrustMarksWithList tests the checkTrustMarksWithList helper.
func TestOIDFedRegistry_CheckTrustMarksWithList(t *testing.T) {
	registry, _ := NewOIDFedRegistry(Config{
		TrustAnchors: []TrustAnchorConfig{{EntityID: "https://ta.example.com"}},
	})

	tests := []struct {
		name          string
		chain         oidfed.TrustChain
		requiredMarks []string
		expected      bool
	}{
		{
			name:          "no required marks",
			chain:         oidfed.TrustChain{},
			requiredMarks: []string{},
			expected:      true,
		},
		{
			name:          "required marks - empty chain",
			chain:         oidfed.TrustChain{},
			requiredMarks: []string{"https://example.com/tm1"},
			expected:      false,
		},
		{
			name: "required marks - all present",
			chain: oidfed.TrustChain{
				&oidfed.EntityStatement{
					EntityStatementPayload: oidfed.EntityStatementPayload{
						Issuer:  "https://entity.example.com",
						Subject: "https://entity.example.com",
						TrustMarks: oidfed.TrustMarkInfos{
							{TrustMarkType: "https://example.com/tm1"},
						},
					},
				},
			},
			requiredMarks: []string{"https://example.com/tm1"},
			expected:      true,
		},
		{
			name: "required marks - missing",
			chain: oidfed.TrustChain{
				&oidfed.EntityStatement{
					EntityStatementPayload: oidfed.EntityStatementPayload{
						Issuer:     "https://entity.example.com",
						Subject:    "https://entity.example.com",
						TrustMarks: oidfed.TrustMarkInfos{},
					},
				},
			},
			requiredMarks: []string{"https://example.com/tm1"},
			expected:      false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := registry.checkTrustMarksWithList(tt.chain, tt.requiredMarks)
			if result != tt.expected {
				t.Errorf("checkTrustMarksWithList() = %v, want %v", result, tt.expected)
			}
		})
	}
}

// TestOIDFedRegistry_GetPresentTrustMarks tests the getPresentTrustMarks helper.
func TestOIDFedRegistry_GetPresentTrustMarks(t *testing.T) {
	registry, _ := NewOIDFedRegistry(Config{
		TrustAnchors: []TrustAnchorConfig{{EntityID: "https://ta.example.com"}},
	})

	tests := []struct {
		name     string
		chain    oidfed.TrustChain
		expected []string
	}{
		{
			name:     "empty chain",
			chain:    oidfed.TrustChain{},
			expected: nil,
		},
		{
			name: "no trust marks",
			chain: oidfed.TrustChain{
				&oidfed.EntityStatement{
					EntityStatementPayload: oidfed.EntityStatementPayload{
						Issuer:  "https://entity.example.com",
						Subject: "https://entity.example.com",
					},
				},
			},
			expected: nil,
		},
		{
			name: "with trust marks",
			chain: oidfed.TrustChain{
				&oidfed.EntityStatement{
					EntityStatementPayload: oidfed.EntityStatementPayload{
						Issuer:  "https://entity.example.com",
						Subject: "https://entity.example.com",
						TrustMarks: oidfed.TrustMarkInfos{
							{TrustMarkType: "https://example.com/tm1"},
							{TrustMarkType: "https://example.com/tm2"},
						},
					},
				},
			},
			expected: []string{"https://example.com/tm1", "https://example.com/tm2"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := registry.getPresentTrustMarks(tt.chain)
			if len(result) != len(tt.expected) {
				t.Errorf("getPresentTrustMarks() length = %d, want %d", len(result), len(tt.expected))
				return
			}
			for i, mark := range result {
				if mark != tt.expected[i] {
					t.Errorf("getPresentTrustMarks()[%d] = %v, want %v", i, mark, tt.expected[i])
				}
			}
		})
	}
}

// TestOIDFedRegistry_BuildTrustChainArray tests the buildTrustChainArray helper.
func TestOIDFedRegistry_BuildTrustChainArray(t *testing.T) {
	registry, _ := NewOIDFedRegistry(Config{
		TrustAnchors: []TrustAnchorConfig{{EntityID: "https://ta.example.com"}},
	})

	now := time.Now()

	tests := []struct {
		name     string
		chain    oidfed.TrustChain
		expected int // number of entries
	}{
		{
			name:     "empty chain",
			chain:    oidfed.TrustChain{},
			expected: 0,
		},
		{
			name: "single element",
			chain: oidfed.TrustChain{
				&oidfed.EntityStatement{
					EntityStatementPayload: oidfed.EntityStatementPayload{
						Issuer:    "https://ta.example.com",
						Subject:   "https://ta.example.com",
						IssuedAt:  unixtime.Unixtime{Time: now},
						ExpiresAt: unixtime.Unixtime{Time: now.Add(time.Hour)},
					},
				},
			},
			expected: 1,
		},
		{
			name: "multi-element",
			chain: oidfed.TrustChain{
				&oidfed.EntityStatement{
					EntityStatementPayload: oidfed.EntityStatementPayload{
						Issuer:  "https://entity.example.com",
						Subject: "https://entity.example.com",
					},
				},
				&oidfed.EntityStatement{
					EntityStatementPayload: oidfed.EntityStatementPayload{
						Issuer:  "https://ta.example.com",
						Subject: "https://ta.example.com",
					},
				},
			},
			expected: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := registry.buildTrustChainArray(tt.chain)
			if len(result) != tt.expected {
				t.Errorf("buildTrustChainArray() length = %d, want %d", len(result), tt.expected)
			}
			for i, entry := range result {
				if entry["iss"] == nil || entry["sub"] == nil {
					t.Errorf("buildTrustChainArray()[%d] missing iss or sub", i)
				}
			}
		})
	}
}

// TestOIDFedRegistry_BuildDetailedTrustChain tests the buildDetailedTrustChain helper.
func TestOIDFedRegistry_BuildDetailedTrustChain(t *testing.T) {
	registry, _ := NewOIDFedRegistry(Config{
		TrustAnchors: []TrustAnchorConfig{{EntityID: "https://ta.example.com"}},
	})

	now := time.Now()

	chain := oidfed.TrustChain{
		&oidfed.EntityStatement{
			EntityStatementPayload: oidfed.EntityStatementPayload{
				Issuer:    "https://entity.example.com",
				Subject:   "https://entity.example.com",
				IssuedAt:  unixtime.Unixtime{Time: now},
				ExpiresAt: unixtime.Unixtime{Time: now.Add(time.Hour)},
				TrustMarks: oidfed.TrustMarkInfos{
					{TrustMarkType: "https://example.com/tm1"},
				},
			},
		},
	}

	result := registry.buildDetailedTrustChain(chain, false)
	if len(result) != 1 {
		t.Fatalf("buildDetailedTrustChain() length = %d, want 1", len(result))
	}

	entry := result[0]
	if entry["iss"] != "https://entity.example.com" {
		t.Errorf("buildDetailedTrustChain()[0]['iss'] = %v, want https://entity.example.com", entry["iss"])
	}
	if entry["trust_marks"] == nil {
		t.Error("buildDetailedTrustChain()[0] should include trust_marks")
	}
}

// TestOIDFedRegistry_ChainToTrustMetadata tests the chainToTrustMetadata helper.
func TestOIDFedRegistry_ChainToTrustMetadata(t *testing.T) {
	registry, _ := NewOIDFedRegistry(Config{
		TrustAnchors: []TrustAnchorConfig{{EntityID: "https://ta.example.com"}},
	})

	tests := []struct {
		name         string
		chain        oidfed.TrustChain
		metadata     map[string]interface{}
		expectNil    bool
		expectIss    string
		expectSub    string
		expectAnchor string
	}{
		{
			name:      "empty chain",
			chain:     oidfed.TrustChain{},
			metadata:  nil,
			expectNil: true,
		},
		{
			name: "single element",
			chain: oidfed.TrustChain{
				&oidfed.EntityStatement{
					EntityStatementPayload: oidfed.EntityStatementPayload{
						Issuer:  "https://ta.example.com",
						Subject: "https://ta.example.com",
					},
				},
			},
			metadata:     map[string]interface{}{"key": "value"},
			expectNil:    false,
			expectIss:    "https://ta.example.com",
			expectSub:    "https://ta.example.com",
			expectAnchor: "https://ta.example.com",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := registry.chainToTrustMetadata(tt.chain, tt.metadata)
			if tt.expectNil {
				if result != nil {
					t.Errorf("chainToTrustMetadata() should return nil for empty chain")
				}
				return
			}
			if result == nil {
				t.Fatalf("chainToTrustMetadata() returned nil, want non-nil")
			}
			if result["iss"] != tt.expectIss {
				t.Errorf("chainToTrustMetadata()['iss'] = %v, want %v", result["iss"], tt.expectIss)
			}
			if result["sub"] != tt.expectSub {
				t.Errorf("chainToTrustMetadata()['sub'] = %v, want %v", result["sub"], tt.expectSub)
			}
			if result["trust_anchor"] != tt.expectAnchor {
				t.Errorf("chainToTrustMetadata()['trust_anchor'] = %v, want %v", result["trust_anchor"], tt.expectAnchor)
			}
		})
	}
}

// TestOIDFedRegistry_BuildResolutionOnlyResponse tests the buildResolutionOnlyResponse helper.
func TestOIDFedRegistry_BuildResolutionOnlyResponse(t *testing.T) {
	registry, _ := NewOIDFedRegistry(Config{
		TrustAnchors: []TrustAnchorConfig{{EntityID: "https://ta.example.com"}},
	})

	chain := oidfed.TrustChain{
		&oidfed.EntityStatement{
			EntityStatementPayload: oidfed.EntityStatementPayload{
				Issuer:  "https://entity.example.com",
				Subject: "https://entity.example.com",
			},
		},
		&oidfed.EntityStatement{
			EntityStatementPayload: oidfed.EntityStatementPayload{
				Issuer:  "https://ta.example.com",
				Subject: "https://ta.example.com",
			},
		},
	}

	metadata := map[string]interface{}{"key": "value"}
	result := registry.buildResolutionOnlyResponse("https://entity.example.com", chain, metadata)

	if !result.Decision {
		t.Error("buildResolutionOnlyResponse() Decision should be true")
	}
	if result.Context == nil {
		t.Fatal("buildResolutionOnlyResponse() Context should not be nil")
	}
	if result.Context.Reason == nil {
		t.Fatal("buildResolutionOnlyResponse() Reason should not be nil")
	}
	if result.Context.Reason["resolution_only"] != true {
		t.Error("buildResolutionOnlyResponse() Reason['resolution_only'] should be true")
	}
	if result.Context.Reason["entity_id"] != "https://entity.example.com" {
		t.Errorf("buildResolutionOnlyResponse() Reason['entity_id'] = %v, want https://entity.example.com", result.Context.Reason["entity_id"])
	}
}

// TestOIDFedRegistry_BuildTrustMetadata tests the buildTrustMetadata helper.
func TestOIDFedRegistry_BuildTrustMetadata(t *testing.T) {
	registry, _ := NewOIDFedRegistry(Config{
		TrustAnchors: []TrustAnchorConfig{{EntityID: "https://ta.example.com"}},
	})

	now := time.Now()

	tests := []struct {
		name              string
		chain             oidfed.TrustChain
		includeTrustChain bool
		includeCerts      bool
		expectNil         bool
	}{
		{
			name:      "empty chain",
			chain:     oidfed.TrustChain{},
			expectNil: true,
		},
		{
			name: "basic chain",
			chain: oidfed.TrustChain{
				&oidfed.EntityStatement{
					EntityStatementPayload: oidfed.EntityStatementPayload{
						Issuer:    "https://entity.example.com",
						Subject:   "https://entity.example.com",
						IssuedAt:  unixtime.Unixtime{Time: now},
						ExpiresAt: unixtime.Unixtime{Time: now.Add(time.Hour)},
					},
				},
			},
			includeTrustChain: false,
			includeCerts:      false,
			expectNil:         false,
		},
		{
			name: "with trust chain",
			chain: oidfed.TrustChain{
				&oidfed.EntityStatement{
					EntityStatementPayload: oidfed.EntityStatementPayload{
						Issuer:    "https://entity.example.com",
						Subject:   "https://entity.example.com",
						IssuedAt:  unixtime.Unixtime{Time: now},
						ExpiresAt: unixtime.Unixtime{Time: now.Add(time.Hour)},
					},
				},
			},
			includeTrustChain: true,
			includeCerts:      false,
			expectNil:         false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := registry.buildTrustMetadata(tt.chain, "https://entity.example.com", tt.includeTrustChain, tt.includeCerts, now, nil)
			if tt.expectNil {
				if result != nil {
					t.Error("buildTrustMetadata() should return nil for empty chain")
				}
				return
			}
			if result == nil {
				t.Fatal("buildTrustMetadata() returned nil, want non-nil")
			}
			if result["entity_id"] != "https://entity.example.com" {
				t.Errorf("buildTrustMetadata()['entity_id'] = %v, want https://entity.example.com", result["entity_id"])
			}
			if tt.includeTrustChain {
				if result["trust_chain"] == nil {
					t.Error("buildTrustMetadata() should include trust_chain when requested")
				}
			} else {
				if result["trust_chain_length"] == nil {
					t.Error("buildTrustMetadata() should include trust_chain_length when trust_chain not requested")
				}
			}
		})
	}
}

// TestOIDFedRegistry_JwksToMap tests the jwksToMap helper.
func TestOIDFedRegistry_JwksToMap(t *testing.T) {
	registry, _ := NewOIDFedRegistry(Config{
		TrustAnchors: []TrustAnchorConfig{{EntityID: "https://ta.example.com"}},
	})

	// Test with nil JWKS
	nilJWKS := oidfedjwx.JWKS{}
	result := registry.jwksToMap(nilJWKS)
	if result != nil {
		t.Errorf("jwksToMap(nil) should return nil, got %v", result)
	}
}

// TestOIDFedRegistry_CertificatesToArray tests the certificatesToArray helper.
func TestOIDFedRegistry_CertificatesToArray(t *testing.T) {
	registry, _ := NewOIDFedRegistry(Config{
		TrustAnchors: []TrustAnchorConfig{{EntityID: "https://ta.example.com"}},
	})

	// Test with empty certs
	result := registry.certificatesToArray([]*x509.Certificate{})
	if len(result) != 0 {
		t.Errorf("certificatesToArray([]) should return empty array, got %d elements", len(result))
	}

	// Test with a real certificate
	cert := &x509.Certificate{
		Subject: pkix.Name{
			CommonName: "Test Entity",
		},
		Issuer: pkix.Name{
			CommonName: "Test CA",
		},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		SerialNumber: big.NewInt(12345),
		DNSNames:     []string{"example.com", "www.example.com"},
	}

	result = registry.certificatesToArray([]*x509.Certificate{cert})
	if len(result) != 1 {
		t.Fatalf("certificatesToArray() should return 1 element, got %d", len(result))
	}
	if result[0]["serial"] == nil {
		t.Error("certificatesToArray() should include serial")
	}
	if result[0]["dns_names"] == nil {
		t.Error("certificatesToArray() should include dns_names")
	}
}

// TestOIDFedRegistry_ExtractCertificates tests the extractCertificates helper.
func TestOIDFedRegistry_ExtractCertificates(t *testing.T) {
	registry, _ := NewOIDFedRegistry(Config{
		TrustAnchors: []TrustAnchorConfig{{EntityID: "https://ta.example.com"}},
	})

	// Test with empty chain
	certs := registry.extractCertificates(oidfed.TrustChain{})
	if len(certs) != 0 {
		t.Errorf("extractCertificates([]) should return empty, got %d", len(certs))
	}

	// Test with chain without JWKS
	chain := oidfed.TrustChain{
		&oidfed.EntityStatement{
			EntityStatementPayload: oidfed.EntityStatementPayload{
				Issuer:  "https://entity.example.com",
				Subject: "https://entity.example.com",
			},
		},
	}
	certs = registry.extractCertificates(chain)
	if len(certs) != 0 {
		t.Errorf("extractCertificates() with no JWKS should return empty, got %d", len(certs))
	}
}

// TestExtractCredentialTypeTrustMarks tests the credential type to trust marks mapping extraction.
func TestExtractCredentialTypeTrustMarks(t *testing.T) {
	tests := []struct {
		name     string
		context  map[string]interface{}
		expected map[string][]string
	}{
		{
			name:     "nil context",
			context:  nil,
			expected: nil,
		},
		{
			name:     "no mapping",
			context:  map[string]interface{}{},
			expected: nil,
		},
		{
			name: "direct map[string][]string",
			context: map[string]interface{}{
				ContextKeyCredentialTypeTrustMarks: map[string][]string{
					"eu.europa.ec.eudi.pid.1": {"https://trust.eu/pid-issuer"},
				},
			},
			expected: map[string][]string{
				"eu.europa.ec.eudi.pid.1": {"https://trust.eu/pid-issuer"},
			},
		},
		{
			name: "JSON-unmarshaled map[string]interface{}",
			context: map[string]interface{}{
				ContextKeyCredentialTypeTrustMarks: map[string]interface{}{
					"eu.europa.ec.eudi.pid.1": []interface{}{"https://trust.eu/pid-issuer", "https://trust.eu/pid-issuer-v2"},
				},
			},
			expected: map[string][]string{
				"eu.europa.ec.eudi.pid.1": {"https://trust.eu/pid-issuer", "https://trust.eu/pid-issuer-v2"},
			},
		},
		{
			name: "multiple credential types",
			context: map[string]interface{}{
				ContextKeyCredentialTypeTrustMarks: map[string][]string{
					"eu.europa.ec.eudi.pid.1": {"https://trust.eu/pid-issuer"},
					"eu.europa.ec.eudi.mdl.1": {"https://trust.eu/mdl-issuer"},
				},
			},
			expected: map[string][]string{
				"eu.europa.ec.eudi.pid.1": {"https://trust.eu/pid-issuer"},
				"eu.europa.ec.eudi.mdl.1": {"https://trust.eu/mdl-issuer"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := extractCredentialTypeTrustMarks(tt.context)
			if tt.expected == nil {
				if result != nil {
					t.Errorf("expected nil, got %v", result)
				}
				return
			}
			if len(result) != len(tt.expected) {
				t.Errorf("expected %d entries, got %d", len(tt.expected), len(result))
			}
			for k, v := range tt.expected {
				if got, ok := result[k]; !ok {
					t.Errorf("expected key %s not found", k)
				} else if !equalStringSlices(got, v) {
					t.Errorf("for key %s: expected %v, got %v", k, v, got)
				}
			}
		})
	}
}

// TestExtractConstraintsFromContext_CredentialTypeTrustMarkDerivation tests that trust marks
// are derived from credential_types when a mapping is present.
func TestExtractConstraintsFromContext_CredentialTypeTrustMarkDerivation(t *testing.T) {
	registry, _ := NewOIDFedRegistry(Config{
		TrustAnchors: []TrustAnchorConfig{{EntityID: "https://ta.example.com"}},
	})

	tests := []struct {
		name           string
		context        map[string]interface{}
		wantTrustMarks []string
		wantCredTypes  []string
	}{
		{
			name: "credential_types with no mapping",
			context: map[string]interface{}{
				ContextKeyCredentialTypes: []string{"eu.europa.ec.eudi.pid.1"},
			},
			wantTrustMarks: nil, // Registry has no default trust marks
			wantCredTypes:  []string{"eu.europa.ec.eudi.pid.1"},
		},
		{
			name: "credential_types with mapping derives trust marks",
			context: map[string]interface{}{
				ContextKeyCredentialTypes: []string{"eu.europa.ec.eudi.pid.1"},
				ContextKeyCredentialTypeTrustMarks: map[string][]string{
					"eu.europa.ec.eudi.pid.1": {"https://trust.eu/pid-issuer"},
				},
			},
			wantTrustMarks: []string{"https://trust.eu/pid-issuer"},
			wantCredTypes:  []string{"eu.europa.ec.eudi.pid.1"},
		},
		{
			name: "multiple credential_types derive multiple trust marks",
			context: map[string]interface{}{
				ContextKeyCredentialTypes: []string{"eu.europa.ec.eudi.pid.1", "eu.europa.ec.eudi.mdl.1"},
				ContextKeyCredentialTypeTrustMarks: map[string][]string{
					"eu.europa.ec.eudi.pid.1": {"https://trust.eu/pid-issuer"},
					"eu.europa.ec.eudi.mdl.1": {"https://trust.eu/mdl-issuer"},
				},
			},
			wantTrustMarks: []string{"https://trust.eu/pid-issuer", "https://trust.eu/mdl-issuer"},
			wantCredTypes:  []string{"eu.europa.ec.eudi.pid.1", "eu.europa.ec.eudi.mdl.1"},
		},
		{
			name: "credential_type without mapping entry is ignored for trust marks",
			context: map[string]interface{}{
				ContextKeyCredentialTypes: []string{"eu.europa.ec.eudi.pid.1", "unknown.vct"},
				ContextKeyCredentialTypeTrustMarks: map[string][]string{
					"eu.europa.ec.eudi.pid.1": {"https://trust.eu/pid-issuer"},
					// unknown.vct has no mapping
				},
			},
			wantTrustMarks: []string{"https://trust.eu/pid-issuer"},
			wantCredTypes:  []string{"eu.europa.ec.eudi.pid.1", "unknown.vct"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := &authzen.EvaluationRequest{
				Subject:  authzen.Subject{Type: "key", ID: "https://entity.example.com"},
				Resource: authzen.Resource{ID: "https://entity.example.com"},
				Context:  tt.context,
			}

			trustMarks, _, credentialTypes, _, _, _ := registry.extractConstraintsFromContext(req)

			if !equalStringSlices(credentialTypes, tt.wantCredTypes) {
				t.Errorf("credentialTypes = %v, want %v", credentialTypes, tt.wantCredTypes)
			}

			// For trust marks, check they contain expected values (order may vary due to merging)
			if tt.wantTrustMarks == nil {
				if len(trustMarks) != 0 {
					t.Errorf("expected no trust marks, got %v", trustMarks)
				}
			} else {
				for _, expected := range tt.wantTrustMarks {
					found := false
					for _, got := range trustMarks {
						if got == expected {
							found = true
							break
						}
					}
					if !found {
						t.Errorf("expected trust mark %s not found in %v", expected, trustMarks)
					}
				}
			}
		})
	}
}
