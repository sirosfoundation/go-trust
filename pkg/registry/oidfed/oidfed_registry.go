// Package oidfed implements a TrustRegistry using OpenID Federation for trust chain validation.
//
// This package provides an implementation of the TrustRegistry interface for OpenID Federation.
// It supports trust chain resolution, trust mark and entity type filtering, and metadata caching.
//
// Key features:
//   - Configurable trust anchors (with optional explicit JWKS)
//   - Required trust marks and entity type filters (default and per-request)
//   - Metadata caching with configurable TTL and size
//   - Trust chain inspection and certificate inclusion in responses
//   - Integration with AuthZEN for policy-based trust evaluation
package oidfed

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	oidfed "github.com/go-oidfed/lib"
	oidfedjwx "github.com/go-oidfed/lib/jwx"
	"github.com/sirosfoundation/go-cryptoutil"
	"github.com/sirosfoundation/go-trust/pkg/authzen"
	"github.com/sirosfoundation/go-trust/pkg/registry"
)

// CacheEntry represents a cached trust chain resolution result.
// It stores the resolved trust chains, the entity ID, the time of resolution,
// expiration, and the trust anchor used.
type CacheEntry struct {
	EntityID      string
	Chains        []oidfed.TrustChain
	ResolvedAt    time.Time
	ExpiresAt     time.Time
	TrustAnchorID string
}

// MetadataCache provides caching for OpenID Federation metadata and trust chains.
// It supports TTL-based expiration and a maximum size with simple eviction.
type MetadataCache struct {
	entries map[string]*CacheEntry
	mu      sync.RWMutex
	ttl     time.Duration
	maxSize int
}

// NewMetadataCache creates a new MetadataCache for OpenID Federation metadata and trust chains.
// If ttl or maxSize are zero, sensible defaults are used (5 minutes, 1000 entries).
func NewMetadataCache(ttl time.Duration, maxSize int) *MetadataCache {
	if ttl == 0 {
		ttl = 5 * time.Minute // Default 5 minute TTL
	}
	if maxSize == 0 {
		maxSize = 1000 // Default max 1000 entries
	}
	return &MetadataCache{
		entries: make(map[string]*CacheEntry),
		ttl:     ttl,
		maxSize: maxSize,
	}
}

// cacheKey generates a cache key from entity ID, trust marks, and entity types.
func (c *MetadataCache) cacheKey(entityID string, trustMarks, entityTypes []string) string {
	h := sha256.New()
	h.Write([]byte(entityID))
	for _, tm := range trustMarks {
		h.Write([]byte("|tm:" + tm))
	}
	for _, et := range entityTypes {
		h.Write([]byte("|et:" + et))
	}
	return hex.EncodeToString(h.Sum(nil))[:32]
}

// Get retrieves a cached entry for the given entity and constraints if it exists and is not expired.
func (c *MetadataCache) Get(entityID string, trustMarks, entityTypes []string) *CacheEntry {
	c.mu.RLock()
	defer c.mu.RUnlock()

	key := c.cacheKey(entityID, trustMarks, entityTypes)
	entry, ok := c.entries[key]
	if !ok {
		return nil
	}

	if time.Now().After(entry.ExpiresAt) {
		return nil // Expired
	}

	return entry
}

// Set stores a cache entry for the given entity and constraints, evicting oldest entries if needed.
func (c *MetadataCache) Set(entityID string, trustMarks, entityTypes []string, chains []oidfed.TrustChain, trustAnchorID string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Simple eviction: if at max size, remove oldest entries
	if len(c.entries) >= c.maxSize {
		c.evictOldest()
	}

	key := c.cacheKey(entityID, trustMarks, entityTypes)
	now := time.Now()
	c.entries[key] = &CacheEntry{
		EntityID:      entityID,
		Chains:        chains,
		ResolvedAt:    now,
		ExpiresAt:     now.Add(c.ttl),
		TrustAnchorID: trustAnchorID,
	}
}

// evictOldest removes the oldest 10% of entries from the cache, or expired entries if present.
func (c *MetadataCache) evictOldest() {
	if len(c.entries) == 0 {
		return
	}

	// Remove 10% of entries (oldest first)
	toRemove := len(c.entries) / 10
	if toRemove < 1 {
		toRemove = 1
	}

	// Simple approach: remove expired + some oldest
	removed := 0
	now := time.Now()
	for k, v := range c.entries {
		if now.After(v.ExpiresAt) || removed < toRemove {
			delete(c.entries, k)
			removed++
		}
	}
}

// Invalidate removes a specific entry from the cache for the given entity and constraints.
func (c *MetadataCache) Invalidate(entityID string, trustMarks, entityTypes []string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	key := c.cacheKey(entityID, trustMarks, entityTypes)
	delete(c.entries, key)
}

// Clear removes all entries from the cache.
func (c *MetadataCache) Clear() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries = make(map[string]*CacheEntry)
}

// Stats returns cache statistics: current size, hits, and misses (hits/misses not yet tracked).
func (c *MetadataCache) Stats() (size int, hits int, misses int) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.entries), 0, 0 // TODO: track hits/misses
}

// OIDFedRegistry implements a TrustRegistry using OpenID Federation.
//
// It resolves trust chains from entities to configured trust anchors and
// evaluates them against AuthZEN access evaluation requests. The registry supports:
//   - Configurable trust anchors with optional explicit JWKS
//   - Required trust marks (configured and/or per-request via context)
//   - Entity type filtering (configured and/or per-request via context)
//   - Metadata caching with configurable TTL and size
//   - Trust chain and certificate inspection in responses
//   - Resolution-only mode for metadata retrieval
type OIDFedRegistry struct {
	// trustAnchors is the set of configured OpenID Federation trust anchors.
	trustAnchors oidfed.TrustAnchors
	// requiredTrustMarks is the default set of required trust marks (can be overridden per request).
	requiredTrustMarks []string
	// entityTypes is the default set of allowed entity types (can be overridden per request).
	entityTypes []string
	// description is a human-readable description of this registry instance.
	description string
	// cache is the metadata and trust chain cache (may be nil for no caching).
	cache *MetadataCache
	// maxChainDepth is the maximum trust chain resolution depth.
	maxChainDepth int
	// cryptoExt provides extensible certificate parsing for non-standard curves.
	cryptoExt *cryptoutil.Extensions
}

// Config holds configuration for creating an OIDFedRegistry.
//
// Fields:
//   - TrustAnchors: List of trust anchor configs (entity ID and optional JWKS)
//   - RequiredTrustMarks: Default required trust marks (can be overridden per request)
//   - EntityTypes: Default entity types to filter (can be overridden per request)
//   - Description: Human-readable description
//   - CacheTTL: Duration to cache resolved trust chains (default: 5 minutes)
//   - MaxCacheSize: Maximum number of cache entries (default: 1000)
//   - MaxChainDepth: Maximum trust chain resolution depth (default: 10)
type Config struct {
	// TrustAnchors defines the federation trust anchors
	TrustAnchors []TrustAnchorConfig `json:"trust_anchors"`

	// RequiredTrustMarks is an optional list of trust mark types that must be present
	// These are the default requirements; requests can specify additional requirements
	RequiredTrustMarks []string `json:"required_trust_marks,omitempty"`

	// EntityTypes filters entities by type (e.g., "openid_provider", "openid_relying_party")
	// These are the default filters; requests can specify additional/different filters
	EntityTypes []string `json:"entity_types,omitempty"`

	// Description of this registry instance
	Description string `json:"description,omitempty"`

	// CacheTTL is the duration to cache resolved trust chains (default: 5 minutes)
	CacheTTL time.Duration `json:"cache_ttl,omitempty"`

	// MaxCacheSize is the maximum number of cache entries (default: 1000)
	MaxCacheSize int `json:"max_cache_size,omitempty"`

	// MaxChainDepth is the maximum trust chain resolution depth (default: 10)
	MaxChainDepth int `json:"max_chain_depth,omitempty"`

	// CryptoExt provides extensible certificate parsing for non-standard curves
	// (e.g. brainpool). If nil, standard x509.ParseCertificate is used.
	CryptoExt *cryptoutil.Extensions `json:"-"`
}

// TrustAnchorConfig defines a single trust anchor for OpenID Federation.
type TrustAnchorConfig struct {
	// EntityID is the entity identifier (URL) of the trust anchor
	EntityID string `json:"entity_id"`

	// JWKS is an optional explicit JWKS for the trust anchor
	// If not provided, it will be fetched from the entity configuration
	JWKS *oidfedjwx.JWKS `json:"jwks,omitempty"`
}

// NewOIDFedRegistry creates a new OIDFedRegistry for OpenID Federation trust chain validation.
// Returns an error if no trust anchors are configured or if any trust anchor is missing an entity ID.
func NewOIDFedRegistry(config Config) (*OIDFedRegistry, error) {
	if len(config.TrustAnchors) == 0 {
		return nil, fmt.Errorf("at least one trust anchor must be configured")
	}

	trustAnchors := make(oidfed.TrustAnchors, len(config.TrustAnchors))
	for i, ta := range config.TrustAnchors {
		if ta.EntityID == "" {
			return nil, fmt.Errorf("trust anchor %d: entity_id is required", i)
		}

		anchor := oidfed.TrustAnchor{
			EntityID: ta.EntityID,
		}
		if ta.JWKS != nil {
			anchor.JWKS = *ta.JWKS
		}
		trustAnchors[i] = anchor
	}

	description := config.Description
	if description == "" {
		description = fmt.Sprintf("OpenID Federation Registry with %d trust anchor(s)", len(trustAnchors))
	}

	maxChainDepth := config.MaxChainDepth
	if maxChainDepth == 0 {
		maxChainDepth = 10
	}

	return &OIDFedRegistry{
		trustAnchors:       trustAnchors,
		requiredTrustMarks: config.RequiredTrustMarks,
		entityTypes:        config.EntityTypes,
		description:        description,
		cache:              NewMetadataCache(config.CacheTTL, config.MaxCacheSize),
		maxChainDepth:      maxChainDepth,
		cryptoExt:          config.CryptoExt,
	}, nil
}

// Name returns the registry name.
func (r *OIDFedRegistry) Name() string {
	return "oidfed-registry"
}

// Description returns a human-readable description of the registry instance.
func (r *OIDFedRegistry) Description() string {
	return r.description
}

// SupportedResourceTypes returns the resource types this registry can evaluate.
// OpenID Federation works with entity identifiers (URLs), so we look for
// entity_id in the resource or subject properties.
func (r *OIDFedRegistry) SupportedResourceTypes() []string {
	// OpenID Federation can work with various resource types
	// as long as they can be mapped to entity identifiers
	return []string{
		"entity",
		"openid_provider",
		"relying_party",
		"oauth_client",
		"oauth_server",
		"federation_entity",
		"jwk", // Can validate JWK against entity JWKS
		"x5c", // Can validate x5c against entity JWKS certificates
	}
}

// SupportsResolutionOnly returns true for OpenID Federation registry.
// The registry supports resolution-only requests where clients can
// retrieve entity configurations and trust chain metadata without
// validating a specific key binding.
func (r *OIDFedRegistry) SupportsResolutionOnly() bool {
	return true
}

// extractConstraintsFromContext extracts OIDF-specific constraints from request context.
// Returns merged constraints from both registry defaults and request context.
func (r *OIDFedRegistry) extractConstraintsFromContext(req *authzen.EvaluationRequest) (trustMarks, entityTypes, credentialTypes []string, includeTrustChain, includeCerts bool, maxDepth int) {
	// Start with registry defaults
	trustMarks = append([]string{}, r.requiredTrustMarks...)
	entityTypes = append([]string{}, r.entityTypes...)
	maxDepth = r.maxChainDepth

	if req.Context == nil {
		return
	}

	// Merge trust marks from request context
	if reqTrustMarks, ok := req.Context[ContextKeyRequiredTrustMarks]; ok {
		switch v := reqTrustMarks.(type) {
		case []string:
			trustMarks = mergeStringSlices(trustMarks, v)
		case []interface{}:
			for _, tm := range v {
				if tmStr, ok := tm.(string); ok {
					trustMarks = mergeStringSlices(trustMarks, []string{tmStr})
				}
			}
		}
	}

	// Override entity types from request context (replace, not merge)
	if reqEntityTypes, ok := req.Context[ContextKeyAllowedEntityTypes]; ok {
		switch v := reqEntityTypes.(type) {
		case []string:
			entityTypes = v
		case []interface{}:
			entityTypes = make([]string, 0, len(v))
			for _, et := range v {
				if etStr, ok := et.(string); ok {
					entityTypes = append(entityTypes, etStr)
				}
			}
		}
	}

	// Include trust chain in response?
	if v, ok := req.Context[ContextKeyIncludeTrustChain].(bool); ok {
		includeTrustChain = v
	}

	// Include certificates in response?
	if v, ok := req.Context[ContextKeyIncludeCertificates].(bool); ok {
		includeCerts = v
	}

	// Max chain depth
	if v, ok := req.Context[ContextKeyMaxChainDepth].(int); ok && v > 0 {
		maxDepth = v
	}
	if v, ok := req.Context[ContextKeyMaxChainDepth].(float64); ok && v > 0 {
		maxDepth = int(v)
	}

	// Extract credential_types from request context
	if reqCredentialTypes, ok := req.Context[ContextKeyCredentialTypes]; ok {
		switch v := reqCredentialTypes.(type) {
		case []string:
			credentialTypes = v
		case []interface{}:
			for _, ct := range v {
				if ctStr, ok := ct.(string); ok {
					credentialTypes = append(credentialTypes, ctStr)
				}
			}
		}
	}

	// If credential_types are specified and we have a mapping, derive additional trust marks
	if len(credentialTypes) > 0 {
		ctTrustMarks := extractCredentialTypeTrustMarks(req.Context)
		if len(ctTrustMarks) > 0 {
			for _, ct := range credentialTypes {
				if tms, ok := ctTrustMarks[ct]; ok {
					trustMarks = mergeStringSlices(trustMarks, tms)
				}
			}
		}
	}

	return
}

// extractCredentialTypeTrustMarks extracts the VCT→trust mark mapping from context.
func extractCredentialTypeTrustMarks(ctx map[string]interface{}) map[string][]string {
	if ctx == nil {
		return nil
	}
	v, ok := ctx[ContextKeyCredentialTypeTrustMarks]
	if !ok {
		return nil
	}

	// Handle map[string][]string directly
	if m, ok := v.(map[string][]string); ok {
		return m
	}

	// Handle JSON-unmarshaled map[string]interface{}
	if m, ok := v.(map[string]interface{}); ok {
		result := make(map[string][]string)
		for k, val := range m {
			switch tms := val.(type) {
			case []string:
				result[k] = tms
			case []interface{}:
				strs := make([]string, 0, len(tms))
				for _, tm := range tms {
					if s, ok := tm.(string); ok {
						strs = append(strs, s)
					}
				}
				if len(strs) > 0 {
					result[k] = strs
				}
			}
		}
		return result
	}

	return nil
}

// shouldBypassCache checks if the request wants to bypass cache.
func (r *OIDFedRegistry) shouldBypassCache(req *authzen.EvaluationRequest) bool {
	if req.Context == nil {
		return false
	}

	if cc, ok := req.Context[ContextKeyCacheControl].(string); ok {
		return cc == "no-cache" || cc == "no-store"
	}
	return false
}

// Evaluate performs an AuthZEN access evaluation using OpenID Federation trust chains.
// For resolution-only requests (where IsResolutionOnlyRequest() returns true), the method
// returns decision=true with the entity configuration in trust_metadata, without validating
// a specific key binding.
//
// The method supports request context parameters for:
// - required_trust_marks: Additional trust marks that must be present
// - allowed_entity_types: Override entity type filter
// - include_trust_chain: Include full trust chain in response
// - include_certificates: Include X.509 certificates in response
// - max_chain_depth: Limit trust chain resolution depth
// - cache_control: Control caching behavior
// - credential_types: Credential type identifiers for audit/filtering
func (r *OIDFedRegistry) Evaluate(ctx context.Context, req *authzen.EvaluationRequest) (*authzen.EvaluationResponse, error) {
	// Extract entity ID from the request
	entityID, err := r.extractEntityID(req)
	if err != nil {
		return &authzen.EvaluationResponse{
			Decision: false,
			Context: &authzen.EvaluationResponseContext{
				Reason: map[string]interface{}{
					"message": "unable to extract entity ID from request",
					"error":   err.Error(),
				},
			},
		}, nil
	}

	// Extract constraints from request context
	trustMarks, entityTypes, credentialTypes, includeTrustChain, includeCerts, _ := r.extractConstraintsFromContext(req)
	bypassCache := r.shouldBypassCache(req)

	// Check cache first (unless bypassed)
	var chains []oidfed.TrustChain
	var cacheEntry *CacheEntry
	now := time.Now()

	if !bypassCache && r.cache != nil {
		cacheEntry = r.cache.Get(entityID, trustMarks, entityTypes)
		if cacheEntry != nil {
			chains = cacheEntry.Chains
		}
	}

	// Resolve trust chains if not cached
	if chains == nil {
		resolver := &oidfed.TrustResolver{
			StartingEntity: entityID,
			TrustAnchors:   r.trustAnchors,
			Types:          entityTypes,
		}

		chains = resolver.ResolveToValidChains()

		// Cache the result
		if len(chains) > 0 && r.cache != nil {
			r.cache.Set(entityID, trustMarks, entityTypes, chains, r.getTrustAnchorID(chains[0]))
		}
	}

	if len(chains) == 0 {
		return &authzen.EvaluationResponse{
			Decision: false,
			Context: &authzen.EvaluationResponseContext{
				Reason: map[string]interface{}{
					"message":      "no valid trust chain found",
					"entity_id":    entityID,
					"entity_types": entityTypes,
				},
			},
		}, nil
	}

	// Select the best chain (first valid chain for now)
	chain := chains[0]

	// Check required trust marks
	if len(trustMarks) > 0 {
		if !r.checkTrustMarksWithList(chain, trustMarks) {
			reason := map[string]interface{}{
				"message":              "required trust marks not present",
				"entity_id":            entityID,
				"required_trust_marks": trustMarks,
				"present_trust_marks":  r.getPresentTrustMarks(chain),
			}
			// Include credential_types if they contributed to the trust mark requirements
			if len(credentialTypes) > 0 {
				reason["requested_credential_types"] = credentialTypes
				reason["credential_type_validation"] = "trust marks derived from credential_types are missing"
			}
			return &authzen.EvaluationResponse{
				Decision: false,
				Context: &authzen.EvaluationResponseContext{
					Reason: reason,
				},
			}, nil
		}
	}

	// Build response metadata
	trustMetadata := r.buildTrustMetadata(chain, entityID, includeTrustChain, includeCerts, now, cacheEntry)

	// Check if this is a resolution-only request
	if req.IsResolutionOnlyRequest() {
		reason := map[string]interface{}{
			"message":            "resolution successful",
			"entity_id":          entityID,
			"resolution_only":    true,
			"trust_chain_length": len(chain),
			"trust_anchor":       r.getTrustAnchorID(chain),
		}
		if len(credentialTypes) > 0 {
			reason["requested_credential_types"] = credentialTypes
			// Check if credential_type validation was performed
			if ctTrustMarks := extractCredentialTypeTrustMarks(req.Context); len(ctTrustMarks) > 0 {
				reason["credential_type_validation"] = "validated"
			}
		}
		return &authzen.EvaluationResponse{
			Decision: true,
			Context: &authzen.EvaluationResponseContext{
				Reason:        reason,
				TrustMetadata: trustMetadata,
			},
		}, nil
	}

	// For full evaluation, check key binding if provided
	matched, matchDetails, err := r.verifyKeyBinding(req, chain)
	if err != nil {
		return &authzen.EvaluationResponse{
			Decision: false,
			Context: &authzen.EvaluationResponseContext{
				Reason: map[string]interface{}{
					"message":   "key binding verification failed",
					"entity_id": entityID,
					"error":     err.Error(),
				},
				TrustMetadata: trustMetadata,
			},
		}, nil
	}

	if !matched {
		return &authzen.EvaluationResponse{
			Decision: false,
			Context: &authzen.EvaluationResponseContext{
				Reason: map[string]interface{}{
					"message":            "key does not match any key in entity JWKS",
					"entity_id":          entityID,
					"trust_chain_length": len(chain),
					"trust_anchor":       r.getTrustAnchorID(chain),
				},
				TrustMetadata: trustMetadata,
			},
		}, nil
	}

	reasonData := map[string]interface{}{
		"entity_id":          entityID,
		"trust_chain_length": len(chain),
		"trust_anchor":       r.getTrustAnchorID(chain),
		"key_binding":        matchDetails,
	}
	if len(credentialTypes) > 0 {
		reasonData["requested_credential_types"] = credentialTypes
		// Check if credential_type validation was performed
		if ctTrustMarks := extractCredentialTypeTrustMarks(req.Context); len(ctTrustMarks) > 0 {
			reasonData["credential_type_validation"] = "validated"
		}
	}

	return &authzen.EvaluationResponse{
		Decision: true,
		Context: &authzen.EvaluationResponseContext{
			Reason:        reasonData,
			TrustMetadata: trustMetadata,
		},
	}, nil
}

// verifyKeyBinding checks if the key in the request matches a key in the entity's JWKS.
// Returns (matched, matchDetails, error).
func (r *OIDFedRegistry) verifyKeyBinding(req *authzen.EvaluationRequest, chain oidfed.TrustChain) (bool, map[string]interface{}, error) {
	if len(chain) == 0 {
		return false, nil, fmt.Errorf("empty trust chain")
	}

	leafStatement := chain[0]
	if leafStatement.JWKS.Set == nil || leafStatement.JWKS.Len() == 0 {
		return false, nil, fmt.Errorf("entity has no JWKS")
	}

	if len(req.Resource.Key) == 0 {
		return false, nil, fmt.Errorf("resource.key is empty")
	}

	// Extract the request key as a JWK map
	requestJWK, ok := req.Resource.Key[0].(map[string]interface{})
	if !ok {
		return false, nil, fmt.Errorf("resource.key[0] must be a JWK object")
	}

	// Compare against each key in the entity's JWKS
	for i := 0; i < leafStatement.JWKS.Len(); i++ {
		key, keyOk := leafStatement.JWKS.Key(i)
		if !keyOk {
			continue
		}

		// Serialize the JWKS key to JSON, then parse as map for comparison
		entityJWK, err := jwkKeyToMap(key)
		if err != nil {
			continue
		}

		if registry.JWKsMatch(requestJWK, entityJWK) {
			details := map[string]interface{}{
				"matched":  true,
				"key_type": entityJWK["kty"],
			}
			if kid, kidOk := entityJWK["kid"].(string); kidOk {
				details["kid"] = kid
			}
			return true, details, nil
		}
	}

	return false, nil, nil
}

// jwkKeyToMap serializes a jwk.Key to a map[string]interface{} for comparison.
func jwkKeyToMap(key interface{}) (map[string]interface{}, error) {
	data, err := json.Marshal(key)
	if err != nil {
		return nil, err
	}
	var m map[string]interface{}
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, err
	}
	return m, nil
}

// Info returns metadata about this registry instance, including trust anchors.
func (r *OIDFedRegistry) Info() registry.RegistryInfo {
	return registry.RegistryInfo{
		Name:         r.Name(),
		Type:         "openid_federation",
		Description:  r.description,
		TrustAnchors: r.getTrustAnchorEntityIDs(),
	}
}

// Healthy returns true if the registry is operational (i.e., has at least one trust anchor).
func (r *OIDFedRegistry) Healthy() bool {
	// OpenID Federation registry is healthy as long as it's configured
	return len(r.trustAnchors) > 0
}

// Refresh triggers an update of cached data.
// For OpenID Federation, this clears the local metadata cache and lets
// the go-oidfed/lib handle re-resolution on the next request.
func (r *OIDFedRegistry) Refresh(ctx context.Context) error {
	// Clear local metadata cache
	if r.cache != nil {
		r.cache.Clear()
	}
	return nil
}

// GetCacheStats returns statistics about the metadata cache.
func (r *OIDFedRegistry) GetCacheStats() map[string]interface{} {
	if r.cache == nil {
		return map[string]interface{}{
			"enabled": false,
		}
	}

	r.cache.mu.RLock()
	defer r.cache.mu.RUnlock()

	return map[string]interface{}{
		"enabled":  true,
		"entries":  len(r.cache.entries),
		"max_size": r.cache.maxSize,
		"ttl":      r.cache.ttl.String(),
	}
}

// mergeStringSlices merges two string slices, eliminating duplicates.
func mergeStringSlices(a, b []string) []string {
	seen := make(map[string]struct{})
	result := make([]string, 0, len(a)+len(b))

	for _, s := range a {
		if _, ok := seen[s]; !ok {
			seen[s] = struct{}{}
			result = append(result, s)
		}
	}
	for _, s := range b {
		if _, ok := seen[s]; !ok {
			seen[s] = struct{}{}
			result = append(result, s)
		}
	}
	return result
}

// checkTrustMarksWithList verifies that all specified trust marks are present in the trust chain.
func (r *OIDFedRegistry) checkTrustMarksWithList(chain oidfed.TrustChain, requiredMarks []string) bool {
	if len(requiredMarks) == 0 {
		return true
	}

	// Get trust marks from the leaf entity (first in chain)
	if len(chain) == 0 || chain[0].TrustMarks == nil {
		return false
	}

	foundMarks := make(map[string]bool)
	for _, tm := range chain[0].TrustMarks {
		foundMarks[tm.TrustMarkType] = true
	}

	// Check all required marks are present
	for _, required := range requiredMarks {
		if !foundMarks[required] {
			return false
		}
	}

	return true
}

// getPresentTrustMarks returns a list of trust mark types present in the chain.
func (r *OIDFedRegistry) getPresentTrustMarks(chain oidfed.TrustChain) []string {
	if len(chain) == 0 || chain[0].TrustMarks == nil {
		return nil
	}

	marks := make([]string, len(chain[0].TrustMarks))
	for i, tm := range chain[0].TrustMarks {
		marks[i] = tm.TrustMarkType
	}
	return marks
}

// buildTrustMetadata builds the trust_metadata for a response.
func (r *OIDFedRegistry) buildTrustMetadata(chain oidfed.TrustChain, entityID string, includeTrustChain, includeCerts bool, evaluatedAt time.Time, cached *CacheEntry) map[string]interface{} {
	if len(chain) == 0 {
		return nil
	}

	leafStatement := chain[0]
	metadata := r.extractMetadata(chain)

	trustMeta := map[string]interface{}{
		"iss":          leafStatement.Issuer,
		"sub":          leafStatement.Subject,
		"entity_id":    entityID,
		"metadata":     metadata,
		"trust_anchor": r.getTrustAnchorID(chain),
		"evaluated_at": evaluatedAt.Format(time.RFC3339),
	}

	// Include issued_at and expires_at
	if !leafStatement.IssuedAt.IsZero() {
		trustMeta["iat"] = leafStatement.IssuedAt.Unix()
	}
	if !leafStatement.ExpiresAt.IsZero() {
		trustMeta["exp"] = leafStatement.ExpiresAt.Unix()
	}

	// Include cache info if relevant
	if cached != nil {
		trustMeta["cached"] = true
		trustMeta["cache_expires_at"] = cached.ExpiresAt.Format(time.RFC3339)
	}

	// Include JWKS keys summary if available
	if leafStatement.JWKS.Set != nil && leafStatement.JWKS.Len() > 0 {
		trustMeta["jwks"] = r.jwksToMap(leafStatement.JWKS)
	}

	// Include full trust chain if requested
	if includeTrustChain {
		trustMeta["trust_chain"] = r.buildDetailedTrustChain(chain, includeCerts)
	} else {
		trustMeta["trust_chain_length"] = len(chain)
	}

	// Include certificates if requested
	if includeCerts {
		certs := r.extractCertificates(chain)
		if len(certs) > 0 {
			trustMeta["certificates"] = r.certificatesToArray(certs)
		}
	}

	return trustMeta
}

// buildDetailedTrustChain builds a detailed trust chain representation.
func (r *OIDFedRegistry) buildDetailedTrustChain(chain oidfed.TrustChain, includeCerts bool) []map[string]interface{} {
	chainArray := make([]map[string]interface{}, len(chain))
	for i, stmt := range chain {
		stmtMap := map[string]interface{}{
			"iss": stmt.Issuer,
			"sub": stmt.Subject,
		}
		if !stmt.IssuedAt.IsZero() {
			stmtMap["iat"] = stmt.IssuedAt.Unix()
		}
		if !stmt.ExpiresAt.IsZero() {
			stmtMap["exp"] = stmt.ExpiresAt.Unix()
		}

		// Include trust marks if present
		if len(stmt.TrustMarks) > 0 {
			marks := make([]map[string]interface{}, len(stmt.TrustMarks))
			for j, tm := range stmt.TrustMarks {
				marks[j] = map[string]interface{}{
					"id": tm.TrustMarkType,
				}
			}
			stmtMap["trust_marks"] = marks
		}

		// Include entity types if metadata available
		if stmt.Metadata != nil {
			types := stmt.Metadata.GuessEntityTypes()
			if len(types) > 0 {
				stmtMap["entity_types"] = types
			}
		}

		chainArray[i] = stmtMap
	}
	return chainArray
}

// certificatesToArray converts X.509 certificates to an array of maps.
func (r *OIDFedRegistry) certificatesToArray(certs []*x509.Certificate) []map[string]interface{} {
	result := make([]map[string]interface{}, len(certs))
	for i, cert := range certs {
		result[i] = map[string]interface{}{
			"subject":    cert.Subject.String(),
			"issuer":     cert.Issuer.String(),
			"not_before": cert.NotBefore.Format(time.RFC3339),
			"not_after":  cert.NotAfter.Format(time.RFC3339),
			"serial":     cert.SerialNumber.String(),
		}
		if len(cert.DNSNames) > 0 {
			result[i]["dns_names"] = cert.DNSNames
		}
		if len(cert.URIs) > 0 {
			uris := make([]string, len(cert.URIs))
			for j, u := range cert.URIs {
				uris[j] = u.String()
			}
			result[i]["uris"] = uris
		}
	}
	return result
}

// extractEntityID extracts the entity identifier from the request.
// It checks subject.entity_id, resource.entity_id, subject.id, or resource.id.
func (r *OIDFedRegistry) extractEntityID(req *authzen.EvaluationRequest) (string, error) {
	// Try subject.entity_id or subject.id first
	if req.Subject.Type == "key" && req.Subject.ID != "" {
		// Check if ID looks like a URL (entity identifier)
		if strings.HasPrefix(req.Subject.ID, "http://") || strings.HasPrefix(req.Subject.ID, "https://") {
			return req.Subject.ID, nil
		}
	}

	// Try resource.entity_id or resource.id
	if req.Resource.ID != "" {
		if strings.HasPrefix(req.Resource.ID, "http://") || strings.HasPrefix(req.Resource.ID, "https://") {
			return req.Resource.ID, nil
		}
	}

	return "", fmt.Errorf("no entity_id found in request subject or resource")
}

// checkTrustMarks verifies that all required trust marks are present in the trust chain.
func (r *OIDFedRegistry) checkTrustMarks(chain oidfed.TrustChain) bool {
	if len(r.requiredTrustMarks) == 0 {
		return true
	}

	// Get trust marks from the leaf entity (first in chain)
	if len(chain) == 0 || chain[0].TrustMarks == nil {
		return false
	}

	trustMarks := chain[0].TrustMarks
	foundMarks := make(map[string]bool)

	for _, tm := range trustMarks {
		foundMarks[tm.TrustMarkType] = true
	}

	// Check all required marks are present
	for _, required := range r.requiredTrustMarks {
		if !foundMarks[required] {
			return false
		}
	}

	return true
}

// extractMetadata extracts useful metadata from the trust chain.
func (r *OIDFedRegistry) extractMetadata(chain oidfed.TrustChain) map[string]interface{} {
	metadata := make(map[string]interface{})

	if len(chain) == 0 {
		return metadata
	}

	leaf := chain[0]

	// Add entity types if metadata is present
	if leaf.Metadata != nil {
		entityTypes := leaf.Metadata.GuessEntityTypes()
		if len(entityTypes) > 0 {
			metadata["entity_types"] = entityTypes
		}
	}

	// Add trust marks
	if len(leaf.TrustMarks) > 0 {
		trustMarkTypes := make([]string, len(leaf.TrustMarks))
		for i, tm := range leaf.TrustMarks {
			trustMarkTypes[i] = tm.TrustMarkType
		}
		metadata["trust_marks"] = trustMarkTypes
	}

	// Add issuer and subject
	metadata["issuer"] = leaf.Issuer
	metadata["subject"] = leaf.Subject

	// Add expiration time
	metadata["expires_at"] = leaf.ExpiresAt.Format(time.RFC3339)

	return metadata
}

// extractCertificates extracts X.509 certificates from the JWKS in the trust chain.
func (r *OIDFedRegistry) extractCertificates(chain oidfed.TrustChain) []*x509.Certificate {
	var certificates []*x509.Certificate

	for _, stmt := range chain {
		if stmt.JWKS.Set == nil {
			continue
		}

		// Iterate through keys in the JWKS
		for i := 0; i < stmt.JWKS.Len(); i++ {
			key, ok := stmt.JWKS.Key(i)
			if !ok {
				continue
			}

			// Extract x5c chain if present (returns [][]byte)
			certChain, ok := key.X509CertChain()
			if !ok {
				continue
			}
			for j := 0; j < certChain.Len(); j++ {
				certBytes, ok := certChain.Get(j)
				if !ok {
					continue
				}
				// Parse the DER-encoded certificate
				cert, err := registry.ParseCertificate(certBytes, r.cryptoExt)
				if err == nil && cert != nil {
					certificates = append(certificates, cert)
				}
			}
		}
	}

	return certificates
}

// getTrustAnchorID returns the entity ID of the trust anchor for this chain.
func (r *OIDFedRegistry) getTrustAnchorID(chain oidfed.TrustChain) string {
	if len(chain) == 0 {
		return ""
	}

	// The last entity in the chain is the trust anchor
	return chain[len(chain)-1].Subject
}

// buildResolutionOnlyResponse creates an EvaluationResponse for resolution-only requests.
// The response includes decision=true and the entity configuration in trust_metadata.
func (r *OIDFedRegistry) buildResolutionOnlyResponse(entityID string, chain oidfed.TrustChain, metadata map[string]interface{}) *authzen.EvaluationResponse {
	return &authzen.EvaluationResponse{
		Decision: true,
		Context: &authzen.EvaluationResponseContext{
			Reason: map[string]interface{}{
				"entity_id":          entityID,
				"resolution_only":    true,
				"trust_chain_length": len(chain),
				"trust_anchor":       r.getTrustAnchorID(chain),
			},
			TrustMetadata: r.chainToTrustMetadata(chain, metadata),
		},
	}
}

// chainToTrustMetadata converts a trust chain and metadata to the trust_metadata format.
// This returns an OpenID Federation entity configuration structure.
func (r *OIDFedRegistry) chainToTrustMetadata(chain oidfed.TrustChain, metadata map[string]interface{}) map[string]interface{} {
	if len(chain) == 0 {
		return nil
	}

	// The first statement in the chain is the leaf entity's configuration
	leafStatement := chain[0]

	trustMeta := map[string]interface{}{
		"iss":          leafStatement.Issuer,
		"sub":          leafStatement.Subject,
		"metadata":     metadata,
		"trust_chain":  r.buildTrustChainArray(chain),
		"trust_anchor": r.getTrustAnchorID(chain),
	}

	// Include issued_at and expires_at
	if !leafStatement.IssuedAt.IsZero() {
		trustMeta["iat"] = leafStatement.IssuedAt.Unix()
	}
	if !leafStatement.ExpiresAt.IsZero() {
		trustMeta["exp"] = leafStatement.ExpiresAt.Unix()
	}

	// Include JWKS keys summary if available
	if leafStatement.JWKS.Set != nil && leafStatement.JWKS.Len() > 0 {
		trustMeta["jwks"] = r.jwksToMap(leafStatement.JWKS)
	}

	return trustMeta
}

// buildTrustChainArray converts the trust chain to an array of entity statements.
func (r *OIDFedRegistry) buildTrustChainArray(chain oidfed.TrustChain) []map[string]interface{} {
	chainArray := make([]map[string]interface{}, len(chain))
	for i, stmt := range chain {
		stmtMap := map[string]interface{}{
			"iss": stmt.Issuer,
			"sub": stmt.Subject,
		}
		if !stmt.IssuedAt.IsZero() {
			stmtMap["iat"] = stmt.IssuedAt.Unix()
		}
		if !stmt.ExpiresAt.IsZero() {
			stmtMap["exp"] = stmt.ExpiresAt.Unix()
		}
		chainArray[i] = stmtMap
	}
	return chainArray
}

// jwksToMap converts a JWKS to a map representation.
func (r *OIDFedRegistry) jwksToMap(jwks oidfedjwx.JWKS) map[string]interface{} {
	if jwks.Set == nil {
		return nil
	}

	keys := make([]map[string]interface{}, 0)
	for i := 0; i < jwks.Len(); i++ {
		key, ok := jwks.Key(i)
		if !ok {
			continue
		}

		keyMap := map[string]interface{}{
			"kty": key.KeyType().String(),
		}

		// Add key ID if present
		if kid, ok := key.KeyID(); ok && kid != "" {
			keyMap["kid"] = kid
		}

		// Add algorithm if present
		if alg, ok := key.Algorithm(); ok && alg.String() != "" {
			keyMap["alg"] = alg.String()
		}

		// Add use if present
		if use, ok := key.KeyUsage(); ok && use != "" {
			keyMap["use"] = use
		}

		keys = append(keys, keyMap)
	}

	return map[string]interface{}{
		"keys": keys,
	}
}

// getTrustAnchorEntityIDs returns a list of configured trust anchor entity IDs.
func (r *OIDFedRegistry) getTrustAnchorEntityIDs() []string {
	ids := make([]string, len(r.trustAnchors))
	for i, ta := range r.trustAnchors {
		ids[i] = ta.EntityID
	}
	return ids
}
