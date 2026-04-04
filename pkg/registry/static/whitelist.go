// Package static provides simple static trust registries.
package static

import (
	"context"
	"crypto"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
	"gopkg.in/yaml.v3"

	"github.com/sirosfoundation/go-trust/pkg/authzen"
	"github.com/sirosfoundation/go-trust/pkg/registry"
)

// DefaultRefreshInterval is the default JWKS refresh interval when none is configured.
// This ensures keys are always periodically refreshed for security.
const DefaultRefreshInterval = 5 * time.Minute

// WhitelistRegistry is a TrustRegistry that maintains a whitelist of trusted subjects
// and validates name-to-key bindings by fetching and caching entity JWKS.
//
// Unlike simple URL-based whitelisting, this registry:
// 1. Resolves each whitelisted entity's JWKS endpoint
// 2. Extracts and normalizes public keys
// 3. Computes SHA-256 fingerprints for each key
// 4. Validates that incoming request keys match a whitelisted entity's keys
type WhitelistRegistry struct {
	name        string
	description string

	mu     sync.RWMutex
	config WhitelistConfig

	// resolvedLists is the merged view of Lists + legacy Issuers/Verifiers/TrustedSubjects.
	// Key is list name, value is list of entity IDs/patterns.
	resolvedLists map[string][]string

	// resolvedActions maps action name -> list name.
	resolvedActions map[string]string

	// keyHashes maps entity ID to a set of allowed key fingerprints.
	// Each entity can have multiple keys (key rotation, different purposes).
	keyHashes map[string]map[string]bool

	// HTTP client for fetching JWKS
	httpClient *http.Client

	// File watching
	configPath string
	watcher    *fsnotify.Watcher
	stopCh     chan struct{}
	stopOnce   sync.Once // guards Close of stopCh
	logger     *slog.Logger

	// Track refresh state for health reporting.
	// keysLoaded is true only when the most recent refresh loaded keys
	// for ALL configured entities without errors.
	keysLoaded  bool
	lastRefresh time.Time

	// Background refresh
	refreshInterval time.Duration
	refreshStopCh   chan struct{}
	refreshOnce     sync.Once // guards Close of refreshStopCh
}

// WhitelistConfig holds the whitelist configuration.
type WhitelistConfig struct {
	// Lists is a map of named entity lists. Each key is a list name and the
	// value is a slice of entity URLs/identifiers (supports wildcards).
	// Use together with Actions to map action names to lists.
	Lists map[string][]string `json:"lists,omitempty" yaml:"lists,omitempty"`

	// Actions maps action names (from request action.name) to list names.
	// For example: {"pid-provider": "pid-issuers", "verifier": "verifiers"}
	Actions map[string]string `json:"actions,omitempty" yaml:"actions,omitempty"`

	// --- Legacy fields (backward compatible) ---
	// When Lists/Actions are not set, these are used to build implicit lists.
	// Legacy "issuers" maps to actions: issuer, credential-issuer, pid-provider.
	// Legacy "verifiers" maps to actions: verifier, credential-verifier.

	// Issuers is a list of trusted credential issuer URLs/identifiers.
	Issuers []string `json:"issuers,omitempty" yaml:"issuers,omitempty"`

	// Verifiers is a list of trusted verifier URLs/identifiers.
	Verifiers []string `json:"verifiers,omitempty" yaml:"verifiers,omitempty"`

	// TrustedSubjects is a catch-all for subjects that should be trusted
	// regardless of role. This is checked if no action-specific list matches.
	TrustedSubjects []string `json:"trusted_subjects,omitempty" yaml:"trusted_subjects,omitempty"`

	// JWKSEndpointPattern specifies an explicit URL pattern for fetching JWKS.
	// When set, metadata discovery is skipped and this pattern is used directly.
	// Use {entity} as placeholder for the entity URL.
	//
	// When empty (default), the registry tries standard metadata discovery first:
	//   1. {entity}/.well-known/jwt-vc-issuer              (SD-JWT VC §5.3, RFC 8615)
	//   2. {entity}/.well-known/oauth-authorization-server  (RFC 8414)
	//   3. {entity}/.well-known/openid-configuration        (OIDC Discovery)
	//   4. {entity}/.well-known/openid-credential-issuer    (OpenID4VCI)
	// and falls back to {entity}/.well-known/jwks.json if no jwks_uri is found.
	JWKSEndpointPattern string `json:"jwks_endpoint_pattern,omitempty" yaml:"jwks_endpoint_pattern,omitempty"`

	// FetchTimeout is the timeout for fetching JWKS (default: 30s).
	FetchTimeout string `json:"fetch_timeout,omitempty" yaml:"fetch_timeout,omitempty"`

	// AllowHTTP allows fetching JWKS over HTTP (default: false, requires HTTPS).
	AllowHTTP bool `json:"allow_http,omitempty" yaml:"allow_http,omitempty"`

	// RefreshInterval specifies how often to refresh JWKS keys.
	// Default: 5m (5 minutes). Set to "0" to disable background refresh.
	// Example: "5m", "1h", "30s"
	RefreshInterval string `json:"refresh_interval,omitempty" yaml:"refresh_interval,omitempty"`
}

// WhitelistOption is a functional option for configuring WhitelistRegistry.
type WhitelistOption func(*WhitelistRegistry)

// WithWhitelistName sets the registry name.
func WithWhitelistName(name string) WhitelistOption {
	return func(r *WhitelistRegistry) {
		r.name = name
	}
}

// WithWhitelistDescription sets the registry description.
func WithWhitelistDescription(desc string) WhitelistOption {
	return func(r *WhitelistRegistry) {
		r.description = desc
	}
}

// WithWhitelistConfig sets the initial configuration.
func WithWhitelistConfig(cfg WhitelistConfig) WhitelistOption {
	return func(r *WhitelistRegistry) {
		r.config = cfg
	}
}

// WithWhitelistLogger sets the logger for file watch events.
func WithWhitelistLogger(logger *slog.Logger) WhitelistOption {
	return func(r *WhitelistRegistry) {
		r.logger = logger
	}
}

// WithHTTPClient sets a custom HTTP client for JWKS fetching.
func WithHTTPClient(client *http.Client) WhitelistOption {
	return func(r *WhitelistRegistry) {
		r.httpClient = client
	}
}

// WithRefreshInterval sets the background refresh interval for JWKS keys.
// If set to 0 (default), no background refresh is performed.
func WithRefreshInterval(interval time.Duration) WhitelistOption {
	return func(r *WhitelistRegistry) {
		r.refreshInterval = interval
	}
}

// NewWhitelistRegistry creates a new whitelist registry.
func NewWhitelistRegistry(opts ...WhitelistOption) *WhitelistRegistry {
	r := &WhitelistRegistry{
		name:        "whitelist",
		description: "Key-binding whitelist for trusted issuers and verifiers",
		config:      WhitelistConfig{},
		logger:      slog.Default(),
		keyHashes:   make(map[string]map[string]bool),
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}

	for _, opt := range opts {
		opt(r)
	}

	r.resolveConfig()

	return r
}

// resolveConfig builds the resolved lists and action mappings from the config.
// It merges the new Lists/Actions format with legacy Issuers/Verifiers/TrustedSubjects.
func (r *WhitelistRegistry) resolveConfig() {
	r.resolvedLists = make(map[string][]string)
	r.resolvedActions = make(map[string]string)

	// Copy explicit lists
	for name, entries := range r.config.Lists {
		r.resolvedLists[name] = entries
	}

	// Copy explicit action mappings
	for action, listName := range r.config.Actions {
		r.resolvedActions[strings.ToLower(action)] = listName
	}

	// Merge legacy issuers into resolved lists and default action mappings
	if len(r.config.Issuers) > 0 {
		r.resolvedLists["issuers"] = appendUnique(r.resolvedLists["issuers"], r.config.Issuers)
		// Only add default mappings if not already explicitly configured
		for _, action := range []string{"issuer", "credential-issuer", "pid-provider", "issue"} {
			if _, exists := r.resolvedActions[action]; !exists {
				r.resolvedActions[action] = "issuers"
			}
		}
	}

	// Merge legacy verifiers
	if len(r.config.Verifiers) > 0 {
		r.resolvedLists["verifiers"] = appendUnique(r.resolvedLists["verifiers"], r.config.Verifiers)
		for _, action := range []string{"verifier", "credential-verifier", "verify"} {
			if _, exists := r.resolvedActions[action]; !exists {
				r.resolvedActions[action] = "verifiers"
			}
		}
	}

	// Merge legacy trusted_subjects
	if len(r.config.TrustedSubjects) > 0 {
		r.resolvedLists["trusted_subjects"] = appendUnique(r.resolvedLists["trusted_subjects"], r.config.TrustedSubjects)
	}
}

// appendUnique appends items to a slice, skipping duplicates.
func appendUnique(existing, items []string) []string {
	seen := make(map[string]bool, len(existing))
	for _, e := range existing {
		seen[e] = true
	}
	for _, item := range items {
		if !seen[item] {
			existing = append(existing, item)
			seen[item] = true
		}
	}
	return existing
}

// NewWhitelistRegistryFromFile creates a whitelist registry from a config file.
// Supports JSON and YAML formats (detected by file extension).
// If watch is true, the registry will monitor the file for changes and reload automatically.
func NewWhitelistRegistryFromFile(path string, watch bool, opts ...WhitelistOption) (*WhitelistRegistry, error) {
	absPath, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("resolving path: %w", err)
	}

	cfg, err := loadWhitelistConfig(absPath)
	if err != nil {
		return nil, err
	}

	opts = append(opts, WithWhitelistConfig(cfg))
	r := NewWhitelistRegistry(opts...)
	r.configPath = absPath

	if watch {
		if err := r.startWatching(); err != nil {
			return nil, fmt.Errorf("starting file watcher: %w", err)
		}
	}

	return r, nil
}

// loadWhitelistConfig loads configuration from a file.
func loadWhitelistConfig(path string) (WhitelistConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return WhitelistConfig{}, fmt.Errorf("reading whitelist config: %w", err)
	}

	var cfg WhitelistConfig
	if strings.HasSuffix(path, ".yaml") || strings.HasSuffix(path, ".yml") {
		if err := yaml.Unmarshal(data, &cfg); err != nil {
			return WhitelistConfig{}, fmt.Errorf("parsing YAML config: %w", err)
		}
	} else {
		if err := json.Unmarshal(data, &cfg); err != nil {
			return WhitelistConfig{}, fmt.Errorf("parsing JSON config: %w", err)
		}
	}

	return cfg, nil
}

// startWatching begins monitoring the config file for changes.
func (r *WhitelistRegistry) startWatching() error {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return fmt.Errorf("creating watcher: %w", err)
	}

	// Watch the directory containing the config file (handles atomic renames)
	dir := filepath.Dir(r.configPath)
	if err := watcher.Add(dir); err != nil {
		_ = watcher.Close() // Best effort cleanup on error path
		return fmt.Errorf("watching directory %s: %w", dir, err)
	}

	r.watcher = watcher
	r.stopCh = make(chan struct{})

	// Capture references for the goroutine to avoid races with Close()
	stopCh := r.stopCh
	events := watcher.Events
	errors := watcher.Errors
	go r.watchLoop(stopCh, events, errors)

	r.logger.Info("started watching config file", "path", r.configPath)
	return nil
}

// watchLoop handles file system events.
// The channels are passed as arguments to avoid data races with Close().
func (r *WhitelistRegistry) watchLoop(stopCh <-chan struct{}, events <-chan fsnotify.Event, errors <-chan error) {
	for {
		select {
		case <-stopCh:
			return
		case event, ok := <-events:
			if !ok {
				return
			}
			// Check if this event is for our config file
			if filepath.Clean(event.Name) != r.configPath {
				continue
			}
			// Reload on write or create (create handles atomic replace via rename)
			if event.Op&(fsnotify.Write|fsnotify.Create) != 0 {
				r.logger.Info("config file changed, reloading", "path", r.configPath, "op", event.Op.String())
				if err := r.reloadConfig(); err != nil {
					r.logger.Error("failed to reload config", "error", err)
				}
			}
		case err, ok := <-errors:
			if !ok {
				return
			}
			r.logger.Error("file watcher error", "error", err)
		}
	}
}

// reloadConfig reloads the configuration from the file.
func (r *WhitelistRegistry) reloadConfig() error {
	cfg, err := loadWhitelistConfig(r.configPath)
	if err != nil {
		return err
	}

	r.mu.Lock()
	r.config = cfg
	r.resolveConfig()
	r.mu.Unlock()

	r.logger.Info("config reloaded",
		"lists", len(r.resolvedLists),
		"actions", len(r.resolvedActions))
	return nil
}

// Close stops the file watcher, refresh loop, and releases resources.
func (r *WhitelistRegistry) Close() error {
	// Use sync.Once to safely close channels without data races.
	// The goroutines reading from these channels will see the close
	// and exit cleanly.
	r.stopOnce.Do(func() {
		if r.stopCh != nil {
			close(r.stopCh)
		}
	})
	r.refreshOnce.Do(func() {
		if r.refreshStopCh != nil {
			close(r.refreshStopCh)
		}
	})

	r.mu.Lock()
	defer r.mu.Unlock()

	if r.watcher != nil {
		err := r.watcher.Close()
		r.watcher = nil
		return err
	}
	return nil
}

// StartRefreshLoop starts a background goroutine that periodically refreshes JWKS keys.
// This should be called after creation if background refresh is desired.
// The loop runs until Close() is called.
func (r *WhitelistRegistry) StartRefreshLoop(ctx context.Context) error {
	// Parse refresh interval from config if not set via option
	if r.refreshInterval == 0 && r.config.RefreshInterval != "" {
		duration, err := time.ParseDuration(r.config.RefreshInterval)
		if err != nil {
			return fmt.Errorf("invalid refresh_interval %q: %w", r.config.RefreshInterval, err)
		}
		r.refreshInterval = duration
	}

	// Apply default refresh interval if not explicitly configured
	if r.refreshInterval == 0 {
		r.refreshInterval = DefaultRefreshInterval
	}

	// Always perform initial refresh to load JWKS keys on startup
	if err := r.Refresh(ctx); err != nil {
		r.logger.Warn("initial refresh failed", "error", err)
		// Continue anyway - keys may be fetched later via background loop
	}

	// Start background loop - capture channel reference to avoid races with Close()
	r.refreshStopCh = make(chan struct{})
	stopCh := r.refreshStopCh
	go r.refreshLoop(stopCh)

	r.logger.Info("started JWKS refresh loop", "interval", r.refreshInterval)
	return nil
}

// refreshLoop periodically refreshes JWKS keys.
// The stopCh is passed as argument to avoid data races with Close().
func (r *WhitelistRegistry) refreshLoop(stopCh <-chan struct{}) {
	ticker := time.NewTicker(r.refreshInterval)
	defer ticker.Stop()

	for {
		select {
		case <-stopCh:
			r.logger.Info("stopping JWKS refresh loop")
			return
		case <-ticker.C:
			ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
			if err := r.Refresh(ctx); err != nil {
				r.logger.Warn("scheduled refresh failed", "error", err)
			} else {
				r.logger.Debug("scheduled refresh completed",
					"entities", len(r.keyHashes),
					"total_keys", r.countTotalKeys())
			}
			cancel()
		}
	}
}

// Evaluate checks if the name-to-key binding is trusted.
// The subject ID must be in the whitelist AND the provided key must match
// one of the entity's registered keys (fetched from their JWKS endpoint).
func (r *WhitelistRegistry) Evaluate(ctx context.Context, req *authzen.EvaluationRequest) (*authzen.EvaluationResponse, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	subjectID := req.Subject.ID
	role := r.extractRole(req)

	// Look up which list this action maps to
	var matchedList string
	var inWhitelist bool

	if listName, ok := r.resolvedActions[role]; ok {
		if entries, ok := r.resolvedLists[listName]; ok {
			if r.matchesList(subjectID, entries) {
				inWhitelist = true
				matchedList = listName
			}
		}
	}

	// Fall back to trusted_subjects catch-all
	if !inWhitelist {
		if entries, ok := r.resolvedLists["trusted_subjects"]; ok {
			if r.matchesList(subjectID, entries) {
				inWhitelist = true
				matchedList = "trusted_subjects"
			}
		}
	}

	if !inWhitelist {
		return r.deny(subjectID, fmt.Sprintf("subject not in whitelist for action '%s'", role))
	}

	// If this is a resolution-only request (no key provided), allow based on whitelist membership
	if req.IsResolutionOnlyRequest() {
		return r.allowResolutionOnly(subjectID, role, matchedList)
	}

	// Verify key binding: extract the key from the request and check against cached hashes
	keyFingerprint, err := r.extractKeyFingerprint(req)
	if err != nil {
		return r.deny(subjectID, fmt.Sprintf("failed to extract key: %s", err))
	}

	// Check if the key fingerprint matches any of the entity's registered keys
	allowedKeys, hasKeys := r.keyHashes[subjectID]
	if !hasKeys || len(allowedKeys) == 0 {
		// No keys cached for this entity - need to refresh
		return r.deny(subjectID, "no keys cached for entity; call Refresh() to load keys")
	}

	if allowedKeys[keyFingerprint] {
		return r.allowWithKey(subjectID, role, matchedList, keyFingerprint)
	}

	return r.deny(subjectID, "key fingerprint does not match any registered keys for this entity")
}

// extractKeyFingerprint extracts and computes fingerprint of the key from the request.
func (r *WhitelistRegistry) extractKeyFingerprint(req *authzen.EvaluationRequest) (string, error) {
	pubKey, err := ExtractPublicKeyFromRequest(req.Resource.Type, req.Resource.Key)
	if err != nil {
		return "", fmt.Errorf("extracting public key: %w", err)
	}

	fingerprint, err := KeyFingerprint(pubKey)
	if err != nil {
		return "", fmt.Errorf("computing fingerprint: %w", err)
	}

	return fingerprint, nil
}

// extractRole extracts the role from the request action.
func (r *WhitelistRegistry) extractRole(req *authzen.EvaluationRequest) string {
	if req.Action != nil && req.Action.Name != "" {
		return strings.ToLower(req.Action.Name)
	}
	return "any"
}

// matchesList checks if subject matches any entry in the list.
// Supports exact match and prefix match (entries ending with *).
func (r *WhitelistRegistry) matchesList(subject string, list []string) bool {
	for _, entry := range list {
		if entry == "*" {
			return true // Wildcard matches all
		}
		if strings.HasSuffix(entry, "*") {
			prefix := strings.TrimSuffix(entry, "*")
			if strings.HasPrefix(subject, prefix) {
				return true
			}
		} else if entry == subject {
			return true
		}
	}
	return false
}

func (r *WhitelistRegistry) allowWithKey(subject, role, matchedList, keyFingerprint string) (*authzen.EvaluationResponse, error) {
	return &authzen.EvaluationResponse{
		Decision: true,
		Context: &authzen.EvaluationResponseContext{
			Reason: map[string]interface{}{
				"user":            fmt.Sprintf("trusted via whitelist (%s)", matchedList),
				"registry":        r.name,
				"type":            "whitelist",
				"role":            role,
				"matched_list":    matchedList,
				"key_fingerprint": keyFingerprint,
			},
			TrustMetadata: map[string]interface{}{
				"trust_framework": "whitelist",
				"registry":        r.name,
				"matched_list":    matchedList,
			},
		},
	}, nil
}

func (r *WhitelistRegistry) allowResolutionOnly(subject, role, matchedList string) (*authzen.EvaluationResponse, error) {
	return &authzen.EvaluationResponse{
		Decision: true,
		Context: &authzen.EvaluationResponseContext{
			Reason: map[string]interface{}{
				"user":            fmt.Sprintf("trusted via whitelist (%s, resolution only)", matchedList),
				"registry":        r.name,
				"type":            "whitelist",
				"role":            role,
				"matched_list":    matchedList,
				"resolution_only": true,
			},
			TrustMetadata: map[string]interface{}{
				"trust_framework": "whitelist",
				"registry":        r.name,
				"matched_list":    matchedList,
			},
		},
	}, nil
}

func (r *WhitelistRegistry) deny(subject, reason string) (*authzen.EvaluationResponse, error) {
	return &authzen.EvaluationResponse{
		Decision: false,
		Context: &authzen.EvaluationResponseContext{
			Reason: map[string]interface{}{
				"user":     reason,
				"admin":    reason,
				"registry": r.name,
				"type":     "whitelist",
				"error":    reason,
			},
			TrustMetadata: map[string]interface{}{
				"trust_framework": "whitelist",
				"registry":        r.name,
			},
		},
	}, nil
}

// SupportedResourceTypes returns the resource types this registry can validate.
func (r *WhitelistRegistry) SupportedResourceTypes() []string {
	return []string{"jwk", "x5c"}
}

// SupportsResolutionOnly returns true since whitelist supports resolution-only requests
// (checking if entity is whitelisted without validating a specific key).
func (r *WhitelistRegistry) SupportsResolutionOnly() bool {
	return true
}

// Info returns metadata about this registry.
func (r *WhitelistRegistry) Info() registry.RegistryInfo {
	r.mu.RLock()
	defer r.mu.RUnlock()

	return registry.RegistryInfo{
		Name:           r.name,
		Type:           "static_whitelist",
		Description:    r.description,
		Version:        "2.0.0",
		ResourceTypes:  []string{"jwk", "x5c"},
		ResolutionOnly: true,
		Healthy:        r.keysLoaded,
	}
}

// Healthy returns true when the most recent JWKS refresh loaded keys for
// all configured entities without errors. Starts false, becomes true after
// first successful refresh, drops back to false if any refresh fails.
func (r *WhitelistRegistry) Healthy() bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.keysLoaded
}

// Refresh fetches JWKS for all whitelisted entities and caches their key fingerprints.
func (r *WhitelistRegistry) Refresh(ctx context.Context) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	// Collect all unique entities from all resolved lists
	entities := make(map[string]bool)
	for _, entries := range r.resolvedLists {
		for _, entry := range entries {
			if entry != "*" && !strings.HasSuffix(entry, "*") {
				entities[entry] = true
			}
		}
	}

	// Clear existing key hashes
	r.keyHashes = make(map[string]map[string]bool)

	// Fetch JWKS for each entity
	var errors []string
	for entity := range entities {
		keys, err := r.fetchEntityKeys(ctx, entity)
		if err != nil {
			r.logger.Warn("failed to fetch keys for entity",
				"entity", entity,
				"error", err)
			errors = append(errors, fmt.Sprintf("%s: %s", entity, err))
			continue
		}

		keySet := make(map[string]bool)
		for _, key := range keys {
			fingerprint, err := KeyFingerprint(key)
			if err != nil {
				r.logger.Warn("failed to compute key fingerprint",
					"entity", entity,
					"error", err)
				continue
			}
			keySet[fingerprint] = true
		}

		if len(keySet) > 0 {
			r.keyHashes[entity] = keySet
			r.logger.Info("loaded keys for entity",
				"entity", entity,
				"key_count", len(keySet))
		}
	}

	r.lastRefresh = time.Now()

	if len(errors) > 0 {
		r.keysLoaded = false
		return fmt.Errorf("failed to fetch keys for %d entities", len(errors))
	}

	r.keysLoaded = true
	r.logger.Info("whitelist keys refreshed",
		"entities", len(r.keyHashes),
		"total_keys", r.countTotalKeys())
	return nil
}

// countTotalKeys returns the total number of cached key fingerprints.
func (r *WhitelistRegistry) countTotalKeys() int {
	count := 0
	for _, keys := range r.keyHashes {
		count += len(keys)
	}
	return count
}

// fetchEntityKeys fetches JWKS from an entity's endpoint.
// When JWKSEndpointPattern is explicitly configured, it is used directly.
// Otherwise, standard metadata discovery is attempted first:
//  1. SD-JWT VC §5.3 JWT VC Issuer Metadata (.well-known/jwt-vc-issuer) — supports inline JWKS
//  2. RFC 8414 OAuth AS Metadata (.well-known/oauth-authorization-server)
//  3. OIDC Discovery (.well-known/openid-configuration)
//  4. OpenID4VCI Metadata (.well-known/openid-credential-issuer)
//
// Falls back to {entity}/.well-known/jwks.json if discovery yields nothing.
func (r *WhitelistRegistry) fetchEntityKeys(ctx context.Context, entity string) ([]crypto.PublicKey, error) {
	if r.config.JWKSEndpointPattern != "" {
		// Explicit pattern configured — use it directly (backward compat)
		return r.fetchJWKSFromURL(ctx, r.buildJWKSURL(entity))
	}

	// 1. Try SD-JWT VC §5.3 (.well-known/jwt-vc-issuer) — may return inline JWKS
	keys, err := r.tryJWTVCIssuerMetadata(ctx, entity)
	if err == nil {
		r.logger.Info("discovered keys via jwt-vc-issuer metadata",
			"entity", entity, "key_count", len(keys))
		return keys, nil
	}
	r.logger.Debug("jwt-vc-issuer discovery failed", "entity", entity, "error", err)

	// 2-4. Try metadata endpoints that expose jwks_uri
	discovered := r.discoverJWKSURI(ctx, entity)
	if discovered != "" {
		return r.fetchJWKSFromURL(ctx, discovered)
	}

	// 5. Fallback to default well-known endpoint
	fallbackURL := r.buildJWKSURL(entity)
	r.logger.Debug("metadata discovery failed, falling back to default",
		"entity", entity, "fallback_url", fallbackURL)
	return r.fetchJWKSFromURL(ctx, fallbackURL)
}

// fetchJWKSFromURL fetches and parses a JWKS from the given URL.
func (r *WhitelistRegistry) fetchJWKSFromURL(ctx context.Context, jwksURL string) ([]crypto.PublicKey, error) {
	// Validate URL scheme
	if !r.config.AllowHTTP && !strings.HasPrefix(jwksURL, "https://") {
		return nil, fmt.Errorf("HTTPS required for JWKS fetch (got %s)", jwksURL)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, jwksURL, nil)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}
	req.Header.Set("Accept", "application/json")

	resp, err := r.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetching JWKS: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("JWKS fetch returned status %d from %s", resp.StatusCode, jwksURL)
	}

	body, err := registry.ReadLimitedBody(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading response: %w", err)
	}

	var jwks map[string]interface{}
	if err := json.Unmarshal(body, &jwks); err != nil {
		return nil, fmt.Errorf("parsing JWKS: %w", err)
	}

	return ExtractPublicKeysFromJWKS(jwks)
}

// tryJWTVCIssuerMetadata attempts SD-JWT VC §5.3 JWT VC Issuer Metadata discovery.
// The well-known URL is constructed per RFC 8615: the well-known string is inserted
// between the host component and the path component of the entity URL.
// The metadata may contain inline "jwks" or a "jwks_uri" reference.
func (r *WhitelistRegistry) tryJWTVCIssuerMetadata(ctx context.Context, entity string) ([]crypto.PublicKey, error) {
	metadataURL := buildWellKnownURL(entity, "jwt-vc-issuer")

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, metadataURL, nil)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}
	req.Header.Set("Accept", "application/json")

	resp, err := r.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetching jwt-vc-issuer metadata: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("jwt-vc-issuer metadata returned status %d", resp.StatusCode)
	}

	body, err := registry.ReadLimitedBody(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading jwt-vc-issuer metadata: %w", err)
	}

	var metadata struct {
		Issuer  string                 `json:"issuer"`
		JWKSURI string                 `json:"jwks_uri,omitempty"`
		JWKS    map[string]interface{} `json:"jwks,omitempty"`
	}
	if err := json.Unmarshal(body, &metadata); err != nil {
		return nil, fmt.Errorf("parsing jwt-vc-issuer metadata: %w", err)
	}

	// Prefer inline JWKS if present
	if metadata.JWKS != nil {
		return ExtractPublicKeysFromJWKS(metadata.JWKS)
	}

	// Fall back to jwks_uri
	if metadata.JWKSURI != "" {
		if !r.config.AllowHTTP && !strings.HasPrefix(metadata.JWKSURI, "https://") {
			return nil, fmt.Errorf("jwks_uri must use HTTPS: %s", metadata.JWKSURI)
		}
		return r.fetchJWKSFromURL(ctx, metadata.JWKSURI)
	}

	return nil, fmt.Errorf("jwt-vc-issuer metadata has neither jwks nor jwks_uri")
}

// discoverJWKSURI attempts to discover the JWKS URI for an entity using standard
// metadata discovery endpoints. It tries, in order:
//  1. RFC 8414 OAuth Authorization Server Metadata (.well-known/oauth-authorization-server)
//  2. OpenID Connect Discovery (.well-known/openid-configuration)
//  3. OpenID4VCI Credential Issuer Metadata (.well-known/openid-credential-issuer)
//
// Returns the discovered jwks_uri, or empty string if all attempts fail.
func (r *WhitelistRegistry) discoverJWKSURI(ctx context.Context, entity string) string {
	entity = strings.TrimSuffix(entity, "/")

	discoveryEndpoints := []string{
		entity + "/.well-known/oauth-authorization-server",
		entity + "/.well-known/openid-configuration",
		entity + "/.well-known/openid-credential-issuer",
	}

	for _, endpoint := range discoveryEndpoints {
		jwksURI, err := r.fetchMetadataJWKSURI(ctx, endpoint)
		if err != nil {
			r.logger.Debug("metadata discovery attempt failed",
				"endpoint", endpoint,
				"error", err)
			continue
		}
		if jwksURI != "" {
			r.logger.Info("discovered JWKS URI via metadata",
				"entity", entity,
				"discovery_endpoint", endpoint,
				"jwks_uri", jwksURI)
			return jwksURI
		}
	}

	return ""
}

// fetchMetadataJWKSURI fetches a metadata document and extracts the jwks_uri field.
func (r *WhitelistRegistry) fetchMetadataJWKSURI(ctx context.Context, metadataURL string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, metadataURL, nil)
	if err != nil {
		return "", fmt.Errorf("creating request: %w", err)
	}
	req.Header.Set("Accept", "application/json")

	resp, err := r.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("fetching metadata: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("metadata fetch returned status %d", resp.StatusCode)
	}

	body, err := registry.ReadLimitedBody(resp.Body)
	if err != nil {
		return "", fmt.Errorf("reading metadata: %w", err)
	}

	var metadata struct {
		JWKSURI string `json:"jwks_uri"`
	}
	if err := json.Unmarshal(body, &metadata); err != nil {
		return "", fmt.Errorf("parsing metadata: %w", err)
	}

	if metadata.JWKSURI == "" {
		return "", fmt.Errorf("no jwks_uri in metadata document at %s", metadataURL)
	}

	// Validate that jwks_uri uses HTTPS (unless AllowHTTP is set)
	if !r.config.AllowHTTP && !strings.HasPrefix(metadata.JWKSURI, "https://") {
		return "", fmt.Errorf("jwks_uri must use HTTPS: %s", metadata.JWKSURI)
	}

	return metadata.JWKSURI, nil
}

// buildWellKnownURL constructs a well-known URL per RFC 8615 §3.
// The well-known suffix is inserted between the host and path components of the entity URL.
// For example, with suffix "jwt-vc-issuer":
//
//	https://example.com           → https://example.com/.well-known/jwt-vc-issuer
//	https://example.com/tenant/1  → https://example.com/.well-known/jwt-vc-issuer/tenant/1
func buildWellKnownURL(entity, suffix string) string {
	entity = strings.TrimSuffix(entity, "/")

	parsed, err := url.Parse(entity)
	if err != nil || parsed.Host == "" {
		// Best-effort fallback: just append
		return entity + "/.well-known/" + suffix
	}

	path := strings.TrimPrefix(parsed.Path, "/")
	base := parsed.Scheme + "://" + parsed.Host

	if path == "" {
		return base + "/.well-known/" + suffix
	}
	return base + "/.well-known/" + suffix + "/" + path
}

// buildJWKSURL constructs the JWKS URL for an entity.
func (r *WhitelistRegistry) buildJWKSURL(entity string) string {
	pattern := r.config.JWKSEndpointPattern
	if pattern == "" {
		pattern = "{entity}/.well-known/jwks.json"
	}

	// Ensure entity has no trailing slash
	entity = strings.TrimSuffix(entity, "/")

	// Replace placeholder
	return strings.ReplaceAll(pattern, "{entity}", entity)
}

// --- Runtime configuration methods ---

// GetConfig returns a copy of the current configuration.
func (r *WhitelistRegistry) GetConfig() WhitelistConfig {
	r.mu.RLock()
	defer r.mu.RUnlock()

	return WhitelistConfig{
		Issuers:         append([]string{}, r.config.Issuers...),
		Verifiers:       append([]string{}, r.config.Verifiers...),
		TrustedSubjects: append([]string{}, r.config.TrustedSubjects...),
	}
}

// SetConfig replaces the entire configuration.
func (r *WhitelistRegistry) SetConfig(cfg WhitelistConfig) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.config = cfg
	r.resolveConfig()
}

// AddIssuer adds an issuer to the whitelist (legacy issuers list).
func (r *WhitelistRegistry) AddIssuer(issuer string) {
	r.mu.Lock()
	defer r.mu.Unlock()

	// Avoid duplicates
	for _, existing := range r.config.Issuers {
		if existing == issuer {
			return
		}
	}
	r.config.Issuers = append(r.config.Issuers, issuer)
	r.resolveConfig()
}

// RemoveIssuer removes an issuer from the whitelist (legacy issuers list).
func (r *WhitelistRegistry) RemoveIssuer(issuer string) {
	r.mu.Lock()
	defer r.mu.Unlock()

	for i, existing := range r.config.Issuers {
		if existing == issuer {
			r.config.Issuers = append(r.config.Issuers[:i], r.config.Issuers[i+1:]...)
			r.resolveConfig()
			return
		}
	}
}

// AddVerifier adds a verifier to the whitelist (legacy verifiers list).
func (r *WhitelistRegistry) AddVerifier(verifier string) {
	r.mu.Lock()
	defer r.mu.Unlock()

	// Avoid duplicates
	for _, existing := range r.config.Verifiers {
		if existing == verifier {
			return
		}
	}
	r.config.Verifiers = append(r.config.Verifiers, verifier)
	r.resolveConfig()
}

// RemoveVerifier removes a verifier from the whitelist (legacy verifiers list).
func (r *WhitelistRegistry) RemoveVerifier(verifier string) {
	r.mu.Lock()
	defer r.mu.Unlock()

	for i, existing := range r.config.Verifiers {
		if existing == verifier {
			r.config.Verifiers = append(r.config.Verifiers[:i], r.config.Verifiers[i+1:]...)
			r.resolveConfig()
			return
		}
	}
}

// Compile-time check that WhitelistRegistry implements TrustRegistry
var _ registry.TrustRegistry = (*WhitelistRegistry)(nil)
