// Package issuerurl implements a TrustRegistry that resolves OpenID4VCI
// issuer metadata by fetching /.well-known/openid-credential-issuer.
//
// This registry handles resolution-only requests with subject.type = "url"
// and returns the raw issuer metadata as trust_metadata in the AuthZEN
// EvaluationResponse. The metadata is returned verbatim (not parsed or
// transformed) to preserve signed_metadata JWT signatures and any other
// integrity-protected fields.
package issuerurl

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/sirosfoundation/go-trust/pkg/authzen"
	"github.com/sirosfoundation/go-trust/pkg/registry"
)

// Config holds configuration for the issuer URL registry.
type Config struct {
	Name        string        `yaml:"name"`
	Description string        `yaml:"description"`
	CacheTTL    time.Duration `yaml:"cache_ttl"`
	HTTPTimeout time.Duration `yaml:"http_timeout"`
	// AllowHTTP permits non-TLS issuer URLs (testing only).
	AllowHTTP bool `yaml:"allow_http"`
	// AllowPrivateIPs permits fetching from private/internal IPs (testing only).
	AllowPrivateIPs bool `yaml:"allow_private_ips"`
}

// cachedMetadata holds cached raw issuer metadata.
type cachedMetadata struct {
	raw       json.RawMessage
	fetchedAt time.Time
}

// Registry implements TrustRegistry for OpenID4VCI issuer metadata resolution.
type Registry struct {
	config     *Config
	httpClient registry.HTTPClientInterface

	mu    sync.RWMutex
	cache map[string]*cachedMetadata // issuerURL -> cached raw metadata
}

// New creates a new issuer URL registry.
func New(cfg *Config) (*Registry, error) {
	if cfg == nil {
		cfg = &Config{}
	}
	if cfg.Name == "" {
		cfg.Name = "issuer-url"
	}
	if cfg.CacheTTL == 0 {
		cfg.CacheTTL = 5 * time.Minute
	}
	if cfg.HTTPTimeout == 0 {
		cfg.HTTPTimeout = 30 * time.Second
	}

	httpClient := registry.NewSafeHTTPClient(registry.SafeClientConfig{
		Timeout:         cfg.HTTPTimeout,
		AllowPrivateIPs: cfg.AllowPrivateIPs,
		AllowHTTP:       cfg.AllowHTTP,
	})

	return &Registry{
		config:     cfg,
		httpClient: httpClient,
		cache:      make(map[string]*cachedMetadata),
	}, nil
}

// Evaluate handles issuer URL resolution requests.
// Only resolution-only requests with subject.type = "url" are supported.
// The raw issuer metadata JSON is returned as trust_metadata.
func (r *Registry) Evaluate(ctx context.Context, req *authzen.EvaluationRequest) (*authzen.EvaluationResponse, error) {
	startTime := time.Now()

	// Only handle URL-type subjects
	if req.Subject.Type != "url" {
		return r.denyWithReason("issuer-url registry only handles subject.type 'url'"), nil
	}

	// Only resolution-only requests
	if !req.IsResolutionOnlyRequest() {
		return r.denyWithReason("issuer-url registry only supports resolution-only requests"), nil
	}

	issuerURL := strings.TrimSuffix(req.Subject.ID, "/")
	if issuerURL == "" {
		return r.denyWithReason("missing issuer URL in subject.id"), nil
	}

	// Validate URL format
	if err := validateIssuerURL(issuerURL, r.config.AllowHTTP); err != nil {
		return r.denyWithReason(fmt.Sprintf("invalid issuer URL: %v", err)), nil
	}

	// Check cache
	if cached := r.getCached(issuerURL); cached != nil {
		return &authzen.EvaluationResponse{
			Decision: true,
			Context: &authzen.EvaluationResponseContext{
				ID: issuerURL,
				Reason: map[string]interface{}{
					"resolution_only": true,
					"resolution_ms":   time.Since(startTime).Milliseconds(),
					"cached":          true,
					"registry":        r.config.Name,
				},
				TrustMetadata: cached,
			},
		}, nil
	}

	// Fetch metadata
	metadataURL := issuerURL + "/.well-known/openid-credential-issuer"
	rawMetadata, err := r.fetchRawMetadata(ctx, metadataURL)
	if err != nil {
		return r.denyWithReason(fmt.Sprintf("failed to fetch issuer metadata: %v", err)), nil
	}

	// Cache the raw metadata
	r.setCache(issuerURL, rawMetadata)

	// Return raw metadata as trust_metadata — no parsing, no transformation.
	// The caller (wallet) is responsible for interpreting the metadata and
	// validating signed_metadata JWTs.
	return &authzen.EvaluationResponse{
		Decision: true,
		Context: &authzen.EvaluationResponseContext{
			ID: issuerURL,
			Reason: map[string]interface{}{
				"resolution_only": true,
				"resolution_ms":   time.Since(startTime).Milliseconds(),
				"cached":          false,
				"registry":        r.config.Name,
			},
			TrustMetadata: rawMetadata,
		},
	}, nil
}

// SupportedResourceTypes returns an empty slice — this registry only handles
// resolution-only requests (no resource.type matching needed).
func (r *Registry) SupportedResourceTypes() []string {
	return []string{}
}

// SupportsResolutionOnly returns true.
func (r *Registry) SupportsResolutionOnly() bool {
	return true
}

// Info returns metadata about this registry.
func (r *Registry) Info() registry.RegistryInfo {
	return registry.RegistryInfo{
		Name:           r.config.Name,
		Type:           "issuer_url",
		Description:    r.config.Description,
		ResolutionOnly: true,
		Healthy:        true,
	}
}

// Healthy returns true (stateless registry, always healthy).
func (r *Registry) Healthy() bool {
	return true
}

// Refresh is a no-op for this registry (no background data to refresh).
func (r *Registry) Refresh(_ context.Context) error {
	return nil
}

// fetchRawMetadata fetches the issuer metadata and returns it as raw JSON bytes.
// The response is NOT parsed into a struct — it is returned verbatim to preserve
// signatures and avoid breaking signed_metadata JWTs.
func (r *Registry) fetchRawMetadata(ctx context.Context, metadataURL string) (json.RawMessage, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, metadataURL, nil)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}
	req.Header.Set("Accept", "application/json")

	resp, err := r.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("HTTP request failed: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("issuer returned HTTP %d", resp.StatusCode)
	}

	body, err := registry.ReadLimitedBody(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading response: %w", err)
	}

	// Validate that the body is valid JSON
	if !json.Valid(body) {
		return nil, fmt.Errorf("response is not valid JSON")
	}

	return json.RawMessage(body), nil
}

// getCached returns cached raw metadata if it exists and hasn't expired.
func (r *Registry) getCached(issuerURL string) json.RawMessage {
	r.mu.RLock()
	defer r.mu.RUnlock()

	entry, ok := r.cache[issuerURL]
	if !ok {
		return nil
	}
	if time.Since(entry.fetchedAt) > r.config.CacheTTL {
		return nil
	}
	return entry.raw
}

// setCache stores raw metadata in the cache.
func (r *Registry) setCache(issuerURL string, raw json.RawMessage) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.cache[issuerURL] = &cachedMetadata{
		raw:       raw,
		fetchedAt: time.Now(),
	}
}

// denyWithReason returns a denial response with the given reason.
func (r *Registry) denyWithReason(reason string) *authzen.EvaluationResponse {
	return &authzen.EvaluationResponse{
		Decision: false,
		Context: &authzen.EvaluationResponseContext{
			Reason: map[string]interface{}{
				"error":    reason,
				"registry": r.config.Name,
			},
		},
	}
}

// validateIssuerURL checks that the URL is well-formed and uses HTTPS.
func validateIssuerURL(issuerURL string, allowHTTP bool) error {
	u, err := url.Parse(issuerURL)
	if err != nil {
		return fmt.Errorf("malformed URL: %w", err)
	}
	if u.Scheme == "" || u.Host == "" {
		return fmt.Errorf("URL must have scheme and host")
	}
	if !allowHTTP && u.Scheme != "https" {
		return fmt.Errorf("URL must use HTTPS")
	}
	if u.Scheme != "https" && u.Scheme != "http" {
		return fmt.Errorf("URL must use HTTP or HTTPS scheme")
	}
	return nil
}
