// Package issuermetadata provides a cached, SSRF-safe resolver for
// OpenID4VCI issuer metadata (/.well-known/openid-credential-issuer).
//
// It is designed to be imported directly by both the AuthZEN trust registry
// (pkg/registry/issuerurl) and application-level code — for example the
// go-wallet-backend OID4VCI engine — so that a single fetch+cache
// implementation is shared with consistent SSRF protection and HTTPS enforcement.
//
// Basic usage:
//
//	resolver, err := issuermetadata.New(issuermetadata.Config{})
//	if err != nil { … }
//	meta, err := resolver.Resolve(ctx, "https://issuer.example.com")
package issuermetadata

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/sirosfoundation/go-trust/pkg/registry"
)

// Config configures a Resolver.
type Config struct {
	// CacheTTL is how long resolved metadata is cached.
	// Default: 5 minutes.
	CacheTTL time.Duration

	// HTTPTimeout is the per-request HTTP timeout.
	// Default: 30 seconds.
	HTTPTimeout time.Duration

	// AllowHTTP permits non-TLS issuer URLs.
	// For testing only; do not set in production.
	AllowHTTP bool

	// AllowPrivateIPs permits fetching from private/internal IP addresses.
	// For testing only; do not set in production.
	AllowPrivateIPs bool
}

type cachedEntry struct {
	parsed    map[string]interface{}
	fetchedAt time.Time
}

// Resolver fetches and caches OpenID4VCI issuer metadata with SSRF protection.
// Safe for concurrent use.
type Resolver struct {
	cfg        Config
	httpClient registry.HTTPClientInterface

	mu    sync.RWMutex
	cache map[string]*cachedEntry
}

// New creates a Resolver with the given configuration.
// Sensible defaults are applied for zero-value durations.
func New(cfg Config) (*Resolver, error) {
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

	return &Resolver{
		cfg:        cfg,
		httpClient: httpClient,
		cache:      make(map[string]*cachedEntry),
	}, nil
}

// Resolve returns the parsed issuer metadata for the given issuer URL,
// using a TTL-cached result when available.
//
// The issuerURL must use HTTPS (unless AllowHTTP is set in Config).
// A trailing slash is stripped before fetching. The endpoint queried is
// <issuerURL>/.well-known/openid-credential-issuer.
//
// The returned map is a direct JSON parse of the metadata document.
// The signed_metadata field, if present, is preserved as a string (JWT).
func (r *Resolver) Resolve(ctx context.Context, issuerURL string) (map[string]interface{}, error) {
	issuerURL = strings.TrimSuffix(issuerURL, "/")

	if err := r.validateURL(issuerURL); err != nil {
		return nil, err
	}

	if cached := r.getCached(issuerURL); cached != nil {
		return cached, nil
	}

	metadataURL := issuerURL + "/.well-known/openid-credential-issuer"
	parsed, err := r.fetch(ctx, metadataURL)
	if err != nil {
		return nil, err
	}

	r.setCache(issuerURL, parsed)
	return parsed, nil
}

func (r *Resolver) validateURL(issuerURL string) error {
	u, err := url.Parse(issuerURL)
	if err != nil {
		return fmt.Errorf("malformed issuer URL: %w", err)
	}
	if u.Scheme == "" || u.Host == "" {
		return fmt.Errorf("issuer URL must have scheme and host")
	}
	if u.Scheme != "https" && u.Scheme != "http" {
		return fmt.Errorf("issuer URL must use HTTP or HTTPS scheme")
	}
	if !r.cfg.AllowHTTP && u.Scheme != "https" {
		return fmt.Errorf("issuer URL must use HTTPS")
	}
	return nil
}

func (r *Resolver) fetch(ctx context.Context, metadataURL string) (map[string]interface{}, error) {
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

	if !json.Valid(body) {
		return nil, fmt.Errorf("response is not valid JSON")
	}

	var parsed map[string]interface{}
	if err := json.Unmarshal(body, &parsed); err != nil {
		return nil, fmt.Errorf("parsing JSON: %w", err)
	}

	// Preserve signed_metadata as a string (JWT) if present.
	if sm, ok := parsed["signed_metadata"]; ok {
		if smStr, ok := sm.(string); ok {
			parsed["signed_metadata"] = smStr
		}
	}

	return parsed, nil
}

func (r *Resolver) getCached(issuerURL string) map[string]interface{} {
	r.mu.RLock()
	defer r.mu.RUnlock()
	entry, ok := r.cache[issuerURL]
	if !ok || time.Since(entry.fetchedAt) > r.cfg.CacheTTL {
		return nil
	}
	return entry.parsed
}

func (r *Resolver) setCache(issuerURL string, parsed map[string]interface{}) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.cache[issuerURL] = &cachedEntry{
		parsed:    parsed,
		fetchedAt: time.Now(),
	}
}
