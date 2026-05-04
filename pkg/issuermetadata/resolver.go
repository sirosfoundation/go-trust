// Package issuermetadata provides a cached, SSRF-safe resolver for
// OpenID4VCI issuer metadata (/.well-known/openid-credential-issuer).
//
// It is designed to be imported directly by both the AuthZEN trust registry
// (pkg/registry/issuerurl) and application-level code — for example the
// go-wallet-backend OID4VCI engine — so that a single fetch+cache
// implementation is shared with consistent SSRF protection and HTTPS enforcement.
//
// When signed_metadata is present in the fetched document, its JWT signature is
// validated against the issuer's JWKS (inline jwks or jwks_uri) and the JWT
// payload claims are returned as the authoritative metadata.
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

	"github.com/go-jose/go-jose/v4"
	"github.com/sirosfoundation/go-trust/pkg/registry"
)

// supportedSignatureAlgorithms is the set of JWS algorithms accepted for
// signed_metadata JWT verification. Symmetric (HMAC) algorithms are excluded
// because they require a shared secret rather than a public key.
var supportedSignatureAlgorithms = []jose.SignatureAlgorithm{
	jose.RS256, jose.RS384, jose.RS512,
	jose.PS256, jose.PS384, jose.PS512,
	jose.ES256, jose.ES384, jose.ES512,
	jose.EdDSA,
}

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

// Resolve returns the authoritative issuer metadata for the given issuer URL,
// using a TTL-cached result when available.
//
// The issuerURL must use HTTPS (unless AllowHTTP is set in Config).
// A trailing slash is stripped before fetching. The endpoint queried is
// <issuerURL>/.well-known/openid-credential-issuer.
//
// When the fetched document contains a signed_metadata field, its JWT
// signature is verified against the issuer's JWKS (inline jwks or jwks_uri).
// On success the JWT payload claims are returned as the authoritative metadata
// and signed_metadata is preserved as a raw string. If verification fails an
// error is returned so the caller never receives unverified metadata claims.
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

	var raw map[string]interface{}
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, fmt.Errorf("parsing JSON: %w", err)
	}

	// If signed_metadata is present, validate its JWT signature and use the
	// JWT payload claims as the authoritative metadata.
	if smVal, ok := raw["signed_metadata"]; ok {
		if smStr, ok := smVal.(string); ok && smStr != "" {
			return r.validateSignedMetadata(ctx, raw, smStr)
		}
	}

	return raw, nil
}

// validateSignedMetadata verifies the signed_metadata JWT against the issuer's
// JWKS and returns the JWT payload claims as the authoritative metadata.
// The signed_metadata string is preserved in the returned map.
//
// Key selection: if the JWT header contains a kid, keys matching that kid are
// tried first. If none match the kid or no kid is present, all JWKS keys are
// tried in order.
func (r *Resolver) validateSignedMetadata(ctx context.Context, raw map[string]interface{}, signedMetadata string) (map[string]interface{}, error) {
	jws, err := jose.ParseSigned(signedMetadata, supportedSignatureAlgorithms)
	if err != nil {
		return nil, fmt.Errorf("parsing signed_metadata JWT: %w", err)
	}

	jwks, err := r.resolveJWKS(ctx, raw)
	if err != nil {
		return nil, fmt.Errorf("resolving JWKS for signed_metadata verification: %w", err)
	}

	// Determine the candidate keys to try for verification.
	// When the JWT header specifies a kid and the JWKS contains matching keys,
	// only those keys are tried. Otherwise all keys are tried.
	candidates := jwks.Keys
	if len(jws.Signatures) > 0 {
		if kid := jws.Signatures[0].Protected.KeyID; kid != "" {
			if matching := jwks.Key(kid); len(matching) > 0 {
				candidates = matching
			}
		}
	}

	var payload []byte
	verified := false
	for i := range candidates {
		pubKey := candidates[i].Public()
		if payload, err = jws.Verify(pubKey.Key); err == nil {
			verified = true
			break
		}
	}
	if !verified {
		return nil, fmt.Errorf("signed_metadata signature verification failed against all JWKS keys")
	}

	var claims map[string]interface{}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, fmt.Errorf("parsing JWT payload claims: %w", err)
	}

	// Preserve signed_metadata as a raw string in the authoritative metadata.
	claims["signed_metadata"] = signedMetadata
	return claims, nil
}

// resolveJWKS returns the JWKS for validating the signed_metadata JWT.
// Inline jwks is preferred over jwks_uri.
func (r *Resolver) resolveJWKS(ctx context.Context, meta map[string]interface{}) (jose.JSONWebKeySet, error) {
	// Prefer inline JWKS.
	if jwksRaw, ok := meta["jwks"]; ok {
		b, err := json.Marshal(jwksRaw)
		if err == nil {
			var jwks jose.JSONWebKeySet
			if err = json.Unmarshal(b, &jwks); err == nil && len(jwks.Keys) > 0 {
				return jwks, nil
			}
		}
	}

	// Fall back to jwks_uri.
	if uri, ok := meta["jwks_uri"].(string); ok && uri != "" {
		return r.fetchJWKSFromURI(ctx, uri)
	}

	return jose.JSONWebKeySet{}, fmt.Errorf("signed_metadata present but no JWKS found in metadata (jwks or jwks_uri required)")
}

// fetchJWKSFromURI fetches and parses a JWKS from the given URI.
func (r *Resolver) fetchJWKSFromURI(ctx context.Context, uri string) (jose.JSONWebKeySet, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, uri, nil)
	if err != nil {
		return jose.JSONWebKeySet{}, fmt.Errorf("creating JWKS request: %w", err)
	}
	req.Header.Set("Accept", "application/json")

	resp, err := r.httpClient.Do(req)
	if err != nil {
		return jose.JSONWebKeySet{}, fmt.Errorf("fetching JWKS: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode != http.StatusOK {
		return jose.JSONWebKeySet{}, fmt.Errorf("JWKS endpoint returned HTTP %d", resp.StatusCode)
	}

	body, err := registry.ReadLimitedBody(resp.Body)
	if err != nil {
		return jose.JSONWebKeySet{}, fmt.Errorf("reading JWKS response: %w", err)
	}

	var jwks jose.JSONWebKeySet
	if err := json.Unmarshal(body, &jwks); err != nil {
		return jose.JSONWebKeySet{}, fmt.Errorf("parsing JWKS: %w", err)
	}
	if len(jwks.Keys) == 0 {
		return jose.JSONWebKeySet{}, fmt.Errorf("JWKS contains no keys")
	}
	return jwks, nil
}

func (r *Resolver) getCached(issuerURL string) map[string]interface{} {
	r.mu.RLock()
	defer r.mu.RUnlock()
	entry, ok := r.cache[issuerURL]
	if !ok || time.Since(entry.fetchedAt) > r.cfg.CacheTTL {
		return nil
	}
	// Deep-copy the cached map so callers cannot mutate shared cache state.
	b, err := json.Marshal(entry.parsed)
	if err != nil {
		return nil
	}
	var result map[string]interface{}
	if err := json.Unmarshal(b, &result); err != nil {
		return nil
	}
	return result
}

func (r *Resolver) setCache(issuerURL string, parsed map[string]interface{}) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.cache[issuerURL] = &cachedEntry{
		parsed:    parsed,
		fetchedAt: time.Now(),
	}
}
