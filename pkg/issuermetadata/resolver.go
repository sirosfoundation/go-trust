// Package issuermetadata provides a cached, SSRF-safe resolver for
// OpenID4VCI issuer metadata (/.well-known/openid-credential-issuer).
//
// It is designed to be imported directly by both the AuthZEN trust registry
// (pkg/registry/issuerurl) and application-level code — for example the
// go-wallet-backend OID4VCI engine — so that a single fetch+cache
// implementation is shared with consistent SSRF protection and HTTPS enforcement.
//
// The resolver supports two metadata distribution formats per OpenID4VCI §12.2.2:
//   - Unsigned JSON (Content-Type: application/json) — returned as-is
//   - Signed JWT (Content-Type: application/jwt) — JWS is verified, claims
//     extracted, and the signing key is submitted for trust evaluation
//
// Additionally, the legacy signed_metadata field within a JSON response is
// supported for backward compatibility.
//
// When a TrustEvaluator is configured, the signing key or certificate chain
// extracted from the JWS header is submitted for trust evaluation using the
// same trust logic as any other credential issuer key validation. Signed data
// whose signer is not trusted results in an error.
//
// Basic usage:
//
//	resolver, err := issuermetadata.New(issuermetadata.Config{})
//	if err != nil { … }
//	meta, err := resolver.Resolve(ctx, "https://issuer.example.com")
package issuermetadata

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"mime"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/sirosfoundation/go-trust/pkg/authzen"
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

// TrustEvaluator is the interface for delegating trust decisions about signing
// keys to the go-trust engine. After a JWT signature is cryptographically
// verified, the signing key or certificate chain is submitted here. If the
// evaluator returns decision=false or an error, the signed metadata is rejected.
//
// This is typically the RegistryManager, but is defined as an interface to
// avoid circular imports and enable testing.
type TrustEvaluator interface {
	Evaluate(ctx context.Context, req *authzen.EvaluationRequest) (*authzen.EvaluationResponse, error)
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

	// TrustEvaluator, when set, is used to evaluate whether the signer of
	// signed metadata is trusted as a credential issuer. If nil, only
	// cryptographic signature verification is performed (no trust decision).
	TrustEvaluator TrustEvaluator

	// PreferSigned controls whether the resolver sends Accept headers
	// preferring signed (application/jwt) responses. Default: true.
	PreferSigned *bool
}

type cachedEntry struct {
	parsed    map[string]interface{}
	fetchedAt time.Time
	validated bool
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

// ResolveResult contains the resolved metadata and cache-hit information.
type ResolveResult struct {
	Metadata  map[string]interface{}
	Cached    bool
	Validated bool
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
	result, err := r.ResolveWithInfo(ctx, issuerURL)
	if err != nil {
		return nil, err
	}
	return result.Metadata, nil
}

// fetchResult is the internal result of a fetch operation.
type fetchResult struct {
	metadata  map[string]interface{}
	validated bool
}

// ResolveWithInfo is like Resolve but additionally reports whether the result
// was served from cache and whether the metadata was validated (signed by a
// trusted issuer).
func (r *Resolver) ResolveWithInfo(ctx context.Context, issuerURL string) (*ResolveResult, error) {
	issuerURL = strings.TrimSuffix(issuerURL, "/")

	if err := r.validateURL(issuerURL); err != nil {
		return nil, err
	}

	if entry := r.getCachedEntry(issuerURL); entry != nil {
		return &ResolveResult{Metadata: deepCopyMap(entry.parsed), Cached: true, Validated: entry.validated}, nil
	}

	metadataURL := issuerURL + "/.well-known/openid-credential-issuer"
	result, err := r.fetch(ctx, issuerURL, metadataURL)
	if err != nil {
		return nil, err
	}

	r.setCache(issuerURL, result.metadata, result.validated)
	return &ResolveResult{Metadata: deepCopyMap(result.metadata), Cached: false, Validated: result.validated}, nil
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

// preferSigned returns whether to prefer signed metadata in Accept headers.
func (r *Resolver) preferSigned() bool {
	if r.cfg.PreferSigned != nil {
		return *r.cfg.PreferSigned
	}
	return true
}

func (r *Resolver) fetch(ctx context.Context, issuerURL, metadataURL string) (*fetchResult, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, metadataURL, nil)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}

	// Content negotiation per OpenID4VCI §12.2.2
	if r.preferSigned() {
		req.Header.Set("Accept", "application/jwt, application/json;q=0.9")
	} else {
		req.Header.Set("Accept", "application/json, application/jwt;q=0.9")
	}

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

	// Determine format from Content-Type header.
	contentType := resp.Header.Get("Content-Type")
	mediaType, _, parseErr := mime.ParseMediaType(contentType)
	if contentType != "" && parseErr != nil {
		return nil, fmt.Errorf("malformed Content-Type %q: %w", contentType, parseErr)
	}

	switch mediaType {
	case "application/jwt":
		// Entire response body is a JWS per OpenID4VCI §12.2.3
		return r.handleJWTResponse(ctx, issuerURL, strings.TrimSpace(string(body)))

	case "application/json", "":
		// Standard JSON response, possibly with legacy signed_metadata field
		return r.handleJSONResponse(ctx, issuerURL, body)

	default:
		return nil, fmt.Errorf("unsupported Content-Type: %s", contentType)
	}
}

// handleJWTResponse processes an application/jwt response (entire body is a JWS).
// Per OpenID4VCI §12.2.3:
// - JOSE header: typ=openidvci-issuer-metadata+jwt, alg must be asymmetric
// - Payload: sub must match issuer URL, iat required
// - Key resolved from JOSE header (x5c, kid, trust_chain)
func (r *Resolver) handleJWTResponse(ctx context.Context, issuerURL, jwtString string) (*fetchResult, error) {
	jws, err := jose.ParseSigned(jwtString, supportedSignatureAlgorithms)
	if err != nil {
		return nil, fmt.Errorf("parsing JWT response: %w", err)
	}

	if len(jws.Signatures) == 0 {
		return nil, fmt.Errorf("JWT response has no signatures")
	}

	headers := jws.Signatures[0].Protected

	// Validate typ header per §12.2.3
	typ, _ := headers.ExtraHeaders[jose.HeaderType].(string)
	if typ != "openidvci-issuer-metadata+jwt" {
		return nil, fmt.Errorf("JWT typ header must be 'openidvci-issuer-metadata+jwt', got %q", typ)
	}

	// Resolve signing key from JOSE header and verify signature
	claims, err := r.verifyJWSFromHeader(ctx, issuerURL, jws)
	if err != nil {
		return nil, err
	}

	// Validate required payload claims per §12.2.3
	if err := validateJWTClaims(claims, issuerURL); err != nil {
		return nil, err
	}

	// Validated is true only when a TrustEvaluator is configured and approved
	// the signer. Without a TrustEvaluator, the signature is verified but no
	// trust decision is made.
	return &fetchResult{metadata: claims, validated: r.cfg.TrustEvaluator != nil}, nil
}

// handleJSONResponse processes an application/json response.
// If signed_metadata is present, validates its JWT and returns the JWT payload.
func (r *Resolver) handleJSONResponse(ctx context.Context, issuerURL string, body []byte) (*fetchResult, error) {
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
			claims, err := r.validateSignedMetadata(ctx, issuerURL, raw, smStr)
			if err != nil {
				return nil, err
			}
			// Validated only when a TrustEvaluator is configured and approved.
			return &fetchResult{metadata: claims, validated: r.cfg.TrustEvaluator != nil}, nil
		}
	}

	return &fetchResult{metadata: raw, validated: false}, nil
}

// validateSignedMetadata verifies the signed_metadata JWT against the issuer's
// JWKS and returns the JWT payload claims as the authoritative metadata.
// The signed_metadata string is preserved in the returned map.
//
// Key resolution order:
//  1. Inline jwks or jwks_uri from the metadata body
//  2. JWT header (x5c certificate chain or embedded key)
//
// When using JWKS, if the JWT header contains a kid, keys matching that kid
// are tried first. If none match the kid or no kid is present, all JWKS keys
// are tried in order.
func (r *Resolver) validateSignedMetadata(ctx context.Context, issuerURL string, raw map[string]interface{}, signedMetadata string) (map[string]interface{}, error) {
	jws, err := jose.ParseSigned(signedMetadata, supportedSignatureAlgorithms)
	if err != nil {
		return nil, fmt.Errorf("parsing signed_metadata JWT: %w", err)
	}

	jwks, jwksErr := r.resolveJWKS(ctx, raw)
	if jwksErr != nil {
		// No JWKS in metadata body — fall back to JWT header key (x5c, embedded key).
		claims, headerErr := r.verifyJWSFromHeader(ctx, issuerURL, jws)
		if headerErr != nil {
			return nil, fmt.Errorf("resolving JWKS for signed_metadata verification: %w (header fallback: %v)", jwksErr, headerErr)
		}
		claims["signed_metadata"] = signedMetadata
		return claims, nil
	}

	// Determine the candidate keys to try for verification.
	candidates := jwks.Keys
	if len(jws.Signatures) > 0 {
		if kid := jws.Signatures[0].Protected.KeyID; kid != "" {
			if matching := jwks.Key(kid); len(matching) > 0 {
				candidates = matching
			}
		}
	}

	var payload []byte
	var verifiedKey *jose.JSONWebKey
	for i := range candidates {
		pubKey := candidates[i].Public()
		if payload, err = jws.Verify(pubKey.Key); err == nil {
			verifiedKey = &pubKey
			break
		}
	}
	if verifiedKey == nil {
		return nil, fmt.Errorf("signed_metadata signature verification failed against all JWKS keys")
	}

	// Trust evaluation: submit the verified signing key to the trust engine.
	if err := r.evaluateSignerTrust(ctx, issuerURL, jws, verifiedKey); err != nil {
		return nil, fmt.Errorf("signer trust evaluation failed: %w", err)
	}

	var claims map[string]interface{}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, fmt.Errorf("parsing JWT payload claims: %w", err)
	}

	claims["signed_metadata"] = signedMetadata
	return claims, nil
}

// verifyJWSFromHeader resolves the signing key from the JWS JOSE header
// (x5c or embedded key) and verifies the signature.
// Returns the verified payload claims.
func (r *Resolver) verifyJWSFromHeader(ctx context.Context, issuerURL string, jws *jose.JSONWebSignature) (map[string]interface{}, error) {
	headers := jws.Signatures[0].Protected

	// Try x5c header: extract certs from the raw JWS header.
	certs, x5cErr := r.extractX5CCerts(jws)
	if x5cErr == nil && len(certs) > 0 {
		leaf := certs[0]
		payload, err := jws.Verify(leaf.PublicKey)
		if err != nil {
			return nil, fmt.Errorf("JWT signature verification failed with x5c leaf: %w", err)
		}

		// Submit the certificate chain for trust evaluation.
		if err := r.evaluateX5CTrust(ctx, issuerURL, certs); err != nil {
			return nil, fmt.Errorf("x5c signer trust evaluation failed: %w", err)
		}

		var claims map[string]interface{}
		if err := json.Unmarshal(payload, &claims); err != nil {
			return nil, fmt.Errorf("parsing JWT payload claims: %w", err)
		}
		return claims, nil
	}

	// If x5c was present but malformed, surface the real error.
	if x5cErr != nil && x5cErr.Error() != "no x5c header" {
		return nil, fmt.Errorf("parsing x5c certificate chain: %w", x5cErr)
	}

	// Try kid — look up from issuer's JWKS (fetch metadata as JSON to get JWKS)
	if kid := headers.KeyID; kid != "" {
		return nil, fmt.Errorf("JWT response with kid but no x5c header: key resolution via kid requires JWKS endpoint (not yet supported for application/jwt responses)")
	}

	return nil, fmt.Errorf("JWT response has no x5c or kid in JOSE header; cannot resolve signing key")
}

// extractX5CCerts extracts x5c certificates from a JWS by looking at the
// ExtraHeaders of the protected header. go-jose v4 parses x5c into an
// unexported field, but we can re-serialize and re-parse via FullSerialize
// to extract the raw base64 strings.
func (r *Resolver) extractX5CCerts(jws *jose.JSONWebSignature) ([]*x509.Certificate, error) {
	if len(jws.Signatures) == 0 {
		return nil, fmt.Errorf("no signatures")
	}

	// Serialize to full JSON form to access the raw protected header.
	fullJSON := jws.FullSerialize()
	var fullMsg struct {
		Protected string `json:"protected"`
	}
	if err := json.Unmarshal([]byte(fullJSON), &fullMsg); err != nil {
		return nil, fmt.Errorf("parsing full JWS: %w", err)
	}

	headerBytes, err := base64.RawURLEncoding.DecodeString(fullMsg.Protected)
	if err != nil {
		return nil, fmt.Errorf("decoding protected header: %w", err)
	}

	var headerMap struct {
		X5C []string `json:"x5c"`
	}
	if err := json.Unmarshal(headerBytes, &headerMap); err != nil {
		return nil, fmt.Errorf("parsing protected header: %w", err)
	}
	if len(headerMap.X5C) == 0 {
		return nil, fmt.Errorf("no x5c header")
	}

	certs := make([]*x509.Certificate, len(headerMap.X5C))
	for i, b64 := range headerMap.X5C {
		der, err := base64.StdEncoding.DecodeString(b64)
		if err != nil {
			return nil, fmt.Errorf("decoding x5c[%d]: %w", i, err)
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, fmt.Errorf("parsing x5c[%d] certificate: %w", i, err)
		}
		certs[i] = cert
	}
	return certs, nil
}

// validateJWTClaims validates required JWT payload claims per OpenID4VCI §12.2.3.
func validateJWTClaims(claims map[string]interface{}, issuerURL string) error {
	// sub MUST match the Credential Issuer Identifier
	sub, _ := claims["sub"].(string)
	if sub == "" {
		return fmt.Errorf("JWT payload missing required 'sub' claim")
	}
	normalizedSub := strings.TrimSuffix(sub, "/")
	normalizedIssuer := strings.TrimSuffix(issuerURL, "/")
	if normalizedSub != normalizedIssuer {
		return fmt.Errorf("JWT 'sub' claim %q does not match issuer URL %q", sub, issuerURL)
	}

	// iat MUST be present
	if _, ok := claims["iat"]; !ok {
		return fmt.Errorf("JWT payload missing required 'iat' claim")
	}

	return nil
}

// evaluateSignerTrust submits the signing key for trust evaluation.
// If no TrustEvaluator is configured, this is a no-op (signature-only verification).
func (r *Resolver) evaluateSignerTrust(ctx context.Context, issuerURL string, jws *jose.JSONWebSignature, verifiedKey *jose.JSONWebKey) error {
	if r.cfg.TrustEvaluator == nil {
		return nil
	}

	// If x5c is present in the header, use certificate chain trust evaluation.
	certs, x5cErr := r.extractX5CCerts(jws)
	if x5cErr == nil && len(certs) > 0 {
		return r.evaluateX5CTrust(ctx, issuerURL, certs)
	}
	// Surface malformed x5c errors (but not "no x5c header").
	if x5cErr != nil && x5cErr.Error() != "no x5c header" {
		return fmt.Errorf("parsing x5c certificate chain: %w", x5cErr)
	}

	// Otherwise evaluate the bare public key as a JWK.
	return r.evaluateJWKTrust(ctx, issuerURL, verifiedKey)
}

// evaluateX5CTrust submits an x5c certificate chain for trust evaluation.
func (r *Resolver) evaluateX5CTrust(ctx context.Context, issuerURL string, certs []*x509.Certificate) error {
	if r.cfg.TrustEvaluator == nil {
		return nil
	}

	// Convert certs to base64 DER strings for the AuthZEN resource.key format.
	key := make([]interface{}, len(certs))
	for i, cert := range certs {
		key[i] = base64.StdEncoding.EncodeToString(cert.Raw)
	}

	req := &authzen.EvaluationRequest{
		Subject: authzen.Subject{
			Type: "key",
			ID:   issuerURL,
		},
		Resource: authzen.Resource{
			Type: "x5c",
			ID:   issuerURL,
			Key:  key,
		},
		Action: &authzen.Action{
			Name: "credential-issuer",
		},
	}

	resp, err := r.cfg.TrustEvaluator.Evaluate(ctx, req)
	if err != nil {
		return fmt.Errorf("trust evaluation error: %w", err)
	}
	if !resp.Decision {
		reason := ""
		if resp.Context != nil && resp.Context.Reason != nil {
			if r, ok := resp.Context.Reason["error"].(string); ok {
				reason = ": " + r
			}
		}
		return fmt.Errorf("signing certificate chain not trusted as credential issuer%s", reason)
	}
	return nil
}

// evaluateJWKTrust submits a bare JWK for trust evaluation.
func (r *Resolver) evaluateJWKTrust(ctx context.Context, issuerURL string, jwk *jose.JSONWebKey) error {
	if r.cfg.TrustEvaluator == nil {
		return nil
	}

	jwkBytes, err := json.Marshal(jwk)
	if err != nil {
		return fmt.Errorf("marshaling JWK for trust evaluation: %w", err)
	}
	var jwkMap map[string]interface{}
	if err := json.Unmarshal(jwkBytes, &jwkMap); err != nil {
		return fmt.Errorf("converting JWK for trust evaluation: %w", err)
	}

	// JWK is submitted as a single-element key array.
	req := &authzen.EvaluationRequest{
		Subject: authzen.Subject{
			Type: "key",
			ID:   issuerURL,
		},
		Resource: authzen.Resource{
			Type: "jwk",
			ID:   issuerURL,
			Key:  []interface{}{jwkMap},
		},
		Action: &authzen.Action{
			Name: "credential-issuer",
		},
	}

	resp, err := r.cfg.TrustEvaluator.Evaluate(ctx, req)
	if err != nil {
		return fmt.Errorf("trust evaluation error: %w", err)
	}
	if !resp.Decision {
		return fmt.Errorf("signing key not trusted as credential issuer")
	}
	return nil
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

func (r *Resolver) getCachedEntry(issuerURL string) *cachedEntry {
	r.mu.RLock()
	defer r.mu.RUnlock()
	entry, ok := r.cache[issuerURL]
	if !ok || time.Since(entry.fetchedAt) > r.cfg.CacheTTL {
		return nil
	}
	return entry
}

func deepCopyMap(m map[string]interface{}) map[string]interface{} {
	b, err := json.Marshal(m)
	if err != nil {
		return nil
	}
	var result map[string]interface{}
	if err := json.Unmarshal(b, &result); err != nil {
		return nil
	}
	return result
}

func (r *Resolver) setCache(issuerURL string, parsed map[string]interface{}, validated bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.cache[issuerURL] = &cachedEntry{
		parsed:    parsed,
		fetchedAt: time.Now(),
		validated: validated,
	}
}
