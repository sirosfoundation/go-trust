// Package didjwks implements a trust registry for the did:jwks DID method.
//
// The did:jwks method enables existing JWKS endpoints (used by OAuth2/OIDC providers)
// to be addressed as DID identifiers. DID documents are dynamically generated from
// the fetched JWKS, making it a purely generative method optimized for cryptographic
// verification.
//
// Resolution algorithm (per the spec):
//  1. Parse the DID to extract domain and optional path
//  2. Convert colons in path to forward slashes
//  3. Fetch JWKS: root DIDs try /.well-known/jwks.json; path DIDs try /{path}/jwks.json
//  4. If not found, attempt OAuth2/OIDC discovery for jwks_uri
//  5. Transform JWKS to DID document format
//
// Fragment matching supports both:
//   - kid: matches the "kid" field of a JWK
//   - JWK Thumbprint (RFC 7638): SHA-256 based canonical key fingerprint
//
// Spec: https://github.com/catena-labs/did-jwks/blob/main/SPEC.md
package didjwks

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/sirosfoundation/go-trust/pkg/authzen"
	"github.com/sirosfoundation/go-trust/pkg/registry"
)

// Config holds configuration for the did:jwks registry.
type Config struct {
	// Timeout is the HTTP request timeout for JWKS and discovery fetches.
	Timeout time.Duration

	// Description is a human-readable description of this registry instance.
	Description string

	// InsecureSkipVerify disables TLS certificate verification (testing only).
	InsecureSkipVerify bool

	// AllowHTTP permits HTTP (non-TLS) resolution (testing only).
	AllowHTTP bool

	// AllowPrivateIPs permits requests to private/internal networks (RFC 1918).
	// WARNING: This should only be used for testing or internal deployments.
	AllowPrivateIPs bool

	// DisableOIDCDiscovery disables the OAuth2/OIDC discovery fallback.
	DisableOIDCDiscovery bool
}

// Registry implements the TrustRegistry interface for the did:jwks method.
type Registry struct {
	httpClient           registry.HTTPClientInterface
	timeout              time.Duration
	description          string
	allowHTTP            bool
	disableOIDCDiscovery bool
}

// NewRegistry creates a new did:jwks trust registry.
//
// The registry uses SafeHTTPClient with SSRF protection that blocks requests
// to private/internal IP addresses by default. This can be overridden with
// AllowPrivateIPs for testing or internal deployments.
func NewRegistry(config Config) (*Registry, error) {
	timeout := config.Timeout
	if timeout == 0 {
		timeout = 30 * time.Second
	}

	description := config.Description
	if description == "" {
		description = "DID JWKS Method (did:jwks) Registry"
	}

	// Use SafeHTTPClient with SSRF protection
	// See ADR 0012: SSRF Mitigation Strategy
	httpClient := registry.NewSafeHTTPClient(registry.SafeClientConfig{
		Timeout:            timeout,
		AllowHTTP:          config.AllowHTTP,
		AllowPrivateIPs:    config.AllowPrivateIPs,
		InsecureSkipVerify: config.InsecureSkipVerify,
	})

	return &Registry{
		httpClient:           httpClient,
		timeout:              timeout,
		description:          description,
		allowHTTP:            config.AllowHTTP,
		disableOIDCDiscovery: config.DisableOIDCDiscovery,
	}, nil
}

// Evaluate implements TrustRegistry.Evaluate by resolving did:jwks DIDs and validating key bindings.
//
// For resolution-only requests, returns the generated DID document in trust_metadata.
// For full evaluation, matches the provided key against the JWKS using both kid and
// JWK thumbprint fragment matching.
func (r *Registry) Evaluate(ctx context.Context, req *authzen.EvaluationRequest) (*authzen.EvaluationResponse, error) {
	startTime := time.Now()

	// Validate that subject.id is a did:jwks identifier
	if !strings.HasPrefix(req.Subject.ID, "did:jwks:") {
		return &authzen.EvaluationResponse{
			Decision: false,
			Context: &authzen.EvaluationResponseContext{
				Reason: map[string]interface{}{
					"error": fmt.Sprintf("subject.id must be a did:jwks identifier, got: %s", req.Subject.ID),
				},
			},
		}, nil
	}

	// Extract base DID and optional fragment
	baseDID, fragment := splitFragment(req.Subject.ID)

	// Parse DID to extract domain and path
	domain, pathSegment, err := parseDID(baseDID)
	if err != nil {
		return denyResponse("invalid did:jwks identifier: "+err.Error(), startTime), nil
	}

	// Resolve JWKS
	jwks, err := r.resolveJWKS(ctx, domain, pathSegment)
	if err != nil {
		return denyResponse(fmt.Sprintf("failed to resolve JWKS: %v", err), startTime), nil
	}

	// Build the DID document from the JWKS
	didDoc, err := buildDIDDocument(baseDID, jwks)
	if err != nil {
		return denyResponse(fmt.Sprintf("failed to build DID document: %v", err), startTime), nil
	}

	// Check policy constraints from request context
	if denial := checkPolicyConstraints(req, domain, startTime); denial != nil {
		return denial, nil
	}

	// Resolution-only request
	if req.IsResolutionOnlyRequest() {
		return buildResolutionOnlyResponse(didDoc, startTime), nil
	}

	// Full trust evaluation: match key against verification methods
	matched, matchedMethod := matchKey(req, didDoc, fragment)
	if !matched {
		return &authzen.EvaluationResponse{
			Decision: false,
			Context: &authzen.EvaluationResponseContext{
				Reason: map[string]interface{}{
					"error":                "no matching verification method found in DID document",
					"verification_methods": len(didDoc.VerificationMethod),
					"fragment":             fragment,
					"resolution_ms":        time.Since(startTime).Milliseconds(),
				},
			},
		}, nil
	}

	return &authzen.EvaluationResponse{
		Decision: true,
		Context: &authzen.EvaluationResponseContext{
			Reason: map[string]interface{}{
				"did":                  didDoc.ID,
				"verification_method":  matchedMethod.ID,
				"key_type":             matchedMethod.Type,
				"resolution_ms":        time.Since(startTime).Milliseconds(),
				"verification_methods": len(didDoc.VerificationMethod),
			},
			TrustMetadata: didDocToTrustMetadata(didDoc),
		},
	}, nil
}

// SupportedResourceTypes returns the resource types this registry can handle.
func (r *Registry) SupportedResourceTypes() []string {
	return []string{"jwk"}
}

// SupportsResolutionOnly returns true — did:jwks supports DID document resolution.
func (r *Registry) SupportsResolutionOnly() bool {
	return true
}

// Info returns metadata about this registry instance.
func (r *Registry) Info() registry.RegistryInfo {
	return registry.RegistryInfo{
		Name:        "didjwks-registry",
		Type:        "did:jwks",
		Description: r.description,
		Version:     "1.0.0",
		TrustAnchors: []string{
			"HTTPS/TLS certificate validation",
			"Domain-based trust (did:jwks method)",
		},
		ResourceTypes:  []string{"jwk"},
		ResolutionOnly: true,
		Healthy:        r.Healthy(),
	}
}

// Healthy returns true if the registry is operational.
func (r *Registry) Healthy() bool {
	return r.httpClient != nil
}

// Refresh is a no-op for did:jwks since JWKS are resolved on-demand.
func (r *Registry) Refresh(_ context.Context) error {
	return nil
}

// SetHTTPClient allows overriding the HTTP client (for testing).
func (r *Registry) SetHTTPClient(client *http.Client) {
	r.httpClient = client
}

// --- DID Parsing ---

// parseDID extracts domain and optional path from a did:jwks identifier.
// did:jwks:example.com => ("example.com", "")
// did:jwks:example.com:api:v1 => ("example.com", "api/v1")
func parseDID(did string) (domain, path string, err error) {
	if !strings.HasPrefix(did, "did:jwks:") {
		return "", "", fmt.Errorf("not a did:jwks identifier")
	}
	methodSpecific := strings.TrimPrefix(did, "did:jwks:")
	if methodSpecific == "" {
		return "", "", fmt.Errorf("empty method-specific identifier")
	}

	// Handle percent-encoded port colons
	methodSpecific = strings.ReplaceAll(methodSpecific, "%3A", "___PORT___")
	methodSpecific = strings.ReplaceAll(methodSpecific, "%3a", "___PORT___")

	parts := strings.Split(methodSpecific, ":")
	domain = strings.ReplaceAll(parts[0], "___PORT___", ":")

	if len(parts) > 1 {
		pathParts := make([]string, 0, len(parts)-1)
		for _, part := range parts[1:] {
			cleaned := strings.ReplaceAll(part, "___PORT___", ":")
			if cleaned != "" {
				pathParts = append(pathParts, cleaned)
			}
		}
		path = strings.Join(pathParts, "/")
	}

	return domain, path, nil
}

// splitFragment splits a DID into base DID and fragment.
// "did:jwks:example.com#key-1" => ("did:jwks:example.com", "key-1")
func splitFragment(did string) (baseDID, fragment string) {
	if idx := strings.Index(did, "#"); idx != -1 {
		return did[:idx], did[idx+1:]
	}
	return did, ""
}

// --- JWKS Resolution ---

// resolveJWKS fetches the JWKS for a did:jwks identifier.
// First tries direct JWKS endpoint, then falls back to OAuth2/OIDC discovery.
func (r *Registry) resolveJWKS(ctx context.Context, domain, path string) (*JWKS, error) {
	scheme := "https"
	if r.allowHTTP {
		scheme = "http"
	}

	// Step 1: Try direct JWKS endpoint
	jwksURL := buildJWKSURL(scheme, domain, path)
	jwks, err := r.fetchJWKS(ctx, jwksURL)
	if err == nil {
		return jwks, nil
	}

	// Step 2: If OIDC discovery is not disabled, try OAuth2/OIDC discovery fallback
	if !r.disableOIDCDiscovery {
		discoveryURL := buildDiscoveryURL(scheme, domain, path)
		jwksURI, discErr := r.fetchDiscoveryJWKSURI(ctx, discoveryURL)
		if discErr == nil && jwksURI != "" {
			jwks, fetchErr := r.fetchJWKS(ctx, jwksURI)
			if fetchErr == nil {
				return jwks, nil
			}
			return nil, fmt.Errorf("JWKS fetch from discovered URI %s failed: %w (direct: %v)", jwksURI, fetchErr, err)
		}
	}

	return nil, fmt.Errorf("JWKS not found at %s (discovery also failed): %w", jwksURL, err)
}

// buildJWKSURL constructs the direct JWKS endpoint URL.
// Root DIDs: https://{domain}/.well-known/jwks.json
// Path DIDs: https://{domain}/{path}/jwks.json
func buildJWKSURL(scheme, domain, path string) string {
	if path == "" {
		return fmt.Sprintf("%s://%s/.well-known/jwks.json", scheme, domain)
	}
	return fmt.Sprintf("%s://%s/%s/jwks.json", scheme, domain, path)
}

// buildDiscoveryURL constructs the OIDC discovery URL.
// Root DIDs: https://{domain}/.well-known/openid-configuration
// Path DIDs (RFC 8414): https://{domain}/.well-known/openid-configuration/{path}
func buildDiscoveryURL(scheme, domain, path string) string {
	if path == "" {
		return fmt.Sprintf("%s://%s/.well-known/openid-configuration", scheme, domain)
	}
	return fmt.Sprintf("%s://%s/.well-known/openid-configuration/%s", scheme, domain, path)
}

// fetchJWKS fetches and parses a JWKS from the given URL.
func (r *Registry) fetchJWKS(ctx context.Context, jwksURL string) (*JWKS, error) {
	// Validate URL
	parsed, err := url.Parse(jwksURL)
	if err != nil {
		return nil, fmt.Errorf("invalid JWKS URL: %w", err)
	}
	if !r.allowHTTP && parsed.Scheme != "https" {
		return nil, fmt.Errorf("JWKS URL must use HTTPS: %s", jwksURL)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, jwksURL, nil)
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
		return nil, fmt.Errorf("HTTP %d from %s", resp.StatusCode, jwksURL)
	}

	body, err := registry.ReadLimitedBody(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading response: %w", err)
	}

	var jwks JWKS
	if err := json.Unmarshal(body, &jwks); err != nil {
		return nil, fmt.Errorf("parsing JWKS: %w", err)
	}

	if len(jwks.Keys) == 0 {
		return nil, fmt.Errorf("JWKS contains no keys")
	}

	return &jwks, nil
}

// fetchDiscoveryJWKSURI fetches an OIDC discovery document and extracts jwks_uri.
func (r *Registry) fetchDiscoveryJWKSURI(ctx context.Context, discoveryURL string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, discoveryURL, nil)
	if err != nil {
		return "", fmt.Errorf("creating request: %w", err)
	}
	req.Header.Set("Accept", "application/json")

	resp, err := r.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("HTTP request failed: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("HTTP %d from %s", resp.StatusCode, discoveryURL)
	}

	body, err := registry.ReadLimitedBody(resp.Body)
	if err != nil {
		return "", fmt.Errorf("reading response: %w", err)
	}

	var discovery struct {
		JWKSURI string `json:"jwks_uri"`
	}
	if err := json.Unmarshal(body, &discovery); err != nil {
		return "", fmt.Errorf("parsing discovery document: %w", err)
	}

	if discovery.JWKSURI == "" {
		return "", fmt.Errorf("no jwks_uri in discovery document")
	}

	// Validate that jwks_uri uses HTTPS (unless testing)
	if !r.allowHTTP {
		parsed, err := url.Parse(discovery.JWKSURI)
		if err != nil || parsed.Scheme != "https" {
			return "", fmt.Errorf("jwks_uri must use HTTPS: %s", discovery.JWKSURI)
		}
	}

	return discovery.JWKSURI, nil
}

// --- DID Document Generation ---

// JWKS represents a JSON Web Key Set.
type JWKS struct {
	Keys []map[string]interface{} `json:"keys"`
}

// DIDDocument represents a generated W3C DID Document for did:jwks.
type DIDDocument struct {
	Context            interface{}          `json:"@context"`
	ID                 string               `json:"id"`
	VerificationMethod []VerificationMethod `json:"verificationMethod,omitempty"`
	Authentication     []string             `json:"authentication,omitempty"`
	AssertionMethod    []string             `json:"assertionMethod,omitempty"`
	KeyAgreement       []string             `json:"keyAgreement,omitempty"`
}

// VerificationMethod represents a verification method in the DID document.
type VerificationMethod struct {
	ID           string                 `json:"id"`
	Type         string                 `json:"type"`
	Controller   string                 `json:"controller"`
	PublicKeyJwk map[string]interface{} `json:"publicKeyJwk"`
	// kid is the original "kid" from the JWK, stored for fragment matching.
	Kid string `json:"-"`
	// thumbprint is the RFC 7638 JWK thumbprint, used as fragment identifier.
	Thumbprint string `json:"-"`
}

// buildDIDDocument generates a DID document from a JWKS per the did:jwks spec.
func buildDIDDocument(did string, jwks *JWKS) (*DIDDocument, error) {
	doc := &DIDDocument{
		Context: "https://www.w3.org/ns/did/v1",
		ID:      did,
	}

	for _, jwk := range jwks.Keys {
		thumbprint, err := jwkThumbprint(jwk)
		if err != nil {
			// Skip keys we can't compute a thumbprint for
			continue
		}

		// The fragment is the thumbprint per the spec
		vmID := fmt.Sprintf("%s#%s", did, thumbprint)

		kid, _ := jwk["kid"].(string)

		vm := VerificationMethod{
			ID:           vmID,
			Type:         "JsonWebKey",
			Controller:   did,
			PublicKeyJwk: jwk,
			Kid:          kid,
			Thumbprint:   thumbprint,
		}

		doc.VerificationMethod = append(doc.VerificationMethod, vm)

		// Per spec: keys with use:"sig" (or unspecified) go to authentication + assertionMethod.
		// Keys with use:"enc" go to keyAgreement.
		use, _ := jwk["use"].(string)
		switch use {
		case "enc":
			doc.KeyAgreement = append(doc.KeyAgreement, vmID)
		default:
			// "sig" or unspecified → authentication + assertionMethod
			doc.Authentication = append(doc.Authentication, vmID)
			doc.AssertionMethod = append(doc.AssertionMethod, vmID)
		}
	}

	if len(doc.VerificationMethod) == 0 {
		return nil, fmt.Errorf("no usable keys in JWKS")
	}

	return doc, nil
}

// --- Fragment Matching ---

// matchKey attempts to match the request's key against verification methods in the DID document.
// If a fragment is specified, it first tries to match by kid, then by JWK thumbprint.
// If no fragment, falls back to JWK key material comparison.
func matchKey(req *authzen.EvaluationRequest, doc *DIDDocument, fragment string) (bool, *VerificationMethod) {
	if req.Resource.Type != "jwk" || len(req.Resource.Key) == 0 {
		return false, nil
	}

	requestJWK, ok := req.Resource.Key[0].(map[string]interface{})
	if !ok {
		return false, nil
	}

	// If a fragment is specified, try to match by fragment first
	if fragment != "" {
		for i := range doc.VerificationMethod {
			vm := &doc.VerificationMethod[i]

			// Match by kid
			if vm.Kid != "" && vm.Kid == fragment {
				// Verify key material also matches
				if registry.JWKsMatch(requestJWK, vm.PublicKeyJwk) {
					return true, vm
				}
			}

			// Match by thumbprint
			if vm.Thumbprint == fragment {
				if registry.JWKsMatch(requestJWK, vm.PublicKeyJwk) {
					return true, vm
				}
			}
		}
	}

	// Fallback: match by key material comparison (no fragment or fragment didn't match)
	for i := range doc.VerificationMethod {
		vm := &doc.VerificationMethod[i]
		if registry.JWKsMatch(requestJWK, vm.PublicKeyJwk) {
			return true, vm
		}
	}

	return false, nil
}

// --- JWK Thumbprint (RFC 7638) ---

// jwkThumbprint computes the RFC 7638 JWK Thumbprint (SHA-256) for a JWK.
// The thumbprint is computed from the canonical JWK representation with only
// the required members for the key type, sorted lexicographically.
func jwkThumbprint(jwk map[string]interface{}) (string, error) {
	kty, ok := jwk["kty"].(string)
	if !ok {
		return "", fmt.Errorf("missing kty")
	}

	// Build the canonical representation with only required members per RFC 7638
	var requiredKeys []string
	switch kty {
	case "EC":
		requiredKeys = []string{"crv", "kty", "x", "y"}
	case "RSA":
		requiredKeys = []string{"e", "kty", "n"}
	case "OKP":
		requiredKeys = []string{"crv", "kty", "x"}
	case "oct":
		requiredKeys = []string{"k", "kty"}
	default:
		return "", fmt.Errorf("unsupported key type: %s", kty)
	}

	// Sort is already lexicographic since we define them in order above,
	// but sort explicitly for correctness
	sort.Strings(requiredKeys)

	// Build canonical JSON object with only required members
	canonical := make(map[string]interface{}, len(requiredKeys))
	for _, key := range requiredKeys {
		val, exists := jwk[key]
		if !exists {
			return "", fmt.Errorf("missing required member %q for key type %s", key, kty)
		}
		canonical[key] = val
	}

	// Marshal with sorted keys
	jsonBytes, err := marshalSorted(canonical, requiredKeys)
	if err != nil {
		return "", fmt.Errorf("encoding canonical JWK: %w", err)
	}

	hash := sha256.Sum256(jsonBytes)
	return base64.RawURLEncoding.EncodeToString(hash[:]), nil
}

// marshalSorted produces JSON with keys in the specified order.
// RFC 7638 requires lexicographic ordering of members.
func marshalSorted(obj map[string]interface{}, sortedKeys []string) ([]byte, error) {
	var buf []byte
	buf = append(buf, '{')
	for i, key := range sortedKeys {
		if i > 0 {
			buf = append(buf, ',')
		}
		keyJSON, err := json.Marshal(key)
		if err != nil {
			return nil, err
		}
		valJSON, err := json.Marshal(obj[key])
		if err != nil {
			return nil, err
		}
		buf = append(buf, keyJSON...)
		buf = append(buf, ':')
		buf = append(buf, valJSON...)
	}
	buf = append(buf, '}')
	return buf, nil
}

// --- Response Helpers ---

func denyResponse(reason string, startTime time.Time) *authzen.EvaluationResponse {
	return &authzen.EvaluationResponse{
		Decision: false,
		Context: &authzen.EvaluationResponseContext{
			Reason: map[string]interface{}{
				"error":         reason,
				"resolution_ms": time.Since(startTime).Milliseconds(),
			},
		},
	}
}

func buildResolutionOnlyResponse(doc *DIDDocument, startTime time.Time) *authzen.EvaluationResponse {
	return &authzen.EvaluationResponse{
		Decision: true,
		Context: &authzen.EvaluationResponseContext{
			Reason: map[string]interface{}{
				"did":                  doc.ID,
				"resolution_only":      true,
				"resolution_ms":        time.Since(startTime).Milliseconds(),
				"verification_methods": len(doc.VerificationMethod),
			},
			TrustMetadata: didDocToTrustMetadata(doc),
		},
	}
}

func didDocToTrustMetadata(doc *DIDDocument) map[string]interface{} {
	meta := map[string]interface{}{
		"@context": doc.Context,
		"id":       doc.ID,
	}

	if len(doc.VerificationMethod) > 0 {
		vms := make([]map[string]interface{}, len(doc.VerificationMethod))
		for i, vm := range doc.VerificationMethod {
			vms[i] = map[string]interface{}{
				"id":           vm.ID,
				"type":         vm.Type,
				"controller":   vm.Controller,
				"publicKeyJwk": vm.PublicKeyJwk,
			}
		}
		meta["verificationMethod"] = vms
	}

	if len(doc.Authentication) > 0 {
		meta["authentication"] = doc.Authentication
	}
	if len(doc.AssertionMethod) > 0 {
		meta["assertionMethod"] = doc.AssertionMethod
	}
	if len(doc.KeyAgreement) > 0 {
		meta["keyAgreement"] = doc.KeyAgreement
	}

	return meta
}

// checkPolicyConstraints checks domain-based policy constraints from request context.
func checkPolicyConstraints(req *authzen.EvaluationRequest, domain string, startTime time.Time) *authzen.EvaluationResponse {
	if req.Context == nil {
		return nil
	}

	// Check allowed_domains
	if allowedDomains := extractStringSlice(req.Context, "allowed_domains"); len(allowedDomains) > 0 {
		if !matchesDomain(domain, allowedDomains) {
			return &authzen.EvaluationResponse{
				Decision: false,
				Context: &authzen.EvaluationResponseContext{
					Reason: map[string]interface{}{
						"error":           "DID domain not in allowed domains for this role",
						"domain":          domain,
						"allowed_domains": allowedDomains,
						"resolution_ms":   time.Since(startTime).Milliseconds(),
					},
				},
			}
		}
	}

	return nil
}

func extractStringSlice(ctx map[string]interface{}, key string) []string {
	v, ok := ctx[key]
	if !ok {
		return nil
	}
	switch s := v.(type) {
	case []string:
		return s
	case []interface{}:
		result := make([]string, 0, len(s))
		for _, item := range s {
			if str, ok := item.(string); ok {
				result = append(result, str)
			}
		}
		return result
	}
	return nil
}

func matchesDomain(domain string, allowedDomains []string) bool {
	for _, allowed := range allowedDomains {
		if allowed == domain {
			return true
		}
		if strings.HasPrefix(allowed, "*.") {
			suffix := allowed[1:]
			if strings.HasSuffix(domain, suffix) && domain != suffix[1:] {
				return true
			}
		}
	}
	return false
}
