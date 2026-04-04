// Package mdociaca provides an mDOC IACA (Issuing Authority Certificate Authority)
// registry for go-trust that verifies X.509 certificate chains against dynamically
// fetched IACA certificates from OpenID4VCI credential issuers.
//
// This registry implements the TrustRegistry interface and can be used alongside
// other registries (ETSI TSL, OpenID Federation, etc.) in the go-trust registry manager.
//
// # Architecture
//
// The mDOC IACA registry:
//  1. Receives trust evaluation requests with an issuer URL (subject.id) and X5C chain (resource.key)
//  2. Fetches the issuer's OpenID4VCI metadata to discover the mdoc_iacas_uri endpoint
//  3. Fetches IACA certificates from the mdoc_iacas_uri endpoint
//  4. Validates the X5C chain against the fetched IACAs
//  5. Optionally enforces issuer allowlist policy
//
// # Usage
//
//	reg, err := mdociaca.New(&mdociaca.Config{
//	    Name:            "mdoc-iaca",
//	    IssuerAllowlist: []string{"https://issuer.example.com"},
//	    CacheTTL:        time.Hour,
//	})
//
//	req := &authzen.EvaluationRequest{
//	    Subject: authzen.Subject{Type: "key", ID: "https://issuer.example.com"},
//	    Resource: authzen.Resource{Type: "x5c", Key: []interface{}{dsB64, iacaB64}},
//	}
//	resp, err := reg.Evaluate(ctx, req)
package mdociaca

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/sirosfoundation/go-cryptoutil"
	"github.com/sirosfoundation/go-trust/pkg/authzen"
	"github.com/sirosfoundation/go-trust/pkg/registry"
)

// Config holds the configuration for an mDOC IACA registry instance.
type Config struct {
	// Name is a unique identifier for this registry instance
	Name string

	// Description is a human-readable description of this registry
	Description string

	// IssuerAllowlist is an optional list of allowed issuer URLs.
	// If non-empty, only issuers in this list are trusted.
	// If empty, all issuers that publish valid IACAs are trusted.
	IssuerAllowlist []string

	// CacheTTL is how long to cache IACA certificates. Default: 1 hour.
	CacheTTL time.Duration

	// HTTPTimeout is the timeout for HTTP requests. Default: 30 seconds.
	HTTPTimeout time.Duration

	// AllowPrivateIPs permits requests to private/internal networks (RFC 1918).
	// WARNING: This should only be used for testing or internal deployments.
	AllowPrivateIPs bool

	// AllowHTTP permits non-TLS (HTTP) connections.
	// WARNING: This should only be used for testing. Production should always use HTTPS.
	AllowHTTP bool

	// CryptoExt provides extensible certificate parsing for non-standard curves
	// (e.g. brainpool). If nil, standard x509.ParseCertificate is used.
	CryptoExt *cryptoutil.Extensions
}

// IssuerMetadata represents OpenID4VCI credential issuer metadata (partial).
type IssuerMetadata struct {
	CredentialIssuer string `json:"credential_issuer"`
	MdocIacasURI     string `json:"mdoc_iacas_uri,omitempty"`
}

// IACAsResponse represents the response from an mdoc_iacas_uri endpoint.
type IACAsResponse struct {
	Iacas []IACACertificate `json:"iacas"`
}

// IACACertificate represents a single IACA certificate in the response.
type IACACertificate struct {
	Certificate string `json:"certificate"` // Base64 DER-encoded X.509 certificate
}

// cachedIACAs holds cached IACA certificates for an issuer.
type cachedIACAs struct {
	certs     []*x509.Certificate
	fetchedAt time.Time
}

// Registry implements TrustRegistry for mDOC IACA certificate validation.
type Registry struct {
	config     *Config
	httpClient registry.HTTPClientInterface
	allowlist  map[string]struct{} // Normalized issuer URLs

	mu    sync.RWMutex
	cache map[string]*cachedIACAs // issuerURL -> cached IACAs
}

// New creates a new mDOC IACA registry with the given configuration.
//
// The registry uses SafeHTTPClient with SSRF protection that blocks requests
// to private/internal IP addresses by default. This can be overridden with
// AllowPrivateIPs for testing or internal deployments.
func New(cfg *Config) (*Registry, error) {
	if cfg == nil {
		cfg = &Config{}
	}

	// Apply defaults
	if cfg.Name == "" {
		cfg.Name = "mdoc-iaca"
	}
	if cfg.CacheTTL == 0 {
		cfg.CacheTTL = time.Hour
	}
	if cfg.HTTPTimeout == 0 {
		cfg.HTTPTimeout = 30 * time.Second
	}

	// Build allowlist map for O(1) lookup
	allowlist := make(map[string]struct{})
	for _, issuer := range cfg.IssuerAllowlist {
		normalized := strings.TrimSuffix(issuer, "/")
		allowlist[normalized] = struct{}{}
	}

	// Use SafeHTTPClient with SSRF protection
	// See ADR 0012: SSRF Mitigation Strategy
	httpClient := registry.NewSafeHTTPClient(registry.SafeClientConfig{
		Timeout:         cfg.HTTPTimeout,
		AllowPrivateIPs: cfg.AllowPrivateIPs,
		AllowHTTP:       cfg.AllowHTTP,
	})

	return &Registry{
		config:     cfg,
		httpClient: httpClient,
		allowlist:  allowlist,
		cache:      make(map[string]*cachedIACAs),
	}, nil
}

// Evaluate verifies an X5C certificate chain against IACA certificates
// fetched from the issuer's mdoc_iacas_uri endpoint.
// Policy constraints from req.Context (set by the policy mapper) are also enforced:
//   - issuer_allowlist: additional issuer restrictions per-role
//   - require_iaca_endpoint: require the issuer to publish mdoc_iacas_uri
func (r *Registry) Evaluate(ctx context.Context, req *authzen.EvaluationRequest) (*authzen.EvaluationResponse, error) {
	// Extract issuer URL from subject.id
	issuerURL := req.Subject.ID
	if issuerURL == "" {
		return r.denyWithReason("missing issuer URL in subject.id"), nil
	}

	// Normalize issuer URL
	issuerURL = strings.TrimSuffix(issuerURL, "/")

	// Check static allowlist from config
	if len(r.allowlist) > 0 {
		if _, ok := r.allowlist[issuerURL]; !ok {
			return r.denyWithReason("issuer not in allowlist"), nil
		}
	}

	// Check dynamic allowlist from policy context (role-based)
	if req.Context != nil {
		if policyAllowlist := extractIssuerAllowlist(req.Context); len(policyAllowlist) > 0 {
			found := false
			for _, allowed := range policyAllowlist {
				if strings.TrimSuffix(allowed, "/") == issuerURL {
					found = true
					break
				}
			}
			if !found {
				return r.denyWithReason("issuer not in policy allowlist for this role"), nil
			}
		}
	}

	// Enforce require_iaca_endpoint policy: pre-check that issuer publishes mdoc_iacas_uri
	if req.Context != nil {
		if reqIACA, ok := req.Context["require_iaca_endpoint"].(bool); ok && reqIACA {
			metadataURL := issuerURL + "/.well-known/openid-credential-issuer"
			metadata, err := r.fetchMetadata(ctx, metadataURL)
			if err != nil {
				return r.denyWithReason(fmt.Sprintf("cannot verify IACA endpoint: %v", err)), nil
			}
			if metadata.MdocIacasURI == "" {
				return r.denyWithReason("issuer does not publish mdoc_iacas_uri (required by policy)"), nil
			}
		}
	}

	// Parse X5C chain from resource.key
	chain, err := r.parseX5CChain(req.Resource.Key)
	if err != nil {
		return r.denyWithReason(fmt.Sprintf("invalid X5C chain: %v", err)), nil
	}
	if len(chain) == 0 {
		return r.denyWithReason("empty X5C chain"), nil
	}

	// Get IACAs (from cache or fetch)
	iacas, err := r.getIACAs(ctx, issuerURL)
	if err != nil {
		return r.denyWithReason(fmt.Sprintf("failed to get IACAs: %v", err)), nil
	}
	if len(iacas) == 0 {
		return r.denyWithReason("no IACAs available from issuer"), nil
	}

	// Validate chain against IACAs
	if r.validateChain(chain, iacas) {
		return &authzen.EvaluationResponse{
			Decision: true,
			Context: &authzen.EvaluationResponseContext{
				Reason: map[string]interface{}{
					"trust_anchor": "mdoc_iaca",
					"issuer":       issuerURL,
					"iaca_count":   len(iacas),
				},
			},
		}, nil
	}

	return r.denyWithReason("certificate chain not trusted by any IACA"), nil
}

// extractIssuerAllowlist extracts issuer_allowlist from request context.
func extractIssuerAllowlist(ctx map[string]interface{}) []string {
	v, ok := ctx["issuer_allowlist"]
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

// SupportedResourceTypes returns the resource types this registry handles.
func (r *Registry) SupportedResourceTypes() []string {
	return []string{"x5c"}
}

// SupportsResolutionOnly returns false - this registry requires X5C chains.
func (r *Registry) SupportsResolutionOnly() bool {
	return false
}

// Info returns metadata about this registry instance.
func (r *Registry) Info() registry.RegistryInfo {
	return registry.RegistryInfo{
		Name:          r.config.Name,
		Type:          "mdoc_iaca",
		Description:   r.config.Description,
		Version:       "1.0.0",
		ResourceTypes: r.SupportedResourceTypes(),
	}
}

// Healthy returns true if the registry is operational.
func (r *Registry) Healthy() bool {
	return true
}

// Refresh clears the IACA cache, forcing fresh fetches on next evaluation.
func (r *Registry) Refresh(ctx context.Context) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.cache = make(map[string]*cachedIACAs)
	return nil
}

// Internal helpers

func (r *Registry) denyWithReason(reason string) *authzen.EvaluationResponse {
	return &authzen.EvaluationResponse{
		Decision: false,
		Context: &authzen.EvaluationResponseContext{
			Reason: map[string]interface{}{
				"error": reason,
			},
		},
	}
}

func (r *Registry) parseX5CChain(key interface{}) ([]*x509.Certificate, error) {
	if key == nil {
		return nil, fmt.Errorf("key is nil")
	}

	// Handle various types
	var certStrings []string

	switch v := key.(type) {
	case []interface{}:
		for _, item := range v {
			if s, ok := item.(string); ok {
				certStrings = append(certStrings, s)
			} else {
				return nil, fmt.Errorf("X5C chain element is not a string")
			}
		}
	case []string:
		certStrings = v
	default:
		return nil, fmt.Errorf("unsupported X5C chain type: %T", key)
	}

	certs := make([]*x509.Certificate, 0, len(certStrings))
	for i, b64 := range certStrings {
		der, err := base64.StdEncoding.DecodeString(b64)
		if err != nil {
			return nil, fmt.Errorf("certificate %d: invalid base64: %w", i, err)
		}
		cert, err := registry.ParseCertificate(der, r.config.CryptoExt)
		if err != nil {
			return nil, fmt.Errorf("certificate %d: invalid X.509: %w", i, err)
		}
		certs = append(certs, cert)
	}

	return certs, nil
}

func (r *Registry) getIACAs(ctx context.Context, issuerURL string) ([]*x509.Certificate, error) {
	// Check cache first
	r.mu.RLock()
	cached, ok := r.cache[issuerURL]
	r.mu.RUnlock()

	if ok && time.Since(cached.fetchedAt) < r.config.CacheTTL {
		return cached.certs, nil
	}

	// Fetch fresh IACAs
	iacas, err := r.fetchIACAs(ctx, issuerURL)
	if err != nil {
		return nil, err
	}

	// Cache the result
	r.mu.Lock()
	r.cache[issuerURL] = &cachedIACAs{
		certs:     iacas,
		fetchedAt: time.Now(),
	}
	r.mu.Unlock()

	return iacas, nil
}

func (r *Registry) fetchIACAs(ctx context.Context, issuerURL string) ([]*x509.Certificate, error) {
	// Fetch issuer metadata
	metadataURL := issuerURL + "/.well-known/openid-credential-issuer"
	metadata, err := r.fetchMetadata(ctx, metadataURL)
	if err != nil {
		return nil, fmt.Errorf("fetch metadata: %w", err)
	}

	if metadata.MdocIacasURI == "" {
		return nil, fmt.Errorf("issuer does not publish mdoc_iacas_uri")
	}

	// Fetch IACAs from the endpoint
	return r.fetchIACACerts(ctx, metadata.MdocIacasURI)
}

func (r *Registry) fetchMetadata(ctx context.Context, url string) (*IssuerMetadata, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")

	resp, err := r.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close() //nolint:errcheck // Body close error is not actionable

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("metadata endpoint returned %d", resp.StatusCode)
	}

	var metadata IssuerMetadata
	if err := json.NewDecoder(registry.LimitedReader(resp.Body)).Decode(&metadata); err != nil {
		return nil, fmt.Errorf("decode metadata: %w", err)
	}

	return &metadata, nil
}

func (r *Registry) fetchIACACerts(ctx context.Context, url string) ([]*x509.Certificate, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")

	resp, err := r.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close() //nolint:errcheck // Body close error is not actionable

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("IACA endpoint returned %d", resp.StatusCode)
	}

	var iacasResp IACAsResponse
	if err := json.NewDecoder(registry.LimitedReader(resp.Body)).Decode(&iacasResp); err != nil {
		return nil, fmt.Errorf("decode IACAs: %w", err)
	}

	certs := make([]*x509.Certificate, 0, len(iacasResp.Iacas))
	for i, iaca := range iacasResp.Iacas {
		der, err := base64.StdEncoding.DecodeString(iaca.Certificate)
		if err != nil {
			return nil, fmt.Errorf("IACA %d: invalid base64: %w", i, err)
		}
		cert, err := registry.ParseCertificate(der, r.config.CryptoExt)
		if err != nil {
			return nil, fmt.Errorf("IACA %d: invalid X.509: %w", i, err)
		}
		certs = append(certs, cert)
	}

	return certs, nil
}

func (r *Registry) validateChain(chain []*x509.Certificate, iacas []*x509.Certificate) bool {
	if len(chain) == 0 || len(iacas) == 0 {
		return false
	}

	// Build certificate pool from IACAs
	roots := x509.NewCertPool()
	for _, iaca := range iacas {
		roots.AddCert(iaca)
	}

	// Build intermediates pool from chain (excluding leaf)
	intermediates := x509.NewCertPool()
	for i := 1; i < len(chain); i++ {
		intermediates.AddCert(chain[i])
	}

	// Verify the leaf certificate
	leaf := chain[0]
	opts := x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		CurrentTime:   time.Now(),
	}

	_, err := leaf.Verify(opts)
	return err == nil
}
