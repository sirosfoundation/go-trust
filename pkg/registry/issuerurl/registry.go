// Package issuerurl implements a TrustRegistry that resolves OpenID4VCI
// issuer metadata by fetching /.well-known/openid-credential-issuer.
//
// This registry handles resolution-only requests with subject.type = "url"
// and returns the parsed issuer metadata as trust_metadata in the AuthZEN
// EvaluationResponse. The fetch+cache logic is provided by the
// pkg/issuermetadata.Resolver, which can also be imported directly by
// application code that needs issuer metadata without going through AuthZEN.
package issuerurl

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/sirosfoundation/go-trust/pkg/authzen"
	"github.com/sirosfoundation/go-trust/pkg/issuermetadata"
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

// Registry implements TrustRegistry for OpenID4VCI issuer metadata resolution.
type Registry struct {
	config   *Config
	resolver *issuermetadata.Resolver
}

// New creates a new issuer URL registry.
func New(cfg *Config) (*Registry, error) {
	if cfg == nil {
		cfg = &Config{}
	}
	if cfg.Name == "" {
		cfg.Name = "issuer-url"
	}

	resolver, err := issuermetadata.New(issuermetadata.Config{
		CacheTTL:        cfg.CacheTTL,
		HTTPTimeout:     cfg.HTTPTimeout,
		AllowHTTP:       cfg.AllowHTTP,
		AllowPrivateIPs: cfg.AllowPrivateIPs,
	})
	if err != nil {
		return nil, fmt.Errorf("creating issuermetadata resolver: %w", err)
	}

	return &Registry{
		config:   cfg,
		resolver: resolver,
	}, nil
}

// Evaluate handles issuer URL resolution requests.
// Accepts requests with subject.type = "url" and either resource.type = "credential_issuer"
// or resolution-only requests (empty resource.type). The parsed issuer metadata JSON
// object is returned as trust_metadata.
func (r *Registry) Evaluate(ctx context.Context, req *authzen.EvaluationRequest) (*authzen.EvaluationResponse, error) {
	startTime := time.Now()

	if req.Subject.Type != "url" {
		return r.denyWithReason("issuer-url registry only handles subject.type 'url'"), nil
	}

	if req.Resource.Type != "" && req.Resource.Type != "credential_issuer" {
		return r.denyWithReason("issuer-url registry only supports resource.type 'credential_issuer'"), nil
	}

	issuerURL := strings.TrimSuffix(req.Subject.ID, "/")
	if issuerURL == "" {
		return r.denyWithReason("missing issuer URL in subject.id"), nil
	}

	parsed, err := r.resolver.ResolveWithInfo(ctx, issuerURL)
	if err != nil {
		return r.denyWithReason(fmt.Sprintf("failed to fetch issuer metadata: %v", err)), nil
	}

	return &authzen.EvaluationResponse{
		Decision: true,
		Context: &authzen.EvaluationResponseContext{
			ID: issuerURL,
			Reason: map[string]interface{}{
				"resolution_only": true,
				"resolution_ms":   time.Since(startTime).Milliseconds(),
				"registry":        r.config.Name,
				"cached":          parsed.Cached,
			},
			TrustMetadata: parsed.Metadata,
		},
	}, nil
}

// SupportedResourceTypes returns the resource types this registry handles.
func (r *Registry) SupportedResourceTypes() []string {
	return []string{"credential_issuer"}
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
