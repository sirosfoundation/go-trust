package static

import (
	"context"
	"crypto/x509"
	"fmt"
	"sync"
	"time"

	"github.com/sirosfoundation/g119612/pkg/utils/x509util"
	"github.com/sirosfoundation/go-trust/pkg/authzen"
	"github.com/sirosfoundation/go-trust/pkg/registry"
)

// SystemCertPoolRegistry is a TrustRegistry that validates X.509 certificates
// against the operating system's root certificate pool. This provides basic
// trust validation using the CA certificates installed on the system.
//
// This is useful for deployments that want simple X.509 validation without
// the complexity of ETSI Trust Status Lists or other frameworks.
//
// Limitations:
//   - Does not check certificate revocation (CRL/OCSP)
//   - Does not enforce specific trust frameworks or service types
//   - Trust is based solely on the system CA bundle
type SystemCertPoolRegistry struct {
	name        string
	description string
	certPool    *x509.CertPool
	loadedAt    time.Time
	mu          sync.RWMutex
	healthy     bool
	lastError   error
}

// SystemCertPoolConfig provides configuration for SystemCertPoolRegistry.
type SystemCertPoolConfig struct {
	// Name is a human-readable identifier for this registry
	Name string

	// Description provides additional context about this registry
	Description string
}

// NewSystemCertPoolRegistry creates a new registry that uses the system
// certificate pool for X.509 validation.
func NewSystemCertPoolRegistry(cfg SystemCertPoolConfig) (*SystemCertPoolRegistry, error) {
	if cfg.Name == "" {
		cfg.Name = "system-cert-pool"
	}
	if cfg.Description == "" {
		cfg.Description = "System X.509 certificate pool"
	}

	r := &SystemCertPoolRegistry{
		name:        cfg.Name,
		description: cfg.Description,
	}

	if err := r.loadSystemCertPool(); err != nil {
		return nil, err
	}

	return r, nil
}

// loadSystemCertPool loads the system's root certificate pool.
func (r *SystemCertPoolRegistry) loadSystemCertPool() error {
	r.mu.Lock()
	defer r.mu.Unlock()

	pool, err := x509.SystemCertPool()
	if err != nil {
		r.lastError = fmt.Errorf("failed to load system cert pool: %w", err)
		r.healthy = false
		return r.lastError
	}

	if pool == nil {
		r.lastError = fmt.Errorf("system cert pool is nil (unsupported on this platform)")
		r.healthy = false
		return r.lastError
	}

	r.certPool = pool
	r.loadedAt = time.Now()
	r.healthy = true
	r.lastError = nil

	return nil
}

// Evaluate validates X.509 certificates against the system certificate pool.
func (r *SystemCertPoolRegistry) Evaluate(ctx context.Context, req *authzen.EvaluationRequest) (*authzen.EvaluationResponse, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	// Check if this is a resolution-only request
	if req.IsResolutionOnlyRequest() {
		return &authzen.EvaluationResponse{
			Decision: false,
			Context: &authzen.EvaluationResponseContext{
				Reason: map[string]interface{}{
					"error": "system cert pool registry does not support resolution-only requests",
				},
			},
		}, nil
	}

	// Parse certificates from request
	var certs []*x509.Certificate
	var parseErr error

	switch req.Resource.Type {
	case "x5c":
		certs, parseErr = x509util.ParseX5CFromArray(req.Resource.Key)
	case "jwk":
		certs, parseErr = x509util.ParseX5CFromJWK(req.Resource.Key)
	default:
		return &authzen.EvaluationResponse{
			Decision: false,
			Context: &authzen.EvaluationResponseContext{
				Reason: map[string]interface{}{
					"error": fmt.Sprintf("unsupported resource type: %s (expected x5c or jwk)", req.Resource.Type),
				},
			},
		}, nil
	}

	if parseErr != nil {
		return &authzen.EvaluationResponse{
			Decision: false,
			Context: &authzen.EvaluationResponseContext{
				Reason: map[string]interface{}{
					"error": parseErr.Error(),
				},
			},
		}, nil
	}

	if len(certs) == 0 {
		return &authzen.EvaluationResponse{
			Decision: false,
			Context: &authzen.EvaluationResponseContext{
				Reason: map[string]interface{}{
					"error": "no certificates found in resource.key",
				},
			},
		}, nil
	}

	// Validate certificate chain against system cert pool
	if r.certPool == nil {
		return &authzen.EvaluationResponse{
			Decision: false,
			Context: &authzen.EvaluationResponseContext{
				Reason: map[string]interface{}{
					"error": "certificate pool not initialized",
				},
			},
		}, nil
	}

	start := time.Now()
	opts := x509.VerifyOptions{
		Roots: r.certPool,
		// ExtKeyUsageAny: WRPACs may carry only id-kp-clientAuth.
		// Go's zero-value KeyUsages defaults to ExtKeyUsageServerAuth.
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}

	// Add intermediate certificates if provided
	if len(certs) > 1 {
		intermediates := x509.NewCertPool()
		for _, cert := range certs[1:] {
			intermediates.AddCert(cert)
		}
		opts.Intermediates = intermediates
	}

	chains, err := certs[0].Verify(opts)
	validationDuration := time.Since(start)

	if err != nil {
		return &authzen.EvaluationResponse{
			Decision: false,
			Context: &authzen.EvaluationResponseContext{
				Reason: map[string]interface{}{
					"error":         err.Error(),
					"validation_ms": validationDuration.Milliseconds(),
				},
			},
		}, nil
	}

	// Success - certificate is trusted
	return &authzen.EvaluationResponse{
		Decision: true,
		Context: &authzen.EvaluationResponseContext{
			Reason: map[string]interface{}{
				"registry":      r.name,
				"type":          "system_cert_pool",
				"validation_ms": validationDuration.Milliseconds(),
				"chain_length":  len(chains),
				"data_loaded":   r.loadedAt.Format(time.RFC3339),
			},
		},
	}, nil
}

// SupportedResourceTypes returns the resource types this registry can handle.
func (r *SystemCertPoolRegistry) SupportedResourceTypes() []string {
	return []string{"x5c", "jwk"}
}

// SupportsResolutionOnly returns false - this registry requires certificate validation.
func (r *SystemCertPoolRegistry) SupportsResolutionOnly() bool {
	return false
}

// Info returns metadata about this registry.
func (r *SystemCertPoolRegistry) Info() registry.RegistryInfo {
	r.mu.RLock()
	defer r.mu.RUnlock()

	return registry.RegistryInfo{
		Name:           r.name,
		Type:           "static_system_cert_pool",
		Description:    r.description,
		Version:        "1.0.0",
		TrustAnchors:   []string{"system"}, // Indicates system CA bundle
		ResourceTypes:  []string{"x5c", "jwk"},
		ResolutionOnly: false,
		Healthy:        r.healthy,
	}
}

// Healthy returns true if the registry is operational.
func (r *SystemCertPoolRegistry) Healthy() bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.healthy
}

// Refresh reloads the system certificate pool.
func (r *SystemCertPoolRegistry) Refresh(ctx context.Context) error {
	return r.loadSystemCertPool()
}

// Compile-time check that SystemCertPoolRegistry implements TrustRegistry
var _ registry.TrustRegistry = (*SystemCertPoolRegistry)(nil)
