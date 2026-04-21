// Package etsi provides a TrustRegistry implementation for ETSI TS 119 612 Trust Status Lists.
//
// This package provides a unified TSLRegistry that can load trust data from:
//   - Local PEM certificate bundles
//   - Local TSL XML files
//   - Remote TSL URLs (with optional reference following)
//
// The registry uses etsi119612.FetchTSLWithOptions directly without any pipeline dependency.
//
// # Usage Examples
//
//	// Load from local PEM bundle (recommended for production)
//	reg, err := etsi.NewTSLRegistry(etsi.TSLConfig{
//	    Name:       "EU-TSL",
//	    CertBundle: "/var/lib/go-trust/eu-trusted-certs.pem",
//	})
//
//	// Load from local TSL XML files
//	reg, err := etsi.NewTSLRegistry(etsi.TSLConfig{
//	    Name:     "EU-TSL",
//	    TSLFiles: []string{"/var/lib/go-trust/eu-lotl.xml"},
//	})
//
//	// Load from remote URL with reference following
//	reg, err := etsi.NewTSLRegistry(etsi.TSLConfig{
//	    Name:         "EU-LOTL",
//	    TSLURLs:      []string{"https://ec.europa.eu/tools/lotl/eu-lotl.xml"},
//	    FollowRefs:   true,
//	    MaxRefDepth:  3,
//	})
package etsi

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/sirosfoundation/g119612/pkg/etsi119612"
	"github.com/sirosfoundation/g119612/pkg/utils/x509util"
	"github.com/sirosfoundation/go-cryptoutil"
	"github.com/sirosfoundation/go-trust/pkg/authzen"
	"github.com/sirosfoundation/go-trust/pkg/registry"
)

// TSLConfig configures an ETSI TSL registry.
type TSLConfig struct {
	// Name is a human-readable identifier for this registry
	Name string

	// Description provides additional context about this registry
	Description string

	// CertBundle is the path to a PEM file containing trusted CA certificates.
	// This is the recommended way to load trust data for production use.
	CertBundle string

	// TSLFiles is a list of paths to local TSL XML files.
	// These files must already exist locally.
	TSLFiles []string

	// TSLURLs is a list of URLs to fetch TSL XML from.
	// Can be file:// URLs for local files or http(s):// URLs for remote.
	TSLURLs []string

	// FollowRefs controls whether to follow TSL references (pointers to other TSLs).
	// Only applicable when loading from TSLURLs.
	// Default: false (don't follow references)
	FollowRefs bool

	// MaxRefDepth controls how deep to follow TSL references.
	// Only used when FollowRefs is true.
	// Default: 3
	MaxRefDepth int

	// FetchTimeout is the timeout for HTTP requests when fetching remote TSLs.
	// Default: 30 seconds
	FetchTimeout time.Duration

	// UserAgent is the User-Agent header for HTTP requests.
	// Default: "Go-Trust/1.0 TSL Registry"
	UserAgent string

	// AllowNetworkAccess controls whether network URLs are permitted.
	// Set to false for production servers that should only use local files.
	// Default: false
	AllowNetworkAccess bool

	// LOTLSignerBundle is the path to a PEM file containing trusted LOTL signer certificates.
	// When set, TSL signatures will be verified against these certificates.
	// This implements ETSI TS 119 615 LOTL signature validation.
	LOTLSignerBundle string

	// RequireSignature controls whether TSLs must have valid signatures.
	// When true, unsigned TSLs or TSLs with invalid signatures will be rejected.
	// When false, signature verification is opportunistic (verify if signer certs are configured).
	// Default: false
	RequireSignature bool

	// FollowPivots controls whether to process ETSI TS 119 615 pivot LOTLs
	// for signer certificate rollover. When true and signature verification fails
	// because the signer is unknown, the registry will fetch pivot LOTLs from
	// SchemeInformationURI to discover new trusted signers.
	// Requires AllowNetworkAccess=true since pivots must be fetched remotely.
	// Default: false
	FollowPivots bool

	// CryptoExt provides extensible certificate parsing for non-standard curves
	// (e.g. brainpool). If nil, standard x509.ParseCertificate is used.
	CryptoExt *cryptoutil.Extensions

	// RefreshInterval is how often to re-fetch TSL data. Zero disables.
	RefreshInterval time.Duration

	// Logger for structured logging. May be nil.
	Logger *slog.Logger
}

// TSLRegistry implements TrustRegistry for ETSI TS 119 612 Trust Status Lists.
// It loads TSL data directly using etsi119612.FetchTSLWithOptions without pipeline dependency.
type TSLRegistry struct {
	config      TSLConfig
	certPool    *x509.CertPool
	certCount   int
	tsls        []*etsi119612.TSL
	loadedAt    time.Time
	sourceFiles []string
	lotlSigners []*x509.Certificate // LOTL signer certificates for signature verification
	mu          sync.RWMutex
	healthy     bool
	lastError   error

	stopCh chan struct{}
}

// NewTSLRegistry creates a new ETSI TSL registry.
// It loads trust data from the configured sources (cert bundles, local files, or URLs).
func NewTSLRegistry(cfg TSLConfig) (*TSLRegistry, error) {
	if cfg.Name == "" {
		cfg.Name = "ETSI-TSL"
	}
	if cfg.Description == "" {
		cfg.Description = "ETSI TS 119 612 Trust Status List Registry"
	}
	if cfg.MaxRefDepth == 0 {
		cfg.MaxRefDepth = 3
	}
	if cfg.FetchTimeout == 0 {
		cfg.FetchTimeout = 30 * time.Second
	}
	if cfg.UserAgent == "" {
		cfg.UserAgent = "Go-Trust/1.0 TSL Registry (+https://github.com/sirosfoundation/go-trust)"
	}

	r := &TSLRegistry{
		config: cfg,
		stopCh: make(chan struct{}),
	}

	if err := r.load(); err != nil {
		return nil, fmt.Errorf("failed to load trust data: %w", err)
	}

	return r, nil
}

// load reads trust data from configured sources.
// I/O and parsing are performed without holding the lock; the lock is only
// held briefly to swap in the new state, so Evaluate/Info/Healthy are not
// blocked during network or file fetches.
func (r *TSLRegistry) load() error {
	var pool *x509.CertPool
	var certCount int
	var tsls []*etsi119612.TSL
	var sourceFiles []string
	var lotlSigners []*x509.Certificate

	// Load LOTL signer certificates if configured
	if r.config.LOTLSignerBundle != "" {
		signers, err := r.loadLOTLSignerBundle(r.config.LOTLSignerBundle)
		if err != nil {
			err = fmt.Errorf("failed to load LOTL signer bundle: %w", err)
			r.setError(err)
			return err
		}
		lotlSigners = signers
	}

	// Load from PEM certificate bundle
	if r.config.CertBundle != "" {
		p, count, err := r.loadCertBundle(r.config.CertBundle)
		if err != nil {
			r.setError(err)
			return err
		}
		pool = p
		certCount = count
		absPath, _ := filepath.Abs(r.config.CertBundle)
		sourceFiles = append(sourceFiles, absPath)
	}

	// Load from local TSL XML files
	for _, tslPath := range r.config.TSLFiles {
		// Reject network URLs in TSLFiles
		if strings.HasPrefix(tslPath, "http://") || strings.HasPrefix(tslPath, "https://") {
			err := fmt.Errorf("network URLs not allowed in TSLFiles: %s", tslPath)
			r.setError(err)
			return err
		}

		tsl, certs, err := r.loadLocalTSL(tslPath)
		if err != nil {
			r.setError(err)
			return err
		}

		// Verify TSL signature if LOTL signers are configured
		updatedSigners, err := r.verifyTSLSignature(tsl, lotlSigners)
		if err != nil {
			r.setError(err)
			return err
		}
		lotlSigners = updatedSigners

		tsls = append(tsls, tsl)
		absPath, _ := filepath.Abs(tslPath)
		sourceFiles = append(sourceFiles, absPath)

		if pool == nil {
			pool = x509.NewCertPool()
		}
		for _, cert := range certs {
			pool.AddCert(cert)
			certCount++
		}
	}

	// Load from TSL URLs (local file:// or remote http(s)://)
	for _, tslURL := range r.config.TSLURLs {
		// Check if network access is allowed
		if !r.config.AllowNetworkAccess {
			if strings.HasPrefix(tslURL, "http://") || strings.HasPrefix(tslURL, "https://") {
				err := fmt.Errorf("network URL not allowed (AllowNetworkAccess=false): %s", tslURL)
				r.setError(err)
				return err
			}
		}

		loadedTSLs, certs, err := r.loadTSLFromURL(tslURL)
		if err != nil {
			r.setError(err)
			return err
		}

		// Verify TSL signatures if LOTL signers are configured
		for _, tsl := range loadedTSLs {
			updatedSigners, err := r.verifyTSLSignature(tsl, lotlSigners)
			if err != nil {
				r.setError(err)
				return err
			}
			lotlSigners = updatedSigners
		}

		tsls = append(tsls, loadedTSLs...)
		sourceFiles = append(sourceFiles, tslURL)

		if pool == nil {
			pool = x509.NewCertPool()
		}
		for _, cert := range certs {
			pool.AddCert(cert)
			certCount++
		}
	}

	// Verify we have some trust data
	if pool == nil || certCount == 0 {
		err := fmt.Errorf("no trust data loaded - configure CertBundle, TSLFiles, or TSLURLs")
		r.setError(err)
		return err
	}

	// Swap in new state under the lock
	r.mu.Lock()
	r.certPool = pool
	r.certCount = certCount
	r.tsls = tsls
	r.sourceFiles = sourceFiles
	r.lotlSigners = lotlSigners
	r.loadedAt = time.Now()
	r.healthy = true
	r.lastError = nil
	r.mu.Unlock()

	return nil
}

// setError records a load failure under the lock.
func (r *TSLRegistry) setError(err error) {
	r.mu.Lock()
	r.lastError = err
	r.healthy = false
	r.mu.Unlock()
}

// loadCertBundle reads certificates from a PEM file.
func (r *TSLRegistry) loadCertBundle(path string) (*x509.CertPool, int, error) {
	absPath, err := filepath.Abs(path)
	if err != nil {
		return nil, 0, fmt.Errorf("invalid cert bundle path: %w", err)
	}

	pemData, err := os.ReadFile(absPath)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to read cert bundle %s: %w", absPath, err)
	}

	pool := x509.NewCertPool()
	var certCount int
	var block *pem.Block
	rest := pemData
	for {
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type == "CERTIFICATE" {
			cert, err := registry.ParseCertificate(block.Bytes, r.config.CryptoExt)
			if err != nil {
				// Log warning but continue - one bad cert shouldn't fail the whole bundle
				continue
			}
			pool.AddCert(cert)
			certCount++
		}
	}

	if certCount == 0 {
		return nil, 0, fmt.Errorf("no valid certificates found in %s", absPath)
	}

	return pool, certCount, nil
}

// loadLOTLSignerBundle reads LOTL signer certificates from a PEM file.
// These certificates are used to verify TSL signatures per ETSI TS 119 615.
func (r *TSLRegistry) loadLOTLSignerBundle(path string) ([]*x509.Certificate, error) {
	absPath, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("invalid LOTL signer bundle path: %w", err)
	}

	pemData, err := os.ReadFile(absPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read LOTL signer bundle %s: %w", absPath, err)
	}

	var certs []*x509.Certificate
	var block *pem.Block
	rest := pemData
	for {
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type == "CERTIFICATE" {
			cert, err := registry.ParseCertificate(block.Bytes, r.config.CryptoExt)
			if err != nil {
				// Log warning but continue
				continue
			}
			certs = append(certs, cert)
		}
	}

	if len(certs) == 0 {
		return nil, fmt.Errorf("no valid certificates found in LOTL signer bundle %s", absPath)
	}

	return certs, nil
}

// verifyTSLSignature verifies that a TSL's signature was created by a trusted LOTL signer.
// This implements ETSI TS 119 615 LOTL signature validation.
// When FollowPivots is enabled and the signer is unknown, it attempts to discover
// new trusted signers via the pivot chain (ETSI TS 119 615 signer rollover).
// Returns the (possibly updated) signer list and nil error if verification succeeds
// or is not required.
func (r *TSLRegistry) verifyTSLSignature(tsl *etsi119612.TSL, lotlSigners []*x509.Certificate) ([]*x509.Certificate, error) {
	// If no LOTL signer certificates configured, skip verification
	if len(lotlSigners) == 0 {
		if r.config.RequireSignature {
			return lotlSigners, fmt.Errorf("signature verification required but no LOTL signer certificates configured")
		}
		return lotlSigners, nil
	}

	// Check if TSL is signed
	if !tsl.Signed {
		if r.config.RequireSignature {
			return lotlSigners, fmt.Errorf("TSL from %s is not signed", tsl.Source)
		}
		return lotlSigners, nil
	}

	// Verify signer certificate is one of the trusted LOTL signers
	signerCert := &tsl.Signer
	if len(signerCert.Raw) == 0 {
		if r.config.RequireSignature {
			return lotlSigners, fmt.Errorf("TSL from %s has no signer certificate", tsl.Source)
		}
		return lotlSigners, nil
	}

	// Check if signer is in the trusted list
	for _, trustedSigner := range lotlSigners {
		if signerCert.Equal(trustedSigner) {
			return lotlSigners, nil // Signature verified - signer is trusted
		}
	}

	// Signer not in trusted list - attempt pivot resolution if enabled
	if r.config.FollowPivots {
		if !r.config.AllowNetworkAccess {
			if r.config.Logger != nil {
				r.config.Logger.Warn("pivot chain resolution skipped because network access is disabled",
					"source", tsl.Source,
				)
			}
		} else {
			updatedSigners, err := r.resolvePivotChain(tsl, lotlSigners)
			if err == nil {
				// Re-check with updated signers
				for _, trustedSigner := range updatedSigners {
					if signerCert.Equal(trustedSigner) {
						if r.config.Logger != nil {
							r.config.Logger.Info("TSL signature verified via pivot chain",
								"source", tsl.Source,
								"signer_cn", signerCert.Subject.CommonName,
							)
						}
						return updatedSigners, nil
					}
				}
			} else if r.config.Logger != nil {
				r.config.Logger.Warn("pivot chain resolution failed", "source", tsl.Source, "error", err)
			}
		}
	}

	if r.config.RequireSignature {
		return lotlSigners, fmt.Errorf("TSL from %s signed by untrusted certificate: %s", tsl.Source, signerCert.Subject.CommonName)
	}

	// Opportunistic verification - log warning but don't fail
	return lotlSigners, nil
}

// loadLocalTSL loads a TSL from a local file path.
func (r *TSLRegistry) loadLocalTSL(path string) (*etsi119612.TSL, []*x509.Certificate, error) {
	absPath, err := filepath.Abs(path)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid TSL path %s: %w", path, err)
	}

	// Verify file exists
	if _, err := os.Stat(absPath); os.IsNotExist(err) {
		return nil, nil, fmt.Errorf("TSL file does not exist: %s", absPath)
	}

	// Use file:// URL for FetchTSLWithOptions
	fileURL := "file://" + absPath

	opts := etsi119612.TSLFetchOptions{
		UserAgent:           r.config.UserAgent,
		Timeout:             r.config.FetchTimeout,
		MaxDereferenceDepth: 0, // Don't follow references for local files
	}

	tsl, err := etsi119612.FetchTSLWithOptions(fileURL, opts)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to load TSL from %s: %w", absPath, err)
	}

	// Extract certificates from TSL
	certs := extractCertsFromTSL(tsl, r.config.CryptoExt)

	return tsl, certs, nil
}

// loadTSLFromURL loads a TSL from a URL (file:// or http(s)://).
func (r *TSLRegistry) loadTSLFromURL(url string) ([]*etsi119612.TSL, []*x509.Certificate, error) {
	// Convert local paths to file:// URLs
	if !strings.HasPrefix(url, "http://") && !strings.HasPrefix(url, "https://") && !strings.HasPrefix(url, "file://") {
		absPath, err := filepath.Abs(url)
		if err != nil {
			return nil, nil, fmt.Errorf("invalid path %s: %w", url, err)
		}
		url = "file://" + absPath
	}

	opts := etsi119612.TSLFetchOptions{
		UserAgent:     r.config.UserAgent,
		Timeout:       r.config.FetchTimeout,
		AcceptHeaders: []string{"application/xml", "text/xml", "application/xhtml+xml", "text/html;q=0.9", "*/*;q=0.8"},
	}

	var tsls []*etsi119612.TSL
	var err error

	if r.config.FollowRefs {
		opts.MaxDereferenceDepth = r.config.MaxRefDepth
		tsls, err = etsi119612.FetchTSLWithReferencesAndOptions(url, opts)
	} else {
		opts.MaxDereferenceDepth = 0
		var tsl *etsi119612.TSL
		tsl, err = etsi119612.FetchTSLWithOptions(url, opts)
		if tsl != nil {
			tsls = []*etsi119612.TSL{tsl}
		}
	}

	if err != nil {
		return nil, nil, fmt.Errorf("failed to load TSL from %s: %w", url, err)
	}

	// Extract certificates from all loaded TSLs
	var allCerts []*x509.Certificate
	for _, tsl := range tsls {
		certs := extractCertsFromTSL(tsl, r.config.CryptoExt)
		allCerts = append(allCerts, certs...)
	}

	return tsls, allCerts, nil
}

// extractCertsFromTSL extracts all X.509 certificates from a TSL.
func extractCertsFromTSL(tsl *etsi119612.TSL, ext *cryptoutil.Extensions) []*x509.Certificate {
	var certs []*x509.Certificate

	if tsl == nil || tsl.StatusList.TslTrustServiceProviderList == nil {
		return certs
	}

	for _, provider := range tsl.StatusList.TslTrustServiceProviderList.TslTrustServiceProvider {
		if provider == nil || provider.TslTSPServices == nil {
			continue
		}
		for _, service := range provider.TslTSPServices.TslTSPService {
			if service == nil || service.TslServiceInformation == nil {
				continue
			}
			serviceCerts := extractCertsFromService(service, ext)
			certs = append(certs, serviceCerts...)
		}
	}

	return certs
}

// extractCertsFromService extracts X.509 certificates from a TSL service entry.
func extractCertsFromService(service *etsi119612.TSPServiceType, ext *cryptoutil.Extensions) []*x509.Certificate {
	var certs []*x509.Certificate

	if service.TslServiceInformation == nil ||
		service.TslServiceInformation.TslServiceDigitalIdentity == nil {
		return certs
	}

	for _, digitalId := range service.TslServiceInformation.TslServiceDigitalIdentity.DigitalId {
		if digitalId == nil || digitalId.X509Certificate == "" {
			continue
		}
		// The certificate is base64 encoded in the XML - decode it
		certBytes, err := base64Decode(digitalId.X509Certificate)
		if err != nil {
			continue
		}
		cert, err := registry.ParseCertificate(certBytes, ext)
		if err != nil {
			continue
		}
		certs = append(certs, cert)
	}

	return certs
}

// base64Decode decodes a base64 string, handling both standard and URL-safe encodings.
func base64Decode(s string) ([]byte, error) {
	// Remove any whitespace
	s = strings.ReplaceAll(s, " ", "")
	s = strings.ReplaceAll(s, "\n", "")
	s = strings.ReplaceAll(s, "\r", "")
	s = strings.ReplaceAll(s, "\t", "")

	// Try standard base64 first
	data, err := base64.StdEncoding.DecodeString(s)
	if err == nil {
		return data, nil
	}

	// Try URL-safe base64
	return base64.URLEncoding.DecodeString(s)
}

// buildFilteredCertPool builds a certificate pool filtered by service types and statuses.
// If no service types or statuses are specified in the request context, the full unfiltered pool is returned.
// When service types and/or statuses are provided (via policy mapping), only certificates from
// TSL services matching those constraints are included.
func (r *TSLRegistry) buildFilteredCertPool(req *authzen.EvaluationRequest) (*x509.CertPool, string) {
	// Check if we have TSLs to filter from
	if len(r.tsls) == 0 {
		// No TSLs loaded - use the pre-built cert pool (from PEM bundle)
		return r.certPool, "unfiltered (pem bundle)"
	}

	// Extract service type and status constraints from request context
	var serviceTypes []string
	var serviceStatuses []string

	if req.Context != nil {
		if v, ok := req.Context["service_types"]; ok {
			switch st := v.(type) {
			case []string:
				serviceTypes = st
			case []interface{}:
				for _, s := range st {
					if str, ok := s.(string); ok {
						serviceTypes = append(serviceTypes, str)
					}
				}
			}
		}
		if v, ok := req.Context["service_statuses"]; ok {
			switch ss := v.(type) {
			case []string:
				serviceStatuses = ss
			case []interface{}:
				for _, s := range ss {
					if str, ok := s.(string); ok {
						serviceStatuses = append(serviceStatuses, str)
					}
				}
			}
		}
	}

	// If no filtering constraints, return the full pre-built pool
	if len(serviceTypes) == 0 && len(serviceStatuses) == 0 {
		return r.certPool, "unfiltered"
	}

	// Build a TSPServicePolicy with the requested constraints
	policy := etsi119612.NewTSPServicePolicy()
	if len(serviceTypes) > 0 {
		for _, st := range serviceTypes {
			policy.AddServiceTypeIdentifier(st)
		}
	}
	if len(serviceStatuses) > 0 {
		// Replace the default "granted" status with explicit statuses
		policy.ServiceStatus = serviceStatuses
	}

	// Build filtered cert pool from all loaded TSLs
	filteredPool := x509.NewCertPool()
	for _, tsl := range r.tsls {
		tslPool := tsl.ToCertPoolWithReferences(policy)
		// Merge TSL pool into filtered pool by extracting subjects
		// Note: x509.CertPool doesn't expose certs directly, so we re-extract from TSL
		tsl.WithTrustServices(func(tsp *etsi119612.TSPType, svc *etsi119612.TSPServiceType) {
			if tsp.Validate(svc, nil, policy) == nil {
				svc.WithCertificates(func(cert *x509.Certificate) {
					filteredPool.AddCert(cert)
				})
			}
		})
		// Also process referenced TSLs
		for _, refTsl := range tsl.Referenced {
			if refTsl != nil {
				refTsl.WithTrustServices(func(tsp *etsi119612.TSPType, svc *etsi119612.TSPServiceType) {
					if tsp.Validate(svc, nil, policy) == nil {
						svc.WithCertificates(func(cert *x509.Certificate) {
							filteredPool.AddCert(cert)
						})
					}
				})
			}
		}
		_ = tslPool // tslPool was used for reference; we built filteredPool directly
	}

	filterDesc := fmt.Sprintf("filtered(service_types=%v, service_statuses=%v)", serviceTypes, serviceStatuses)
	return filteredPool, filterDesc
}

// extractCredentialTypes extracts credential_types from request context.
// This is used for audit purposes - including in both success and error responses.
func extractCredentialTypes(req *authzen.EvaluationRequest) []string {
	if req.Context == nil {
		return nil
	}
	v, ok := req.Context["credential_types"]
	if !ok {
		return nil
	}
	switch ct := v.(type) {
	case []string:
		return ct
	case []interface{}:
		result := make([]string, 0, len(ct))
		for _, c := range ct {
			if str, ok := c.(string); ok {
				result = append(result, str)
			}
		}
		return result
	}
	return nil
}

// addCredentialTypesToReason adds credential_types to a reason map if present.
func addCredentialTypesToReason(reason map[string]interface{}, credTypes []string) {
	if len(credTypes) > 0 {
		reason["requested_credential_types"] = credTypes
	}
}

// Evaluate implements TrustRegistry.Evaluate by validating X.509 certificates
// against a certificate pool derived from the loaded TSLs.
// When policy constraints (service_types, service_statuses) are present in req.Context,
// the cert pool is dynamically filtered to include only certificates from matching TSL services.
func (r *TSLRegistry) Evaluate(ctx context.Context, req *authzen.EvaluationRequest) (*authzen.EvaluationResponse, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	// Extract credential_types early for inclusion in all responses (audit)
	credentialTypes := extractCredentialTypes(req)

	// Check if this is a resolution-only request
	if req.IsResolutionOnlyRequest() {
		reason := map[string]interface{}{
			"error": "ETSI TSL registry does not support resolution-only requests",
		}
		addCredentialTypesToReason(reason, credentialTypes)
		return &authzen.EvaluationResponse{
			Decision: false,
			Context: &authzen.EvaluationResponseContext{
				Reason: reason,
			},
		}, nil
	}

	// Extract certificates from resource.key based on resource.type
	var certs []*x509.Certificate
	var parseErr error

	switch req.Resource.Type {
	case "x5c", "x509_san_dns", "x509_san_uri":
		certs, parseErr = x509util.ParseX5CFromArray(req.Resource.Key)
	case "jwk":
		certs, parseErr = x509util.ParseX5CFromJWK(req.Resource.Key)
	default:
		// Distinguish between known-but-unsupported schemes and completely unknown ones
		// This helps with security monitoring and debugging
		knownUnsupported := map[string]string{
			"x509_san_email": "email SAN validation not yet implemented",
			"x509_san_ip":    "IP address SAN validation not yet implemented",
		}
		if hint, known := knownUnsupported[req.Resource.Type]; known {
			reason := map[string]interface{}{
				"error":           fmt.Sprintf("resource type '%s' is recognized but not supported: %s", req.Resource.Type, hint),
				"supported_types": r.SupportedResourceTypes(),
				"security_note":   "this may indicate a client misconfiguration or attempted scheme mismatch attack",
			}
			addCredentialTypesToReason(reason, credentialTypes)
			return &authzen.EvaluationResponse{
				Decision: false,
				Context: &authzen.EvaluationResponseContext{
					Reason: reason,
				},
			}, nil
		}
		reason := map[string]interface{}{
			"error":           fmt.Sprintf("unsupported resource type: %s", req.Resource.Type),
			"supported_types": r.SupportedResourceTypes(),
		}
		addCredentialTypesToReason(reason, credentialTypes)
		return &authzen.EvaluationResponse{
			Decision: false,
			Context: &authzen.EvaluationResponseContext{
				Reason: reason,
			},
		}, nil
	}

	if parseErr != nil {
		reason := map[string]interface{}{
			"error": parseErr.Error(),
		}
		addCredentialTypesToReason(reason, credentialTypes)
		return &authzen.EvaluationResponse{
			Decision: false,
			Context: &authzen.EvaluationResponseContext{
				Reason: reason,
			},
		}, nil
	}

	if len(certs) == 0 {
		reason := map[string]interface{}{
			"error": "no certificates found in resource.key",
		}
		addCredentialTypesToReason(reason, credentialTypes)
		return &authzen.EvaluationResponse{
			Decision: false,
			Context: &authzen.EvaluationResponseContext{
				Reason: reason,
			},
		}, nil
	}

	// Build (possibly filtered) cert pool based on policy constraints in request context
	pool, poolDesc := r.buildFilteredCertPool(req)
	if pool == nil {
		reason := map[string]interface{}{
			"error": "certificate pool not initialized",
		}
		addCredentialTypesToReason(reason, credentialTypes)
		return &authzen.EvaluationResponse{
			Decision: false,
			Context: &authzen.EvaluationResponseContext{
				Reason: reason,
			},
		}, nil
	}

	start := time.Now()
	opts := x509.VerifyOptions{
		Roots: pool,
	}

	// Add intermediate certificates if provided in the chain
	// This is required for leaf certs signed by intermediate CAs (not directly by root)
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
		reason := map[string]interface{}{
			"error":         err.Error(),
			"validation_ms": validationDuration.Milliseconds(),
			"pool_filter":   poolDesc,
		}
		addCredentialTypesToReason(reason, credentialTypes)
		return &authzen.EvaluationResponse{
			Decision: false,
			Context: &authzen.EvaluationResponseContext{
				Reason: reason,
			},
		}, nil
	}

	// For x509_san_dns, additionally verify that Subject.ID matches a DNS SAN in the leaf certificate
	// This implements OpenID4VP section 5.9.3 client_id verification
	if req.Resource.Type == "x509_san_dns" {
		clientID := req.Subject.ID
		leafCert := certs[0]
		sanMatched := false

		for _, dnsName := range leafCert.DNSNames {
			if dnsName == clientID {
				sanMatched = true
				break
			}
			// Support wildcard certificates (e.g., *.example.com)
			// Per RFC 6125, wildcards match only a single label
			if strings.HasPrefix(dnsName, "*.") {
				// *.example.com matches sub.example.com but NOT example.com or deep.sub.example.com
				suffix := dnsName[1:]     // *.example.com -> .example.com
				baseDomain := dnsName[2:] // *.example.com -> example.com
				if strings.HasSuffix(clientID, suffix) && clientID != baseDomain {
					// Ensure only a single label before the suffix (no nested subdomains)
					prefix := strings.TrimSuffix(clientID, suffix)
					if !strings.Contains(prefix, ".") {
						sanMatched = true
						break
					}
				}
			}
		}

		if !sanMatched {
			reason := map[string]interface{}{
				"error":           fmt.Sprintf("subject.id '%s' not found in certificate DNS SANs", clientID),
				"dns_sans":        leafCert.DNSNames,
				"validation_ms":   validationDuration.Milliseconds(),
				"scheme_mismatch": "ensure client_id_scheme matches certificate SAN type (use x509_san_uri for URI SANs)",
			}
			addCredentialTypesToReason(reason, credentialTypes)
			return &authzen.EvaluationResponse{
				Decision: false,
				Context: &authzen.EvaluationResponseContext{
					Reason: reason,
				},
			}, nil
		}
	}

	// For x509_san_uri, verify that Subject.ID matches a URI SAN in the leaf certificate
	// This implements OpenID4VP section 5.9.4 client_id verification for URI-based identifiers
	if req.Resource.Type == "x509_san_uri" {
		clientID := req.Subject.ID
		leafCert := certs[0]
		sanMatched := false

		for _, uri := range leafCert.URIs {
			if uri != nil && uri.String() == clientID {
				sanMatched = true
				break
			}
		}

		if !sanMatched {
			// Extract URI strings for error response
			uriSANs := make([]string, 0, len(leafCert.URIs))
			for _, uri := range leafCert.URIs {
				if uri != nil {
					uriSANs = append(uriSANs, uri.String())
				}
			}
			reason := map[string]interface{}{
				"error":           fmt.Sprintf("subject.id '%s' not found in certificate URI SANs", clientID),
				"uri_sans":        uriSANs,
				"validation_ms":   validationDuration.Milliseconds(),
				"scheme_mismatch": "ensure client_id_scheme matches certificate SAN type (use x509_san_dns for DNS SANs)",
			}
			addCredentialTypesToReason(reason, credentialTypes)
			return &authzen.EvaluationResponse{
				Decision: false,
				Context: &authzen.EvaluationResponseContext{
					Reason: reason,
				},
			}, nil
		}
	}

	// Build response reason map
	reason := map[string]interface{}{
		"tsl_count":     len(r.tsls),
		"trusted_certs": r.certCount,
		"validation_ms": validationDuration.Milliseconds(),
		"chain_length":  len(chains),
		"data_loaded":   r.loadedAt.Format(time.RFC3339),
		"pool_filter":   poolDesc,
	}

	// Include credential_types in response if specified
	addCredentialTypesToReason(reason, credentialTypes)

	// Success - certificate is trusted
	return &authzen.EvaluationResponse{
		Decision: true,
		Context: &authzen.EvaluationResponseContext{
			Reason: reason,
		},
	}, nil
}

// SupportedResourceTypes returns the resource types this registry can handle.
// Supports:
// - x5c: X.509 certificate chain (validates chain against TSL)
// - jwk: JWK with x5c claim (validates chain against TSL)
// - x509_san_dns: OpenID4VP client_id type where Subject.ID must match a DNS SAN in the certificate
// - x509_san_uri: OpenID4VP client_id type where Subject.ID must match a URI SAN in the certificate
func (r *TSLRegistry) SupportedResourceTypes() []string {
	return []string{"x5c", "jwk", "x509_san_dns", "x509_san_uri"}
}

// SupportsResolutionOnly returns false - ETSI TSL requires certificate validation.
func (r *TSLRegistry) SupportsResolutionOnly() bool {
	return false
}

// Info returns metadata about this registry.
func (r *TSLRegistry) Info() registry.RegistryInfo {
	r.mu.RLock()
	defer r.mu.RUnlock()

	trustAnchors := make([]string, 0, len(r.tsls))
	for _, tsl := range r.tsls {
		if tsl != nil {
			summary := tsl.Summary()
			if territory, ok := summary["territory"].(string); ok {
				trustAnchors = append(trustAnchors, fmt.Sprintf("TSL:%s", territory))
			}
		}
	}
	// Add source files as trust anchors if no TSL territories
	if len(trustAnchors) == 0 {
		trustAnchors = append(trustAnchors, r.sourceFiles...)
	}

	info := registry.RegistryInfo{
		Name:         r.config.Name,
		Type:         "etsi_tsl",
		Description:  r.config.Description,
		Version:      "1.0.0",
		TrustAnchors: trustAnchors,
	}
	if !r.loadedAt.IsZero() {
		loadedAt := r.loadedAt
		info.LastUpdated = &loadedAt
	}
	return info
}

// Healthy returns true if the registry has loaded trust data successfully.
func (r *TSLRegistry) Healthy() bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.healthy && r.certPool != nil && r.certCount > 0
}

// Refresh reloads trust data from the configured sources.
func (r *TSLRegistry) Refresh(ctx context.Context) error {
	return r.load()
}

// StartRefreshLoop starts a background goroutine that periodically re-fetches
// TSL data. Must be called after NewTSLRegistry.
func (r *TSLRegistry) StartRefreshLoop(ctx context.Context) error {
	interval := r.config.RefreshInterval
	if interval == 0 {
		return nil // disabled
	}
	if interval < 0 {
		return fmt.Errorf("RefreshInterval must be positive, got %v", interval)
	}

	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				if err := r.load(); err != nil && r.config.Logger != nil {
					r.config.Logger.Warn("TSL refresh failed", slog.String("error", err.Error()))
				}
			case <-r.stopCh:
				return
			case <-ctx.Done():
				return
			}
		}
	}()
	return nil
}

// Stop halts the background refresh loop.
func (r *TSLRegistry) Stop() {
	select {
	case <-r.stopCh:
	default:
		close(r.stopCh)
	}
}

// CertificateCount returns the number of trusted certificates loaded.
func (r *TSLRegistry) CertificateCount() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.certCount
}

// TSLCount returns the number of loaded TSLs.
func (r *TSLRegistry) TSLCount() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.tsls)
}

// LoadedAt returns when the trust data was last loaded.
func (r *TSLRegistry) LoadedAt() time.Time {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.loadedAt
}

// LastError returns the last error encountered during loading.
func (r *TSLRegistry) LastError() error {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.lastError
}

// TSLs returns the loaded TSL objects.
func (r *TSLRegistry) TSLs() []*etsi119612.TSL {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.tsls
}

// CertPool returns the loaded certificate pool.
func (r *TSLRegistry) CertPool() *x509.CertPool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.certPool
}
