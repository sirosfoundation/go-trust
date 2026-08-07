// Package fidomds3 provides a TrustRegistry backed by the FIDO Alliance
// Metadata Service v3 (MDS3) - the official, periodically-updated,
// cryptographically-signed registry of certified FIDO2/CTAP2 authenticator
// models (e.g. YubiKeys), their trust-anchor certificates, and their
// certification/revocation status.
//
// It fetches the MDS3 blob, verifies its own JWT signature and parses it
// (reusing github.com/go-webauthn/webauthn's metadata package rather than
// reimplementing MDS3 parsing/verification), indexes entries by AAGUID, and
// periodically re-fetches on a ticker - the same fetch/validate/index/
// refresh-loop shape as the lote and etsi registries in this package tree,
// just for a JSON/JWT-signed FIDO-specific format rather than an ETSI
// TSL/LoTE one.
package fidomds3

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/go-webauthn/webauthn/metadata"
	"github.com/google/uuid"

	"github.com/sirosfoundation/go-trust/pkg/authzen"
	"github.com/sirosfoundation/go-trust/pkg/registry"
)

// Config configures a FIDO MDS3 registry instance.
type Config struct {
	Name        string
	Description string

	// URL is the MDS3 blob endpoint. Defaults to metadata.ProductionMDSURL
	// (the FIDO Alliance's own production endpoint) if empty.
	URL string

	// FetchTimeout is the timeout for fetching the MDS3 blob. Default: 30s.
	FetchTimeout time.Duration

	// RefreshInterval is how often to re-fetch the MDS3 blob. Zero disables
	// periodic refresh (the registry still loads once at construction).
	RefreshInterval time.Duration

	// RootCertificatePEM overrides the trust anchor used to verify the MDS3
	// blob's own JWT signature (base64 DER, no PEM armor - matches
	// metadata.WithRootCertificate's expected format). Empty uses
	// go-webauthn's built-in production FIDO Alliance root. Override for a
	// non-production MDS instance (e.g. FIDO's conformance/testing MDS) or
	// in tests.
	RootCertificatePEM string

	// CachePath, if set, persists the raw (still-signed) MDS3 blob to this
	// file path on every successful fetch, and loads from it at
	// construction time before attempting any network call. This means a
	// process restart doesn't have to block on - or fail because of - a
	// live fetch: New() serves the last-known-good, disk-cached blob
	// immediately (re-verifying its JWT signature exactly as a live fetch
	// would, never trusting the file blindly), then attempts a live
	// refresh in the background; a live-refresh failure at that point is
	// non-fatal (logged, stale data continues to be served) precisely
	// because there's already a verified fallback. Without CachePath set,
	// New() falls back to today's behavior: it must complete a live fetch
	// to succeed at all. Empty disables disk persistence entirely.
	CachePath string

	// Logger for structured logging. May be nil.
	Logger *slog.Logger

	// HTTPClient overrides the client used to fetch the blob. Primarily for
	// tests; production deployments should leave this nil (default client).
	HTTPClient *http.Client
}

// Registry is a TrustRegistry backed by FIDO Alliance MDS3 data.
type Registry struct {
	config Config

	mu          sync.RWMutex
	entries     map[uuid.UUID]*metadata.Entry
	healthy     bool
	lastUpdated time.Time

	stopCh chan struct{}
}

var _ registry.TrustRegistry = (*Registry)(nil)

// New creates a new FIDO MDS3 registry with the given config, performing an
// initial synchronous fetch.
func New(cfg Config) (*Registry, error) {
	if cfg.Name == "" {
		cfg.Name = "fido-mds3"
	}
	if cfg.Description == "" {
		cfg.Description = "FIDO Alliance Metadata Service v3"
	}
	if cfg.URL == "" {
		cfg.URL = metadata.ProductionMDSURL
	}
	if cfg.FetchTimeout == 0 {
		cfg.FetchTimeout = 30 * time.Second
	}

	r := &Registry{
		config:  cfg,
		entries: make(map[uuid.UUID]*metadata.Entry),
		stopCh:  make(chan struct{}),
	}

	loadedFromDisk := false
	if cfg.CachePath != "" {
		if raw, err := r.loadFromDisk(); err != nil {
			if r.config.Logger != nil {
				r.config.Logger.Warn("FIDO MDS3 disk cache unusable, will require a live fetch",
					slog.String("path", cfg.CachePath), slog.String("error", err.Error()))
			}
		} else if err := r.decodeAndIndex(raw); err != nil {
			if r.config.Logger != nil {
				r.config.Logger.Warn("FIDO MDS3 disk cache failed verification, will require a live fetch",
					slog.String("path", cfg.CachePath), slog.String("error", err.Error()))
			}
		} else {
			loadedFromDisk = true
			if r.config.Logger != nil {
				r.config.Logger.Info("FIDO MDS3 loaded from disk cache, will refresh live in the background",
					slog.String("path", cfg.CachePath))
			}
		}
	}

	if err := r.refresh(); err != nil {
		if loadedFromDisk {
			// Already have a verified, if possibly stale, index from disk -
			// a failed live refresh right now is not fatal, exactly the
			// same "degrade to stale data" tolerance refresh() already
			// gives a mid-life ticker failure.
			if r.config.Logger != nil {
				r.config.Logger.Warn("FIDO MDS3 initial live refresh failed, continuing with disk-cached data",
					slog.String("error", err.Error()))
			}
			r.setHealthy(true)
			return r, nil
		}
		return nil, fmt.Errorf("initial FIDO MDS3 load failed (no usable disk cache): %w", err)
	}

	return r, nil
}

// StartRefreshLoop starts a background goroutine that periodically re-fetches
// the MDS3 blob. Must be called after New.
func (r *Registry) StartRefreshLoop(ctx context.Context) error {
	interval := r.config.RefreshInterval
	if interval == 0 {
		return nil // disabled
	}

	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				if err := r.refresh(); err != nil && r.config.Logger != nil {
					r.config.Logger.Warn("FIDO MDS3 refresh failed", slog.String("error", err.Error()))
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
func (r *Registry) Stop() {
	select {
	case <-r.stopCh:
	default:
		close(r.stopCh)
	}
}

// refresh fetches the MDS3 blob live, decodes/verifies/indexes it (see
// decodeAndIndex), and - if CachePath is set - persists the raw bytes to
// disk on success. On failure the previously-loaded index (if any) is left
// in place - a transient fetch failure degrades to stale data, it does not
// blank the registry.
func (r *Registry) refresh() error {
	raw, err := r.fetchRaw()
	if err != nil {
		r.setHealthy(false)
		return err
	}

	if err := r.decodeAndIndex(raw); err != nil {
		return err
	}

	if r.config.CachePath != "" {
		if err := r.saveToDisk(raw); err != nil && r.config.Logger != nil {
			// Best-effort only - the in-memory index is already valid and
			// serving; a disk-cache write failure just means a future
			// restart won't have this round's data as its warm-start
			// fallback, matching internal/registry/fetcher.go's convention
			// in go-wallet-backend for this exact class of failure.
			r.config.Logger.Warn("failed to persist FIDO MDS3 disk cache", slog.String("error", err.Error()))
		}
	}

	return nil
}

// fetchRaw performs the live HTTP GET for the MDS3 blob and returns its raw
// (still-signed) bytes.
func (r *Registry) fetchRaw() ([]byte, error) {
	client := r.config.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: r.config.FetchTimeout}
	}

	req, err := http.NewRequest(http.MethodGet, r.config.URL, nil) //nolint:noctx // timeout set via client
	if err != nil {
		return nil, fmt.Errorf("build MDS3 request: %w", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch MDS3 blob: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck // Body close error is not actionable

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("MDS3 endpoint returned %d", resp.StatusCode)
	}

	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read MDS3 response body: %w", err)
	}
	return raw, nil
}

// decodeAndIndex verifies (JWT signature against the configured/default
// FIDO Alliance root) and parses raw MDS3 blob bytes - from either a live
// fetch or the disk cache, the trust bar is identical either way - then
// atomically swaps in a fresh AAGUID index. On failure the previous index
// (if any) is left untouched and healthy is set false.
func (r *Registry) decodeAndIndex(raw []byte) error {
	// WithIgnoreEntryParsingErrors: a handful of unparseable individual
	// entries (e.g. a malformed statement for one obscure authenticator)
	// should not take down the whole blob - matches how the lote registry
	// tolerates partial parse failures.
	decoderOpts := []metadata.DecoderOption{metadata.WithIgnoreEntryParsingErrors()}
	if r.config.RootCertificatePEM != "" {
		decoderOpts = append(decoderOpts, metadata.WithRootCertificate(r.config.RootCertificatePEM))
	}
	decoder, err := metadata.NewDecoder(decoderOpts...)
	if err != nil {
		r.setHealthy(false)
		return fmt.Errorf("create MDS3 decoder: %w", err)
	}

	payload, err := decoder.DecodeBytes(raw)
	if err != nil {
		r.setHealthy(false)
		return fmt.Errorf("decode/verify MDS3 blob: %w", err)
	}

	parsed, err := decoder.Parse(payload)
	if err != nil {
		r.setHealthy(false)
		return fmt.Errorf("parse MDS3 blob: %w", err)
	}

	entries := parsed.ToMap()

	r.mu.Lock()
	r.entries = entries
	r.healthy = true
	r.lastUpdated = time.Now()
	r.mu.Unlock()

	if r.config.Logger != nil {
		r.config.Logger.Info("FIDO MDS3 index updated",
			slog.Int("entries", len(entries)),
			slog.Time("next_update", parsed.Parsed.NextUpdate))
	}

	return nil
}

// loadFromDisk reads the raw MDS3 blob bytes from CachePath. Returns an
// error if CachePath is unset, the file doesn't exist, or it can't be read -
// callers treat any error here as "no usable disk cache", not a fatal
// condition.
func (r *Registry) loadFromDisk() ([]byte, error) {
	if r.config.CachePath == "" {
		return nil, errors.New("no cache path configured")
	}
	return os.ReadFile(r.config.CachePath)
}

// saveToDisk persists raw MDS3 blob bytes to CachePath via a write-then-
// rename so a crash mid-write can never leave a truncated/corrupt cache
// file for the next startup to (fail to) load.
func (r *Registry) saveToDisk(raw []byte) error {
	dir := filepath.Dir(r.config.CachePath)
	tmp, err := os.CreateTemp(dir, ".fidomds3-*.tmp")
	if err != nil {
		return fmt.Errorf("create temp cache file: %w", err)
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath) //nolint:errcheck // no-op once renamed below

	if _, err := tmp.Write(raw); err != nil {
		tmp.Close() //nolint:errcheck,gosec // already returning the write error
		return fmt.Errorf("write temp cache file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temp cache file: %w", err)
	}
	if err := os.Rename(tmpPath, r.config.CachePath); err != nil {
		return fmt.Errorf("rename temp cache file into place: %w", err)
	}
	return nil
}

func (r *Registry) setHealthy(healthy bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.healthy = healthy
}

// --- TrustRegistry interface ---

// Evaluate checks an x5c attestation certificate chain against the FIDO
// MDS3 entry for the AAGUID identified by subject.id/resource.id. Per the
// AuthZEN Trust Registry Profile, subject.id and resource.id are the "name"
// half of a name-to-key binding - here, the name is the authenticator
// model's AAGUID (a UUID), and the key is the x5c chain an attestation
// object claims was produced by that model.
func (r *Registry) Evaluate(ctx context.Context, req *authzen.EvaluationRequest) (*authzen.EvaluationResponse, error) {
	aaguid, err := uuid.Parse(req.Subject.ID)
	if err != nil {
		return r.denyWithReason(fmt.Sprintf("subject.id is not a valid AAGUID: %v", err)), nil
	}

	r.mu.RLock()
	entry, ok := r.entries[aaguid]
	r.mu.RUnlock()

	if !ok {
		return r.denyWithReason(fmt.Sprintf("no FIDO MDS3 entry for AAGUID %s", aaguid)), nil
	}

	chain, err := parseX5CChain(req.Resource.Key)
	if err != nil {
		return r.denyWithReason(fmt.Sprintf("invalid x5c chain: %v", err)), nil
	}
	if len(chain) == 0 {
		return r.denyWithReason("empty x5c chain"), nil
	}

	if err := metadata.ValidateStatusReports(entry.StatusReports, nil, metadata.DefaultUndesiredAuthenticatorStatuses()); err != nil {
		return r.denyWithReason(fmt.Sprintf("authenticator status not acceptable: %v", err)), nil
	}

	if len(entry.MetadataStatement.AttestationRootCertificates) == 0 {
		return r.denyWithReason("MDS3 entry has no attestation root certificates"), nil
	}

	roots := x509.NewCertPool()
	for _, root := range entry.MetadataStatement.AttestationRootCertificates {
		roots.AddCert(root)
	}

	intermediates := x509.NewCertPool()
	for i := 1; i < len(chain); i++ {
		intermediates.AddCert(chain[i])
	}

	if _, err := chain[0].Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		CurrentTime:   time.Now(),
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}); err != nil {
		return r.denyWithReason(fmt.Sprintf("x5c chain does not verify against MDS3 attestation roots: %v", err)), nil
	}

	return &authzen.EvaluationResponse{
		Decision: true,
		Context: &authzen.EvaluationResponseContext{
			Reason: map[string]interface{}{
				"trust_anchor":         "fido_mds3",
				"aaguid":               aaguid.String(),
				"description":          entry.MetadataStatement.Description,
				"attestation_root_cas": len(entry.MetadataStatement.AttestationRootCertificates),
			},
		},
	}, nil
}

// SupportedResourceTypes returns the resource types this registry handles.
func (r *Registry) SupportedResourceTypes() []string {
	return []string{"x5c"}
}

// SupportsResolutionOnly returns false - this registry requires an x5c chain.
func (r *Registry) SupportsResolutionOnly() bool {
	return false
}

// Info returns metadata about this registry instance.
func (r *Registry) Info() registry.RegistryInfo {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var lastUpdated *time.Time
	if !r.lastUpdated.IsZero() {
		t := r.lastUpdated
		lastUpdated = &t
	}

	return registry.RegistryInfo{
		Name:          r.config.Name,
		Type:          "fido_mds3",
		Description:   r.config.Description,
		Version:       "1.0.0",
		TrustAnchors:  []string{r.config.URL},
		ResourceTypes: r.SupportedResourceTypes(),
		Healthy:       r.healthy,
		LastUpdated:   lastUpdated,
	}
}

// Healthy returns true if the most recent fetch succeeded.
func (r *Registry) Healthy() bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.healthy
}

// Refresh triggers an immediate re-fetch of the MDS3 blob.
func (r *Registry) Refresh(ctx context.Context) error {
	return r.refresh()
}

// --- internal helpers ---

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

// parseX5CChain decodes an AuthZEN resource.key array (base64-encoded DER
// certificates, leaf first) into parsed certificates.
func parseX5CChain(key []interface{}) ([]*x509.Certificate, error) {
	certs := make([]*x509.Certificate, 0, len(key))
	for i, item := range key {
		s, ok := item.(string)
		if !ok {
			return nil, fmt.Errorf("chain element %d is not a string", i)
		}
		der, err := base64.StdEncoding.DecodeString(s)
		if err != nil {
			return nil, fmt.Errorf("chain element %d: invalid base64: %w", i, err)
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, fmt.Errorf("chain element %d: invalid X.509: %w", i, err)
		}
		certs = append(certs, cert)
	}
	return certs, nil
}
