// Package lote provides a TrustRegistry backed by ETSI TS 119 602 Lists of
// Trusted Entities (LoTE). It loads LoTE documents (JSON or XML) from URLs or
// local files, indexes entities by identifier and digital identity, and evaluates
// AuthZEN trust requests against them. It also supports loading Lists of Trusted
// Lists (LoTL) and following their pointers to discover individual LoTEs.
package lote

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/sirosfoundation/g119612/pkg/etsi119602"
	"github.com/sirosfoundation/go-cryptoutil"
	"github.com/sirosfoundation/go-trust/pkg/authzen"
	"github.com/sirosfoundation/go-trust/pkg/registry"
)

// Config configures a LoTE registry instance.
type Config struct {
	Name        string
	Description string

	// Sources are LoTE document locations (URLs or file paths).
	// Both JSON and XML formats are auto-detected.
	Sources []string

	// LoTLSources are LoTL document locations (URLs or file paths).
	// Each LoTL's PointersToOtherLoTEs are followed to discover LoTEs.
	// Both JSON and XML formats are auto-detected.
	LoTLSources []string

	// MaxDereferenceDepth limits nested LoTL resolution. Zero means no limit.
	MaxDereferenceDepth int

	// VerifyJWS controls whether JWS signatures on LoTE documents are verified.
	VerifyJWS bool

	// FetchTimeout is the timeout for fetching remote LoTE documents.
	FetchTimeout time.Duration

	// RefreshInterval is how often to re-fetch LoTE documents. Zero disables.
	RefreshInterval time.Duration

	// Logger for structured logging. May be nil.
	Logger *slog.Logger

	// CryptoExt provides extensible certificate parsing for non-standard curves
	// (e.g. brainpool). If nil, standard x509.ParseCertificate is used.
	CryptoExt *cryptoutil.Extensions
}

// Registry is a TrustRegistry backed by ETSI TS 119 602 LoTE documents.
type Registry struct {
	config Config

	mu          sync.RWMutex
	lotes       []*etsi119602.ListOfTrustedEntities
	index       *entityIndex
	healthy     bool
	lastUpdated time.Time

	stopCh chan struct{}
}

// entityIndex is a lookup structure built from loaded LoTEs.
type entityIndex struct {
	// byID maps entity ID (subject URL) → entity data.
	byID map[string]*indexedEntity

	// byKeyHash maps SHA-256 key hash → set of entity IDs that have that key.
	byKeyHash map[string]map[string]bool
}

// indexedEntity holds a single entity and its precomputed key hashes.
type indexedEntity struct {
	entity    etsi119602.TrustedEntity
	entityID  string
	territory string
	keyHashes map[string]bool // SHA-256 fingerprints of all digital identities
	// certPool contains X.509 certificates from this entity's digital identities,
	// used as trust anchors for PKIX path validation of x5c requests.
	certPool *x509.CertPool
}

var _ registry.TrustRegistry = (*Registry)(nil)

// New creates a new LoTE registry with the given config.
func New(cfg Config) (*Registry, error) {
	if len(cfg.Sources) == 0 && len(cfg.LoTLSources) == 0 {
		return nil, fmt.Errorf("lote registry requires at least one source or lotl_sources")
	}
	if cfg.Name == "" {
		cfg.Name = "LoTE"
	}
	if cfg.Description == "" {
		cfg.Description = "ETSI TS 119 602 List of Trusted Entities"
	}
	if cfg.FetchTimeout == 0 {
		cfg.FetchTimeout = 30 * time.Second
	}

	r := &Registry{
		config: cfg,
		index:  &entityIndex{byID: make(map[string]*indexedEntity), byKeyHash: make(map[string]map[string]bool)},
		stopCh: make(chan struct{}),
	}

	if err := r.refresh(); err != nil {
		return nil, fmt.Errorf("initial LoTE load failed: %w", err)
	}

	return r, nil
}

// StartRefreshLoop starts a background goroutine that periodically re-fetches
// LoTE documents. Must be called after New.
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
					r.config.Logger.Warn("LoTE refresh failed", slog.String("error", err.Error()))
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

// --- TrustRegistry interface ---

func (r *Registry) Evaluate(_ context.Context, req *authzen.EvaluationRequest) (*authzen.EvaluationResponse, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	subjectID := req.Subject.ID

	// Extract credential_types early for inclusion in all responses (audit).
	credentialTypes := extractCredentialTypes(req)

	// Look up entity by subject ID.
	ent, ok := r.index.byID[subjectID]
	if !ok {
		reason := map[string]interface{}{
			"admin": fmt.Sprintf("entity %q not found in any LoTE", subjectID),
		}
		addCredentialTypesToReason(reason, credentialTypes)
		return &authzen.EvaluationResponse{
			Decision: false,
			Context: &authzen.EvaluationResponseContext{
				Reason: reason,
			},
		}, nil
	}

	// Per ETSI TS 119 602-1: presence in the list = trusted (no entity-level status).
	// Withdrawn services are excluded during indexing.

	// Resolution-only: no key check needed.
	if req.IsResolutionOnlyRequest() {
		return &authzen.EvaluationResponse{
			Decision: true,
			Context: &authzen.EvaluationResponseContext{
				TrustMetadata: ent.entity,
			},
		}, nil
	}

	// Validate key binding.
	// For x5c: try direct key match first, then PKIX path validation
	// against the entity's X.509 trust anchors.
	// For jwk: direct key match only.
	keyHash, err := hashResourceKey(req, r.config.CryptoExt)
	if err != nil {
		reason := map[string]interface{}{"admin": fmt.Sprintf("failed to hash resource key: %v", err)}
		addCredentialTypesToReason(reason, credentialTypes)
		return &authzen.EvaluationResponse{
			Decision: false,
			Context: &authzen.EvaluationResponseContext{
				Reason: reason,
			},
		}, nil
	}

	if ent.keyHashes[keyHash] {
		return r.buildSuccessResponse(subjectID, ent.territory, "key matches entity", credentialTypes), nil
	}

	// For x5c: attempt PKIX path validation if the entity has X.509 trust anchors.
	if req.Resource.Type == "x5c" && ent.certPool != nil {
		if resp := r.validateX5CChain(req, ent, credentialTypes); resp != nil {
			return resp, nil
		}
	}

	reason := map[string]interface{}{
		"admin": fmt.Sprintf("key does not match any digital identity of entity %q", subjectID),
	}
	addCredentialTypesToReason(reason, credentialTypes)
	return &authzen.EvaluationResponse{
		Decision: false,
		Context: &authzen.EvaluationResponseContext{
			Reason: reason,
		},
	}, nil
}

func (r *Registry) SupportedResourceTypes() []string {
	return []string{"jwk", "x5c"}
}

func (r *Registry) SupportsResolutionOnly() bool {
	return true
}

func (r *Registry) Info() registry.RegistryInfo {
	r.mu.RLock()
	defer r.mu.RUnlock()
	info := registry.RegistryInfo{
		Name:           r.config.Name,
		Type:           "lote",
		Description:    r.config.Description,
		TrustAnchors:   append(append([]string{}, r.config.Sources...), r.config.LoTLSources...),
		ResourceTypes:  r.SupportedResourceTypes(),
		ResolutionOnly: true,
		Healthy:        r.healthy,
	}
	if !r.lastUpdated.IsZero() {
		lastUpdated := r.lastUpdated
		info.LastUpdated = &lastUpdated
	}
	return info
}

func (r *Registry) Healthy() bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.healthy
}

func (r *Registry) Refresh(ctx context.Context) error {
	return r.refresh()
}

// buildSuccessResponse creates a successful EvaluationResponse with credential_types
// from the request context included for audit purposes.
func (r *Registry) buildSuccessResponse(subjectID, territory, detail string, credentialTypes []string) *authzen.EvaluationResponse {
	reason := map[string]interface{}{
		"admin": fmt.Sprintf("%s %q in LoTE (territory: %s)", detail, subjectID, territory),
	}
	addCredentialTypesToReason(reason, credentialTypes)

	return &authzen.EvaluationResponse{
		Decision: true,
		Context: &authzen.EvaluationResponseContext{
			Reason: reason,
		},
	}
}

// extractCredentialTypes extracts credential_types from the request context.
func extractCredentialTypes(req *authzen.EvaluationRequest) []string {
	if req.Context == nil {
		return nil
	}
	return extractStringSlice(req.Context, "credential_types")
}

// addCredentialTypesToReason adds credential_types to a reason map if present.
func addCredentialTypesToReason(reason map[string]interface{}, credTypes []string) {
	if len(credTypes) > 0 {
		reason["requested_credential_types"] = credTypes
	}
}

// extractStringSlice extracts a []string from a context map value.
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

// validateX5CChain attempts PKIX path validation of the x5c certificate chain
// against the entity's X.509 trust anchors. Returns a positive response if
// validation succeeds, nil if it fails (allowing the caller to fall through).
func (r *Registry) validateX5CChain(req *authzen.EvaluationRequest, ent *indexedEntity, credentialTypes []string) *authzen.EvaluationResponse {
	certs, err := parseX5CCerts(req, r.config.CryptoExt)
	if err != nil || len(certs) == 0 {
		return nil
	}

	opts := x509.VerifyOptions{
		Roots: ent.certPool,
	}
	if len(certs) > 1 {
		intermediates := x509.NewCertPool()
		for _, cert := range certs[1:] {
			intermediates.AddCert(cert)
		}
		opts.Intermediates = intermediates
	}

	if _, err := certs[0].Verify(opts); err == nil {
		return r.buildSuccessResponse(ent.entityID, ent.territory, "x5c chain validates against trust anchor for entity", credentialTypes)
	}
	return nil
}

// parseX5CCerts extracts X.509 certificates from an x5c resource key.
func parseX5CCerts(req *authzen.EvaluationRequest, ext *cryptoutil.Extensions) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	for _, k := range req.Resource.Key {
		b64, ok := k.(string)
		if !ok {
			continue
		}
		der, err := base64.StdEncoding.DecodeString(b64)
		if err != nil {
			return nil, fmt.Errorf("failed to decode x5c cert: %w", err)
		}
		cert, err := registry.ParseCertificate(der, ext)
		if err != nil {
			return nil, fmt.Errorf("failed to parse x5c cert: %w", err)
		}
		certs = append(certs, cert)
	}
	return certs, nil
}

// --- internals ---

func (r *Registry) refresh() error {
	var lotes []*etsi119602.ListOfTrustedEntities

	opts := &etsi119602.FetchOptions{
		Timeout: r.config.FetchTimeout,
	}

	// Load direct LoTE sources (JSON or XML, auto-detected).
	for _, src := range r.config.Sources {
		lote, err := etsi119602.FetchLoTE(src, opts)
		if err != nil {
			return fmt.Errorf("failed to fetch LoTE from %s: %w", src, err)
		}
		lotes = append(lotes, lote)
	}

	// Load LoTL sources and follow pointers to discover LoTEs.
	visited := make(map[string]bool)
	for _, src := range r.config.LoTLSources {
		discovered, err := r.resolveLoTL(src, opts, 0, visited)
		if err != nil {
			return fmt.Errorf("failed to resolve LoTL from %s: %w", src, err)
		}
		lotes = append(lotes, discovered...)
	}

	idx := buildIndex(lotes, r.config.CryptoExt)

	r.mu.Lock()
	r.lotes = lotes
	r.index = idx
	r.healthy = true
	r.lastUpdated = time.Now()
	r.mu.Unlock()

	if r.config.Logger != nil {
		r.config.Logger.Info("LoTE registry refreshed",
			slog.Int("sources", len(r.config.Sources)),
			slog.Int("lotl_sources", len(r.config.LoTLSources)),
			slog.Int("lotes_loaded", len(lotes)),
			slog.Int("entities", len(idx.byID)))
	}

	return nil
}

func buildIndex(lotes []*etsi119602.ListOfTrustedEntities, ext *cryptoutil.Extensions) *entityIndex {
	idx := &entityIndex{
		byID:      make(map[string]*indexedEntity),
		byKeyHash: make(map[string]map[string]bool),
	}

	for _, lote := range lotes {
		territory := lote.ListAndSchemeInformation.SchemeTerritory
		for _, ent := range lote.TrustedEntitiesList {
			id := entityID(ent)
			ie := &indexedEntity{
				entity:    ent,
				entityID:  id,
				territory: territory,
				keyHashes: make(map[string]bool),
			}

			// Index service digital identities; skip withdrawn services.
			for _, svc := range ent.TrustedEntityServices {
				if isWithdrawnStatus(svc.ServiceInformation.ServiceStatus) {
					continue
				}
				sdi := svc.ServiceInformation.ServiceDigitalIdentity
				hashes := hashServiceDigitalIdentity(sdi, ext)
				for _, h := range hashes {
					ie.keyHashes[h] = true
					if idx.byKeyHash[h] == nil {
						idx.byKeyHash[h] = make(map[string]bool)
					}
					idx.byKeyHash[h][id] = true
				}

				// Add X.509 certs to the entity's cert pool for path validation.
				for _, cert509 := range sdi.X509Certificates {
					der, err := base64.StdEncoding.DecodeString(cert509.Val)
					if err == nil {
						cert, err := registry.ParseCertificate(der, ext)
						if err == nil {
							if ie.certPool == nil {
								ie.certPool = x509.NewCertPool()
							}
							ie.certPool.AddCert(cert)
						}
					}
				}
			}

			idx.byID[id] = ie
		}
	}

	return idx
}

// hashServiceDigitalIdentity produces SHA-256 fingerprints for an ETSI TS 119 602-1
// ServiceDigitalIdentity containing X.509 certificates, JWK public key values,
// and/or X.509 subject names.
func hashServiceDigitalIdentity(sdi etsi119602.ServiceDigitalIdentity, ext *cryptoutil.Extensions) []string {
	var hashes []string

	// X.509 certificates
	for _, cert509 := range sdi.X509Certificates {
		der, err := base64.StdEncoding.DecodeString(cert509.Val)
		if err == nil {
			cert, err := registry.ParseCertificate(der, ext)
			if err == nil {
				pubDER, err := x509.MarshalPKIXPublicKey(cert.PublicKey)
				if err == nil {
					h := sha256.Sum256(pubDER)
					hashes = append(hashes, fmt.Sprintf("%x", h))
				}
			}
		}
	}

	// JWK public key values
	for _, jwk := range sdi.PublicKeyValues {
		data, err := json.Marshal(jwk)
		if err == nil {
			h := sha256.Sum256(data)
			hashes = append(hashes, fmt.Sprintf("%x", h))
		}
		if h := hashJWKPublicKey(jwk); h != "" {
			hashes = append(hashes, h)
		}
	}

	// X.509 subject names
	for _, subj := range sdi.X509SubjectNames {
		h := sha256.Sum256([]byte(subj))
		hashes = append(hashes, fmt.Sprintf("%x", h))
	}

	return hashes
}

// hashJWKPublicKey hashes just the public key material of a JWK for
// deterministic comparison.
func hashJWKPublicKey(jwk map[string]interface{}) string {
	kty, ok := jwk["kty"].(string)
	if !ok {
		return ""
	}

	var parts []string
	parts = append(parts, "kty="+kty)

	switch kty {
	case "EC":
		if crv, ok := jwk["crv"].(string); ok {
			parts = append(parts, "crv="+crv)
		}
		if x, ok := jwk["x"].(string); ok {
			parts = append(parts, "x="+x)
		}
		if y, ok := jwk["y"].(string); ok {
			parts = append(parts, "y="+y)
		}
	case "RSA":
		if n, ok := jwk["n"].(string); ok {
			parts = append(parts, "n="+n)
		}
		if e, ok := jwk["e"].(string); ok {
			parts = append(parts, "e="+e)
		}
	case "OKP":
		if crv, ok := jwk["crv"].(string); ok {
			parts = append(parts, "crv="+crv)
		}
		if x, ok := jwk["x"].(string); ok {
			parts = append(parts, "x="+x)
		}
	default:
		return ""
	}

	canonical := strings.Join(parts, "|")
	h := sha256.Sum256([]byte(canonical))
	return fmt.Sprintf("%x", h)
}

// hashResourceKey produces a SHA-256 fingerprint from a request resource key,
// using the same algorithm as hashDigitalIdentity so values match.
func hashResourceKey(req *authzen.EvaluationRequest, ext *cryptoutil.Extensions) (string, error) {
	if len(req.Resource.Key) == 0 {
		return "", fmt.Errorf("resource.key is empty")
	}

	switch req.Resource.Type {
	case "x5c":
		// x5c: array of base64-encoded DER certificates; use the first (leaf)
		certB64, ok := req.Resource.Key[0].(string)
		if !ok {
			return "", fmt.Errorf("x5c key[0] is not a string")
		}
		der, err := base64.StdEncoding.DecodeString(certB64)
		if err != nil {
			return "", fmt.Errorf("failed to decode x5c cert: %w", err)
		}
		cert, err := registry.ParseCertificate(der, ext)
		if err != nil {
			return "", fmt.Errorf("failed to parse x5c cert: %w", err)
		}
		pubDER, err := x509.MarshalPKIXPublicKey(cert.PublicKey)
		if err != nil {
			return "", fmt.Errorf("failed to marshal public key: %w", err)
		}
		h := sha256.Sum256(pubDER)
		return fmt.Sprintf("%x", h), nil

	case "jwk":
		// jwk: array with a single JWK object
		jwkMap, ok := req.Resource.Key[0].(map[string]interface{})
		if !ok {
			// Try JSON re-encoding (gin may decode as json.RawMessage or similar)
			data, err := json.Marshal(req.Resource.Key[0])
			if err != nil {
				return "", fmt.Errorf("cannot marshal jwk key: %w", err)
			}
			if err := json.Unmarshal(data, &jwkMap); err != nil {
				return "", fmt.Errorf("cannot unmarshal jwk key: %w", err)
			}
		}
		if h := hashJWKPublicKey(jwkMap); h != "" {
			return h, nil
		}
		// Fallback: canonical JSON hash
		data, err := json.Marshal(jwkMap)
		if err != nil {
			return "", fmt.Errorf("cannot marshal jwk: %w", err)
		}
		h := sha256.Sum256(data)
		return fmt.Sprintf("%x", h), nil

	default:
		return "", fmt.Errorf("unsupported resource type: %s", req.Resource.Type)
	}
}

// resolveLoTL fetches a LoTL document and follows its pointers to load LoTEs.
// Nested LoTLs (pointers with LoTL scheme types) are resolved recursively up
// to MaxDereferenceDepth. The visited set prevents cycles.
func (r *Registry) resolveLoTL(location string, opts *etsi119602.FetchOptions, depth int, visited map[string]bool) ([]*etsi119602.ListOfTrustedEntities, error) {
	if r.config.MaxDereferenceDepth > 0 && depth >= r.config.MaxDereferenceDepth {
		if r.config.Logger != nil {
			r.config.Logger.Warn("LoTL dereference depth limit reached",
				slog.String("location", location),
				slog.Int("depth", depth))
		}
		return nil, nil
	}

	if visited[location] {
		if r.config.Logger != nil {
			r.config.Logger.Warn("LoTL cycle detected, skipping",
				slog.String("location", location))
		}
		return nil, nil
	}
	visited[location] = true

	if r.config.Logger != nil {
		r.config.Logger.Info("resolving LoTL", slog.String("location", location), slog.Int("depth", depth))
	}

	lotl, err := etsi119602.FetchLoTL(location, opts)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch LoTL from %s: %w", location, err)
	}

	var lotes []*etsi119602.ListOfTrustedEntities

	for _, ptr := range lotl.ListAndSchemeInformation.PointersToOtherLoTE {
		if ptr.LoTELocation == "" {
			continue
		}

		if etsi119602.IsLoTLSchemeType(pointerSchemeType(ptr)) {
			// Nested LoTL — resolve recursively.
			nested, err := r.resolveLoTL(ptr.LoTELocation, opts, depth+1, visited)
			if err != nil {
				if r.config.Logger != nil {
					r.config.Logger.Warn("failed to resolve nested LoTL",
						slog.String("location", ptr.LoTELocation),
						slog.String("error", err.Error()))
				}
				continue
			}
			lotes = append(lotes, nested...)
		} else {
			// LoTE pointer — fetch the LoTE directly.
			lote, err := etsi119602.FetchLoTE(ptr.LoTELocation, opts)
			if err != nil {
				if r.config.Logger != nil {
					r.config.Logger.Warn("failed to fetch LoTE from LoTL pointer",
						slog.String("location", ptr.LoTELocation),
						slog.String("error", err.Error()))
				}
				continue
			}
			lotes = append(lotes, lote)
		}
	}

	if r.config.Logger != nil {
		r.config.Logger.Info("LoTL resolved",
			slog.String("location", location),
			slog.Int("lotes_discovered", len(lotes)))
	}

	return lotes, nil
}

// entityID derives the entity identifier from a TrustedEntity.
// Prefers TEInformationURI[0].URIValue, falls back to TEName[0].Value.
func entityID(ent etsi119602.TrustedEntity) string {
	if len(ent.TrustedEntityInformation.TEInformationURI) > 0 {
		return ent.TrustedEntityInformation.TEInformationURI[0].URIValue
	}
	if len(ent.TrustedEntityInformation.TEName) > 0 {
		return ent.TrustedEntityInformation.TEName[0].Value
	}
	return ""
}

// isWithdrawnStatus returns true if the service status URI indicates withdrawal.
func isWithdrawnStatus(status string) bool {
	return strings.Contains(strings.ToLower(status), "withdrawn")
}

// pointerSchemeType extracts the LoTE type from a LoTL pointer's qualifiers.
func pointerSchemeType(ptr etsi119602.OtherLoTEPointer) string {
	if len(ptr.LoTEQualifiers) > 0 {
		return ptr.LoTEQualifiers[0].LoTEType
	}
	return ""
}
