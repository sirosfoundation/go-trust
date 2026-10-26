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
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/sirosfoundation/g119612/pkg/etsi119602"
	"github.com/sirosfoundation/go-cryptoutil"
	"github.com/sirosfoundation/go-trust/pkg/authzen"
	"github.com/sirosfoundation/go-trust/pkg/registry"
	"github.com/sirosfoundation/go-trust/pkg/registry/rpcert"
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

	// VerifyJWS requires JWS signature verification of every LoTE and LoTL
	// document (direct sources, LoTL sources and everything reached through
	// LoTL pointers). It needs trust anchors: New fails if VerifyJWS is set
	// and TrustAnchorProvider is nil or yields no pool. Verification is also
	// enabled whenever a TrustAnchorProvider yields a pool, even if VerifyJWS is
	// false, so configuring anchors can never be silently ineffective.
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

	// TrustAnchorProvider supplies root certificates used to anchor the LoTE
	// signer certificate chain for JWS signature verification per ETSI TS 119 615.
	// When nil (or when the provider returns a nil pool) and VerifyJWS is false,
	// signature verification is skipped — suitable for test environments or
	// deployments where the source is trusted through other means (HTTPS,
	// controlled distribution). With VerifyJWS true a missing pool is an error.
	// For APTITUDE/EUDI production use, inject an implementation that fetches
	// roots from the OJEU or a pinned bundle.
	TrustAnchorProvider LoTETrustAnchorProvider

	// RegisterClient is an optional National Register client used as a fallback
	// when WRPAC/WRPRC issuer resolution fails (AUTHZ-WRPAC-01-FAIL per RFC003).
	// When nil, no register fallback is attempted and the request is denied.
	// Inject a real implementation pointing at the national common REST API
	// (GET /wrp) for production APTITUDE/EUDI deployments.
	RegisterClient rpcert.NationalRegisterClient
}

// Registry is a TrustRegistry backed by ETSI TS 119 602 LoTE documents.
type Registry struct {
	config Config

	mu          sync.RWMutex
	lotes       []*etsi119602.ListOfTrustedEntities
	index       *entityIndex
	profiles    *rpcert.ProfileRegistry
	healthy     bool
	lastUpdated time.Time
	// lotlNextUpdates are the NextUpdate values of the LoTLs followed to load
	// lotes (see resolveState).
	lotlNextUpdates []time.Time

	stopCh chan struct{}
}

// entityIndex is a lookup structure built from loaded LoTEs.
type entityIndex struct {
	// byID maps entity ID (subject URL) → entity data.
	byID map[string]*indexedEntity

	// byKeyHash maps SHA-256 key hash → set of entity IDs that have that key.
	byKeyHash map[string]map[string]bool

	// globalCertPool is the union of all entity certPools, used for
	// CA-anchored chain validation when subject.id is not itself a listed entity
	// (e.g. Access Certificate lists enumerate CAs, not individual RPs).
	globalCertPool *x509.CertPool
}

// indexedEntity holds a single entity and its precomputed key hashes.
type indexedEntity struct {
	entity     etsi119602.TrustedEntity
	entityID   string
	territory  string
	schemeType string          // LoTE schemeType URI (determines status checking behavior)
	keyHashes  map[string]bool // SHA-256 fingerprints of all digital identities
	// certPool contains X.509 certificates from this entity's digital identities,
	// used as trust anchors for PKIX path validation of x5c requests.
	certPool *x509.CertPool
}

// Pub-EAA service status URIs per ETSI TS 119 602 Annex H.
const (
	pubEAAStatusNotified  = "http://uri.etsi.org/19602/PubEAAProvidersList/SvcStatus/notified"
	pubEAAStatusWithdrawn = "http://uri.etsi.org/19602/PubEAAProvidersList/SvcStatus/withdrawn"
)

// hasNotifiedService checks if a Pub-EAA entity has at least one active (non-withdrawn)
// service with "notified" status. Per ETSI TS 119 602 Annex H, Pub-EAA services must
// have explicit ServiceStatus; only "notified" confers trust.
// Withdrawn services are excluded regardless of their status value.
func hasNotifiedService(entity etsi119602.TrustedEntity) bool {
	for _, svc := range entity.TrustedEntityServices {
		if isWithdrawnStatus(svc.ServiceInformation.ServiceStatus) {
			continue
		}
		if svc.ServiceInformation.ServiceStatus == pubEAAStatusNotified {
			return true
		}
	}
	return false
}

// allServicesWithdrawnOrAbsent returns true when every service in a Pub-EAA entity
// either has a withdrawn status or has no status set at all. Used to produce a
// more informative denial reason than the generic "no notified service" message.
func allServicesWithdrawnOrAbsent(entity etsi119602.TrustedEntity) bool {
	for _, svc := range entity.TrustedEntityServices {
		s := svc.ServiceInformation.ServiceStatus
		if s != "" && !isWithdrawnStatus(s) {
			return false
		}
	}
	return true
}

var _ registry.TrustRegistry = (*Registry)(nil)

// New creates a new LoTE registry with the given config.
func New(cfg Config) (*Registry, error) {
	if len(cfg.Sources) == 0 && len(cfg.LoTLSources) == 0 {
		return nil, fmt.Errorf("lote registry requires at least one source or lotl_sources")
	}
	if cfg.VerifyJWS && cfg.TrustAnchorProvider == nil {
		return nil, ErrVerifyJWSNoAnchors
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
		config:   cfg,
		profiles: rpcert.DefaultProfileRegistry(),
		index:    &entityIndex{byID: make(map[string]*indexedEntity), byKeyHash: make(map[string]map[string]bool)},
		stopCh:   make(chan struct{}),
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

func (r *Registry) Evaluate(ctx context.Context, req *authzen.EvaluationRequest) (*authzen.EvaluationResponse, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	subjectID := req.Subject.ID

	// Extract credential_types early for inclusion in all responses (audit).
	credentialTypes := extractCredentialTypes(req)

	// Look up entity by subject ID.
	ent, ok := r.index.byID[subjectID]
	if !ok {
		// For x5c requests: the list may enumerate CAs rather than individual
		// relying parties (e.g. an Access Certificate list). Attempt CA-anchored
		// chain validation against the combined pool of all listed entity certs.
		// This matches the model described in issue #90.
		if req.Resource.Type == "x5c" && r.index.globalCertPool != nil {
			if resp := r.validateX5CChainCA(req, credentialTypes); resp != nil {
				return resp, nil
			}
		}
		// National Register fallback (RFC003 AUTHZ-WRPAC-01-FAIL / AUTHZ-WRPRC-01-FAIL):
		// when issuer resolution fails and a register client is configured, attempt
		// a register lookup before denying. A successful register response is treated
		// as equivalent to "registered but not yet notified in LoTE".
		// Release the RLock before the (potentially blocking) network call to avoid
		// stalling concurrent refreshes or other evaluations under the writer lock.
		if r.config.RegisterClient != nil {
			regClient := r.config.RegisterClient
			r.mu.RUnlock()
			regEnt, regErr := regClient.LookupRP(ctx, subjectID)
			r.mu.RLock()
			if regErr == nil && regEnt != nil && regEnt.IsValid() {
				reason := map[string]interface{}{
					"admin":               fmt.Sprintf("entity %q resolved via National Register fallback (not in LoTE)", subjectID),
					"registration_status": string(regEnt.RegistrationStatus),
				}
				addCredentialTypesToReason(reason, credentialTypes)
				return &authzen.EvaluationResponse{
					Decision: true,
					Context: &authzen.EvaluationResponseContext{
						Reason:        reason,
						TrustMetadata: regEnt,
					},
				}, nil
			}
		}
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

	// Check trust status based on LoTE profile type (ETSI TS 119 602 compliance).
	// - Pub-EAA (Annex H): ServiceStatus is mandatory, check at service level
	// - All other profiles (PID, Wallet, WRPAC, WRPRC, Registrars): presence in list = trusted
	// Withdrawn services are excluded during indexing for all profiles.
	if etsi119602.IsPubEAASchemeType(ent.schemeType) {
		// Pub-EAA requires explicit service status check (ETSI TS 119 602 Annex H).
		if !hasNotifiedService(ent.entity) {
			adminMsg := fmt.Sprintf("entity %q has no service with 'notified' status", subjectID)
			if allServicesWithdrawnOrAbsent(ent.entity) {
				adminMsg = fmt.Sprintf("entity %q has no active services (all withdrawn or status absent)", subjectID)
			}
			reason := map[string]interface{}{"admin": adminMsg}
			addCredentialTypesToReason(reason, credentialTypes)
			return &authzen.EvaluationResponse{
				Decision: false,
				Context:  &authzen.EvaluationResponseContext{Reason: reason},
			}, nil
		}
	}
	// For non-Pub-EAA profiles: presence in list means trusted (no status check needed)

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

// SetProfiles replaces the RP certificate profile registry used during
// x5c enrichment. Pass nil to disable profile-based enrichment.
func (r *Registry) SetProfiles(profiles *rpcert.ProfileRegistry) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.profiles = profiles
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

// Freshness reports when the LoTEs were loaded and the earliest NextUpdate among
// them. A decision may rest on any loaded LoTE, so if one of them has no usable
// NextUpdate the registry's NextUpdate is unknown rather than another list's date.
// The LoTLs followed to discover LoTEs count as lists, and the NextUpdate is
// unknown when a National Register fallback is configured.
func (r *Registry) Freshness() registry.Freshness {
	r.mu.RLock()
	defer r.mu.RUnlock()
	// A National Register fallback can authorise a decision with data that has
	// no freshness contract.
	if r.config.RegisterClient != nil {
		return registry.Freshness{AsOf: r.lastUpdated}
	}
	next := append(make([]time.Time, 0, len(r.lotes)+len(r.lotlNextUpdates)), r.lotlNextUpdates...)
	for _, l := range r.lotes {
		if l == nil {
			continue
		}
		next = append(next, registry.ParseSourceTime(l.ListAndSchemeInformation.NextUpdate))
	}
	return registry.Freshness{AsOf: r.lastUpdated, NextUpdate: registry.EarliestKnown(next...)}
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
		// ExtKeyUsageAny: WRPACs may carry only id-kp-clientAuth.
		// Go's zero-value KeyUsages defaults to ExtKeyUsageServerAuth.
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}
	if len(certs) > 1 {
		intermediates := x509.NewCertPool()
		for _, cert := range certs[1:] {
			intermediates.AddCert(cert)
		}
		opts.Intermediates = intermediates
	}

	if _, err := certs[0].Verify(opts); err == nil {
		// Post-chain-validation enrichment: cert policy OID check + RP identity extraction
		enrichment := registry.EnrichX5CResponseWithProfiles(req, certs[0], r.profiles)
		if !enrichment.Decision {
			reason := map[string]interface{}{
				"admin": fmt.Sprintf("x5c chain valid for entity %q but enrichment check failed", ent.entityID),
			}
			for k, v := range enrichment.FailureReason {
				reason[k] = v
			}
			addCredentialTypesToReason(reason, credentialTypes)
			return &authzen.EvaluationResponse{
				Decision: false,
				Context: &authzen.EvaluationResponseContext{
					Reason: reason,
				},
			}
		}
		resp := r.buildSuccessResponse(ent.entityID, ent.territory, "x5c chain validates against trust anchor for entity", credentialTypes)
		registry.ApplyEnrichmentToResponse(resp, enrichment)
		return resp
	}
	return nil
}

// validateX5CChainCA handles the CA-anchored trust model (issue #90): when the
// subject.id is not itself a listed entity — as is the case for Access Certificate
// trust lists that enumerate CAs rather than individual relying parties — the x5c
// chain is validated against the combined pool of all listed entity certs.
// Returns a positive response if the chain validates, nil otherwise.
func (r *Registry) validateX5CChainCA(req *authzen.EvaluationRequest, credentialTypes []string) *authzen.EvaluationResponse {
	certs, err := parseX5CCerts(req, r.config.CryptoExt)
	if err != nil || len(certs) == 0 {
		return nil
	}

	opts := x509.VerifyOptions{
		Roots: r.index.globalCertPool,
		// ExtKeyUsageAny: access certificates may carry only id-kp-clientAuth.
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}
	if len(certs) > 1 {
		intermediates := x509.NewCertPool()
		for _, cert := range certs[1:] {
			intermediates.AddCert(cert)
		}
		opts.Intermediates = intermediates
	}

	if _, err := certs[0].Verify(opts); err != nil {
		return nil // chain does not validate against any listed CA
	}

	// Chaining to a listed CA proves the certificate was validly issued by
	// one of the LoTE's own trust anchors; it says nothing about whether it
	// belongs to the identity req.Subject.ID is claiming. When the caller
	// used one of OpenID4VP's certificate-binding client_id_schemes
	// (x509_san_dns/x509_san_uri/x509_hash - recovered via OriginalSubjectID
	// since RegistryManager may have rewritten Subject.ID), verify the
	// binding before trusting the chain. Requests that don't use one of
	// these schemes (e.g. a plain RP identifier under an Access Certificate
	// list, issue #90) are unaffected - there is no additional claim to bind
	// in that model, so behavior is unchanged for them.
	if scheme, value, ok := registry.ParseClientIDScheme(registry.OriginalSubjectID(req)); ok {
		if bindErr := registry.VerifyLeafBinding(scheme, value, certs[0]); bindErr != nil {
			reason := map[string]interface{}{
				"admin": fmt.Sprintf("x5c chain validates against a listed CA but certificate binding check failed: %s", bindErr),
			}
			addCredentialTypesToReason(reason, credentialTypes)
			return &authzen.EvaluationResponse{
				Decision: false,
				Context:  &authzen.EvaluationResponseContext{Reason: reason},
			}
		}
	}

	// Find which listed entity's CA pool the chain validates against (for metadata
	// and profile-aware status checking).
	matchedEnt := r.findMatchingEntityForChain(certs)
	if matchedEnt == nil {
		// chain validated against globalCertPool but we can't identify the CA entity;
		// this should not normally happen — treat as unresolvable.
		return nil
	}
	matchedID := matchedEnt.entityID
	territory := matchedEnt.territory

	// For Pub-EAA LoTEs: the CA-anchored path must also enforce the notified-status
	// requirement. A chain anchored to a Pub-EAA CA whose services are not notified
	// must be rejected, matching the behaviour of the direct-lookup path.
	if etsi119602.IsPubEAASchemeType(matchedEnt.schemeType) {
		if !hasNotifiedService(matchedEnt.entity) {
			adminMsg := fmt.Sprintf("x5c chain anchors to Pub-EAA CA %q which has no service with 'notified' status", matchedID)
			if allServicesWithdrawnOrAbsent(matchedEnt.entity) {
				adminMsg = fmt.Sprintf("x5c chain anchors to Pub-EAA CA %q which has no active services (all withdrawn or status absent)", matchedID)
			}
			reason := map[string]interface{}{"admin": adminMsg}
			addCredentialTypesToReason(reason, credentialTypes)
			return &authzen.EvaluationResponse{
				Decision: false,
				Context:  &authzen.EvaluationResponseContext{Reason: reason},
			}
		}
	}

	// Post-chain-validation enrichment (profile / WRPRC checks).
	enrichment := registry.EnrichX5CResponseWithProfiles(req, certs[0], r.profiles)
	if !enrichment.Decision {
		reason := map[string]interface{}{
			"admin": fmt.Sprintf("x5c chain validates against CA %q in LoTE but enrichment check failed", matchedID),
		}
		for k, v := range enrichment.FailureReason {
			reason[k] = v
		}
		addCredentialTypesToReason(reason, credentialTypes)
		return &authzen.EvaluationResponse{
			Decision: false,
			Context:  &authzen.EvaluationResponseContext{Reason: reason},
		}
	}

	resp := r.buildSuccessResponse(req.Subject.ID, territory,
		fmt.Sprintf("x5c chain validates against CA-anchored entity %q for subject", matchedID),
		credentialTypes)
	registry.ApplyEnrichmentToResponse(resp, enrichment)
	return resp
}

// findMatchingEntityForChain identifies which listed entity's cert pool the given
// chain validates against. Returns the first matched indexedEntity, or nil if none match.
func (r *Registry) findMatchingEntityForChain(certs []*x509.Certificate) *indexedEntity {
	for _, ent := range r.index.byID {
		if ent.certPool == nil {
			continue
		}
		opts := x509.VerifyOptions{
			Roots:     ent.certPool,
			KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
		}
		if len(certs) > 1 {
			intermediates := x509.NewCertPool()
			for _, cert := range certs[1:] {
				intermediates.AddCert(cert)
			}
			opts.Intermediates = intermediates
		}
		if _, err := certs[0].Verify(opts); err == nil {
			return ent
		}
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

	// Resolve trust anchors once per refresh. A nil pool skips verification
	// unless VerifyJWS demands it, in which case refresh fails closed.
	var taPool *x509.CertPool
	if r.config.TrustAnchorProvider != nil {
		var taErr error
		taPool, taErr = r.config.TrustAnchorProvider.TrustAnchors(context.Background())
		if taErr != nil {
			return fmt.Errorf("lote: resolving trust anchors: %w", taErr)
		}
	}
	if r.config.VerifyJWS && taPool == nil {
		return ErrVerifyJWSNoAnchors
	}

	// Load direct LoTE sources (JSON or XML, auto-detected).
	for _, src := range r.config.Sources {
		if taPool != nil {
			lote, err := r.fetchVerifiedLoTE(src, taPool)
			if err != nil {
				return err
			}
			lotes = append(lotes, lote)
			continue
		}
		lote, err := etsi119602.FetchLoTE(src, opts)
		if err != nil {
			return fmt.Errorf("failed to fetch LoTE from %s: %w", src, err)
		}
		lotes = append(lotes, lote)
	}

	// Load LoTL sources and follow pointers to discover LoTEs.
	st := &resolveState{visited: make(map[string]bool)}
	for _, src := range r.config.LoTLSources {
		discovered, err := r.resolveLoTL(src, opts, 0, st, taPool)
		if err != nil {
			return fmt.Errorf("failed to resolve LoTL from %s: %w", src, err)
		}
		lotes = append(lotes, discovered...)
	}

	idx := buildIndex(lotes, r.config.CryptoExt)

	r.mu.Lock()
	r.lotes = lotes
	r.lotlNextUpdates = st.lotlNextUpdates
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
		schemeType := lote.ListAndSchemeInformation.LoTEType
		isPubEAA := etsi119602.IsPubEAASchemeType(schemeType)
		for _, ent := range lote.TrustedEntitiesList {
			id := entityID(ent)
			ie := &indexedEntity{
				entity:     ent,
				entityID:   id,
				territory:  territory,
				schemeType: schemeType,
				keyHashes:  make(map[string]bool),
			}

			// Index service digital identities.
			// - Non-Pub-EAA LoTEs: skip withdrawn services only (presence = trusted).
			// - Pub-EAA LoTEs (ETSI TS 119 602 Annex H): only index services with
			//   an explicit "notified" status. Services with absent, withdrawn, or
			//   any other status are excluded so that a key from a non-notified
			//   service is never reachable through the index even when the entity
			//   also has a notified service.
			for _, svc := range ent.TrustedEntityServices {
				status := svc.ServiceInformation.ServiceStatus
				if isPubEAA {
					if status != pubEAAStatusNotified {
						continue
					}
				} else {
					if isWithdrawnStatus(status) {
						continue
					}
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
							// Also add to the global pool for CA-anchored chain
							// validation (issue #90).
							if idx.globalCertPool == nil {
								idx.globalCertPool = x509.NewCertPool()
							}
							idx.globalCertPool.AddCert(cert)
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

// ErrVerifyJWSNoAnchors is returned when JWS verification is required but no
// trust anchors are available. The registry refuses to load rather than fall
// back to unverified content.
var ErrVerifyJWSNoAnchors = errors.New("lote: verify_jws is enabled but no trust anchors are available")

// fetchVerifiedPayload fetches src, verifies its JWS against roots and returns
// the verified payload. The returned bytes are what was signed, so there is no
// second fetch between verification and use.
func (r *Registry) fetchVerifiedPayload(src string, roots *x509.CertPool) ([]byte, error) {
	raw, err := fetchRawSource(src, r.config.FetchTimeout)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch raw LoTE from %s: %w", src, err)
	}
	signer, payload, err := verifyLoTEJWS(context.Background(), raw, roots, time.Now())
	if err != nil {
		return nil, fmt.Errorf("LoTE signature verification failed for %s: %w", src, err)
	}
	if r.config.Logger != nil {
		r.config.Logger.Info("LoTE JWS signature verified",
			slog.String("source", src),
			slog.String("signer", signer.Subject.CommonName))
	}
	return payload, nil
}

// fetchVerifiedLoTE is fetchVerifiedPayload followed by parsing the payload.
func (r *Registry) fetchVerifiedLoTE(src string, roots *x509.CertPool) (*etsi119602.ListOfTrustedEntities, error) {
	payload, err := r.fetchVerifiedPayload(src, roots)
	if err != nil {
		return nil, err
	}
	lote, err := etsi119602.ParseLoTE(payload)
	if err != nil {
		return nil, fmt.Errorf("failed to parse verified LoTE from %s: %w", src, err)
	}
	return lote, nil
}

// resolveState is the per-refresh state shared by LoTL resolution.
type resolveState struct {
	// visited is the set of LoTL locations already followed (cycle cut).
	visited map[string]bool
	// lotlNextUpdates holds the NextUpdate of every LoTL followed, nested ones
	// included; a zero time is a LoTL without a usable date.
	lotlNextUpdates []time.Time
}

// resolveLoTL fetches a LoTL document and follows its pointers to load LoTEs.
// Nested LoTLs (pointers with LoTL scheme types) are resolved recursively up
// to MaxDereferenceDepth. The visited set prevents cycles.
//
// When roots is non-nil every document is JWS-verified against it: the LoTL
// itself and each LoTE or nested LoTL it points to. A LoTL that fails
// verification is an error (never parsed); a pointer target that fails
// verification is logged at error level and skipped, exactly like a pointer
// target that cannot be fetched, so it never contributes entities.
func (r *Registry) resolveLoTL(location string, opts *etsi119602.FetchOptions, depth int, st *resolveState, roots *x509.CertPool) ([]*etsi119602.ListOfTrustedEntities, error) {
	if r.config.MaxDereferenceDepth > 0 && depth >= r.config.MaxDereferenceDepth {
		if r.config.Logger != nil {
			r.config.Logger.Warn("LoTL dereference depth limit reached",
				slog.String("location", location),
				slog.Int("depth", depth))
		}
		return nil, nil
	}

	if st.visited[location] {
		if r.config.Logger != nil {
			r.config.Logger.Warn("LoTL cycle detected, skipping",
				slog.String("location", location))
		}
		return nil, nil
	}

	if r.config.Logger != nil {
		r.config.Logger.Info("resolving LoTL", slog.String("location", location), slog.Int("depth", depth))
	}

	lotl, err := r.loadLoTL(location, opts, roots)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch LoTL from %s: %w", location, err)
	}
	// Mark visited only once the LoTL has loaded (and verified, when required)
	// and before following its pointers, so cycles are still cut. A LoTL that
	// failed to verify must stay unvisited: the visited set is shared across
	// top-level sources, and marking it earlier would let a later top-level
	// reference to the same location skip verification and "succeed".
	st.visited[location] = true
	// The LoTL decides which LoTEs are loaded: when it is replaced a pointer may
	// go away, so its deadline bounds the loaded LoTEs too. Undated is unknown.
	st.lotlNextUpdates = append(st.lotlNextUpdates, registry.ParseSourceTime(lotl.ListAndSchemeInformation.NextUpdate))

	var lotes []*etsi119602.ListOfTrustedEntities
	for _, ptr := range lotl.ListAndSchemeInformation.PointersToOtherLoTE {
		if ptr.LoTELocation == "" {
			continue
		}
		lotes = append(lotes, r.resolvePointer(ptr, opts, depth, st, roots)...)
	}

	if r.config.Logger != nil {
		r.config.Logger.Info("LoTL resolved",
			slog.String("location", location),
			slog.Int("lotes_discovered", len(lotes)))
	}

	return lotes, nil
}

// loadLoTL fetches a LoTL, verifying its JWS first when roots is non-nil.
func (r *Registry) loadLoTL(location string, opts *etsi119602.FetchOptions, roots *x509.CertPool) (*etsi119602.ListOfTrustedLists, error) {
	if roots == nil {
		return etsi119602.FetchLoTL(location, opts)
	}
	payload, err := r.fetchVerifiedPayload(location, roots)
	if err != nil {
		return nil, err
	}
	return etsi119602.ParseLoTL(payload)
}

// resolvePointer loads the target of one LoTL pointer: a nested LoTL is
// resolved recursively, anything else is loaded as a LoTE. Failures (including
// signature verification failures) are logged at error level and the target is
// skipped, so an unverified document never contributes entities.
func (r *Registry) resolvePointer(ptr etsi119602.OtherLoTEPointer, opts *etsi119602.FetchOptions, depth int, st *resolveState, roots *x509.CertPool) []*etsi119602.ListOfTrustedEntities {
	var out []*etsi119602.ListOfTrustedEntities
	var err error
	kind := "LoTE"
	if etsi119602.IsLoTLSchemeType(pointerSchemeType(ptr)) {
		kind = "nested LoTL"
		out, err = r.resolveLoTL(ptr.LoTELocation, opts, depth+1, st, roots)
	} else {
		var lote *etsi119602.ListOfTrustedEntities
		if roots != nil {
			lote, err = r.fetchVerifiedLoTE(ptr.LoTELocation, roots)
		} else {
			lote, err = etsi119602.FetchLoTE(ptr.LoTELocation, opts)
		}
		if err == nil {
			out = []*etsi119602.ListOfTrustedEntities{lote}
		}
	}
	if err != nil {
		if r.config.Logger != nil {
			r.config.Logger.Error("failed to load "+kind+" from LoTL pointer; source skipped",
				slog.String("location", ptr.LoTELocation),
				slog.String("error", err.Error()))
		}
		return nil
	}
	return out
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
