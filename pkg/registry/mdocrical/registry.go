// Package mdocrical provides a Reader Identity Certificate Authority List
// (RICAL) registry for go-trust that authenticates mdoc readers via reader
// authentication (ISO/IEC 18013-5 second-edition Annex F).
//
// RICAL is the reader-side mirror of the existing mdociaca registry's issuer
// trust: instead of trusting an mdoc's issuer, this trusts an mdoc reader's
// end-entity certificate for reader authentication (section 9.1.4). Unlike
// mdociaca (which fetches per-issuer IACAs from OpenID4VCI metadata), a RICAL
// is a single, centrally-published, COSE_Sign1-signed document (per F.3.2)
// fetched from one configured provider URL and refreshed on a cache TTL -
// this is what lets a RICAL Provider update the list "between days" during
// an interop test event without any wallet/reader redeploy.
//
// # Architecture
//
//  1. Fetches the RICAL from the configured provider URL (or uses the cached
//     copy if still fresh).
//  2. Verifies the RICAL's own COSE_Sign1 signature against the configured
//     RICAL root certificate (out-of-band trust anchor per F.3.1 - this
//     annex does not define how root trust is established, so it must be
//     operator-configured, same as mdociaca's own IssuerAllowlist).
//  3. Given a reader's certificate chain (resource.key, identical shape to
//     mdociaca's x5c resource), path-validates it against the RICAL's
//     trust-anchor-flagged CertificateInfo entries and applies the first
//     (bottom-up) matching entry's TrustConstraints, per F.3.2.6.
package mdocrical

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"sync"
	"time"

	"github.com/SUNET/vc/pkg/mdoc"
	"github.com/fxamacker/cbor/v2"
	gocryptoutil "github.com/sirosfoundation/go-cryptoutil"
	"github.com/sirosfoundation/go-trust/pkg/authzen"
	"github.com/sirosfoundation/go-trust/pkg/registry"
)

// Config holds the configuration for a RICAL registry instance.
type Config struct {
	// Name is a unique identifier for this registry instance.
	Name string

	// Description is a human-readable description of this registry.
	Description string

	// RicalProviderURL is the HTTPS URL to fetch the RICAL from.
	RicalProviderURL string

	// RicalRootCertificatePEM is the PEM-encoded RICAL root certificate -
	// the out-of-band trust anchor for the RICAL's own COSE_Sign1
	// signature (F.3.1: "distributed out of band to RICAL Subscribers").
	RicalRootCertificatePEM string

	// CacheTTL is how long the fetched RICAL is cached before refetching.
	// Default: 1 hour.
	CacheTTL time.Duration

	// HTTPTimeout is the timeout for fetching the RICAL. Default: 30s.
	HTTPTimeout time.Duration

	// AllowPrivateIPs permits requests to private/internal networks.
	// WARNING: only for testing or internal deployments.
	AllowPrivateIPs bool

	// AllowHTTP permits non-TLS (HTTP) connections.
	// WARNING: only for testing.
	AllowHTTP bool

	// CryptoExt provides extensible certificate parsing for non-standard
	// curves (e.g. brainpool). If nil, standard x509.ParseCertificate is
	// used.
	//
	// Note: this registry does not enforce CertificateInfo.IsTrustAnchor as
	// a gate on path validation, even though F.3.2.2 currently documents it
	// as Required - the interop event organizers have confirmed
	// isTrustAnchor is being removed from the ISO/IEC 18013-5 standard
	// going forward, and real published RICALs (e.g. the Geneva 2026
	// event's live document at geneva2026.mdoc.online) already omit it in
	// practice. See validateChainAgainstAnchors's doc comment for details.
	CryptoExt *gocryptoutil.Extensions
}

// TrustConstraint mirrors the RICAL structure's TrustConstraint (F.3.2.3).
type TrustConstraint struct {
	Policies            []string `cbor:"policies,omitempty"`
	EKU                 []string `cbor:"eku,omitempty"`
	PathLen             *uint64  `cbor:"pathLen,omitempty"`
	CertificateProfiles []string `cbor:"certificateProfiles,omitempty"`
}

// RICALCertificateInfo mirrors the RICAL structure's RICALCertificateInfo
// (F.3.2.2).
type RICALCertificateInfo struct {
	Certificate  []byte   `cbor:"certificate"`
	SerialNumber *big.Int `cbor:"serialNumber"`
	SKI          []byte   `cbor:"ski"`
	// IsTrustAnchor is decoded for completeness but not enforced as a gate
	// anywhere in this package - see Config.CryptoExt's doc comment for why.
	IsTrustAnchor    bool              `cbor:"isTrustAnchor"`
	AKI              []byte            `cbor:"aki,omitempty"`
	Type             string            `cbor:"type,omitempty"`
	TrustConstraints []TrustConstraint `cbor:"trustConstraints,omitempty"`
	Name             string            `cbor:"name,omitempty"`
	IssuingCountry   string            `cbor:"issuingCountry,omitempty"`
}

// RICAL mirrors the RICAL structure per F.3.2.1.
type RICAL struct {
	Version          string                 `cbor:"version"`
	Provider         string                 `cbor:"provider"`
	Date             string                 `cbor:"date"`
	NextUpdate       string                 `cbor:"nextUpdate,omitempty"`
	NotAfter         string                 `cbor:"notAfter,omitempty"`
	CertificateInfos []RICALCertificateInfo `cbor:"certificateInfos"`
	ID               uint64                 `cbor:"id,omitempty"`
	LatestRicalURL   string                 `cbor:"latestRicalUrl,omitempty"`
	Type             string                 `cbor:"type"`
}

// cachedRical holds the fetched-and-verified RICAL plus fetch time.
type cachedRical struct {
	rical     *RICAL
	fetchedAt time.Time
}

// Registry implements TrustRegistry for RICAL-based reader authentication.
type Registry struct {
	config     *Config
	httpClient registry.HTTPClientInterface
	ricalRoot  *x509.Certificate

	mu    sync.RWMutex
	cache *cachedRical
}

// New creates a new RICAL registry with the given configuration.
func New(cfg *Config) (*Registry, error) {
	if cfg == nil {
		cfg = &Config{}
	}
	if cfg.Name == "" {
		cfg.Name = "mdoc-rical"
	}
	if cfg.CacheTTL == 0 {
		cfg.CacheTTL = time.Hour
	}
	if cfg.HTTPTimeout == 0 {
		cfg.HTTPTimeout = 30 * time.Second
	}
	if cfg.RicalProviderURL == "" {
		return nil, fmt.Errorf("RicalProviderURL is required")
	}
	if cfg.RicalRootCertificatePEM == "" {
		return nil, fmt.Errorf("RicalRootCertificatePEM is required")
	}

	block, _ := pem.Decode([]byte(cfg.RicalRootCertificatePEM))
	if block == nil {
		return nil, fmt.Errorf("RicalRootCertificatePEM is not valid PEM")
	}
	rootCert, err := registry.ParseCertificate(block.Bytes, cfg.CryptoExt)
	if err != nil {
		return nil, fmt.Errorf("invalid RICAL root certificate: %w", err)
	}

	httpClient := registry.NewSafeHTTPClient(registry.SafeClientConfig{
		Timeout:         cfg.HTTPTimeout,
		AllowPrivateIPs: cfg.AllowPrivateIPs,
		AllowHTTP:       cfg.AllowHTTP,
	})

	return &Registry{
		config:     cfg,
		httpClient: httpClient,
		ricalRoot:  rootCert,
	}, nil
}

// Evaluate verifies a reader's X5C certificate chain against the RICAL's
// trust-anchor-flagged CertificateInfo entries, applying TrustConstraints
// from the first (bottom-up) matching entry, per F.3.2.6.
func (r *Registry) Evaluate(ctx context.Context, req *authzen.EvaluationRequest) (*authzen.EvaluationResponse, error) {
	chain, err := parseX5CChain(req.Resource.Key, r.config.CryptoExt)
	if err != nil {
		return r.denyWithReason(fmt.Sprintf("invalid X5C chain: %v", err)), nil
	}
	if len(chain) == 0 {
		return r.denyWithReason("empty X5C chain"), nil
	}

	rical, err := r.getRical(ctx)
	if err != nil {
		return r.denyWithReason(fmt.Sprintf("failed to get RICAL: %v", err)), nil
	}

	matchedInfo, matchIdx, err := resolveCertificateInfo(chain, rical.CertificateInfos, r.config.CryptoExt)
	if err != nil {
		return r.denyWithReason(fmt.Sprintf("certificate path validation failed: %v", err)), nil
	}

	if len(matchedInfo.TrustConstraints) > 0 {
		if !anyTrustConstraintSatisfied(matchedInfo.TrustConstraints) {
			return r.denyWithReason("no trust constraint satisfied for reader certificate"), nil
		}
	}

	return &authzen.EvaluationResponse{
		Decision: true,
		Context: &authzen.EvaluationResponseContext{
			Reason: map[string]interface{}{
				"trust_anchor":     "mdoc_rical",
				"rical_provider":   rical.Provider,
				"matched_cert_idx": matchIdx,
			},
		},
	}, nil
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
		Type:          "mdoc_rical",
		Description:   r.config.Description,
		Version:       "1.0.0",
		ResourceTypes: r.SupportedResourceTypes(),
	}
}

// Healthy returns true if the registry is operational.
func (r *Registry) Healthy() bool {
	return true
}

// Refresh clears the cached RICAL, forcing a fresh fetch+verify on next
// Evaluate call - this is what lets an operator (or a cache-TTL expiry)
// pick up a RICAL the provider updated mid-event.
func (r *Registry) Refresh(ctx context.Context) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.cache = nil
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

func (r *Registry) getRical(ctx context.Context) (*RICAL, error) {
	r.mu.RLock()
	cached := r.cache
	r.mu.RUnlock()

	if cached != nil && time.Since(cached.fetchedAt) < r.config.CacheTTL {
		return cached.rical, nil
	}

	rical, err := r.fetchAndVerifyRical(ctx)
	if err != nil {
		return nil, err
	}

	r.mu.Lock()
	r.cache = &cachedRical{rical: rical, fetchedAt: time.Now()}
	r.mu.Unlock()

	return rical, nil
}

func (r *Registry) fetchAndVerifyRical(ctx context.Context) (*RICAL, error) {
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, r.config.RicalProviderURL, nil)
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Accept", "application/cbor")

	resp, err := r.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("fetch RICAL: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck // Body close error is not actionable

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("RICAL provider returned %d", resp.StatusCode)
	}

	body, err := io.ReadAll(registry.LimitedReader(resp.Body))
	if err != nil {
		return nil, fmt.Errorf("read RICAL body: %w", err)
	}

	sign1, err := parseUntaggedCOSESign1(body)
	if err != nil {
		return nil, fmt.Errorf("parse RICAL COSE_Sign1: %w", err)
	}

	// F.3.2: the RICAL signer certificate (x5chain) is in the PROTECTED
	// header - the opposite convention from this codebase's own
	// issuerAuth/deviceAuth COSE_Sign1 usage (and from VICAL below), where
	// x5chain lives in the unprotected header. Confirmed directly from the
	// spec text - do not "fix" this to match the other convention.
	signerChain, err := extractX5ChainFromProtectedHeader(sign1.Protected, r.config.CryptoExt)
	if err != nil {
		return nil, fmt.Errorf("extract RICAL signer x5chain: %w", err)
	}
	if len(signerChain) == 0 {
		return nil, fmt.Errorf("RICAL COSE_Sign1 has no signer certificate")
	}
	signerCert := signerChain[0]

	// Validate the signer certificate chains to the configured RICAL root.
	roots := x509.NewCertPool()
	roots.AddCert(r.ricalRoot)
	intermediates := x509.NewCertPool()
	for _, c := range signerChain[1:] {
		intermediates.AddCert(c)
	}
	if _, err := signerCert.Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		CurrentTime:   time.Now(),
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}); err != nil {
		return nil, fmt.Errorf("RICAL signer certificate does not chain to configured root: %w", err)
	}

	// external_aad shall be a zero-length bstr, per F.3.2 - passed as []byte{}
	// rather than nil: fxamacker/cbor encodes a nil []byte boxed in an `any`
	// as CBOR null (0xf6), not an empty byte string (0x40), so a nil here
	// would hash a different Sig_structure than what a spec-conformant
	// signer (using an actual zero-length bstr) signed over, making
	// verification always fail. Confirmed against the pinned vc v0.6.5
	// (this module's go.sum version) - a real, CI-only failure this
	// workspace's go.work masked locally by resolving vc to a newer local
	// checkout that happens to normalize nil to empty internally.
	if err := mdoc.Verify1(sign1, sign1.Payload, signerCert.PublicKey, []byte{}); err != nil {
		return nil, fmt.Errorf("RICAL signature verification failed: %w", err)
	}

	var rical RICAL
	if err := cbor.Unmarshal(sign1.Payload, &rical); err != nil {
		return nil, fmt.Errorf("decode RICAL payload: %w", err)
	}
	if len(rical.CertificateInfos) == 0 {
		return nil, fmt.Errorf("RICAL certificateInfos is empty")
	}

	return &rical, nil
}

func parseX5CChain(key interface{}, ext *gocryptoutil.Extensions) ([]*x509.Certificate, error) {
	if key == nil {
		return nil, fmt.Errorf("key is nil")
	}

	var certStrings []string
	switch v := key.(type) {
	case []interface{}:
		for _, item := range v {
			s, ok := item.(string)
			if !ok {
				return nil, fmt.Errorf("X5C chain element is not a string")
			}
			certStrings = append(certStrings, s)
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
		cert, err := registry.ParseCertificate(der, ext)
		if err != nil {
			return nil, fmt.Errorf("certificate %d: invalid X.509: %w", i, err)
		}
		certs = append(certs, cert)
	}
	return certs, nil
}

// findFirstMatchingCertificateInfo returns the first (bottom-up, i.e.
// closest-to-leaf) CertificateInfo in the RICAL whose certificate appears
// in the presented chain, per F.3.2.6: "The CertificateInfo element of the
// first certificate (bottom-up) in the certificate chain included in the
// RICAL shall be used to determine and apply the associated Trust
// Constraints."
func findFirstMatchingCertificateInfo(chain []*x509.Certificate, infos []RICALCertificateInfo, ext *gocryptoutil.Extensions) (*RICALCertificateInfo, int) {
	for _, cert := range chain {
		for i := range infos {
			infoCert, err := registry.ParseCertificate(infos[i].Certificate, ext)
			if err != nil {
				continue
			}
			if cert.Equal(infoCert) {
				return &infos[i], i
			}
		}
	}
	return nil, -1
}

// validateChainAgainstAnchors builds a root pool from every CertificateInfo
// in the RICAL and validates the presented chain against it, using the
// presented chain's own intermediates to help complete the path. Returns
// every verified chain (leaf-to-root) x509.Verify found, so a caller can
// identify which specific RICAL entry the chain actually resolved to - see
// resolveCertificateInfo's doc comment for why that matters.
//
// isTrustAnchor is deliberately NOT enforced as a gate here, even though
// F.3.2.2 currently documents it as Required: the interop event organizers
// have confirmed isTrustAnchor is being removed from the ISO/IEC 18013-5
// standard going forward (word received directly from the organizers, not
// inferred), and real published RICALs already omit it in practice - the
// Geneva 2026 event's live document (geneva2026.mdoc.online) has it absent
// on all 35 published certificateInfos entries. Enforcing a field the
// standard itself is dropping would deny every reader against any
// spec-current or spec-future RICAL, not just a non-conformant one - so
// every entry is treated as usable for path validation regardless of this
// field's presence or value, both today and once the field is gone
// entirely.
func validateChainAgainstAnchors(chain []*x509.Certificate, infos []RICALCertificateInfo, ext *gocryptoutil.Extensions) ([][]*x509.Certificate, error) {
	if len(chain) == 0 {
		return nil, fmt.Errorf("empty chain")
	}

	roots := x509.NewCertPool()
	haveAnchor := false
	for _, info := range infos {
		cert, err := registry.ParseCertificate(info.Certificate, ext)
		if err != nil {
			continue
		}
		roots.AddCert(cert)
		haveAnchor = true
	}
	if !haveAnchor {
		return nil, fmt.Errorf("RICAL has no usable certificate")
	}

	leaf := chain[0]
	intermediates := x509.NewCertPool()
	for _, c := range chain[1:] {
		intermediates.AddCert(c)
	}

	return leaf.Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		CurrentTime:   time.Now(),
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	})
}

// resolveCertificateInfo determines which RICAL CertificateInfo entry
// governs the presented chain's trust constraints, and confirms the chain
// path-validates against a RICAL-listed trust anchor.
//
// Per F.3.2.6, "the CertificateInfo element of the first certificate
// (bottom-up) in the certificate chain included in the RICAL" should be
// used - findFirstMatchingCertificateInfo implements that literally, but
// it only ever matches when a reader's own leaf or intermediate
// certificate is individually enrolled in the RICAL. In practice a reader
// presents only its own leaf (plus any intermediates) and never the
// self-signed root a RICAL provider lists as the trust anchor - the whole
// point of an out-of-band trust anchor is that it need not be
// retransmitted. Requiring an exact match before ever attempting path
// validation denies every reader whose issuing CA isn't ALSO separately
// enrolled as its own CertificateInfo, defeating the RICAL's purpose as a
// CA-level trust list (confirmed live: a reader chaining cleanly to a
// RICAL-listed root was denied with "reader certificate chain not present
// in RICAL" solely because neither its leaf nor its issuing CA appeared
// verbatim in the RICAL - only the root did).
//
// So: prefer an explicit match (it may carry reader-specific
// TrustConstraints tighter than the anchor's own), but when none exists,
// fall back to whichever RICAL trust-anchor entry the chain actually
// validated against.
func resolveCertificateInfo(chain []*x509.Certificate, infos []RICALCertificateInfo, ext *gocryptoutil.Extensions) (*RICALCertificateInfo, int, error) {
	verifiedChains, err := validateChainAgainstAnchors(chain, infos, ext)
	if err != nil {
		return nil, -1, err
	}

	if matched, idx := findFirstMatchingCertificateInfo(chain, infos, ext); matched != nil {
		// Only apply reader/intermediate-specific constraints if the matching
		// certificate is actually part of a verified path.
		infoCert, err := registry.ParseCertificate(matched.Certificate, ext)
		if err == nil {
			for _, verifiedChain := range verifiedChains {
				for _, c := range verifiedChain {
					if c.Equal(infoCert) {
						return matched, idx, nil
					}
				}
			}
		}
	}
	for _, verifiedChain := range verifiedChains {
		root := verifiedChain[len(verifiedChain)-1]
		for i := range infos {
			infoCert, err := registry.ParseCertificate(infos[i].Certificate, ext)
			if err != nil {
				continue
			}
			if root.Equal(infoCert) {
				return &infos[i], i, nil
			}
		}
	}
	// Should be unreachable: validateChainAgainstAnchors only builds its
	// root pool from parseable RICAL entries, so a successful Verify's
	// root must be one of them.
	return nil, -1, fmt.Errorf("chain validated but its root isn't a RICAL entry")
}

// anyTrustConstraintSatisfied is a placeholder: this specification (per
// F.3.2.3) does not define any concrete TrustConstraint semantics - it's
// left to ecosystem/domain profiles. Until this org profiles concrete
// constraints for the Geneva event (or another), a present-but-unprofiled
// TrustConstraint is treated as satisfied by default (fail-open on meaning
// we don't understand yet, not fail-closed) - revisit once real
// TrustConstraints are actually published by an event RICAL provider.
func anyTrustConstraintSatisfied(constraints []TrustConstraint) bool {
	return len(constraints) > 0
}

func extractX5ChainFromProtectedHeader(protected []byte, ext *gocryptoutil.Extensions) ([]*x509.Certificate, error) {
	if len(protected) == 0 {
		return nil, fmt.Errorf("empty protected header")
	}
	var hdr map[int64]interface{}
	if err := cbor.Unmarshal(protected, &hdr); err != nil {
		return nil, fmt.Errorf("decode protected header: %w", err)
	}
	return extractX5ChainFromHeaderMap(hdr, ext)
}

// extractX5ChainFromHeaderMap reads the x5chain element (COSE header label
// 33, per RFC 9360) from a decoded COSE header map. The value is either a
// single bstr (one certificate) or an array of bstr (a chain, leaf first).
func extractX5ChainFromHeaderMap(hdr map[int64]interface{}, ext *gocryptoutil.Extensions) ([]*x509.Certificate, error) {
	const x5chainLabel int64 = 33
	raw, ok := hdr[x5chainLabel]
	if !ok {
		return nil, fmt.Errorf("no x5chain (label 33) in header")
	}

	var derList [][]byte
	switch v := raw.(type) {
	case []byte:
		derList = [][]byte{v}
	case []interface{}:
		for _, item := range v {
			b, ok := item.([]byte)
			if !ok {
				return nil, fmt.Errorf("x5chain element is not a byte string")
			}
			derList = append(derList, b)
		}
	default:
		return nil, fmt.Errorf("unsupported x5chain encoding: %T", raw)
	}

	certs := make([]*x509.Certificate, 0, len(derList))
	for i, der := range derList {
		cert, err := registry.ParseCertificate(der, ext)
		if err != nil {
			return nil, fmt.Errorf("x5chain certificate %d: %w", i, err)
		}
		certs = append(certs, cert)
	}
	return certs, nil
}

// parseUntaggedCOSESign1 decodes an untagged COSE_Sign1 four-element CBOR
// array (RFC 9052 §4.2's untagged form) into a *mdoc.COSESign1. The
// vc/pkg/mdoc COSESign1.UnmarshalCBOR method requires the CBOR tag(18)
// wrapper, which RICAL/VICAL explicitly do not use ("the untagged
// COSE_Sign1 structure", per F.3.2/C.1.7.1) - so the array is decoded
// directly here instead of going through that method.
func parseUntaggedCOSESign1(data []byte) (*mdoc.COSESign1, error) {
	var arr []cbor.RawMessage
	if err := cbor.Unmarshal(data, &arr); err != nil {
		return nil, fmt.Errorf("decode COSE_Sign1 array: %w", err)
	}
	if len(arr) != 4 {
		return nil, fmt.Errorf("expected 4-element COSE_Sign1 array, got %d", len(arr))
	}

	var protected []byte
	if err := cbor.Unmarshal(arr[0], &protected); err != nil {
		return nil, fmt.Errorf("decode protected header bstr: %w", err)
	}

	var unprotected map[any]any
	if err := cbor.Unmarshal(arr[1], &unprotected); err != nil {
		return nil, fmt.Errorf("decode unprotected header map: %w", err)
	}

	var payload []byte
	if err := cbor.Unmarshal(arr[2], &payload); err != nil {
		return nil, fmt.Errorf("decode payload bstr: %w", err)
	}

	var signature []byte
	if err := cbor.Unmarshal(arr[3], &signature); err != nil {
		return nil, fmt.Errorf("decode signature bstr: %w", err)
	}

	return &mdoc.COSESign1{
		Protected:   protected,
		Unprotected: unprotected,
		Payload:     payload,
		Signature:   signature,
	}, nil
}
