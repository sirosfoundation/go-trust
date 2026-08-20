// Package vical provides a Verified Issuer Certificate Authority List
// (VICAL) registry for go-trust that authenticates mdoc issuers per
// ISO/IEC 18013-5 Annex C, enforcing the per-certificate doctype
// restrictions VICAL defines.
//
// This is the issuer-trust counterpart to the existing mdocrical registry's
// reader trust (Annex F): a single, centrally-published, COSE_Sign1-signed
// document fetched from one configured provider URL and refreshed on a
// cache TTL. Unlike the org's existing pkg/registry/mdociaca (which fetches
// per-issuer IACAs from each issuer's own OpenID4VCI metadata - a
// SIROS-internal convention, not the ISO mechanism), this validates a real
// VICAL and enforces each CertificateInfo's required "docType" list - the
// requirement mdociaca has no concept of at all, since it never sees a
// real VICAL structure.
package vical

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

// Config holds the configuration for a VICAL registry instance.
type Config struct {
	// Name is a unique identifier for this registry instance.
	Name string

	// Description is a human-readable description of this registry.
	Description string

	// VicalProviderURL is the HTTPS URL to fetch the VICAL from.
	VicalProviderURL string

	// VicalRootCertificatePEM is the PEM-encoded VICAL root certificate -
	// the out-of-band trust anchor for the VICAL's own COSE_Sign1
	// signature, distributed out of band per Annex C.
	VicalRootCertificatePEM string

	// CacheTTL is how long the fetched VICAL is cached before refetching.
	// Default: 1 hour.
	CacheTTL time.Duration

	// HTTPTimeout is the timeout for fetching the VICAL. Default: 30s.
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
	CryptoExt *gocryptoutil.Extensions
}

// CertificateInfo mirrors the VICAL structure's CertificateInfo (C.1.7.1).
// Every certificate in a VICAL is a trust point - unlike RICAL there is no
// separate isTrustAnchor flag.
type CertificateInfo struct {
	Certificate        []byte   `cbor:"certificate"`
	SerialNumber       *big.Int `cbor:"serialNumber"`
	SKI                []byte   `cbor:"ski"`
	DocType            []string `cbor:"docType"`
	CertificateProfile []string `cbor:"certificateProfile,omitempty"`
	IssuingAuthority   string   `cbor:"issuingAuthority,omitempty"`
	IssuingCountry     string   `cbor:"issuingCountry,omitempty"`
}

// VICAL mirrors the VICAL structure per C.1.7.1.
type VICAL struct {
	Version          string            `cbor:"version"`
	VicalProvider    string            `cbor:"vicalProvider"`
	VicalIssueID     uint64            `cbor:"vicalIssueID,omitempty"`
	Date             string            `cbor:"date"`
	NextUpdate       string            `cbor:"nextUpdate,omitempty"`
	NotAfter         string            `cbor:"notAfter,omitempty"`
	CertificateInfos []CertificateInfo `cbor:"certificateInfos"`
	VicalURL         string            `cbor:"vicalURL,omitempty"`
}

// cachedVical holds the fetched-and-verified VICAL plus fetch time.
type cachedVical struct {
	vical     *VICAL
	fetchedAt time.Time
}

// Registry implements TrustRegistry for VICAL-based issuer authentication.
type Registry struct {
	config     *Config
	httpClient registry.HTTPClientInterface
	vicalRoot  *x509.Certificate

	mu    sync.RWMutex
	cache *cachedVical
}

// New creates a new VICAL registry with the given configuration.
func New(cfg *Config) (*Registry, error) {
	if cfg == nil {
		cfg = &Config{}
	}
	if cfg.Name == "" {
		cfg.Name = "mdoc-vical"
	}
	if cfg.CacheTTL == 0 {
		cfg.CacheTTL = time.Hour
	}
	if cfg.HTTPTimeout == 0 {
		cfg.HTTPTimeout = 30 * time.Second
	}
	if cfg.VicalProviderURL == "" {
		return nil, fmt.Errorf("VicalProviderURL is required")
	}
	if cfg.VicalRootCertificatePEM == "" {
		return nil, fmt.Errorf("VicalRootCertificatePEM is required")
	}

	block, _ := pem.Decode([]byte(cfg.VicalRootCertificatePEM))
	if block == nil {
		return nil, fmt.Errorf("VicalRootCertificatePEM is not valid PEM")
	}
	rootCert, err := registry.ParseCertificate(block.Bytes, cfg.CryptoExt)
	if err != nil {
		return nil, fmt.Errorf("invalid VICAL root certificate: %w", err)
	}

	httpClient := registry.NewSafeHTTPClient(registry.SafeClientConfig{
		Timeout:         cfg.HTTPTimeout,
		AllowPrivateIPs: cfg.AllowPrivateIPs,
		AllowHTTP:       cfg.AllowHTTP,
	})

	return &Registry{
		config:     cfg,
		httpClient: httpClient,
		vicalRoot:  rootCert,
	}, nil
}

// Evaluate verifies an issuer's X5C certificate chain against the VICAL's
// CertificateInfo entries, enforcing the matched entry's docType list if
// req.Context["doc_type"] is present (skipped, not denied, if the caller
// doesn't supply one - enforcement requires the caller to actually know
// what doctype it's asking about).
func (r *Registry) Evaluate(ctx context.Context, req *authzen.EvaluationRequest) (*authzen.EvaluationResponse, error) {
	chain, err := parseX5CChain(req.Resource.Key, r.config.CryptoExt)
	if err != nil {
		return r.denyWithReason(fmt.Sprintf("invalid X5C chain: %v", err)), nil
	}
	if len(chain) == 0 {
		return r.denyWithReason("empty X5C chain"), nil
	}

	vical, err := r.getVical(ctx)
	if err != nil {
		return r.denyWithReason(fmt.Sprintf("failed to get VICAL: %v", err)), nil
	}

	matchedInfo, matchIdx := findFirstMatchingCertificateInfo(chain, vical.CertificateInfos, r.config.CryptoExt)
	if matchedInfo == nil {
		return r.denyWithReason("issuer certificate chain not present in VICAL"), nil
	}

	if err := validateChainAgainstVical(chain, vical.CertificateInfos, r.config.CryptoExt); err != nil {
		return r.denyWithReason(fmt.Sprintf("certificate path validation failed: %v", err)), nil
	}

	if requestedDocType, ok := req.Context["doc_type"].(string); ok && requestedDocType != "" {
		found := false
		for _, dt := range matchedInfo.DocType {
			if dt == requestedDocType {
				found = true
				break
			}
		}
		if !found {
			return r.denyWithReason(fmt.Sprintf("certificate not listed in VICAL for docType %q", requestedDocType)), nil
		}
	}

	return &authzen.EvaluationResponse{
		Decision: true,
		Context: &authzen.EvaluationResponseContext{
			Reason: map[string]interface{}{
				"trust_anchor":     "mdoc_vical",
				"vical_provider":   vical.VicalProvider,
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
		Type:          "mdoc_vical",
		Description:   r.config.Description,
		Version:       "1.0.0",
		ResourceTypes: r.SupportedResourceTypes(),
	}
}

// Healthy returns true if the registry is operational.
func (r *Registry) Healthy() bool {
	return true
}

// Refresh clears the cached VICAL, forcing a fresh fetch+verify on next
// Evaluate call - this is what lets a VICAL provider's mid-event update be
// picked up.
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

func (r *Registry) getVical(ctx context.Context) (*VICAL, error) {
	r.mu.RLock()
	cached := r.cache
	r.mu.RUnlock()

	if cached != nil && time.Since(cached.fetchedAt) < r.config.CacheTTL {
		return cached.vical, nil
	}

	vical, err := r.fetchAndVerifyVical(ctx)
	if err != nil {
		return nil, err
	}

	r.mu.Lock()
	r.cache = &cachedVical{vical: vical, fetchedAt: time.Now()}
	r.mu.Unlock()

	return vical, nil
}

func (r *Registry) fetchAndVerifyVical(ctx context.Context) (*VICAL, error) {
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, r.config.VicalProviderURL, nil)
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Accept", "application/cbor")

	resp, err := r.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("fetch VICAL: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck // Body close error is not actionable

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("VICAL provider returned %d", resp.StatusCode)
	}

	body, err := io.ReadAll(registry.LimitedReader(resp.Body))
	if err != nil {
		return nil, fmt.Errorf("read VICAL body: %w", err)
	}

	sign1, err := parseUntaggedCOSESign1(body)
	if err != nil {
		return nil, fmt.Errorf("parse VICAL COSE_Sign1: %w", err)
	}

	// C.1.7.1: the VICAL signer certificate (x5chain) is in the
	// UNPROTECTED header - matching this codebase's own issuerAuth/
	// deviceAuth convention (opposite of RICAL's protected-header
	// placement, see mdocrical). Extracted locally rather than via
	// mdoc.GetCertificateChainFromSign1: the pinned vc v0.6.5 version of
	// that helper only ever reads sign1.Protected, never Unprotected (this
	// workspace's go.work masked that locally by resolving vc to a newer
	// checkout where it does check both) - always returning "no x5chain in
	// headers" for any real, spec-conformant VICAL against the released
	// dependency version.
	signerChain, err := extractX5ChainFromUnprotectedHeader(sign1.Unprotected, r.config.CryptoExt)
	if err != nil {
		return nil, fmt.Errorf("extract VICAL signer x5chain: %w", err)
	}
	if len(signerChain) == 0 {
		return nil, fmt.Errorf("VICAL COSE_Sign1 has no signer certificate")
	}
	signerCert := signerChain[0]

	roots := x509.NewCertPool()
	roots.AddCert(r.vicalRoot)
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
		return nil, fmt.Errorf("VICAL signer certificate does not chain to configured root: %w", err)
	}

	// external_aad shall be a zero-length bstr, per C.1.7.1 - passed as
	// []byte{} rather than nil: see mdocrical/registry.go's identical
	// Verify1 call for why nil silently breaks verification against the
	// pinned vc v0.6.5 (CBOR-encodes as null, not an empty bstr).
	if err := mdoc.Verify1(sign1, sign1.Payload, signerCert.PublicKey, []byte{}); err != nil {
		return nil, fmt.Errorf("VICAL signature verification failed: %w", err)
	}

	var vical VICAL
	if err := cbor.Unmarshal(sign1.Payload, &vical); err != nil {
		return nil, fmt.Errorf("decode VICAL payload: %w", err)
	}
	if len(vical.CertificateInfos) == 0 {
		return nil, fmt.Errorf("VICAL certificateInfos is empty")
	}

	return &vical, nil
}

// extractX5ChainFromUnprotectedHeader reads the x5chain element (COSE
// header label 33, per RFC 9360) from a COSE_Sign1's decoded unprotected
// header map. Label lookup checks both uint64 and int64 key forms since the
// map was decoded from CBOR into map[any]any (no fixed key type forced by
// the destination, unlike mdocrical's protected-header map[int64]any) -
// fxamacker/cbor decodes a positive CBOR integer key into uint64 for such a
// map, but checking both defensively costs nothing. The value is either a
// single bstr (one certificate) or an array of bstr (a chain, leaf first).
func extractX5ChainFromUnprotectedHeader(unprotected map[any]any, ext *gocryptoutil.Extensions) ([]*x509.Certificate, error) {
	const x5chainLabel = 33
	raw, ok := unprotected[uint64(x5chainLabel)]
	if !ok {
		raw, ok = unprotected[int64(x5chainLabel)]
	}
	if !ok {
		return nil, fmt.Errorf("no x5chain (label 33) in header")
	}

	var derList [][]byte
	switch v := raw.(type) {
	case []byte:
		derList = [][]byte{v}
	case []any:
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

func findFirstMatchingCertificateInfo(chain []*x509.Certificate, infos []CertificateInfo, ext *gocryptoutil.Extensions) (*CertificateInfo, int) {
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

// validateChainAgainstVical builds a root pool from every CertificateInfo
// (every listed certificate is itself a trust point per C.1.7.1 - VICAL has
// no separate isTrustAnchor flag the way RICAL does) and validates the
// presented chain against it.
func validateChainAgainstVical(chain []*x509.Certificate, infos []CertificateInfo, ext *gocryptoutil.Extensions) error {
	if len(chain) == 0 {
		return fmt.Errorf("empty chain")
	}

	roots := x509.NewCertPool()
	for _, info := range infos {
		cert, err := registry.ParseCertificate(info.Certificate, ext)
		if err != nil {
			continue
		}
		roots.AddCert(cert)
	}

	leaf := chain[0]
	intermediates := x509.NewCertPool()
	for _, c := range chain[1:] {
		intermediates.AddCert(c)
	}

	_, err := leaf.Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		CurrentTime:   time.Now(),
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	})
	return err
}

// parseUntaggedCOSESign1 decodes an untagged COSE_Sign1 four-element CBOR
// array into a *mdoc.COSESign1 - see mdocrical's identical helper for why
// this bypasses COSESign1.UnmarshalCBOR (which requires the tag(18)
// wrapper VICAL/RICAL explicitly do not use).
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
