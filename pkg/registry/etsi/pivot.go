package etsi

import (
	"crypto/x509"
	"fmt"
	"regexp"
	"sort"
	"strconv"

	"github.com/sirosfoundation/g119612/pkg/etsi119612"
	"github.com/sirosfoundation/go-trust/pkg/registry"
)

// pivotURLPattern matches LOTL pivot URLs like "eu-lotl-pivot-341.xml".
var pivotURLPattern = regexp.MustCompile(`-pivot-(\d+)\.xml$`)

// pivotURL associates a pivot URL with its sequence number for sorting.
type pivotURL struct {
	URL      string
	Sequence int
}

// extractPivotURLs extracts pivot LOTL URLs from a TSL's SchemeInformationURI.
// Pivot URLs follow the pattern *-pivot-<sequence>.xml per ETSI TS 119 615.
// Returns URLs sorted oldest-to-newest (ascending sequence number).
func extractPivotURLs(tsl *etsi119612.TSL) []string {
	if tsl == nil {
		return nil
	}

	info := tsl.StatusList.TslSchemeInformation
	if info == nil || info.TslSchemeInformationURI == nil {
		return nil
	}

	var pivots []pivotURL
	for _, uri := range info.TslSchemeInformationURI.URI {
		if uri == nil {
			continue
		}
		matches := pivotURLPattern.FindStringSubmatch(uri.Value)
		if matches == nil {
			continue
		}
		seq, err := strconv.Atoi(matches[1])
		if err != nil {
			continue
		}
		// Deduplicate: same URL may appear with different lang attributes
		found := false
		for _, p := range pivots {
			if p.URL == uri.Value {
				found = true
				break
			}
		}
		if !found {
			pivots = append(pivots, pivotURL{URL: uri.Value, Sequence: seq})
		}
	}

	// Sort oldest first (ascending sequence number)
	sort.Slice(pivots, func(i, j int) bool {
		return pivots[i].Sequence < pivots[j].Sequence
	})

	urls := make([]string, len(pivots))
	for i, p := range pivots {
		urls[i] = p.URL
	}
	return urls
}

// extractSignerCertsFromPointers extracts X.509 certificates from a TSL's
// PointersToOtherTSL ServiceDigitalIdentities. If lotlLocation is non-empty,
// only certificates from pointers whose TSLLocation matches are returned.
// This is used to find the new signer certificate in a pivot LOTL.
func (r *TSLRegistry) extractSignerCertsFromPointers(tsl *etsi119612.TSL, lotlLocation string) []*x509.Certificate {
	if tsl == nil {
		return nil
	}

	info := tsl.StatusList.TslSchemeInformation
	if info == nil || info.TslPointersToOtherTSL == nil {
		return nil
	}

	var certs []*x509.Certificate
	for _, pointer := range info.TslPointersToOtherTSL.TslOtherTSLPointer {
		if pointer == nil {
			continue
		}

		// If lotlLocation is specified, only extract from matching pointers
		if lotlLocation != "" && pointer.TSLLocation != lotlLocation {
			continue
		}

		if pointer.TslServiceDigitalIdentities == nil {
			continue
		}

		for _, sdi := range pointer.TslServiceDigitalIdentities.TslServiceDigitalIdentity {
			if sdi == nil {
				continue
			}
			for _, digitalId := range sdi.DigitalId {
				if digitalId == nil || digitalId.X509Certificate == "" {
					continue
				}
				certBytes, err := base64Decode(digitalId.X509Certificate)
				if err != nil {
					continue
				}
				cert, err := registry.ParseCertificate(certBytes, r.config.CryptoExt)
				if err != nil {
					continue
				}
				certs = append(certs, cert)
			}
		}
	}
	return certs
}

// resolvePivotChain attempts to discover new trusted LOTL signer certificates
// by processing the ETSI TS 119 615 pivot chain. It extracts pivot URLs from
// the TSL's SchemeInformationURI, fetches each pivot (oldest first), verifies
// its signature against the current trust set, and extracts new signer
// certificates from verified pivots.
//
// Returns the accumulated set of trusted signer certificates (including the
// original lotlSigners plus any discovered via pivots).
func (r *TSLRegistry) resolvePivotChain(tsl *etsi119612.TSL, lotlSigners []*x509.Certificate) ([]*x509.Certificate, error) {
	pivotURLs := extractPivotURLs(tsl)
	if len(pivotURLs) == 0 {
		return lotlSigners, fmt.Errorf("no pivot URLs found in SchemeInformationURI")
	}

	// Accumulate trusted signers as we walk the chain
	trustedSigners := make([]*x509.Certificate, len(lotlSigners))
	copy(trustedSigners, lotlSigners)

	// The LOTL location is the source URL of the TSL we're trying to verify
	lotlLocation := tsl.Source

	var pivotVerified bool  // at least one pivot was signature-verified
	var newSignerFound bool // at least one new signer cert was discovered

	// Process pivots oldest-to-newest so trust chains build incrementally
	for _, pivotURL := range pivotURLs {
		if r.config.Logger != nil {
			r.config.Logger.Info("fetching pivot LOTL", "url", pivotURL)
		}

		opts := etsi119612.TSLFetchOptions{
			UserAgent:           r.config.UserAgent,
			Timeout:             r.config.FetchTimeout,
			AcceptHeaders:       []string{"application/xml", "text/xml", "application/xhtml+xml", "*/*;q=0.8"},
			MaxDereferenceDepth: 0, // Don't follow references in pivots
		}

		pivotTSL, err := etsi119612.FetchTSLWithOptions(pivotURL, opts)
		if err != nil {
			if r.config.Logger != nil {
				r.config.Logger.Warn("failed to fetch pivot LOTL", "url", pivotURL, "error", err)
			}
			continue
		}

		// Verify the pivot's signature against current trusted signers
		if err := r.verifyTSLSignatureStrict(pivotTSL, trustedSigners); err != nil {
			if r.config.Logger != nil {
				r.config.Logger.Debug("pivot LOTL not verifiable with current trust set", "url", pivotURL, "error", err)
			}
			continue
		}

		pivotVerified = true

		// Extract new signer certificates from the pivot's PointersToOtherTSL.
		// Look for pointers to the same LOTL location (or all pointers if location is empty).
		newSigners := r.extractSignerCertsFromPointers(pivotTSL, lotlLocation)
		if len(newSigners) == 0 {
			// Also try without location filter - the pivot may point to a different URL
			newSigners = r.extractSignerCertsFromPointers(pivotTSL, "")
		}

		for _, newSigner := range newSigners {
			if !containsCert(trustedSigners, newSigner) {
				trustedSigners = append(trustedSigners, newSigner)
				newSignerFound = true
				if r.config.Logger != nil {
					r.config.Logger.Info("discovered new LOTL signer via pivot",
						"pivot", pivotURL,
						"signer_cn", newSigner.Subject.CommonName,
					)
				}
			}
		}
	}

	if !pivotVerified {
		return lotlSigners, fmt.Errorf("no pivot LOTLs could be verified with the current trust set")
	}
	if !newSignerFound {
		return trustedSigners, fmt.Errorf("pivot LOTLs were verified but no new signer certificates were discovered")
	}

	return trustedSigners, nil
}

// verifyTSLSignatureStrict checks that a TSL's signature was created by one
// of the provided trusted signers. Returns an error if verification fails.
// Unlike verifyTSLSignature, this always enforces verification (no opportunistic mode).
func (r *TSLRegistry) verifyTSLSignatureStrict(tsl *etsi119612.TSL, trustedSigners []*x509.Certificate) error {
	if len(trustedSigners) == 0 {
		return fmt.Errorf("no trusted signers provided")
	}
	if !tsl.Signed {
		return fmt.Errorf("TSL from %s is not signed", tsl.Source)
	}

	signerCert := &tsl.Signer
	if len(signerCert.Raw) == 0 {
		return fmt.Errorf("TSL from %s has no signer certificate", tsl.Source)
	}

	for _, trusted := range trustedSigners {
		if signerCert.Equal(trusted) {
			return nil
		}
	}

	return fmt.Errorf("TSL from %s signed by untrusted certificate: %s", tsl.Source, signerCert.Subject.CommonName)
}

// containsCert checks if a certificate is already in the list (by raw bytes equality).
func containsCert(certs []*x509.Certificate, cert *x509.Certificate) bool {
	for _, c := range certs {
		if c.Equal(cert) {
			return true
		}
	}
	return false
}
