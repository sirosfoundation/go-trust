// Package lote — classic ETSI TS 119 612 TSL pointers in a LoTL.
//
// A LoTL may point at a classic XML Trusted Status List (TS 119 612, scheme
// type ".../TrstSvc/TrustedList/TSLType/EUgeneric") instead of a TS 119 602
// LoTE. Such pointers are loaded through the TSL parser and converted with
// etsi119602.FromTSL so they are indexed alongside native LoTEs.
//
// When signature verification is on (trust anchors available) a classic TSL is
// never loaded unverified: its XMLDSig must verify and the signer certificate
// must chain to the trust anchors. See verifyTSLSignature.
package lote

import (
	"context"
	"crypto/x509"
	"encoding/xml"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/beevik/etree"

	"github.com/sirosfoundation/g119612/pkg/dsig"
	"github.com/sirosfoundation/g119612/pkg/etsi119602"
	"github.com/sirosfoundation/g119612/pkg/etsi119612"
)

const (
	// classicTSLTypeMarker is the path fragment shared by all TS 119 612 TSL
	// type URIs (e.g. http://uri.etsi.org/TrstSvc/TrustedList/TSLType/EUgeneric).
	classicTSLTypeMarker = "/TrstSvc/TrustedList/TSLType/"

	xmlDSigNS = "http://www.w3.org/2000/09/xmldsig#"
)

// IsClassicTSLSchemeType reports whether a pointer's scheme type URI names a
// classic ETSI TS 119 612 TSL (EUgeneric, CClist, ...) rather than a LoTE.
func IsClassicTSLSchemeType(schemeType string) bool {
	return strings.Contains(schemeType, classicTSLTypeMarker)
}

// classicTrustedStatuses are the TS 119 612 service status names (last path
// segment of the Svcstatus URI) that confer trust. Every other status
// (withdrawn, deprecatedatnationallevel, supervisionincessation,
// accreditationceased, accreditationrevoked, ...) means the service is not
// currently trusted. The registry's default rule for LoTEs, "skip withdrawn",
// would wrongly trust most of those.
var classicTrustedStatuses = map[string]bool{
	"granted":                   true,
	"recognisedatnationallevel": true,
	"accredited":                true,
	"undersupervision":          true,
	"setbynationallaw":          true,
}

// classicStatusTrusted reports whether a TS 119 612 service status URI confers trust.
func classicStatusTrusted(status string) bool {
	// Real TSLs use both ".../Svcstatus/granted" and ".../Svcstatus/granted/".
	status = strings.TrimRight(status, "/")
	name := status[strings.LastIndex(status, "/")+1:]
	return classicTrustedStatuses[strings.ToLower(name)]
}

// loadClassicTSL loads the classic TSL at location and converts it to a LoTE.
// With roots non-nil the TSL is fetched once, its XMLDSig verified against
// roots, and the verified bytes are what gets parsed. With roots nil it is
// loaded unverified.
func (r *Registry) loadClassicTSL(location string, roots *x509.CertPool) (*etsi119602.ListOfTrustedEntities, error) {
	var tsl *etsi119612.TSL
	var err error
	if roots != nil {
		tsl, err = r.fetchVerifiedTSL(location, roots)
	} else {
		tsl, err = r.fetchUnverifiedTSL(location)
	}
	if err != nil {
		return nil, err
	}
	lote := etsi119602.FromTSL(tsl)
	qualifyClassicEntityIDs(lote, location)
	if len(lote.ListAndSchemeInformation.PointersToOtherLoTE) > 0 && r.config.Logger != nil {
		r.config.Logger.Warn("classic TSL has pointers to other TSLs; they are not followed",
			slog.String("location", location))
	}
	return lote, nil
}

// fetchUnverifiedTSL loads a TSL without dereferencing its own pointers.
func (r *Registry) fetchUnverifiedTSL(location string) (*etsi119612.TSL, error) {
	opts := etsi119612.DefaultTSLFetchOptions
	opts.MaxDereferenceDepth = 0
	opts.CryptoExt = r.config.CryptoExt
	if r.config.FetchTimeout > 0 {
		opts.Timeout = r.config.FetchTimeout
	}
	src := location
	if !strings.HasPrefix(src, "http://") && !strings.HasPrefix(src, "https://") && !strings.HasPrefix(src, "file://") {
		src = "file://" + src // the TSL fetcher only reads local files via file://
	}
	tsl, err := etsi119612.FetchTSLWithOptions(src, opts)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch classic TSL from %s: %w", location, err)
	}
	return tsl, nil
}

// fetchVerifiedTSL fetches location once, verifies the XMLDSig over exactly
// those bytes and parses the verified content (never the raw bytes).
func (r *Registry) fetchVerifiedTSL(location string, roots *x509.CertPool) (*etsi119612.TSL, error) {
	raw, err := fetchRawSource(location, r.config.FetchTimeout)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch classic TSL from %s: %w", location, err)
	}
	signer, verified, err := verifyTSLSignature(context.Background(), raw, roots, time.Now())
	if err != nil {
		return nil, fmt.Errorf("classic TSL signature verification failed for %s: %w", location, err)
	}
	tsl := &etsi119612.TSL{Source: location, Signed: true, Signer: *signer}
	if err := xml.Unmarshal(verified, &tsl.StatusList); err != nil {
		return nil, fmt.Errorf("failed to parse verified classic TSL from %s: %w", location, err)
	}
	tsl.CleanCerts()
	if r.config.Logger != nil {
		r.config.Logger.Info("classic TSL XMLDSig verified",
			slog.String("source", location),
			slog.String("signer", signer.Subject.CommonName))
	}
	return tsl, nil
}

// qualifyClassicEntityIDs makes the synthetic entity IDs produced by FromTSL
// unique across lists. FromTSL derives them from service type and position
// ("<svctype>#tsp0-svc0"), so two classic TSLs would otherwise collide in the
// registry's byID index and one list's entities would silently replace the
// other's.
func qualifyClassicEntityIDs(lote *etsi119602.ListOfTrustedEntities, location string) {
	for i := range lote.TrustedEntitiesList {
		uris := lote.TrustedEntitiesList[i].TrustedEntityInformation.TEInformationURI
		if len(uris) == 0 {
			continue
		}
		id := uris[0].URIValue
		if h := strings.LastIndex(id, "#"); h >= 0 {
			id = id[h:]
		} else {
			id = "#" + id
		}
		uris[0].URIValue = location + id
	}
}

// verifyTSLSignature verifies the enveloped XMLDSig of a classic TSL and
// returns the signer certificate and the verified document bytes. Callers MUST
// parse the returned bytes, not raw.
//
// Why this is not simply dsig.VerifyXMLSignature(raw, anchors): the g119612
// verifier takes a flat list of exact signer certificates and only accepts a
// signature whose embedded certificate is byte-equal to one of them. It does no
// chain building, and an x509.CertPool cannot be enumerated into that list. The
// trust_anchor_bundle holds CA roots, so go-trust does the chain validation
// itself and then hands the chain-validated leaf to the library as the sole
// trusted certificate. The library then checks the signature value, that the
// signed Reference covers the document root (enveloped-signature transform
// applied to the root), the digest, and the leaf's validity period, and
// returns the signed content.
//
// go-trust additionally enforces, fail closed:
//   - exactly one ds:Signature in the whole document, and it is a direct child
//     of the root element (no signature hidden in an extension or wrapper
//     element, no second signature the library might pick instead);
//   - a KeyInfo certificate chain that validates to roots at now;
//   - no SHA-1 signature or digest algorithms.
//
// Not checked: revocation, XAdES SignedProperties/signing time.
func verifyTSLSignature(_ context.Context, raw []byte, roots *x509.CertPool, now time.Time) (*x509.Certificate, []byte, error) {
	if roots == nil {
		return nil, nil, errors.New("lote: no trust anchors available for XMLDSig verification")
	}
	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(raw); err != nil {
		return nil, nil, fmt.Errorf("lote: parsing TSL XML: %w", err)
	}
	sig, err := soleRootSignature(doc)
	if err != nil {
		return nil, nil, err
	}
	if err := rejectSHA1(sig); err != nil {
		return nil, nil, err
	}
	leaf, intermediates, err := signatureKeyInfoChain(sig)
	if err != nil {
		return nil, nil, err
	}
	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		CurrentTime:   now,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}); err != nil {
		return nil, nil, fmt.Errorf("lote: TSL signer certificate chain validation failed: %w", err)
	}
	verified, err := dsig.VerifyXMLSignature(raw, []*x509.Certificate{leaf})
	if err != nil {
		return nil, nil, fmt.Errorf("lote: %w", err)
	}
	out := etree.NewDocument()
	out.SetRoot(verified.Copy())
	payload, err := out.WriteToBytes()
	if err != nil {
		return nil, nil, fmt.Errorf("lote: serialising verified TSL: %w", err)
	}
	return leaf, payload, nil
}

func isDSig(e *etree.Element, tag string) bool {
	return e.Tag == tag && e.NamespaceURI() == xmlDSigNS
}

// soleRootSignature returns the document's only ds:Signature, requiring it to
// be a direct child of the root element.
func soleRootSignature(doc *etree.Document) (*etree.Element, error) {
	root := doc.Root()
	if root == nil {
		return nil, errors.New("lote: TSL document has no root element")
	}
	var all []*etree.Element
	var walk func(e *etree.Element)
	walk = func(e *etree.Element) {
		for _, c := range e.ChildElements() {
			if isDSig(c, "Signature") {
				all = append(all, c)
			}
			walk(c)
		}
	}
	walk(root)
	switch {
	case len(all) == 0:
		return nil, errors.New("lote: TSL is not signed (no ds:Signature)")
	case len(all) > 1:
		return nil, fmt.Errorf("lote: TSL has %d ds:Signature elements, exactly one is required", len(all))
	case all[0].Parent() != root:
		return nil, errors.New("lote: TSL ds:Signature is not a direct child of the document root")
	}
	return all[0], nil
}

// rejectSHA1 refuses SHA-1 signature and digest methods.
func rejectSHA1(sig *etree.Element) error {
	for _, tag := range []string{"SignatureMethod", "DigestMethod"} {
		for _, e := range sig.FindElements(".//" + tag) {
			if !isDSig(e, tag) {
				continue
			}
			if alg := e.SelectAttrValue("Algorithm", ""); strings.Contains(strings.ToLower(alg), "sha1") {
				return fmt.Errorf("lote: TSL signature uses SHA-1 (%s)", alg)
			}
		}
	}
	return nil
}

// signatureKeyInfoChain extracts the signer chain from KeyInfo/X509Data. The
// first X509Certificate is the signer (the same one the library verifies
// with); the rest are candidate intermediates.
func signatureKeyInfoChain(sig *etree.Element) (*x509.Certificate, *x509.CertPool, error) {
	var b64 []string
	for _, e := range sig.FindElements("./KeyInfo/X509Data/X509Certificate") {
		if !isDSig(e, "X509Certificate") {
			continue
		}
		b64 = append(b64, strings.Join(strings.Fields(e.Text()), ""))
	}
	if len(b64) == 0 {
		return nil, nil, errors.New("lote: TSL signature has no X509Certificate in KeyInfo")
	}
	leaf, intermediates, err := parseX5CChainRaw(b64)
	if err != nil {
		return nil, nil, fmt.Errorf("lote: parsing TSL signer chain: %w", err)
	}
	return leaf, intermediates, nil
}
