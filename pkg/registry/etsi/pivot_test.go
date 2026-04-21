package etsi

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/sirosfoundation/g119612/pkg/etsi119612"
)

// generateTestCertAndKey creates a self-signed test certificate and returns
// the parsed cert, PEM bytes, and private key.
func generateTestCertAndKey(t *testing.T, cn string) (*x509.Certificate, []byte, *rsa.PrivateKey) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}

	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   cn,
			Organization: []string{"Test"},
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("failed to create certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("failed to parse certificate: %v", err)
	}

	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	return cert, pemBytes, key
}

// makeTSLWithSigner creates a minimal TSL struct that reports as signed by the given cert.
func makeTSLWithSigner(source string, signer *x509.Certificate, schemeInfoURIs []string) *etsi119612.TSL {
	var uris []*etsi119612.NonEmptyMultiLangURIType
	for _, u := range schemeInfoURIs {
		uris = append(uris, &etsi119612.NonEmptyMultiLangURIType{Value: u})
	}

	tsl := &etsi119612.TSL{
		Source: source,
		Signed: signer != nil,
		StatusList: etsi119612.TrustStatusListType{
			TslSchemeInformation: &etsi119612.TSLSchemeInformationType{
				TslSchemeInformationURI: &etsi119612.NonEmptyMultiLangURIListType{
					URI: uris,
				},
			},
		},
	}
	if signer != nil {
		tsl.Signer = *signer
	}
	return tsl
}

// addPointerWithCerts adds a pointer to another TSL location with embedded signer certificates.
func addPointerWithCerts(tsl *etsi119612.TSL, location string, certs []*x509.Certificate) {
	info := tsl.StatusList.TslSchemeInformation
	if info.TslPointersToOtherTSL == nil {
		info.TslPointersToOtherTSL = &etsi119612.OtherTSLPointersType{}
	}

	var sdiList []*etsi119612.DigitalIdentityListType
	for _, cert := range certs {
		b64 := base64.StdEncoding.EncodeToString(cert.Raw)
		sdiList = append(sdiList, &etsi119612.DigitalIdentityListType{
			DigitalId: []*etsi119612.DigitalIdentityType{
				{X509Certificate: b64},
			},
		})
	}

	pointer := &etsi119612.OtherTSLPointerType{
		TSLLocation: location,
		TslServiceDigitalIdentities: &etsi119612.ServiceDigitalIdentityListType{
			TslServiceDigitalIdentity: sdiList,
		},
	}

	info.TslPointersToOtherTSL.TslOtherTSLPointer = append(
		info.TslPointersToOtherTSL.TslOtherTSLPointer, pointer)
}

// --- Tests for extractPivotURLs ---

func TestExtractPivotURLs(t *testing.T) {
	tsl := makeTSLWithSigner("https://example.com/lotl.xml", nil, []string{
		"https://ec.europa.eu/tools/lotl/eu-lotl-pivot-341.xml",
		"https://ec.europa.eu/tools/lotl/eu-lotl-pivot-335.xml",
		"https://ec.europa.eu/tools/lotl/eu-lotl-pivot-300.xml",
		"https://ec.europa.eu/tools/lotl/eu-lotl-pivot-282.xml",
		"https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=uriserv:OJ.C_.2019.276.01.0001.01.ENG",
		"https://ec.europa.eu/tools/lotl/eu-lotl-legalnotice.html#en",
	})

	urls := extractPivotURLs(tsl)

	if len(urls) != 4 {
		t.Fatalf("expected 4 pivot URLs, got %d: %v", len(urls), urls)
	}

	// Should be sorted oldest first (ascending sequence number)
	expected := []string{
		"https://ec.europa.eu/tools/lotl/eu-lotl-pivot-282.xml",
		"https://ec.europa.eu/tools/lotl/eu-lotl-pivot-300.xml",
		"https://ec.europa.eu/tools/lotl/eu-lotl-pivot-335.xml",
		"https://ec.europa.eu/tools/lotl/eu-lotl-pivot-341.xml",
	}
	for i, url := range urls {
		if url != expected[i] {
			t.Errorf("pivot[%d]: expected %s, got %s", i, expected[i], url)
		}
	}
}

func TestExtractPivotURLs_NoPivots(t *testing.T) {
	tsl := makeTSLWithSigner("https://example.com/tsl.xml", nil, []string{
		"https://example.com/info",
		"https://example.com/legal",
	})

	urls := extractPivotURLs(tsl)
	if len(urls) != 0 {
		t.Errorf("expected no pivot URLs, got %d: %v", len(urls), urls)
	}
}

func TestExtractPivotURLs_NilTSL(t *testing.T) {
	urls := extractPivotURLs(nil)
	if urls != nil {
		t.Errorf("expected nil, got %v", urls)
	}
}

func TestExtractPivotURLs_EmptySchemeInfo(t *testing.T) {
	tsl := &etsi119612.TSL{}
	urls := extractPivotURLs(tsl)
	if urls != nil {
		t.Errorf("expected nil, got %v", urls)
	}
}

func TestExtractPivotURLs_Deduplication(t *testing.T) {
	// Same pivot URL with different language tags
	tsl := &etsi119612.TSL{
		StatusList: etsi119612.TrustStatusListType{
			TslSchemeInformation: &etsi119612.TSLSchemeInformationType{
				TslSchemeInformationURI: &etsi119612.NonEmptyMultiLangURIListType{
					URI: []*etsi119612.NonEmptyMultiLangURIType{
						{Value: "https://example.com/lotl-pivot-100.xml"},
						{Value: "https://example.com/lotl-pivot-100.xml"}, // duplicate
						{Value: "https://example.com/lotl-pivot-200.xml"},
					},
				},
			},
		},
	}

	urls := extractPivotURLs(tsl)
	if len(urls) != 2 {
		t.Fatalf("expected 2 deduplicated pivot URLs, got %d: %v", len(urls), urls)
	}
}

// --- Tests for extractSignerCertsFromPointers ---

func TestExtractSignerCertsFromPointers(t *testing.T) {
	cert1, _, _ := generateTestCertAndKey(t, "Signer A")
	cert2, _, _ := generateTestCertAndKey(t, "Signer B")

	tsl := makeTSLWithSigner("https://example.com/pivot.xml", nil, nil)
	addPointerWithCerts(tsl, "https://example.com/lotl.xml", []*x509.Certificate{cert1, cert2})

	reg := &TSLRegistry{config: TSLConfig{}}

	// Extract with matching location
	certs := reg.extractSignerCertsFromPointers(tsl, "https://example.com/lotl.xml")
	if len(certs) != 2 {
		t.Fatalf("expected 2 certs, got %d", len(certs))
	}

	// Extract with non-matching location
	certs = reg.extractSignerCertsFromPointers(tsl, "https://other.com/lotl.xml")
	if len(certs) != 0 {
		t.Errorf("expected 0 certs for non-matching location, got %d", len(certs))
	}

	// Extract with empty location (all pointers)
	certs = reg.extractSignerCertsFromPointers(tsl, "")
	if len(certs) != 2 {
		t.Fatalf("expected 2 certs with empty filter, got %d", len(certs))
	}
}

func TestExtractSignerCertsFromPointers_MultiplePointers(t *testing.T) {
	certA, _, _ := generateTestCertAndKey(t, "Signer A")
	certB, _, _ := generateTestCertAndKey(t, "Signer B")

	tsl := makeTSLWithSigner("https://example.com/pivot.xml", nil, nil)
	addPointerWithCerts(tsl, "https://example.com/lotl.xml", []*x509.Certificate{certA})
	addPointerWithCerts(tsl, "https://example.com/other.xml", []*x509.Certificate{certB})

	reg := &TSLRegistry{config: TSLConfig{}}

	// Only get certs from matching pointer
	certs := reg.extractSignerCertsFromPointers(tsl, "https://example.com/lotl.xml")
	if len(certs) != 1 {
		t.Fatalf("expected 1 cert, got %d", len(certs))
	}
	if certs[0].Subject.CommonName != "Signer A" {
		t.Errorf("expected Signer A, got %s", certs[0].Subject.CommonName)
	}

	// Get all certs with empty filter
	certs = reg.extractSignerCertsFromPointers(tsl, "")
	if len(certs) != 2 {
		t.Errorf("expected 2 certs with empty filter, got %d", len(certs))
	}
}

// --- Tests for verifyTSLSignatureStrict ---

func TestVerifyTSLSignatureStrict_Trusted(t *testing.T) {
	cert, _, _ := generateTestCertAndKey(t, "Signer")
	tsl := makeTSLWithSigner("https://example.com/tsl.xml", cert, nil)

	reg := &TSLRegistry{config: TSLConfig{}}
	err := reg.verifyTSLSignatureStrict(tsl, []*x509.Certificate{cert})
	if err != nil {
		t.Errorf("expected nil error, got: %v", err)
	}
}

func TestVerifyTSLSignatureStrict_Untrusted(t *testing.T) {
	signer, _, _ := generateTestCertAndKey(t, "Signer")
	otherCert, _, _ := generateTestCertAndKey(t, "Other")
	tsl := makeTSLWithSigner("https://example.com/tsl.xml", signer, nil)

	reg := &TSLRegistry{config: TSLConfig{}}
	err := reg.verifyTSLSignatureStrict(tsl, []*x509.Certificate{otherCert})
	if err == nil {
		t.Error("expected error for untrusted signer")
	}
}

func TestVerifyTSLSignatureStrict_Unsigned(t *testing.T) {
	tsl := makeTSLWithSigner("https://example.com/tsl.xml", nil, nil)

	reg := &TSLRegistry{config: TSLConfig{}}
	err := reg.verifyTSLSignatureStrict(tsl, []*x509.Certificate{})
	if err == nil {
		t.Error("expected error for unsigned TSL")
	}
}

// --- Tests for containsCert ---

func TestContainsCert(t *testing.T) {
	cert1, _, _ := generateTestCertAndKey(t, "Cert1")
	cert2, _, _ := generateTestCertAndKey(t, "Cert2")

	if !containsCert([]*x509.Certificate{cert1, cert2}, cert1) {
		t.Error("expected cert1 to be found")
	}

	cert3, _, _ := generateTestCertAndKey(t, "Cert3")
	if containsCert([]*x509.Certificate{cert1, cert2}, cert3) {
		t.Error("expected cert3 not to be found")
	}

	if containsCert(nil, cert1) {
		t.Error("expected empty list to return false")
	}
}

// --- Tests for resolvePivotChain ---

func TestResolvePivotChain_NoPivotURLs(t *testing.T) {
	signer, _, _ := generateTestCertAndKey(t, "Signer")
	tsl := makeTSLWithSigner("https://example.com/lotl.xml", signer, nil) // no pivot URLs

	reg := &TSLRegistry{config: TSLConfig{}}
	_, err := reg.resolvePivotChain(tsl, []*x509.Certificate{signer})
	if err == nil {
		t.Error("expected error when no pivot URLs found")
	}
}

func TestResolvePivotChain_WithHTTPServer(t *testing.T) {
	// Create three signers to simulate a two-hop rollover:
	// Known signer: signerA
	// Pivot 100 signed by signerA, contains signerB
	// Pivot 200 signed by signerB, contains signerC
	// Current LOTL signed by signerC
	signerA, _, _ := generateTestCertAndKey(t, "Signer A")
	signerB, _, _ := generateTestCertAndKey(t, "Signer B")
	signerC, _, _ := generateTestCertAndKey(t, "Signer C")

	// Create pivot TSLs as in-memory structs
	pivot100 := makeTSLWithSigner("", signerA, nil)
	addPointerWithCerts(pivot100, "https://example.com/lotl.xml", []*x509.Certificate{signerB})

	pivot200 := makeTSLWithSigner("", signerB, nil)
	addPointerWithCerts(pivot200, "https://example.com/lotl.xml", []*x509.Certificate{signerC})

	// We can't easily serve signed XML via HTTP and have the TSL fetch parse it
	// since FetchTSLWithOptions validates real XML signatures.
	// Instead, test the helper functions directly.

	// Test that extractSignerCertsFromPointers works for the pivot chain
	reg := &TSLRegistry{config: TSLConfig{}}

	// Pivot 100: signed by A, should extract B
	certsFrom100 := reg.extractSignerCertsFromPointers(pivot100, "https://example.com/lotl.xml")
	if len(certsFrom100) != 1 {
		t.Fatalf("expected 1 cert from pivot 100, got %d", len(certsFrom100))
	}
	if !certsFrom100[0].Equal(signerB) {
		t.Error("pivot 100 should contain signer B")
	}

	// Pivot 200: signed by B, should extract C
	certsFrom200 := reg.extractSignerCertsFromPointers(pivot200, "https://example.com/lotl.xml")
	if len(certsFrom200) != 1 {
		t.Fatalf("expected 1 cert from pivot 200, got %d", len(certsFrom200))
	}
	if !certsFrom200[0].Equal(signerC) {
		t.Error("pivot 200 should contain signer C")
	}

	// Simulate the chain-walking logic manually:
	// Start with signerA, verify pivot 100 → get signerB → verify pivot 200 → get signerC
	trustedSigners := []*x509.Certificate{signerA}

	// Verify pivot 100 against current trust set
	err := reg.verifyTSLSignatureStrict(pivot100, trustedSigners)
	if err != nil {
		t.Fatalf("pivot 100 should be verifiable with signerA: %v", err)
	}
	// Extract new signers
	for _, c := range certsFrom100 {
		if !containsCert(trustedSigners, c) {
			trustedSigners = append(trustedSigners, c)
		}
	}

	// Verify pivot 200 against updated trust set (now includes signerB)
	err = reg.verifyTSLSignatureStrict(pivot200, trustedSigners)
	if err != nil {
		t.Fatalf("pivot 200 should be verifiable with signerB: %v", err)
	}
	for _, c := range certsFrom200 {
		if !containsCert(trustedSigners, c) {
			trustedSigners = append(trustedSigners, c)
		}
	}

	// Now signerC should be in the trust set
	if !containsCert(trustedSigners, signerC) {
		t.Error("signerC should be in trust set after walking pivot chain")
	}
	if len(trustedSigners) != 3 {
		t.Errorf("expected 3 signers (A, B, C), got %d", len(trustedSigners))
	}
}

// --- Tests for verifyTSLSignature with pivot support ---

func TestVerifyTSLSignature_ReturnsUpdatedSigners(t *testing.T) {
	// When FollowPivots is false and signer is trusted, returns original signers
	cert, _, _ := generateTestCertAndKey(t, "Signer")
	tsl := makeTSLWithSigner("https://example.com/tsl.xml", cert, nil)

	reg := &TSLRegistry{config: TSLConfig{}}
	signers := []*x509.Certificate{cert}
	updated, err := reg.verifyTSLSignature(tsl, signers)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(updated) != 1 {
		t.Errorf("expected 1 signer, got %d", len(updated))
	}
}

func TestVerifyTSLSignature_UntrustedWithRequireSignature(t *testing.T) {
	signer, _, _ := generateTestCertAndKey(t, "Signer")
	otherCert, _, _ := generateTestCertAndKey(t, "Other")
	tsl := makeTSLWithSigner("https://example.com/tsl.xml", signer, nil)

	reg := &TSLRegistry{config: TSLConfig{RequireSignature: true}}
	_, err := reg.verifyTSLSignature(tsl, []*x509.Certificate{otherCert})
	if err == nil {
		t.Error("expected error for untrusted signer with RequireSignature")
	}
}

func TestVerifyTSLSignature_OpportunisticUntrusted(t *testing.T) {
	signer, _, _ := generateTestCertAndKey(t, "Signer")
	otherCert, _, _ := generateTestCertAndKey(t, "Other")
	tsl := makeTSLWithSigner("https://example.com/tsl.xml", signer, nil)

	reg := &TSLRegistry{config: TSLConfig{RequireSignature: false}}
	_, err := reg.verifyTSLSignature(tsl, []*x509.Certificate{otherCert})
	if err != nil {
		t.Errorf("opportunistic mode should not fail: %v", err)
	}
}

func TestVerifyTSLSignature_NoSigners(t *testing.T) {
	signer, _, _ := generateTestCertAndKey(t, "Signer")
	tsl := makeTSLWithSigner("https://example.com/tsl.xml", signer, nil)

	// With RequireSignature=false, should pass
	reg := &TSLRegistry{config: TSLConfig{RequireSignature: false}}
	_, err := reg.verifyTSLSignature(tsl, nil)
	if err != nil {
		t.Errorf("should pass with no signers and RequireSignature=false: %v", err)
	}

	// With RequireSignature=true, should fail
	reg2 := &TSLRegistry{config: TSLConfig{RequireSignature: true}}
	_, err = reg2.verifyTSLSignature(tsl, nil)
	if err == nil {
		t.Error("should fail with no signers and RequireSignature=true")
	}
}

// --- Tests for extractPivotURLs with real test data ---

func TestExtractPivotURLs_FromEULOTL(t *testing.T) {
	tslPath := filepath.Join("testdata", "eu-lotl.xml")
	if _, err := os.Stat(tslPath); os.IsNotExist(err) {
		t.Skip("testdata/eu-lotl.xml not found")
	}

	tsl, err := etsi119612.FetchTSLWithOptions("file://"+mustAbs(t, tslPath), etsi119612.TSLFetchOptions{
		MaxDereferenceDepth: 0,
	})
	if err != nil {
		t.Fatalf("failed to load EU LOTL: %v", err)
	}

	urls := extractPivotURLs(tsl)
	if len(urls) == 0 {
		t.Fatal("expected pivot URLs from EU LOTL, got none")
	}

	// EU LOTL should have pivots 282, 300, 335, 341
	t.Logf("found %d pivot URLs:", len(urls))
	for _, u := range urls {
		t.Logf("  %s", u)
	}

	// Verify sorted oldest-first
	if len(urls) >= 2 {
		// The first should be the oldest (lowest sequence number)
		if urls[0] != "https://ec.europa.eu/tools/lotl/eu-lotl-pivot-282.xml" {
			t.Errorf("first pivot should be oldest (282), got: %s", urls[0])
		}
	}
}

// --- Integration test: pivot resolution with HTTP test server ---

func TestResolvePivotChain_HTTPIntegration(t *testing.T) {
	// This test verifies that resolvePivotChain correctly fetches pivot LOTLs
	// via HTTP. We serve minimal unsigned XML that will fail signature validation,
	// which means the pivot won't be trusted - this tests error handling.

	signerA, _, _ := generateTestCertAndKey(t, "Signer A")

	// Create a test server serving a minimal TSL XML
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Serve a minimal unsigned TSL XML
		w.Header().Set("Content-Type", "application/xml")
		fmt.Fprintf(w, `<?xml version="1.0" encoding="UTF-8"?>
<TrustServiceStatusList xmlns="http://uri.etsi.org/02231/v2#">
  <SchemeInformation>
    <TSLVersionIdentifier>5</TSLVersionIdentifier>
    <TSLSequenceNumber>100</TSLSequenceNumber>
    <TSLType>http://uri.etsi.org/TrstSvc/TrustedList/TSLType/EUlistofthelists</TSLType>
    <SchemeOperatorName><Name xml:lang="en">Test</Name></SchemeOperatorName>
    <SchemeName><Name xml:lang="en">Test</Name></SchemeName>
    <SchemeInformationURI><URI xml:lang="en">http://test</URI></SchemeInformationURI>
    <StatusDeterminationApproach>http://test</StatusDeterminationApproach>
    <HistoricalInformationPeriod>0</HistoricalInformationPeriod>
    <ListIssueDateTime>2024-01-01T00:00:00Z</ListIssueDateTime>
    <NextUpdate><dateTime>2030-01-01T00:00:00Z</dateTime></NextUpdate>
  </SchemeInformation>
</TrustServiceStatusList>`)
	}))
	defer server.Close()

	// Create LOTL with pivot URLs pointing to our test server.
	// The pivot filename must match the production pivot URL pattern
	// (`-pivot-<seq>.xml`) so resolvePivotChain will actually attempt an HTTP fetch.
	lotl := makeTSLWithSigner(server.URL+"/lotl.xml", signerA, []string{
		server.URL + "/eu-lotl-pivot-100.xml",
	})

	reg := &TSLRegistry{config: TSLConfig{
		FollowPivots: true,
		FetchTimeout: 5 * time.Second,
	}}

	// resolvePivotChain should attempt to fetch the pivot, but since the served
	// TSL is unsigned, verification will fail and the chain resolution will fail
	_, err := reg.resolvePivotChain(lotl, []*x509.Certificate{signerA})
	if err == nil {
		t.Error("expected error since pivot TSL is unsigned")
	}
	t.Logf("correctly got error: %v", err)
}

func mustAbs(t *testing.T, path string) string {
	t.Helper()
	abs, err := filepath.Abs(path)
	if err != nil {
		t.Fatalf("failed to get absolute path: %v", err)
	}
	return abs
}
