package mdocrical

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/sirosfoundation/go-trust/pkg/authzen"
)

// =============================================================================
// Test certificate + RICAL fixture helpers
// =============================================================================

func generateCA(t *testing.T, cn string) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create CA cert: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse CA cert: %v", err)
	}
	return cert, key
}

func generateLeaf(t *testing.T, issuer *x509.Certificate, issuerKey *ecdsa.PrivateKey, cn string, serial int64) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := x509.Certificate{
		SerialNumber:          big.NewInt(serial),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(2 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, issuer, &key.PublicKey, issuerKey)
	if err != nil {
		t.Fatalf("create leaf cert: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse leaf cert: %v", err)
	}
	return cert, key
}

func certPEM(cert *x509.Certificate) string {
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}))
}

func certBase64(cert *x509.Certificate) string {
	return base64.StdEncoding.EncodeToString(cert.Raw)
}

// buildSignedRical CBOR-encodes the given RICAL payload, builds an untagged
// COSE_Sign1 with the signer's x5chain in the PROTECTED header (per F.3.2),
// and signs it with signerKey - mirroring exactly the Sig_structure
// computation vc/pkg/mdoc.Verify1 performs, so the fixture is verifiable by
// the real code path, not just internally self-consistent.
func buildSignedRical(t *testing.T, rical *RICAL, signerCert *x509.Certificate, signerKey *ecdsa.PrivateKey) []byte {
	t.Helper()

	payload, err := cbor.Marshal(rical)
	if err != nil {
		t.Fatalf("marshal RICAL payload: %v", err)
	}

	protectedMap := map[int64]interface{}{
		1:  int64(-7), // ES256
		33: signerCert.Raw,
	}
	protected, err := cbor.Marshal(protectedMap)
	if err != nil {
		t.Fatalf("marshal protected header: %v", err)
	}

	sigStructure := []interface{}{
		"Signature1",
		protected,
		[]byte{},
		payload,
	}
	toBeSigned, err := cbor.Marshal(sigStructure)
	if err != nil {
		t.Fatalf("marshal Sig_structure: %v", err)
	}

	digest := sha256.Sum256(toBeSigned)
	r, s, err := ecdsa.Sign(rand.Reader, signerKey, digest[:])
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])

	arr := []interface{}{protected, map[interface{}]interface{}{}, payload, sig}
	encoded, err := cbor.Marshal(arr)
	if err != nil {
		t.Fatalf("marshal COSE_Sign1 array: %v", err)
	}
	return encoded
}

type mockRicalServer struct {
	server *httptest.Server
	body   []byte
	fail   bool
}

func newMockRicalServer(t *testing.T, body []byte) *mockRicalServer {
	t.Helper()
	mock := &mockRicalServer{body: body}
	mux := http.NewServeMux()
	mux.HandleFunc("/rical", func(w http.ResponseWriter, r *http.Request) {
		if mock.fail {
			http.Error(w, "simulated error", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/cbor")
		w.Write(mock.body) //nolint:errcheck
	})
	mock.server = httptest.NewServer(mux)
	return mock
}

func (m *mockRicalServer) URL() string { return m.server.URL + "/rical" }
func (m *mockRicalServer) Close()      { m.server.Close() }

// =============================================================================
// Tests
// =============================================================================

func TestNew_RequiresProviderURLAndRoot(t *testing.T) {
	if _, err := New(&Config{}); err == nil {
		t.Fatal("expected error for missing RicalProviderURL")
	}
	if _, err := New(&Config{RicalProviderURL: "https://example.com/rical"}); err == nil {
		t.Fatal("expected error for missing RicalRootCertificatePEM")
	}
}

func TestEvaluate_TrustedReaderChain(t *testing.T) {
	ricalRoot, ricalRootKey := generateCA(t, "Test RICAL Root")
	signerCert, signerKey := generateLeaf(t, ricalRoot, ricalRootKey, "Test RICAL Signer", 2)

	readerCA, readerCAKey := generateCA(t, "Test Reader CA")
	readerLeaf, _ := generateLeaf(t, readerCA, readerCAKey, "Test Reader", 3)

	rical := &RICAL{
		Version:  "1.0",
		Provider: "test-provider",
		Date:     time.Now().UTC().Format(time.RFC3339),
		Type:     "org.iso.18013.5.1.reader_authentication",
		CertificateInfos: []RICALCertificateInfo{
			{
				Certificate:   readerCA.Raw,
				SerialNumber:  readerCA.SerialNumber,
				SKI:           readerCA.SubjectKeyId,
				IsTrustAnchor: true,
			},
		},
	}
	body := buildSignedRical(t, rical, signerCert, signerKey)
	mock := newMockRicalServer(t, body)
	defer mock.Close()

	reg, err := New(&Config{
		RicalProviderURL:        mock.URL(),
		RicalRootCertificatePEM: certPEM(ricalRoot),
		AllowHTTP:               true,
		AllowPrivateIPs:         true,
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	req := &authzen.EvaluationRequest{
		Resource: authzen.Resource{
			Type: "x5c",
			Key:  []interface{}{certBase64(readerLeaf), certBase64(readerCA)},
		},
	}

	resp, err := reg.Evaluate(context.Background(), req)
	if err != nil {
		t.Fatalf("Evaluate() error = %v", err)
	}
	if !resp.Decision {
		t.Fatalf("expected trusted decision, got denied: %+v", resp.Context)
	}
}

func TestEvaluate_UntrustedReaderChain(t *testing.T) {
	ricalRoot, ricalRootKey := generateCA(t, "Test RICAL Root")
	signerCert, signerKey := generateLeaf(t, ricalRoot, ricalRootKey, "Test RICAL Signer", 2)

	// A reader CA NOT listed in the RICAL.
	otherCA, otherCAKey := generateCA(t, "Untrusted Reader CA")
	otherLeaf, _ := generateLeaf(t, otherCA, otherCAKey, "Untrusted Reader", 3)

	// The RICAL only lists an unrelated CA as trust anchor.
	listedCA, _ := generateCA(t, "Listed Reader CA")

	rical := &RICAL{
		Version:  "1.0",
		Provider: "test-provider",
		Date:     time.Now().UTC().Format(time.RFC3339),
		Type:     "org.iso.18013.5.1.reader_authentication",
		CertificateInfos: []RICALCertificateInfo{
			{
				Certificate:   listedCA.Raw,
				SerialNumber:  listedCA.SerialNumber,
				SKI:           listedCA.SubjectKeyId,
				IsTrustAnchor: true,
			},
		},
	}
	body := buildSignedRical(t, rical, signerCert, signerKey)
	mock := newMockRicalServer(t, body)
	defer mock.Close()

	reg, err := New(&Config{
		RicalProviderURL:        mock.URL(),
		RicalRootCertificatePEM: certPEM(ricalRoot),
		AllowHTTP:               true,
		AllowPrivateIPs:         true,
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	req := &authzen.EvaluationRequest{
		Resource: authzen.Resource{
			Type: "x5c",
			Key:  []interface{}{certBase64(otherLeaf), certBase64(otherCA)},
		},
	}

	resp, err := reg.Evaluate(context.Background(), req)
	if err != nil {
		t.Fatalf("Evaluate() error = %v", err)
	}
	if resp.Decision {
		t.Fatal("expected denied decision for reader chain not in RICAL")
	}
}

// TestEvaluate_TrustedReaderChainOmittingRoot covers the real-world case a
// live interop test caught: a reader presents only its own leaf (no
// intermediates, and critically no copy of the self-signed root a RICAL
// provider lists as the trust anchor - the anchor is distributed
// out-of-band precisely so it need not be retransmitted). The chain still
// path-validates cleanly against the RICAL-listed root, but no certificate
// in the presented chain is byte-identical to any RICALCertificateInfo, so
// the previous exact-match-only implementation denied every such reader
// with "reader certificate chain not present in RICAL".
func TestEvaluate_TrustedReaderChainOmittingRoot(t *testing.T) {
	ricalRoot, ricalRootKey := generateCA(t, "Test RICAL Root")
	signerCert, signerKey := generateLeaf(t, ricalRoot, ricalRootKey, "Test RICAL Signer", 2)

	readerCA, readerCAKey := generateCA(t, "Test Reader CA")
	readerLeaf, _ := generateLeaf(t, readerCA, readerCAKey, "Test Reader", 3)

	rical := &RICAL{
		Version:  "1.0",
		Provider: "test-provider",
		Date:     time.Now().UTC().Format(time.RFC3339),
		Type:     "org.iso.18013.5.1.reader_authentication",
		CertificateInfos: []RICALCertificateInfo{
			{
				Certificate:   readerCA.Raw,
				SerialNumber:  readerCA.SerialNumber,
				SKI:           readerCA.SubjectKeyId,
				IsTrustAnchor: true,
			},
		},
	}
	body := buildSignedRical(t, rical, signerCert, signerKey)
	mock := newMockRicalServer(t, body)
	defer mock.Close()

	reg, err := New(&Config{
		RicalProviderURL:        mock.URL(),
		RicalRootCertificatePEM: certPEM(ricalRoot),
		AllowHTTP:               true,
		AllowPrivateIPs:         true,
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	req := &authzen.EvaluationRequest{
		Resource: authzen.Resource{
			Type: "x5c",
			// Leaf only - no readerCA, unlike TestEvaluate_TrustedReaderChain.
			Key: []interface{}{certBase64(readerLeaf)},
		},
	}

	resp, err := reg.Evaluate(context.Background(), req)
	if err != nil {
		t.Fatalf("Evaluate() error = %v", err)
	}
	if !resp.Decision {
		t.Fatalf("expected trusted decision for a chain that validates against a RICAL trust anchor even without an exact chain-member match, got denied: %+v", resp.Context)
	}
}

// TestEvaluate_TrustedDespiteMissingIsTrustAnchor documents that isTrustAnchor
// is not enforced as a gate: a RICAL whose CertificateInfo entries omit it
// entirely (F.3.2.2 currently documents it as Required) still trusts a chain
// that validates to one of its entries. The interop event organizers have
// confirmed isTrustAnchor is being removed from the ISO/IEC 18013-5 standard
// going forward, and real published RICALs already omit it in practice - the
// Geneva 2026 event's live document (geneva2026.mdoc.online) has it absent on
// all 35 published entries.
func TestEvaluate_TrustedDespiteMissingIsTrustAnchor(t *testing.T) {
	ricalRoot, ricalRootKey := generateCA(t, "Test RICAL Root")
	signerCert, signerKey := generateLeaf(t, ricalRoot, ricalRootKey, "Test RICAL Signer", 2)

	readerCA, readerCAKey := generateCA(t, "Test Reader CA")
	readerLeaf, _ := generateLeaf(t, readerCA, readerCAKey, "Test Reader", 3)

	rical := &RICAL{
		Version:  "1.0",
		Provider: "test-provider",
		Date:     time.Now().UTC().Format(time.RFC3339),
		Type:     "org.iso.18013.5.1.reader_authentication",
		CertificateInfos: []RICALCertificateInfo{
			{
				Certificate:  readerCA.Raw,
				SerialNumber: readerCA.SerialNumber,
				SKI:          readerCA.SubjectKeyId,
				// IsTrustAnchor intentionally omitted (zero value: false).
			},
		},
	}
	body := buildSignedRical(t, rical, signerCert, signerKey)
	mock := newMockRicalServer(t, body)
	defer mock.Close()

	reg, err := New(&Config{
		RicalProviderURL:        mock.URL(),
		RicalRootCertificatePEM: certPEM(ricalRoot),
		AllowHTTP:               true,
		AllowPrivateIPs:         true,
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	req := &authzen.EvaluationRequest{
		Resource: authzen.Resource{
			Type: "x5c",
			Key:  []interface{}{certBase64(readerLeaf), certBase64(readerCA)},
		},
	}

	resp, err := reg.Evaluate(context.Background(), req)
	if err != nil {
		t.Fatalf("Evaluate() error = %v", err)
	}
	if !resp.Decision {
		t.Fatalf("expected trusted decision even though no CertificateInfo has isTrustAnchor=true, got denied: %+v", resp.Context)
	}
}

// TestEvaluate_SkipsUnparseableCertificateInfoEntry documents that a
// malformed/unparseable CertificateInfo entry in the RICAL doesn't abort
// evaluation for the rest - validateChainAgainstAnchors builds its root pool
// from every entry it CAN parse, silently skipping ones it can't, so a single
// bad entry doesn't deny readers that validate against a different, good
// entry.
func TestEvaluate_SkipsUnparseableCertificateInfoEntry(t *testing.T) {
	ricalRoot, ricalRootKey := generateCA(t, "Test RICAL Root")
	signerCert, signerKey := generateLeaf(t, ricalRoot, ricalRootKey, "Test RICAL Signer", 2)

	readerCA, readerCAKey := generateCA(t, "Test Reader CA")
	readerLeaf, _ := generateLeaf(t, readerCA, readerCAKey, "Test Reader", 3)

	rical := &RICAL{
		Version:  "1.0",
		Provider: "test-provider",
		Date:     time.Now().UTC().Format(time.RFC3339),
		Type:     "org.iso.18013.5.1.reader_authentication",
		CertificateInfos: []RICALCertificateInfo{
			{
				Certificate: []byte("not-a-real-certificate"),
			},
			{
				Certificate:  readerCA.Raw,
				SerialNumber: readerCA.SerialNumber,
				SKI:          readerCA.SubjectKeyId,
			},
		},
	}
	body := buildSignedRical(t, rical, signerCert, signerKey)
	mock := newMockRicalServer(t, body)
	defer mock.Close()

	reg, err := New(&Config{
		RicalProviderURL:        mock.URL(),
		RicalRootCertificatePEM: certPEM(ricalRoot),
		AllowHTTP:               true,
		AllowPrivateIPs:         true,
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	req := &authzen.EvaluationRequest{
		Resource: authzen.Resource{
			Type: "x5c",
			Key:  []interface{}{certBase64(readerLeaf), certBase64(readerCA)},
		},
	}

	resp, err := reg.Evaluate(context.Background(), req)
	if err != nil {
		t.Fatalf("Evaluate() error = %v", err)
	}
	if !resp.Decision {
		t.Fatalf("expected trusted decision despite an unparseable CertificateInfo entry, got denied: %+v", resp.Context)
	}
}

func TestEvaluate_RicalSignedByWrongRoot(t *testing.T) {
	ricalRoot, _ := generateCA(t, "Real RICAL Root")
	// Signed by a DIFFERENT root than the one configured as trusted.
	rogueRoot, rogueRootKey := generateCA(t, "Rogue RICAL Root")
	signerCert, signerKey := generateLeaf(t, rogueRoot, rogueRootKey, "Rogue Signer", 2)

	readerCA, readerCAKey := generateCA(t, "Test Reader CA")
	readerLeaf, _ := generateLeaf(t, readerCA, readerCAKey, "Test Reader", 3)

	rical := &RICAL{
		Version:  "1.0",
		Provider: "test-provider",
		Date:     time.Now().UTC().Format(time.RFC3339),
		Type:     "org.iso.18013.5.1.reader_authentication",
		CertificateInfos: []RICALCertificateInfo{
			{Certificate: readerCA.Raw, SerialNumber: readerCA.SerialNumber, SKI: readerCA.SubjectKeyId, IsTrustAnchor: true},
		},
	}
	body := buildSignedRical(t, rical, signerCert, signerKey)
	mock := newMockRicalServer(t, body)
	defer mock.Close()

	reg, err := New(&Config{
		RicalProviderURL:        mock.URL(),
		RicalRootCertificatePEM: certPEM(ricalRoot), // the REAL root, not rogueRoot
		AllowHTTP:               true,
		AllowPrivateIPs:         true,
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	req := &authzen.EvaluationRequest{
		Resource: authzen.Resource{
			Type: "x5c",
			Key:  []interface{}{certBase64(readerLeaf), certBase64(readerCA)},
		},
	}

	resp, err := reg.Evaluate(context.Background(), req)
	if err != nil {
		t.Fatalf("Evaluate() error = %v", err)
	}
	if resp.Decision {
		t.Fatal("expected denied decision when RICAL is signed by an untrusted root")
	}
}

func TestRefresh_ClearsCache(t *testing.T) {
	ricalRoot, ricalRootKey := generateCA(t, "Test RICAL Root")
	signerCert, signerKey := generateLeaf(t, ricalRoot, ricalRootKey, "Test RICAL Signer", 2)
	readerCA, _ := generateCA(t, "Test Reader CA")

	rical := &RICAL{
		Version: "1.0", Provider: "p", Date: time.Now().UTC().Format(time.RFC3339),
		Type: "org.iso.18013.5.1.reader_authentication",
		CertificateInfos: []RICALCertificateInfo{
			{Certificate: readerCA.Raw, SerialNumber: readerCA.SerialNumber, SKI: readerCA.SubjectKeyId, IsTrustAnchor: true},
		},
	}
	body := buildSignedRical(t, rical, signerCert, signerKey)
	mock := newMockRicalServer(t, body)
	defer mock.Close()

	reg, err := New(&Config{
		RicalProviderURL:        mock.URL(),
		RicalRootCertificatePEM: certPEM(ricalRoot),
		AllowHTTP:               true,
		AllowPrivateIPs:         true,
		CacheTTL:                time.Hour,
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	if _, err := reg.getRical(context.Background()); err != nil {
		t.Fatalf("initial fetch failed: %v", err)
	}

	mock.fail = true
	if _, err := reg.getRical(context.Background()); err != nil {
		t.Fatalf("expected cached RICAL to be served without a fresh fetch: %v", err)
	}

	if err := reg.Refresh(context.Background()); err != nil {
		t.Fatalf("Refresh() error = %v", err)
	}
	if _, err := reg.getRical(context.Background()); err == nil {
		t.Fatal("expected fetch to fail after Refresh() cleared the cache while the server is down")
	}
}
