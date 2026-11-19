package vical

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
// Test certificate + VICAL fixture helpers
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

// buildSignedVical CBOR-encodes the given VICAL payload and builds an
// untagged COSE_Sign1 with the signer's x5chain in the UNPROTECTED header
// (per C.1.7.1 - opposite of RICAL's protected-header placement), signed
// with signerKey via the exact Sig_structure computation vc/pkg/mdoc.Verify1
// performs.
func buildSignedVical(t *testing.T, vical *VICAL, signerCert *x509.Certificate, signerKey *ecdsa.PrivateKey) []byte {
	t.Helper()

	payload, err := cbor.Marshal(vical)
	if err != nil {
		t.Fatalf("marshal VICAL payload: %v", err)
	}

	protectedMap := map[int64]interface{}{1: int64(-7)} // alg: ES256 only
	protected, err := cbor.Marshal(protectedMap)
	if err != nil {
		t.Fatalf("marshal protected header: %v", err)
	}

	unprotectedMap := map[interface{}]interface{}{int64(33): signerCert.Raw}

	sigStructure := []interface{}{"Signature1", protected, []byte{}, payload}
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

	arr := []interface{}{protected, unprotectedMap, payload, sig}
	encoded, err := cbor.Marshal(arr)
	if err != nil {
		t.Fatalf("marshal COSE_Sign1 array: %v", err)
	}
	return encoded
}

type mockVicalServer struct {
	server *httptest.Server
	body   []byte
	fail   bool
}

func newMockVicalServer(t *testing.T, body []byte) *mockVicalServer {
	t.Helper()
	mock := &mockVicalServer{body: body}
	mux := http.NewServeMux()
	mux.HandleFunc("/vical", func(w http.ResponseWriter, r *http.Request) {
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

func (m *mockVicalServer) URL() string { return m.server.URL + "/vical" }
func (m *mockVicalServer) Close()      { m.server.Close() }

// =============================================================================
// Tests
// =============================================================================

func TestNew_RequiresProviderURLAndRoot(t *testing.T) {
	if _, err := New(&Config{}); err == nil {
		t.Fatal("expected error for missing VicalProviderURL")
	}
	if _, err := New(&Config{VicalProviderURL: "https://example.com/vical"}); err == nil {
		t.Fatal("expected error for missing VicalRootCertificatePEM")
	}
}

func TestEvaluate_TrustedIssuerChain_MatchingDocType(t *testing.T) {
	vicalRoot, vicalRootKey := generateCA(t, "Test VICAL Root")
	signerCert, signerKey := generateLeaf(t, vicalRoot, vicalRootKey, "Test VICAL Signer", 2)

	issuerCA, issuerCAKey := generateCA(t, "Test IACA")
	issuerLeaf, _ := generateLeaf(t, issuerCA, issuerCAKey, "Test DS", 3)

	vical := &VICAL{
		Version:       "1.0",
		VicalProvider: "test-provider",
		Date:          time.Now().UTC().Format(time.RFC3339),
		CertificateInfos: []CertificateInfo{
			{
				Certificate:  issuerCA.Raw,
				SerialNumber: issuerCA.SerialNumber,
				SKI:          issuerCA.SubjectKeyId,
				DocType:      []string{"org.iso.18013.5.1.mDL"},
			},
		},
	}
	body := buildSignedVical(t, vical, signerCert, signerKey)
	mock := newMockVicalServer(t, body)
	defer mock.Close()

	reg, err := New(&Config{
		VicalProviderURL:        mock.URL(),
		VicalRootCertificatePEM: certPEM(vicalRoot),
		AllowHTTP:               true,
		AllowPrivateIPs:         true,
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	req := &authzen.EvaluationRequest{
		Resource: authzen.Resource{
			Type: "x5c",
			Key:  []interface{}{certBase64(issuerLeaf), certBase64(issuerCA)},
		},
		Context: map[string]interface{}{"doc_type": "org.iso.18013.5.1.mDL"},
	}

	resp, err := reg.Evaluate(context.Background(), req)
	if err != nil {
		t.Fatalf("Evaluate() error = %v", err)
	}
	if !resp.Decision {
		t.Fatalf("expected trusted decision, got denied: %+v", resp.Context)
	}
}

func TestEvaluate_DeniesMismatchedDocType(t *testing.T) {
	vicalRoot, vicalRootKey := generateCA(t, "Test VICAL Root")
	signerCert, signerKey := generateLeaf(t, vicalRoot, vicalRootKey, "Test VICAL Signer", 2)

	issuerCA, issuerCAKey := generateCA(t, "Test IACA")
	issuerLeaf, _ := generateLeaf(t, issuerCA, issuerCAKey, "Test DS", 3)

	// The VICAL only lists this CA as trusted for mDL, not for a PID.
	vical := &VICAL{
		Version:       "1.0",
		VicalProvider: "test-provider",
		Date:          time.Now().UTC().Format(time.RFC3339),
		CertificateInfos: []CertificateInfo{
			{
				Certificate:  issuerCA.Raw,
				SerialNumber: issuerCA.SerialNumber,
				SKI:          issuerCA.SubjectKeyId,
				DocType:      []string{"org.iso.18013.5.1.mDL"},
			},
		},
	}
	body := buildSignedVical(t, vical, signerCert, signerKey)
	mock := newMockVicalServer(t, body)
	defer mock.Close()

	reg, err := New(&Config{
		VicalProviderURL:        mock.URL(),
		VicalRootCertificatePEM: certPEM(vicalRoot),
		AllowHTTP:               true,
		AllowPrivateIPs:         true,
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	req := &authzen.EvaluationRequest{
		Resource: authzen.Resource{
			Type: "x5c",
			Key:  []interface{}{certBase64(issuerLeaf), certBase64(issuerCA)},
		},
		Context: map[string]interface{}{"doc_type": "eu.europa.ec.eudi.pid.1"},
	}

	resp, err := reg.Evaluate(context.Background(), req)
	if err != nil {
		t.Fatalf("Evaluate() error = %v", err)
	}
	if resp.Decision {
		t.Fatal("expected denied decision for docType not listed in VICAL for this CA")
	}
}

func TestEvaluate_NoDocTypeRequested_SkipsEnforcement(t *testing.T) {
	vicalRoot, vicalRootKey := generateCA(t, "Test VICAL Root")
	signerCert, signerKey := generateLeaf(t, vicalRoot, vicalRootKey, "Test VICAL Signer", 2)

	issuerCA, issuerCAKey := generateCA(t, "Test IACA")
	issuerLeaf, _ := generateLeaf(t, issuerCA, issuerCAKey, "Test DS", 3)

	vical := &VICAL{
		Version:       "1.0",
		VicalProvider: "test-provider",
		Date:          time.Now().UTC().Format(time.RFC3339),
		CertificateInfos: []CertificateInfo{
			{Certificate: issuerCA.Raw, SerialNumber: issuerCA.SerialNumber, SKI: issuerCA.SubjectKeyId, DocType: []string{"org.iso.18013.5.1.mDL"}},
		},
	}
	body := buildSignedVical(t, vical, signerCert, signerKey)
	mock := newMockVicalServer(t, body)
	defer mock.Close()

	reg, err := New(&Config{
		VicalProviderURL:        mock.URL(),
		VicalRootCertificatePEM: certPEM(vicalRoot),
		AllowHTTP:               true,
		AllowPrivateIPs:         true,
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	req := &authzen.EvaluationRequest{
		Resource: authzen.Resource{
			Type: "x5c",
			Key:  []interface{}{certBase64(issuerLeaf), certBase64(issuerCA)},
		},
	}

	resp, err := reg.Evaluate(context.Background(), req)
	if err != nil {
		t.Fatalf("Evaluate() error = %v", err)
	}
	if !resp.Decision {
		t.Fatalf("expected trust decision when no doc_type is requested (enforcement skipped), got denied: %+v", resp.Context)
	}
}

func TestEvaluate_UntrustedIssuerChain(t *testing.T) {
	vicalRoot, vicalRootKey := generateCA(t, "Test VICAL Root")
	signerCert, signerKey := generateLeaf(t, vicalRoot, vicalRootKey, "Test VICAL Signer", 2)

	otherCA, otherCAKey := generateCA(t, "Untrusted IACA")
	otherLeaf, _ := generateLeaf(t, otherCA, otherCAKey, "Untrusted DS", 3)

	listedCA, _ := generateCA(t, "Listed IACA")

	vical := &VICAL{
		Version:       "1.0",
		VicalProvider: "test-provider",
		Date:          time.Now().UTC().Format(time.RFC3339),
		CertificateInfos: []CertificateInfo{
			{Certificate: listedCA.Raw, SerialNumber: listedCA.SerialNumber, SKI: listedCA.SubjectKeyId, DocType: []string{"org.iso.18013.5.1.mDL"}},
		},
	}
	body := buildSignedVical(t, vical, signerCert, signerKey)
	mock := newMockVicalServer(t, body)
	defer mock.Close()

	reg, err := New(&Config{
		VicalProviderURL:        mock.URL(),
		VicalRootCertificatePEM: certPEM(vicalRoot),
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
		t.Fatal("expected denied decision for issuer chain not in VICAL")
	}
}

func TestEvaluate_VicalSignedByWrongRoot(t *testing.T) {
	vicalRoot, _ := generateCA(t, "Real VICAL Root")
	rogueRoot, rogueRootKey := generateCA(t, "Rogue VICAL Root")
	signerCert, signerKey := generateLeaf(t, rogueRoot, rogueRootKey, "Rogue Signer", 2)

	issuerCA, issuerCAKey := generateCA(t, "Test IACA")
	issuerLeaf, _ := generateLeaf(t, issuerCA, issuerCAKey, "Test DS", 3)

	vical := &VICAL{
		Version:       "1.0",
		VicalProvider: "test-provider",
		Date:          time.Now().UTC().Format(time.RFC3339),
		CertificateInfos: []CertificateInfo{
			{Certificate: issuerCA.Raw, SerialNumber: issuerCA.SerialNumber, SKI: issuerCA.SubjectKeyId, DocType: []string{"org.iso.18013.5.1.mDL"}},
		},
	}
	body := buildSignedVical(t, vical, signerCert, signerKey)
	mock := newMockVicalServer(t, body)
	defer mock.Close()

	reg, err := New(&Config{
		VicalProviderURL:        mock.URL(),
		VicalRootCertificatePEM: certPEM(vicalRoot), // the REAL root, not rogueRoot
		AllowHTTP:               true,
		AllowPrivateIPs:         true,
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	req := &authzen.EvaluationRequest{
		Resource: authzen.Resource{
			Type: "x5c",
			Key:  []interface{}{certBase64(issuerLeaf), certBase64(issuerCA)},
		},
	}

	resp, err := reg.Evaluate(context.Background(), req)
	if err != nil {
		t.Fatalf("Evaluate() error = %v", err)
	}
	if resp.Decision {
		t.Fatal("expected denied decision when VICAL is signed by an untrusted root")
	}
}

// trustAnchorEnv builds a VICAL registry over a signed list and an issuer chain.
func trustAnchorEnv(t *testing.T, mutate func(*VICAL)) (*Registry, *x509.Certificate, *x509.Certificate) {
	t.Helper()
	vicalRoot, vicalRootKey := generateCA(t, "Test VICAL Root")
	signerCert, signerKey := generateLeaf(t, vicalRoot, vicalRootKey, "Test VICAL Signer", 2)
	issuerCA, issuerCAKey := generateCA(t, "Test IACA")
	issuerLeaf, _ := generateLeaf(t, issuerCA, issuerCAKey, "Test DS", 3)
	v := &VICAL{
		Version: "1.0", VicalProvider: "p", Date: time.Now().UTC().Format(time.RFC3339),
		CertificateInfos: []CertificateInfo{{
			Certificate: issuerCA.Raw, SerialNumber: issuerCA.SerialNumber, SKI: issuerCA.SubjectKeyId,
			DocType: []string{"org.iso.18013.5.1.mDL"}, CertificateProfile: []string{"urn:iaca"},
			IssuingAuthority: "Authority", IssuingCountry: "SE",
		}, {Certificate: []byte("not a certificate")}},
	}
	if mutate != nil {
		mutate(v)
	}
	mock := newMockVicalServer(t, buildSignedVical(t, v, signerCert, signerKey))
	t.Cleanup(mock.Close)
	reg, err := New(&Config{Name: "iaca-vical", VicalProviderURL: mock.URL(), VicalRootCertificatePEM: certPEM(vicalRoot), AllowHTTP: true, AllowPrivateIPs: true})
	if err != nil {
		t.Fatal(err)
	}
	return reg, issuerLeaf, issuerCA
}

func TestTrustAnchors_OnPositiveEvaluationOnlyWhenEnabled(t *testing.T) {
	reg, leaf, ca := trustAnchorEnv(t, nil)
	eval := func(ctx map[string]interface{}) *authzen.EvaluationResponse {
		resp, err := reg.Evaluate(context.Background(), &authzen.EvaluationRequest{
			Resource: authzen.Resource{Type: "x5c", Key: []interface{}{certBase64(leaf), certBase64(ca)}}, Context: ctx})
		if err != nil || !resp.Decision {
			t.Fatalf("expected trusted: %v %+v", err, resp)
		}
		return resp
	}
	if resp := eval(nil); len(resp.Context.TrustAnchors) != 0 {
		t.Error("anchors must not appear unless the policy enables them")
	}
	resp := eval(map[string]interface{}{authzen.TrustAnchorsPolicyContextKey: []string{"vical"}})
	if len(resp.Context.TrustAnchors) != 1 {
		t.Fatalf("want one set, got %+v", resp.Context.TrustAnchors)
	}
	set := resp.Context.TrustAnchors[0]
	if set.Registry != "iaca-vical" || set.Type != "vical" || set.TTLSeconds != 86400 {
		t.Errorf("unexpected set header: %+v", set)
	}
	if len(set.Anchors) != 1 {
		t.Fatalf("the unparseable entry must be skipped: %+v", set.Anchors)
	}
	a := set.Anchors[0]
	if a.X5C != certBase64(ca) || a.DocTypes[0] != "org.iso.18013.5.1.mDL" || a.CertificateProfiles[0] != "urn:iaca" || a.IssuingAuthority != "Authority" || a.IssuingCountry != "SE" {
		t.Errorf("anchor does not mirror the VICAL entry: %+v", a)
	}
}

func TestTrustAnchors_Preload(t *testing.T) {
	reg, _, _ := trustAnchorEnv(t, nil)
	preload := func(subject string, types ...string) *authzen.EvaluationRequest {
		return &authzen.EvaluationRequest{
			Subject: authzen.Subject{Type: "key", ID: subject},
			Context: map[string]interface{}{authzen.TrustAnchorsPolicyContextKey: types},
		}
	}
	if !reg.SupportsResolutionOnlyFor(preload("iaca-vical", "vical")) || reg.SupportsResolutionOnly() {
		t.Error("resolution-only support exists only for an enabled preload of this registry")
	}
	if reg.SupportsResolutionOnlyFor(preload("iaca-vical", "rical")) || reg.SupportsResolutionOnlyFor(preload("elsewhere", "vical")) {
		t.Error("not enabled or not named: no support")
	}
	resp, err := reg.Evaluate(context.Background(), preload("iaca-vical", "vical"))
	if err != nil || !resp.Decision || len(resp.Context.TrustAnchors) != 1 {
		t.Fatalf("preload must deliver the anchors: %v %+v", err, resp)
	}
	// Even if routed here, a request the policy did not enable is a denial with no anchors.
	resp, _ = reg.Evaluate(context.Background(), preload("iaca-vical"))
	if resp.Decision || (resp.Context != nil && len(resp.Context.TrustAnchors) != 0) {
		t.Errorf("not enabled: denial without anchors, got %+v", resp)
	}
}

func TestTrustAnchors_ExpiredListOffersNothing(t *testing.T) {
	reg, _, _ := trustAnchorEnv(t, func(v *VICAL) { v.NotAfter = time.Now().Add(-time.Hour).UTC().Format(time.RFC3339) })
	resp, _ := reg.Evaluate(context.Background(), &authzen.EvaluationRequest{
		Subject: authzen.Subject{Type: "key", ID: "iaca-vical"},
		Context: map[string]interface{}{authzen.TrustAnchorsPolicyContextKey: []string{"vical"}},
	})
	if resp.Decision || len(resp.Context.TrustAnchors) != 0 {
		t.Errorf("an expired list must not be offered: %+v", resp)
	}
}

func TestTrustAnchors_TTLFromNextUpdate(t *testing.T) {
	reg, _, _ := trustAnchorEnv(t, func(v *VICAL) { v.NextUpdate = time.Now().Add(2 * time.Hour).UTC().Format(time.RFC3339) })
	resp, _ := reg.Evaluate(context.Background(), &authzen.EvaluationRequest{
		Subject: authzen.Subject{Type: "key", ID: "iaca-vical"},
		Context: map[string]interface{}{authzen.TrustAnchorsPolicyContextKey: []string{"vical"}},
	})
	ttl := resp.Context.TrustAnchors[0].TTLSeconds
	if ttl < 7190 || ttl > 7200 {
		t.Errorf("ttl %d, want about 7200", ttl)
	}
}
