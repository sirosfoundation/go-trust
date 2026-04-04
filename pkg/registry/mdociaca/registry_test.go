package mdociaca

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/sirosfoundation/go-trust/pkg/authzen"
)

// =============================================================================
// Test Certificate Generation Helpers
// =============================================================================

// generateIACACertificate creates a self-signed IACA root CA certificate.
func generateIACACertificate(t *testing.T, country, org, cn string) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate ECDSA key: %v", err)
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Country:      []string{country},
			Organization: []string{org},
			CommonName:   cn,
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            1,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatalf("failed to create certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("failed to parse certificate: %v", err)
	}

	return cert, privateKey
}

// generateDSCertificate creates a Document Signer certificate signed by an IACA.
func generateDSCertificate(t *testing.T, iaca *x509.Certificate, iacaKey *ecdsa.PrivateKey, cn string) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate ECDSA key: %v", err)
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject: pkix.Name{
			Country:      iaca.Subject.Country,
			Organization: iaca.Subject.Organization,
			CommonName:   cn,
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(2 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
		BasicConstraintsValid: true,
		IsCA:                  false,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, iaca, &privateKey.PublicKey, iacaKey)
	if err != nil {
		t.Fatalf("failed to create DS certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("failed to parse DS certificate: %v", err)
	}

	return cert, privateKey
}

// certToBase64 encodes a certificate as base64 DER.
func certToBase64(cert *x509.Certificate) string {
	return base64.StdEncoding.EncodeToString(cert.Raw)
}

// =============================================================================
// Mock HTTP Server
// =============================================================================

type mockIssuerServer struct {
	server       *httptest.Server
	iacaCerts    []*x509.Certificate
	metadata     *IssuerMetadata
	iacasURI     string
	failIacas    bool
	failMetadata bool
}

func newMockIssuerServer(t *testing.T, iacaCerts []*x509.Certificate) *mockIssuerServer {
	t.Helper()

	mock := &mockIssuerServer{
		iacaCerts: iacaCerts,
	}

	mux := http.NewServeMux()

	mux.HandleFunc("/.well-known/openid-credential-issuer", func(w http.ResponseWriter, r *http.Request) {
		if mock.failMetadata {
			http.Error(w, "simulated metadata error", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(mock.metadata)
	})

	mux.HandleFunc("/iacas", func(w http.ResponseWriter, r *http.Request) {
		if mock.failIacas {
			http.Error(w, "simulated IACA error", http.StatusInternalServerError)
			return
		}

		iacas := make([]IACACertificate, len(mock.iacaCerts))
		for i, cert := range mock.iacaCerts {
			iacas[i] = IACACertificate{
				Certificate: certToBase64(cert),
			}
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(IACAsResponse{Iacas: iacas})
	})

	mock.server = httptest.NewServer(mux)
	mock.iacasURI = mock.server.URL + "/iacas"
	mock.metadata = &IssuerMetadata{
		CredentialIssuer: mock.server.URL,
		MdocIacasURI:     mock.iacasURI,
	}

	return mock
}

func (m *mockIssuerServer) Close() {
	m.server.Close()
}

func (m *mockIssuerServer) URL() string {
	return m.server.URL
}

// =============================================================================
// Unit Tests
// =============================================================================

func TestNew_DefaultConfig(t *testing.T) {
	// Test with nil config to verify default config handling.
	// This is safe because New() doesn't perform network calls.
	reg, err := New(nil)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	if reg.config.Name != "mdoc-iaca" {
		t.Errorf("expected default name 'mdoc-iaca', got %q", reg.config.Name)
	}
	if reg.config.CacheTTL != time.Hour {
		t.Errorf("expected default CacheTTL 1h, got %v", reg.config.CacheTTL)
	}
	if reg.config.HTTPTimeout != 30*time.Second {
		t.Errorf("expected default HTTPTimeout 30s, got %v", reg.config.HTTPTimeout)
	}
}

func TestNew_CustomConfig(t *testing.T) {
	cfg := &Config{
		Name:            "custom-mdoc-iaca",
		Description:     "Test registry",
		IssuerAllowlist: []string{"https://issuer.example.com", "https://issuer2.example.com/"},
		CacheTTL:        2 * time.Hour,
		HTTPTimeout:     15 * time.Second,
		AllowPrivateIPs: true,
	}

	reg, err := New(cfg)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	if reg.config.Name != "custom-mdoc-iaca" {
		t.Errorf("expected name 'custom-mdoc-iaca', got %q", reg.config.Name)
	}

	// Check allowlist normalization (trailing slash removed)
	if _, ok := reg.allowlist["https://issuer2.example.com"]; !ok {
		t.Error("allowlist should contain normalized issuer2 URL (without trailing slash)")
	}
}

func TestRegistry_Info(t *testing.T) {
	reg, _ := New(&Config{
		Name:        "test-registry",
		Description: "Test description",
	})

	info := reg.Info()

	if info.Name != "test-registry" {
		t.Errorf("Info().Name = %q, want 'test-registry'", info.Name)
	}
	if info.Type != "mdoc_iaca" {
		t.Errorf("Info().Type = %q, want 'mdoc_iaca'", info.Type)
	}
}

func TestRegistry_SupportedResourceTypes(t *testing.T) {
	reg, _ := New(&Config{AllowPrivateIPs: true, AllowHTTP: true})

	types := reg.SupportedResourceTypes()

	if len(types) != 1 || types[0] != "x5c" {
		t.Errorf("SupportedResourceTypes() = %v, want [x5c]", types)
	}
}

func TestRegistry_SupportsResolutionOnly(t *testing.T) {
	reg, _ := New(&Config{AllowPrivateIPs: true, AllowHTTP: true})

	if reg.SupportsResolutionOnly() {
		t.Error("SupportsResolutionOnly() should return false")
	}
}

func TestRegistry_Healthy(t *testing.T) {
	reg, _ := New(&Config{AllowPrivateIPs: true, AllowHTTP: true})

	if !reg.Healthy() {
		t.Error("Healthy() should return true")
	}
}

// =============================================================================
// Integration Tests with Mock Server
// =============================================================================

func TestRegistry_Evaluate_ValidChain(t *testing.T) {
	iaca, iacaKey := generateIACACertificate(t, "SE", "SUNET", "Sweden IACA")
	ds, _ := generateDSCertificate(t, iaca, iacaKey, "Sweden DS")

	mock := newMockIssuerServer(t, []*x509.Certificate{iaca})
	defer mock.Close()

	reg, _ := New(&Config{AllowPrivateIPs: true, AllowHTTP: true})

	req := &authzen.EvaluationRequest{
		Subject: authzen.Subject{
			Type: "key",
			ID:   mock.URL(),
		},
		Resource: authzen.Resource{
			Type: "x5c",
			Key:  []interface{}{certToBase64(ds), certToBase64(iaca)},
		},
	}

	resp, err := reg.Evaluate(context.Background(), req)
	if err != nil {
		t.Fatalf("Evaluate() error = %v", err)
	}

	if !resp.Decision {
		reason := "unknown"
		if resp.Context != nil && resp.Context.Reason != nil {
			reason = fmt.Sprintf("%v", resp.Context.Reason)
		}
		t.Errorf("expected true decision for valid chain, got false. Reason: %s", reason)
	}

	if resp.Context != nil && resp.Context.Reason != nil {
		if resp.Context.Reason["trust_anchor"] != "mdoc_iaca" {
			t.Errorf("expected trust_anchor='mdoc_iaca', got %v", resp.Context.Reason["trust_anchor"])
		}
	}
}

func TestRegistry_Evaluate_SelfSignedIACA(t *testing.T) {
	iaca, _ := generateIACACertificate(t, "FI", "DVV", "Finland IACA")

	mock := newMockIssuerServer(t, []*x509.Certificate{iaca})
	defer mock.Close()

	reg, _ := New(&Config{AllowPrivateIPs: true, AllowHTTP: true})

	req := &authzen.EvaluationRequest{
		Subject: authzen.Subject{
			Type: "key",
			ID:   mock.URL(),
		},
		Resource: authzen.Resource{
			Type: "x5c",
			Key:  []interface{}{certToBase64(iaca)},
		},
	}

	resp, err := reg.Evaluate(context.Background(), req)
	if err != nil {
		t.Fatalf("Evaluate() error = %v", err)
	}

	if !resp.Decision {
		t.Error("expected IACA to validate against itself")
	}
}

func TestRegistry_Evaluate_UntrustedCert(t *testing.T) {
	iaca, _ := generateIACACertificate(t, "SE", "SUNET", "Sweden IACA")
	untrusted, _ := generateIACACertificate(t, "FI", "DVV", "Finland IACA")

	mock := newMockIssuerServer(t, []*x509.Certificate{iaca})
	defer mock.Close()

	reg, _ := New(&Config{AllowPrivateIPs: true, AllowHTTP: true})

	req := &authzen.EvaluationRequest{
		Subject: authzen.Subject{
			Type: "key",
			ID:   mock.URL(),
		},
		Resource: authzen.Resource{
			Type: "x5c",
			Key:  []interface{}{certToBase64(untrusted)},
		},
	}

	resp, err := reg.Evaluate(context.Background(), req)
	if err != nil {
		t.Fatalf("Evaluate() error = %v", err)
	}

	if resp.Decision {
		t.Error("expected false decision for untrusted certificate")
	}
}

func TestRegistry_Evaluate_IssuerAllowlist_Blocked(t *testing.T) {
	iaca, _ := generateIACACertificate(t, "SE", "SUNET", "Sweden IACA")

	mock := newMockIssuerServer(t, []*x509.Certificate{iaca})
	defer mock.Close()

	reg, _ := New(&Config{
		IssuerAllowlist: []string{"https://other-issuer.example.com"},
		AllowPrivateIPs: true,
		AllowHTTP:       true,
	})

	req := &authzen.EvaluationRequest{
		Subject: authzen.Subject{
			Type: "key",
			ID:   mock.URL(),
		},
		Resource: authzen.Resource{
			Type: "x5c",
			Key:  []interface{}{certToBase64(iaca)},
		},
	}

	resp, err := reg.Evaluate(context.Background(), req)
	if err != nil {
		t.Fatalf("Evaluate() error = %v", err)
	}

	if resp.Decision {
		t.Error("expected false decision for issuer not in allowlist")
	}

	if resp.Context != nil && resp.Context.Reason != nil {
		if resp.Context.Reason["error"] != "issuer not in allowlist" {
			t.Errorf("expected 'issuer not in allowlist' error, got %v", resp.Context.Reason["error"])
		}
	}
}

func TestRegistry_Evaluate_IssuerAllowlist_Allowed(t *testing.T) {
	iaca, _ := generateIACACertificate(t, "SE", "SUNET", "Sweden IACA")

	mock := newMockIssuerServer(t, []*x509.Certificate{iaca})
	defer mock.Close()

	reg, _ := New(&Config{
		IssuerAllowlist: []string{mock.URL()},
		AllowPrivateIPs: true,
		AllowHTTP:       true,
	})

	req := &authzen.EvaluationRequest{
		Subject: authzen.Subject{
			Type: "key",
			ID:   mock.URL(),
		},
		Resource: authzen.Resource{
			Type: "x5c",
			Key:  []interface{}{certToBase64(iaca)},
		},
	}

	resp, err := reg.Evaluate(context.Background(), req)
	if err != nil {
		t.Fatalf("Evaluate() error = %v", err)
	}

	if !resp.Decision {
		t.Error("expected true decision for issuer in allowlist")
	}
}

func TestRegistry_Evaluate_EmptyChain(t *testing.T) {
	iaca, _ := generateIACACertificate(t, "SE", "SUNET", "Sweden IACA")

	mock := newMockIssuerServer(t, []*x509.Certificate{iaca})
	defer mock.Close()

	reg, _ := New(&Config{AllowPrivateIPs: true, AllowHTTP: true})

	req := &authzen.EvaluationRequest{
		Subject: authzen.Subject{
			Type: "key",
			ID:   mock.URL(),
		},
		Resource: authzen.Resource{
			Type: "x5c",
			Key:  []interface{}{},
		},
	}

	resp, err := reg.Evaluate(context.Background(), req)
	if err != nil {
		t.Fatalf("Evaluate() error = %v", err)
	}

	if resp.Decision {
		t.Error("expected false decision for empty chain")
	}
}

func TestRegistry_Evaluate_NoMdocIacasURI(t *testing.T) {
	iaca, _ := generateIACACertificate(t, "SE", "SUNET", "Sweden IACA")

	mock := newMockIssuerServer(t, []*x509.Certificate{iaca})
	mock.metadata.MdocIacasURI = ""
	defer mock.Close()

	reg, _ := New(&Config{AllowPrivateIPs: true, AllowHTTP: true})

	req := &authzen.EvaluationRequest{
		Subject: authzen.Subject{
			Type: "key",
			ID:   mock.URL(),
		},
		Resource: authzen.Resource{
			Type: "x5c",
			Key:  []interface{}{certToBase64(iaca)},
		},
	}

	resp, err := reg.Evaluate(context.Background(), req)
	if err != nil {
		t.Fatalf("Evaluate() error = %v", err)
	}

	if resp.Decision {
		t.Error("expected false decision when issuer doesn't publish mdoc_iacas_uri")
	}
}

func TestRegistry_Evaluate_MetadataFetchError(t *testing.T) {
	iaca, _ := generateIACACertificate(t, "SE", "SUNET", "Sweden IACA")

	mock := newMockIssuerServer(t, []*x509.Certificate{iaca})
	mock.failMetadata = true
	defer mock.Close()

	reg, _ := New(&Config{AllowPrivateIPs: true, AllowHTTP: true})

	req := &authzen.EvaluationRequest{
		Subject: authzen.Subject{
			Type: "key",
			ID:   mock.URL(),
		},
		Resource: authzen.Resource{
			Type: "x5c",
			Key:  []interface{}{certToBase64(iaca)},
		},
	}

	resp, err := reg.Evaluate(context.Background(), req)
	if err != nil {
		t.Fatalf("Evaluate() error = %v", err)
	}

	if resp.Decision {
		t.Error("expected false decision when metadata fetch fails")
	}
}

func TestRegistry_Evaluate_IACFetchError(t *testing.T) {
	iaca, _ := generateIACACertificate(t, "SE", "SUNET", "Sweden IACA")

	mock := newMockIssuerServer(t, []*x509.Certificate{iaca})
	mock.failIacas = true
	defer mock.Close()

	reg, _ := New(&Config{AllowPrivateIPs: true, AllowHTTP: true})

	req := &authzen.EvaluationRequest{
		Subject: authzen.Subject{
			Type: "key",
			ID:   mock.URL(),
		},
		Resource: authzen.Resource{
			Type: "x5c",
			Key:  []interface{}{certToBase64(iaca)},
		},
	}

	resp, err := reg.Evaluate(context.Background(), req)
	if err != nil {
		t.Fatalf("Evaluate() error = %v", err)
	}

	if resp.Decision {
		t.Error("expected false decision when IACA fetch fails")
	}
}

func TestRegistry_Evaluate_InvalidCertBase64(t *testing.T) {
	iaca, _ := generateIACACertificate(t, "SE", "SUNET", "Sweden IACA")

	mock := newMockIssuerServer(t, []*x509.Certificate{iaca})
	defer mock.Close()

	reg, _ := New(&Config{AllowPrivateIPs: true, AllowHTTP: true})

	req := &authzen.EvaluationRequest{
		Subject: authzen.Subject{
			Type: "key",
			ID:   mock.URL(),
		},
		Resource: authzen.Resource{
			Type: "x5c",
			Key:  []interface{}{"not-valid-base64!!!"},
		},
	}

	resp, err := reg.Evaluate(context.Background(), req)
	if err != nil {
		t.Fatalf("Evaluate() error = %v", err)
	}

	if resp.Decision {
		t.Error("expected false decision for invalid base64")
	}
}

func TestRegistry_Evaluate_NilKey(t *testing.T) {
	iaca, _ := generateIACACertificate(t, "SE", "SUNET", "Sweden IACA")

	mock := newMockIssuerServer(t, []*x509.Certificate{iaca})
	defer mock.Close()

	reg, _ := New(&Config{AllowPrivateIPs: true, AllowHTTP: true})

	req := &authzen.EvaluationRequest{
		Subject: authzen.Subject{
			Type: "key",
			ID:   mock.URL(),
		},
		Resource: authzen.Resource{
			Type: "x5c",
			Key:  nil,
		},
	}

	resp, err := reg.Evaluate(context.Background(), req)
	if err != nil {
		t.Fatalf("Evaluate() error = %v", err)
	}

	if resp.Decision {
		t.Error("expected false decision for nil key")
	}
}

func TestRegistry_Evaluate_MissingIssuerURL(t *testing.T) {
	reg, _ := New(&Config{AllowPrivateIPs: true, AllowHTTP: true})

	req := &authzen.EvaluationRequest{
		Subject: authzen.Subject{
			Type: "key",
			ID:   "",
		},
		Resource: authzen.Resource{
			Type: "x5c",
			Key:  []interface{}{"dGVzdA=="},
		},
	}

	resp, err := reg.Evaluate(context.Background(), req)
	if err != nil {
		t.Fatalf("Evaluate() error = %v", err)
	}

	if resp.Decision {
		t.Error("expected false decision for missing issuer URL")
	}

	if resp.Context != nil && resp.Context.Reason != nil {
		if resp.Context.Reason["error"] != "missing issuer URL in subject.id" {
			t.Errorf("expected 'missing issuer URL' error, got %v", resp.Context.Reason["error"])
		}
	}
}

// =============================================================================
// Cache Tests
// =============================================================================

func TestRegistry_Caching(t *testing.T) {
	iaca, _ := generateIACACertificate(t, "SE", "SUNET", "Sweden IACA")

	mock := newMockIssuerServer(t, []*x509.Certificate{iaca})
	defer mock.Close()

	reg, _ := New(&Config{
		CacheTTL:        5 * time.Minute,
		AllowPrivateIPs: true,
		AllowHTTP:       true,
	})

	req := &authzen.EvaluationRequest{
		Subject: authzen.Subject{
			Type: "key",
			ID:   mock.URL(),
		},
		Resource: authzen.Resource{
			Type: "x5c",
			Key:  []interface{}{certToBase64(iaca)},
		},
	}

	// First request - should fetch
	_, err := reg.Evaluate(context.Background(), req)
	if err != nil {
		t.Fatalf("First Evaluate() error = %v", err)
	}

	// Disable the mock server endpoints
	mock.failIacas = true
	mock.failMetadata = true

	// Second request - should use cache
	resp, err := reg.Evaluate(context.Background(), req)
	if err != nil {
		t.Fatalf("Second Evaluate() error = %v", err)
	}

	if !resp.Decision {
		t.Error("expected cache to be used for second request")
	}
}

func TestRegistry_Refresh_ClearsCache(t *testing.T) {
	iaca, _ := generateIACACertificate(t, "SE", "SUNET", "Sweden IACA")

	mock := newMockIssuerServer(t, []*x509.Certificate{iaca})
	defer mock.Close()

	reg, _ := New(&Config{AllowPrivateIPs: true, AllowHTTP: true})

	req := &authzen.EvaluationRequest{
		Subject: authzen.Subject{
			Type: "key",
			ID:   mock.URL(),
		},
		Resource: authzen.Resource{
			Type: "x5c",
			Key:  []interface{}{certToBase64(iaca)},
		},
	}

	// First request - populates cache
	_, err := reg.Evaluate(context.Background(), req)
	if err != nil {
		t.Fatalf("First Evaluate() error = %v", err)
	}

	// Refresh - clears cache
	if err := reg.Refresh(context.Background()); err != nil {
		t.Fatalf("Refresh() error = %v", err)
	}

	// Disable mock endpoints
	mock.failIacas = true
	mock.failMetadata = true

	// Next request should fail because cache was cleared
	resp, err := reg.Evaluate(context.Background(), req)
	if err != nil {
		t.Fatalf("Post-refresh Evaluate() error = %v", err)
	}

	if resp.Decision {
		t.Error("expected failure after cache refresh with failing endpoints")
	}
}

// =============================================================================
// Multi-IACA Tests
// =============================================================================

func TestRegistry_Evaluate_MultipleIACAs(t *testing.T) {
	iaca1, iacaKey1 := generateIACACertificate(t, "SE", "SUNET", "Sweden IACA 1")
	iaca2, _ := generateIACACertificate(t, "SE", "SUNET", "Sweden IACA 2")
	ds, _ := generateDSCertificate(t, iaca1, iacaKey1, "Sweden DS")

	mock := newMockIssuerServer(t, []*x509.Certificate{iaca1, iaca2})
	defer mock.Close()

	reg, _ := New(&Config{AllowPrivateIPs: true, AllowHTTP: true})

	req := &authzen.EvaluationRequest{
		Subject: authzen.Subject{
			Type: "key",
			ID:   mock.URL(),
		},
		Resource: authzen.Resource{
			Type: "x5c",
			Key:  []interface{}{certToBase64(ds), certToBase64(iaca1)},
		},
	}

	resp, err := reg.Evaluate(context.Background(), req)
	if err != nil {
		t.Fatalf("Evaluate() error = %v", err)
	}

	if !resp.Decision {
		t.Error("expected chain to validate against one of the IACAs")
	}

	if resp.Context != nil && resp.Context.Reason != nil {
		if resp.Context.Reason["iaca_count"] != 2 {
			t.Errorf("expected iaca_count=2, got %v", resp.Context.Reason["iaca_count"])
		}
	}
}

// =============================================================================
// Edge Cases
// =============================================================================

func TestRegistry_Evaluate_TrailingSlashNormalization(t *testing.T) {
	iaca, _ := generateIACACertificate(t, "SE", "SUNET", "Sweden IACA")

	mock := newMockIssuerServer(t, []*x509.Certificate{iaca})
	defer mock.Close()

	// Allowlist with trailing slash
	reg, _ := New(&Config{
		IssuerAllowlist: []string{mock.URL() + "/"},
		AllowPrivateIPs: true,
		AllowHTTP:       true,
	})

	// Request without trailing slash
	req := &authzen.EvaluationRequest{
		Subject: authzen.Subject{
			Type: "key",
			ID:   mock.URL(),
		},
		Resource: authzen.Resource{
			Type: "x5c",
			Key:  []interface{}{certToBase64(iaca)},
		},
	}

	resp, err := reg.Evaluate(context.Background(), req)
	if err != nil {
		t.Fatalf("Evaluate() error = %v", err)
	}

	if !resp.Decision {
		t.Error("expected URL normalization to match with/without trailing slash")
	}
}

func TestRegistry_Evaluate_NonStringElementInChain(t *testing.T) {
	iaca, _ := generateIACACertificate(t, "SE", "SUNET", "Sweden IACA")

	mock := newMockIssuerServer(t, []*x509.Certificate{iaca})
	defer mock.Close()

	reg, _ := New(&Config{AllowPrivateIPs: true, AllowHTTP: true})

	// Include a non-string element in the chain
	req := &authzen.EvaluationRequest{
		Subject: authzen.Subject{
			Type: "key",
			ID:   mock.URL(),
		},
		Resource: authzen.Resource{
			Type: "x5c",
			Key:  []interface{}{certToBase64(iaca), 12345}, // int instead of string
		},
	}

	resp, err := reg.Evaluate(context.Background(), req)
	if err != nil {
		t.Fatalf("Evaluate() error = %v", err)
	}

	if resp.Decision {
		t.Error("expected false decision for non-string element in chain")
	}
}
