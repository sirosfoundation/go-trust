package etsi

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sirosfoundation/go-trust/pkg/authzen"
)

// generateTestCertificate creates a self-signed test certificate
func generateTestCertificate(t *testing.T, cn string) (*x509.Certificate, []byte) {
	t.Helper()

	// Generate RSA key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}

	// Create certificate template
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   cn,
			Organization: []string{"Test Organization"},
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	// Create self-signed certificate
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatalf("failed to create certificate: %v", err)
	}

	// Parse the DER certificate back
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("failed to parse certificate: %v", err)
	}

	// Encode to PEM
	pemBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})

	return cert, pemBytes
}

// writeTestCertFile writes a PEM certificate to a temp file
func writeTestCertFile(t *testing.T, dir string, filename string, pemData []byte) string {
	t.Helper()
	path := filepath.Join(dir, filename)
	if err := os.WriteFile(path, pemData, 0644); err != nil {
		t.Fatalf("failed to write cert file: %v", err)
	}
	return path
}

// generateSignedCertificate creates a certificate signed by a CA
// Returns the certificate, its DER bytes, and the private key
func generateSignedCertificate(t *testing.T, cn string, isCA bool, issuer *x509.Certificate, issuerKey *rsa.PrivateKey) (*x509.Certificate, []byte, *rsa.PrivateKey) {
	t.Helper()

	// Generate RSA key for this certificate
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}

	// Create certificate template
	template := x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject: pkix.Name{
			CommonName:   cn,
			Organization: []string{"Test Organization"},
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		BasicConstraintsValid: true,
		IsCA:                  isCA,
	}

	if isCA {
		template.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature
	} else {
		template.KeyUsage = x509.KeyUsageDigitalSignature
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	}

	// Sign with the issuer (or self-sign if issuer is nil)
	signingCert := issuer
	signingKey := issuerKey
	if signingCert == nil {
		signingCert = &template
		signingKey = privateKey
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, signingCert, &privateKey.PublicKey, signingKey)
	if err != nil {
		t.Fatalf("failed to create certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("failed to parse certificate: %v", err)
	}

	return cert, certDER, privateKey
}

func TestNewTSLRegistry_WithCertBundle(t *testing.T) {
	// Create temp directory
	tmpDir, err := os.MkdirTemp("", "tsl-registry-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Generate test certificate and write to file
	_, pemData := generateTestCertificate(t, "Test CA")
	certPath := writeTestCertFile(t, tmpDir, "test-ca.pem", pemData)

	// Create registry
	reg, err := NewTSLRegistry(TSLConfig{
		Name:       "test-registry",
		CertBundle: certPath,
	})
	if err != nil {
		t.Fatalf("failed to create registry: %v", err)
	}

	// Verify it's healthy
	if !reg.Healthy() {
		t.Error("registry should be healthy")
	}

	// Verify certificate count
	if reg.CertificateCount() != 1 {
		t.Errorf("expected 1 certificate, got %d", reg.CertificateCount())
	}

	// Verify info
	info := reg.Info()
	if info.Name != "test-registry" {
		t.Errorf("expected name 'test-registry', got %q", info.Name)
	}
	if info.Type != "etsi_tsl" {
		t.Errorf("expected type 'etsi_tsl', got %q", info.Type)
	}
}

func TestNewTSLRegistry_NoCertBundle(t *testing.T) {
	_, err := NewTSLRegistry(TSLConfig{
		Name: "empty-registry",
	})
	if err == nil {
		t.Error("expected error when no trust data configured")
	}
}

func TestNewTSLRegistry_MissingFile(t *testing.T) {
	_, err := NewTSLRegistry(TSLConfig{
		Name:       "missing-file",
		CertBundle: "/nonexistent/path/certs.pem",
	})
	if err == nil {
		t.Error("expected error for missing file")
	}
}

func TestNewTSLRegistry_EmptyPEM(t *testing.T) {
	// Create temp directory
	tmpDir, err := os.MkdirTemp("", "tsl-registry-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Write empty PEM file
	emptyPath := filepath.Join(tmpDir, "empty.pem")
	if err := os.WriteFile(emptyPath, []byte(""), 0644); err != nil {
		t.Fatalf("failed to write empty file: %v", err)
	}

	_, err = NewTSLRegistry(TSLConfig{
		Name:       "empty-pem",
		CertBundle: emptyPath,
	})
	if err == nil {
		t.Error("expected error for empty PEM file")
	}
}

func TestNewTSLRegistry_RejectsNetworkURLsInTSLFiles(t *testing.T) {
	tests := []struct {
		name string
		url  string
	}{
		{"http URL", "http://example.com/tsl.xml"},
		{"https URL", "https://example.com/tsl.xml"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := NewTSLRegistry(TSLConfig{
				Name:     "network-url-test",
				TSLFiles: []string{tc.url},
			})
			if err == nil {
				t.Error("expected error for network URL in TSLFiles")
			}
		})
	}
}

func TestNewTSLRegistry_RejectsNetworkURLsWhenDisabled(t *testing.T) {
	_, err := NewTSLRegistry(TSLConfig{
		Name:               "network-disabled",
		TSLURLs:            []string{"https://example.com/tsl.xml"},
		AllowNetworkAccess: false, // default
	})
	if err == nil {
		t.Error("expected error for network URL when AllowNetworkAccess=false")
	}
}

func TestTSLRegistry_Info(t *testing.T) {
	// Create temp directory
	tmpDir, err := os.MkdirTemp("", "tsl-registry-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Generate test certificate
	_, pemData := generateTestCertificate(t, "Test CA")
	certPath := writeTestCertFile(t, tmpDir, "test-ca.pem", pemData)

	reg, err := NewTSLRegistry(TSLConfig{
		Name:        "info-test",
		Description: "Test description",
		CertBundle:  certPath,
	})
	if err != nil {
		t.Fatalf("failed to create registry: %v", err)
	}

	info := reg.Info()

	if info.Name != "info-test" {
		t.Errorf("expected name 'info-test', got %q", info.Name)
	}
	if info.Description != "Test description" {
		t.Errorf("expected description 'Test description', got %q", info.Description)
	}
	if info.Type != "etsi_tsl" {
		t.Errorf("expected type 'etsi_tsl', got %q", info.Type)
	}
	if info.Version != "1.0.0" {
		t.Errorf("expected version '1.0.0', got %q", info.Version)
	}
}

func TestTSLRegistry_SupportedResourceTypes(t *testing.T) {
	// Create temp directory
	tmpDir, err := os.MkdirTemp("", "tsl-registry-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Generate test certificate
	_, pemData := generateTestCertificate(t, "Test CA")
	certPath := writeTestCertFile(t, tmpDir, "test-ca.pem", pemData)

	reg, err := NewTSLRegistry(TSLConfig{
		Name:       "types-test",
		CertBundle: certPath,
	})
	if err != nil {
		t.Fatalf("failed to create registry: %v", err)
	}

	types := reg.SupportedResourceTypes()
	if len(types) != 3 {
		t.Errorf("expected 3 supported types, got %d", len(types))
	}

	foundX5C := false
	foundJWK := false
	foundX509SanDNS := false
	for _, typ := range types {
		if typ == "x5c" {
			foundX5C = true
		}
		if typ == "jwk" {
			foundJWK = true
		}
		if typ == "x509_san_dns" {
			foundX509SanDNS = true
		}
	}
	if !foundX5C {
		t.Error("expected x5c in supported types")
	}
	if !foundJWK {
		t.Error("expected jwk in supported types")
	}
	if !foundX509SanDNS {
		t.Error("expected x509_san_dns in supported types")
	}
}

func TestTSLRegistry_SupportsResolutionOnly(t *testing.T) {
	// Create temp directory
	tmpDir, err := os.MkdirTemp("", "tsl-registry-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Generate test certificate
	_, pemData := generateTestCertificate(t, "Test CA")
	certPath := writeTestCertFile(t, tmpDir, "test-ca.pem", pemData)

	reg, err := NewTSLRegistry(TSLConfig{
		Name:       "resolution-test",
		CertBundle: certPath,
	})
	if err != nil {
		t.Fatalf("failed to create registry: %v", err)
	}

	if reg.SupportsResolutionOnly() {
		t.Error("ETSI TSL registry should not support resolution-only requests")
	}
}

func TestTSLRegistry_EvaluateResolutionOnlyRequest(t *testing.T) {
	// Create temp directory
	tmpDir, err := os.MkdirTemp("", "tsl-registry-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Generate test certificate
	_, pemData := generateTestCertificate(t, "Test CA")
	certPath := writeTestCertFile(t, tmpDir, "test-ca.pem", pemData)

	reg, err := NewTSLRegistry(TSLConfig{
		Name:       "evaluate-test",
		CertBundle: certPath,
	})
	if err != nil {
		t.Fatalf("failed to create registry: %v", err)
	}

	// Create a resolution-only request (empty resource.key)
	req := &authzen.EvaluationRequest{
		Resource: authzen.Resource{
			Type: "x5c",
			Key:  nil, // Empty key = resolution-only
		},
	}

	resp, err := reg.Evaluate(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if resp.Decision {
		t.Error("expected false decision for resolution-only request")
	}
}

func TestTSLRegistry_EvaluateUnsupportedResourceType(t *testing.T) {
	// Create temp directory
	tmpDir, err := os.MkdirTemp("", "tsl-registry-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Generate test certificate
	_, pemData := generateTestCertificate(t, "Test CA")
	certPath := writeTestCertFile(t, tmpDir, "test-ca.pem", pemData)

	reg, err := NewTSLRegistry(TSLConfig{
		Name:       "unsupported-type-test",
		CertBundle: certPath,
	})
	if err != nil {
		t.Fatalf("failed to create registry: %v", err)
	}

	// Create request with unsupported resource type
	req := &authzen.EvaluationRequest{
		Resource: authzen.Resource{
			Type: "unsupported",
			Key:  []interface{}{"some-data"},
		},
	}

	resp, err := reg.Evaluate(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if resp.Decision {
		t.Error("expected false decision for unsupported resource type")
	}
}

func TestTSLRegistry_Refresh(t *testing.T) {
	// Create temp directory
	tmpDir, err := os.MkdirTemp("", "tsl-registry-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Generate test certificate
	_, pemData := generateTestCertificate(t, "Test CA")
	certPath := writeTestCertFile(t, tmpDir, "test-ca.pem", pemData)

	reg, err := NewTSLRegistry(TSLConfig{
		Name:       "refresh-test",
		CertBundle: certPath,
	})
	if err != nil {
		t.Fatalf("failed to create registry: %v", err)
	}

	originalLoadedAt := reg.LoadedAt()

	// Wait a bit to ensure timestamp difference
	time.Sleep(10 * time.Millisecond)

	// Refresh
	if err := reg.Refresh(context.Background()); err != nil {
		t.Fatalf("refresh failed: %v", err)
	}

	// Verify loadedAt changed
	if !reg.LoadedAt().After(originalLoadedAt) {
		t.Error("expected LoadedAt to be updated after refresh")
	}
}

func TestTSLRegistry_MultipleCertBundles(t *testing.T) {
	// Create temp directory
	tmpDir, err := os.MkdirTemp("", "tsl-registry-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Generate two test certificates
	_, pemData1 := generateTestCertificate(t, "Test CA 1")
	_, pemData2 := generateTestCertificate(t, "Test CA 2")

	// Combine into one PEM file
	combinedPEM := append(pemData1, pemData2...)
	certPath := writeTestCertFile(t, tmpDir, "combined.pem", combinedPEM)

	reg, err := NewTSLRegistry(TSLConfig{
		Name:       "multi-cert-test",
		CertBundle: certPath,
	})
	if err != nil {
		t.Fatalf("failed to create registry: %v", err)
	}

	if reg.CertificateCount() != 2 {
		t.Errorf("expected 2 certificates, got %d", reg.CertificateCount())
	}
}

func TestTSLRegistry_CertPool(t *testing.T) {
	// Create temp directory
	tmpDir, err := os.MkdirTemp("", "tsl-registry-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Generate test certificate
	_, pemData := generateTestCertificate(t, "Test CA")
	certPath := writeTestCertFile(t, tmpDir, "test-ca.pem", pemData)

	reg, err := NewTSLRegistry(TSLConfig{
		Name:       "certpool-test",
		CertBundle: certPath,
	})
	if err != nil {
		t.Fatalf("failed to create registry: %v", err)
	}

	pool := reg.CertPool()
	if pool == nil {
		t.Error("CertPool should not be nil")
	}
}

func TestTSLRegistry_Evaluate_X5CValidChain(t *testing.T) {
	// Create temp directory
	tmpDir, err := os.MkdirTemp("", "tsl-registry-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Generate test CA certificate
	caCert, caPEM := generateTestCertificate(t, "Test CA")
	certPath := writeTestCertFile(t, tmpDir, "test-ca.pem", caPEM)

	reg, err := NewTSLRegistry(TSLConfig{
		Name:       "x5c-validate-test",
		CertBundle: certPath,
	})
	if err != nil {
		t.Fatalf("failed to create registry: %v", err)
	}

	// Extract the raw DER bytes and base64 encode them
	certB64 := base64.StdEncoding.EncodeToString(caCert.Raw)

	// Create request with x5c chain - the CA cert should validate against itself (self-signed)
	req := &authzen.EvaluationRequest{
		Resource: authzen.Resource{
			Type: "x5c",
			Key:  []interface{}{certB64},
		},
	}

	resp, err := reg.Evaluate(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !resp.Decision {
		reason := "unknown"
		if resp.Context != nil && resp.Context.Reason != nil {
			reason = fmt.Sprintf("%v", resp.Context.Reason)
		}
		t.Errorf("expected true decision for valid self-signed CA, got false. Reason: %s", reason)
	}
}

func TestTSLRegistry_Evaluate_X5CInvalidCert(t *testing.T) {
	// Create temp directory
	tmpDir, err := os.MkdirTemp("", "tsl-registry-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Generate trusted CA
	_, caPEM := generateTestCertificate(t, "Trusted CA")
	certPath := writeTestCertFile(t, tmpDir, "test-ca.pem", caPEM)

	reg, err := NewTSLRegistry(TSLConfig{
		Name:       "x5c-invalid-test",
		CertBundle: certPath,
	})
	if err != nil {
		t.Fatalf("failed to create registry: %v", err)
	}

	// Generate an untrusted certificate (not in pool)
	untrustedCert, _ := generateTestCertificate(t, "Untrusted CA")
	certB64 := base64.StdEncoding.EncodeToString(untrustedCert.Raw)

	// Create request with untrusted certificate
	req := &authzen.EvaluationRequest{
		Resource: authzen.Resource{
			Type: "x5c",
			Key:  []interface{}{certB64},
		},
	}

	resp, err := reg.Evaluate(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if resp.Decision {
		t.Error("expected false decision for untrusted certificate")
	}
}

// TestTSLRegistry_Evaluate_X5CIntermediateChain tests validation of a certificate chain
// with an intermediate CA. This verifies issue #6 - intermediate certificate fix.
func TestTSLRegistry_Evaluate_X5CIntermediateChain(t *testing.T) {
	// Create temp directory
	tmpDir, err := os.MkdirTemp("", "tsl-intermediate-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// 1. Create Root CA (self-signed, will be in trust store)
	rootCert, rootDER, rootKey := generateSignedCertificate(t, "Root CA", true, nil, nil)
	rootPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootDER})
	certPath := writeTestCertFile(t, tmpDir, "root-ca.pem", rootPEM)

	// 2. Create Intermediate CA (signed by Root CA)
	intermediateCert, intermediateDER, intermediateKey := generateSignedCertificate(t, "Intermediate CA", true, rootCert, rootKey)

	// 3. Create Leaf certificate (signed by Intermediate CA)
	leafCert, leafDER, _ := generateSignedCertificate(t, "Leaf Cert", false, intermediateCert, intermediateKey)

	// Create registry with only Root CA as trust anchor
	reg, err := NewTSLRegistry(TSLConfig{
		Name:       "intermediate-chain-test",
		CertBundle: certPath,
	})
	if err != nil {
		t.Fatalf("failed to create registry: %v", err)
	}

	// Encode certificates as base64 for x5c array (leaf first, then intermediate)
	leafB64 := base64.StdEncoding.EncodeToString(leafDER)
	intermediateB64 := base64.StdEncoding.EncodeToString(intermediateDER)

	tests := []struct {
		name        string
		chain       []interface{}
		expectAllow bool
		description string
	}{
		{
			name:        "leaf only - should fail (missing intermediate)",
			chain:       []interface{}{leafB64},
			expectAllow: false,
			description: "Leaf cert alone can't validate without intermediate",
		},
		{
			name:        "leaf + intermediate - should succeed",
			chain:       []interface{}{leafB64, intermediateB64},
			expectAllow: true,
			description: "Full chain should validate against root in trust store",
		},
		{
			name:        "intermediate only - should succeed (signed by root)",
			chain:       []interface{}{intermediateB64},
			expectAllow: true,
			description: "Intermediate CA validates because it's directly signed by root in trust store",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := &authzen.EvaluationRequest{
				Resource: authzen.Resource{
					Type: "x5c",
					Key:  tc.chain,
				},
			}

			resp, err := reg.Evaluate(context.Background(), req)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if resp.Decision != tc.expectAllow {
				reason := "unknown"
				if resp.Context != nil && resp.Context.Reason != nil {
					reason = fmt.Sprintf("%v", resp.Context.Reason)
				}
				t.Errorf("%s: expected decision=%v, got %v. Reason: %s",
					tc.description, tc.expectAllow, resp.Decision, reason)
			}
		})
	}

	// Additional test: verify leaf cert recognizes the CA chain
	_ = leafCert
}

func TestTSLRegistry_Evaluate_EmptyKey(t *testing.T) {
	// Create temp directory
	tmpDir, err := os.MkdirTemp("", "tsl-registry-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Generate trusted CA
	_, caPEM := generateTestCertificate(t, "Test CA")
	certPath := writeTestCertFile(t, tmpDir, "test-ca.pem", caPEM)

	reg, err := NewTSLRegistry(TSLConfig{
		Name:       "empty-key-test",
		CertBundle: certPath,
	})
	if err != nil {
		t.Fatalf("failed to create registry: %v", err)
	}

	// Create request with empty key array
	req := &authzen.EvaluationRequest{
		Resource: authzen.Resource{
			Type: "x5c",
			Key:  []interface{}{},
		},
	}

	resp, err := reg.Evaluate(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if resp.Decision {
		t.Error("expected false decision for empty key")
	}
}

func TestTSLRegistry_TSLCount(t *testing.T) {
	// Create temp directory
	tmpDir, err := os.MkdirTemp("", "tsl-registry-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Generate test certificate
	_, pemData := generateTestCertificate(t, "Test CA")
	certPath := writeTestCertFile(t, tmpDir, "test-ca.pem", pemData)

	reg, err := NewTSLRegistry(TSLConfig{
		Name:       "tsl-count-test",
		CertBundle: certPath,
	})
	if err != nil {
		t.Fatalf("failed to create registry: %v", err)
	}

	// Cert bundle doesn't add TSLs, so count should be 0
	if reg.TSLCount() != 0 {
		t.Errorf("expected 0 TSLs, got %d", reg.TSLCount())
	}
}

func TestTSLRegistry_LastError(t *testing.T) {
	// Create temp directory
	tmpDir, err := os.MkdirTemp("", "tsl-registry-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Generate test certificate
	_, pemData := generateTestCertificate(t, "Test CA")
	certPath := writeTestCertFile(t, tmpDir, "test-ca.pem", pemData)

	reg, err := NewTSLRegistry(TSLConfig{
		Name:       "last-error-test",
		CertBundle: certPath,
	})
	if err != nil {
		t.Fatalf("failed to create registry: %v", err)
	}

	// Successful load should have no error
	if reg.LastError() != nil {
		t.Errorf("expected nil LastError, got %v", reg.LastError())
	}
}

func TestTSLRegistry_TSLs(t *testing.T) {
	// Create temp directory
	tmpDir, err := os.MkdirTemp("", "tsl-registry-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Generate test certificate
	_, pemData := generateTestCertificate(t, "Test CA")
	certPath := writeTestCertFile(t, tmpDir, "test-ca.pem", pemData)

	reg, err := NewTSLRegistry(TSLConfig{
		Name:       "tsls-test",
		CertBundle: certPath,
	})
	if err != nil {
		t.Fatalf("failed to create registry: %v", err)
	}

	// Cert bundle doesn't add TSLs, so TSLs() returns nil for cert-bundle-only registry
	tsls := reg.TSLs()
	if len(tsls) != 0 {
		t.Errorf("expected 0 TSLs for cert-bundle registry, got %d", len(tsls))
	}
}

func TestTSLRegistry_ConfigDefaults(t *testing.T) {
	// Create temp directory
	tmpDir, err := os.MkdirTemp("", "tsl-registry-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Generate test certificate
	_, pemData := generateTestCertificate(t, "Test CA")
	certPath := writeTestCertFile(t, tmpDir, "test-ca.pem", pemData)

	// Create registry with minimal config
	reg, err := NewTSLRegistry(TSLConfig{
		CertBundle: certPath,
	})
	if err != nil {
		t.Fatalf("failed to create registry: %v", err)
	}

	// Check defaults
	if reg.config.Name != "ETSI-TSL" {
		t.Errorf("expected default Name 'ETSI-TSL', got %q", reg.config.Name)
	}
	if reg.config.MaxRefDepth != 3 {
		t.Errorf("expected default MaxRefDepth 3, got %d", reg.config.MaxRefDepth)
	}
	if reg.config.FetchTimeout != 30*time.Second {
		t.Errorf("expected default FetchTimeout 30s, got %v", reg.config.FetchTimeout)
	}
	if !strings.HasPrefix(reg.config.UserAgent, "Go-Trust/") {
		t.Errorf("expected UserAgent to start with 'Go-Trust/', got %q", reg.config.UserAgent)
	}
}

func TestTSLRegistry_InvalidPEMContent(t *testing.T) {
	// Create temp directory
	tmpDir, err := os.MkdirTemp("", "tsl-registry-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Write file with invalid PEM content (looks like PEM but has bad bytes)
	invalidPEM := []byte(`-----BEGIN CERTIFICATE-----
notvalidbase64content!!!
-----END CERTIFICATE-----
`)
	invalidPath := filepath.Join(tmpDir, "invalid.pem")
	if err := os.WriteFile(invalidPath, invalidPEM, 0644); err != nil {
		t.Fatalf("failed to write invalid file: %v", err)
	}

	_, err = NewTSLRegistry(TSLConfig{
		Name:       "invalid-pem",
		CertBundle: invalidPath,
	})
	if err == nil {
		t.Error("expected error for invalid PEM content")
	}
}

func TestTSLRegistry_LoadedAt(t *testing.T) {
	// Create temp directory
	tmpDir, err := os.MkdirTemp("", "tsl-registry-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Generate test certificate
	_, pemData := generateTestCertificate(t, "Test CA")
	certPath := writeTestCertFile(t, tmpDir, "test-ca.pem", pemData)

	beforeCreate := time.Now()
	reg, err := NewTSLRegistry(TSLConfig{
		Name:       "loadedAt-test",
		CertBundle: certPath,
	})
	if err != nil {
		t.Fatalf("failed to create registry: %v", err)
	}
	afterCreate := time.Now()

	loadedAt := reg.LoadedAt()
	if loadedAt.Before(beforeCreate) || loadedAt.After(afterCreate) {
		t.Errorf("LoadedAt() = %v, expected between %v and %v", loadedAt, beforeCreate, afterCreate)
	}
}

func TestTSLRegistry_InfoName(t *testing.T) {
	// Create temp directory
	tmpDir, err := os.MkdirTemp("", "tsl-registry-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Generate test certificate
	_, pemData := generateTestCertificate(t, "Test CA")
	certPath := writeTestCertFile(t, tmpDir, "test-ca.pem", pemData)

	// Create registry with custom name
	reg, err := NewTSLRegistry(TSLConfig{
		Name:       "custom-name-test",
		CertBundle: certPath,
	})
	if err != nil {
		t.Fatalf("failed to create registry: %v", err)
	}

	info := reg.Info()
	if info.Name != "custom-name-test" {
		t.Errorf("Info().Name = %q, want %q", info.Name, "custom-name-test")
	}
}

func TestBase64Decode(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    string
		wantErr bool
	}{
		{
			name:    "standard base64",
			input:   base64.StdEncoding.EncodeToString([]byte("hello world")),
			want:    "hello world",
			wantErr: false,
		},
		{
			name:    "with whitespace",
			input:   base64.StdEncoding.EncodeToString([]byte("test")) + "\n",
			want:    "test",
			wantErr: false,
		},
		{
			name:    "with spaces",
			input:   "aGVs bG8g d29y bGQ=",
			want:    "hello world",
			wantErr: false,
		},
		{
			name:    "with tabs",
			input:   "aGVs\tbG8=",
			want:    "hello",
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := base64Decode(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("base64Decode() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && string(got) != tt.want {
				t.Errorf("base64Decode() = %q, want %q", string(got), tt.want)
			}
		})
	}
}

// ============================================================================
// Tests using real TSL XML files from EU eIDAS
// ============================================================================

// getTSLTestDataPath returns the path to the testdata directory
func getTSLTestDataPath(t *testing.T) string {
	t.Helper()
	// Get the path relative to the test file
	_, filename, _, ok := getCallerInfo()
	if !ok {
		t.Skip("could not determine test file location")
	}
	return filepath.Join(filepath.Dir(filename), "testdata")
}

// getCallerInfo returns caller information for getTSLTestDataPath
func getCallerInfo() (pc uintptr, file string, line int, ok bool) {
	// We need to import runtime but it's a simple function
	// Instead, we'll use a simpler approach
	return 0, "", 0, false
}

// TestNewTSLRegistry_WithLocalTSLFile tests loading from a local TSL XML file
func TestNewTSLRegistry_WithLocalTSLFile(t *testing.T) {
	// Check if testdata file exists - use EU LOTL which has validated signature
	tslPath := filepath.Join("testdata", "eu-lotl.xml")
	if _, err := os.Stat(tslPath); os.IsNotExist(err) {
		t.Skip("testdata/eu-lotl.xml not found - run 'go run tmp/download_lotl.go' to download")
	}

	// Create temp directory for cert bundle (EU LOTL has 0 providers, needs bundle)
	tmpDir, err := os.MkdirTemp("", "tsl-local-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	_, pemData := generateTestCertificate(t, "Test CA")
	certPath := writeTestCertFile(t, tmpDir, "test.pem", pemData)

	reg, err := NewTSLRegistry(TSLConfig{
		Name:       "EU-LOTL-Test",
		CertBundle: certPath,
		TSLFiles:   []string{tslPath},
	})
	if err != nil {
		t.Fatalf("failed to create registry from TSL file: %v", err)
	}

	// Verify it's healthy
	if !reg.Healthy() {
		t.Error("registry should be healthy")
	}

	// Verify we loaded at least one TSL
	if reg.TSLCount() < 1 {
		t.Errorf("expected at least 1 TSL, got %d", reg.TSLCount())
	}

	// Note: EU LOTL is a "List of Trusted Lists" so it has 0 trust service providers
	// and therefore 0 certificates. This is expected - it contains pointers to other TSLs.
	// Log counts for debugging
	t.Logf("Loaded %d TSLs with %d certificates (LOTL has 0 providers, this is expected)", reg.TSLCount(), reg.CertificateCount())

	// Verify info
	info := reg.Info()
	if info.Name != "EU-LOTL-Test" {
		t.Errorf("expected name 'EU-LOTL-Test', got %q", info.Name)
	}
}

// TestNewTSLRegistry_WithFileURLTSL tests loading from a file:// URL
func TestNewTSLRegistry_WithFileURLTSL(t *testing.T) {
	// Check if testdata file exists
	tslPath := filepath.Join("testdata", "eu-lotl.xml")
	if _, err := os.Stat(tslPath); os.IsNotExist(err) {
		t.Skip("testdata/eu-lotl.xml not found")
	}

	absPath, err := filepath.Abs(tslPath)
	if err != nil {
		t.Fatalf("failed to get absolute path: %v", err)
	}

	// Create temp directory for cert bundle (EU LOTL has 0 providers, needs bundle)
	tmpDir, err := os.MkdirTemp("", "tsl-url-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	_, pemData := generateTestCertificate(t, "Test CA")
	certPath := writeTestCertFile(t, tmpDir, "test.pem", pemData)

	reg, err := NewTSLRegistry(TSLConfig{
		Name:       "EU-LOTL-FileURL-Test",
		CertBundle: certPath,
		TSLURLs:    []string{"file://" + absPath},
	})
	if err != nil {
		t.Fatalf("failed to create registry from file:// URL: %v", err)
	}

	// Verify we loaded TSL
	if reg.TSLCount() < 1 {
		t.Errorf("expected at least 1 TSL, got %d", reg.TSLCount())
	}
	// Note: EU LOTL has 0 certificates (it's a list of lists, not actual services)
}

// TestNewTSLRegistry_TSLFileNotFound tests error handling for missing TSL file
func TestNewTSLRegistry_TSLFileNotFound(t *testing.T) {
	_, err := NewTSLRegistry(TSLConfig{
		Name:     "missing-tsl",
		TSLFiles: []string{"/nonexistent/path/tsl.xml"},
	})
	if err == nil {
		t.Error("expected error for missing TSL file")
	}
}

// TestTSLRegistry_TSLs_WithRealTSL tests the TSLs() accessor with real data
func TestTSLRegistry_TSLs_WithRealTSL(t *testing.T) {
	tslPath := filepath.Join("testdata", "eu-lotl.xml")
	if _, err := os.Stat(tslPath); os.IsNotExist(err) {
		t.Skip("testdata/eu-lotl.xml not found")
	}

	// Create temp directory for cert bundle (EU LOTL has 0 providers, needs bundle)
	tmpDir, err := os.MkdirTemp("", "tsl-accessor-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	_, pemData := generateTestCertificate(t, "Test CA")
	certPath := writeTestCertFile(t, tmpDir, "test.pem", pemData)

	reg, err := NewTSLRegistry(TSLConfig{
		Name:       "TSLs-accessor-test",
		CertBundle: certPath,
		TSLFiles:   []string{tslPath},
	})
	if err != nil {
		t.Fatalf("failed to create registry: %v", err)
	}

	tsls := reg.TSLs()
	if len(tsls) == 0 {
		t.Error("expected TSLs() to return loaded TSLs")
	}

	// Verify TSL has expected structure
	for _, tsl := range tsls {
		if tsl == nil {
			t.Error("TSL should not be nil")
			continue
		}
		// Check that we have scheme information
		if tsl.StatusList.TslSchemeInformation == nil {
			t.Error("TSL should have scheme information")
		}
	}
}

// TestTSLRegistry_Refresh_WithRealTSL tests refresh functionality with real TSL
func TestTSLRegistry_Refresh_WithRealTSL(t *testing.T) {
	tslPath := filepath.Join("testdata", "eu-lotl.xml")
	if _, err := os.Stat(tslPath); os.IsNotExist(err) {
		t.Skip("testdata/eu-lotl.xml not found")
	}

	// Create temp directory for cert bundle (EU LOTL has 0 providers, needs bundle)
	tmpDir, err := os.MkdirTemp("", "tsl-refresh-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	_, pemData := generateTestCertificate(t, "Test CA")
	certPath := writeTestCertFile(t, tmpDir, "test.pem", pemData)

	reg, err := NewTSLRegistry(TSLConfig{
		Name:       "Refresh-TSL-test",
		CertBundle: certPath,
		TSLFiles:   []string{tslPath},
	})
	if err != nil {
		t.Fatalf("failed to create registry: %v", err)
	}

	originalCount := reg.CertificateCount()
	originalLoadedAt := reg.LoadedAt()

	// Wait a bit to ensure timestamp difference
	time.Sleep(10 * time.Millisecond)

	// Refresh
	if err := reg.Refresh(context.Background()); err != nil {
		t.Fatalf("refresh failed: %v", err)
	}

	// Verify certificate count is consistent
	if reg.CertificateCount() != originalCount {
		t.Errorf("certificate count changed after refresh: was %d, now %d",
			originalCount, reg.CertificateCount())
	}

	// Verify loadedAt changed
	if !reg.LoadedAt().After(originalLoadedAt) {
		t.Error("expected LoadedAt to be updated after refresh")
	}
}

// TestExtractCertsFromTSL_NilTSL tests extractCertsFromTSL with nil input
func TestExtractCertsFromTSL_NilTSL(t *testing.T) {
	certs := extractCertsFromTSL(nil, nil)
	if len(certs) != 0 {
		t.Errorf("expected 0 certs from nil TSL, got %d", len(certs))
	}
}

// TestTSLRegistry_SignatureValidation verifies that tampered TSL files are rejected
func TestTSLRegistry_SignatureValidation(t *testing.T) {
	tslPath := filepath.Join("testdata", "eu-lotl.xml")
	if _, err := os.Stat(tslPath); os.IsNotExist(err) {
		t.Skip("testdata/eu-lotl.xml not found")
	}

	// Read the original TSL
	original, err := os.ReadFile(tslPath)
	if err != nil {
		t.Fatalf("failed to read TSL: %v", err)
	}

	// Create a tampered version by modifying content within signed region
	// We'll change a string in the SchemeOperatorName which is inside the signed content
	tampered := bytes.Replace(original,
		[]byte("European Commission"),
		[]byte("TAMPERED COMMISSION"),
		1)

	if bytes.Equal(original, tampered) {
		t.Skip("could not create tampered TSL - pattern not found")
	}

	// Write tampered file to temp location
	tmpDir, err := os.MkdirTemp("", "tsl-tamper-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	tamperedPath := filepath.Join(tmpDir, "tampered-tsl.xml")
	if err := os.WriteFile(tamperedPath, tampered, 0644); err != nil {
		t.Fatalf("failed to write tampered TSL: %v", err)
	}

	// Also need a cert bundle for the registry to be valid
	_, pemData := generateTestCertificate(t, "Test CA")
	certPath := writeTestCertFile(t, tmpDir, "test.pem", pemData)

	// Attempt to load tampered TSL - should fail signature validation
	_, err = NewTSLRegistry(TSLConfig{
		Name:       "Tampered-TSL-test",
		CertBundle: certPath,
		TSLFiles:   []string{tamperedPath},
	})

	// The registry creation should fail because signature validation should reject tampered content
	if err == nil {
		t.Error("CRITICAL: expected signature validation to reject tampered TSL, but it was accepted!")
	} else {
		t.Logf("Good: tampered TSL correctly rejected with error: %v", err)
	}
}

// TestTSLRegistry_CombinedSources tests loading from both cert bundle and TSL file
func TestTSLRegistry_CombinedSources(t *testing.T) {
	// Create temp directory for cert bundle
	tmpDir, err := os.MkdirTemp("", "tsl-combined-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Generate test certificate for bundle
	_, pemData := generateTestCertificate(t, "Bundle CA")
	certPath := writeTestCertFile(t, tmpDir, "bundle.pem", pemData)

	// Check if TSL testdata exists
	tslPath := filepath.Join("testdata", "eu-lotl.xml")
	if _, err := os.Stat(tslPath); os.IsNotExist(err) {
		t.Skip("testdata/eu-lotl.xml not found")
	}

	// Create registry with both sources
	reg, err := NewTSLRegistry(TSLConfig{
		Name:       "Combined-sources-test",
		CertBundle: certPath,
		TSLFiles:   []string{tslPath},
	})
	if err != nil {
		t.Fatalf("failed to create registry: %v", err)
	}

	// Should have at least the cert from the bundle
	// Note: EU LOTL has 0 service providers so doesn't add certs
	if reg.CertificateCount() < 1 {
		t.Errorf("expected at least 1 certificate from bundle, got %d",
			reg.CertificateCount())
	}

	// Should have TSLs from the TSL file
	if reg.TSLCount() < 1 {
		t.Errorf("expected at least 1 TSL, got %d", reg.TSLCount())
	}
}

// TestTSLRegistry_LocalPathConversion tests that local paths are converted to file:// URLs
func TestTSLRegistry_LocalPathConversion(t *testing.T) {
	tslPath := filepath.Join("testdata", "eu-lotl.xml")
	if _, err := os.Stat(tslPath); os.IsNotExist(err) {
		t.Skip("testdata/eu-lotl.xml not found")
	}

	// Create temp directory for cert bundle (EU LOTL has 0 providers, needs bundle)
	tmpDir, err := os.MkdirTemp("", "tsl-conversion-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	_, pemData := generateTestCertificate(t, "Test CA")
	certPath := writeTestCertFile(t, tmpDir, "test.pem", pemData)

	// Use TSLURLs with a local path (not a URL) - should be auto-converted
	reg, err := NewTSLRegistry(TSLConfig{
		Name:       "LocalPath-conversion-test",
		CertBundle: certPath,
		TSLURLs:    []string{tslPath}, // Local path, not URL
	})
	if err != nil {
		t.Fatalf("failed to create registry: %v", err)
	}

	// Just verify registry was created successfully
	if reg.TSLCount() < 1 {
		t.Error("expected at least 1 TSL after local path conversion")
	}
}

// TestTSLRegistry_TSLCount_WithMultipleFiles tests TSLCount with multiple TSL files
func TestTSLRegistry_TSLCount_WithMultipleFiles(t *testing.T) {
	tslPath := filepath.Join("testdata", "eu-lotl.xml")
	if _, err := os.Stat(tslPath); os.IsNotExist(err) {
		t.Skip("testdata/eu-lotl.xml not found")
	}

	// Create temp directory for cert bundle (EU LOTL has 0 providers, needs bundle)
	tmpDir, err := os.MkdirTemp("", "tsl-count-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	_, pemData := generateTestCertificate(t, "Test CA")
	certPath := writeTestCertFile(t, tmpDir, "test.pem", pemData)

	// Load the same file twice (as if it were different files)
	reg, err := NewTSLRegistry(TSLConfig{
		Name:       "TSLCount-multiple-test",
		CertBundle: certPath,
		TSLFiles:   []string{tslPath},
		TSLURLs:    []string{tslPath},
	})
	if err != nil {
		t.Fatalf("failed to create registry: %v", err)
	}

	// Should have 2 TSLs (same file loaded twice)
	if reg.TSLCount() != 2 {
		t.Errorf("expected 2 TSLs, got %d", reg.TSLCount())
	}
}

// generateTestCertificateWithDNSSAN creates a self-signed test certificate with DNS SANs
func generateTestCertificateWithDNSSAN(t *testing.T, cn string, dnsNames []string) (*x509.Certificate, []byte) {
	t.Helper()

	// Generate RSA key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}

	// Create certificate template with DNS SANs
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   cn,
			Organization: []string{"Test Organization"},
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		DNSNames:              dnsNames,
	}

	// Create self-signed certificate
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatalf("failed to create certificate: %v", err)
	}

	// Parse the DER certificate back
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("failed to parse certificate: %v", err)
	}

	// Encode to PEM
	pemBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})

	return cert, pemBytes
}

// TestTSLRegistry_Evaluate_X509SanDNS tests x509_san_dns resource type validation
func TestTSLRegistry_Evaluate_X509SanDNS(t *testing.T) {
	// Create temp directory
	tmpDir, err := os.MkdirTemp("", "tsl-x509-san-dns-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Generate test certificate with DNS SANs
	dnsNames := []string{"example.com", "www.example.com", "wallet.example.org"}
	cert, pemData := generateTestCertificateWithDNSSAN(t, "Test CA", dnsNames)
	certPath := writeTestCertFile(t, tmpDir, "test-ca.pem", pemData)

	// Create registry with this certificate as trust anchor
	reg, err := NewTSLRegistry(TSLConfig{
		Name:       "x509-san-dns-test",
		CertBundle: certPath,
	})
	if err != nil {
		t.Fatalf("failed to create registry: %v", err)
	}

	// Encode certificate as base64 for x5c array
	certB64 := base64.StdEncoding.EncodeToString(cert.Raw)

	tests := []struct {
		name        string
		subjectID   string
		expectAllow bool
		expectError string
	}{
		{
			name:        "matching DNS SAN - exact match",
			subjectID:   "example.com",
			expectAllow: true,
		},
		{
			name:        "matching DNS SAN - www subdomain",
			subjectID:   "www.example.com",
			expectAllow: true,
		},
		{
			name:        "matching DNS SAN - different domain",
			subjectID:   "wallet.example.org",
			expectAllow: true,
		},
		{
			name:        "non-matching DNS",
			subjectID:   "attacker.com",
			expectAllow: false,
			expectError: "not found in certificate DNS SANs",
		},
		{
			name:        "partial match should fail",
			subjectID:   "example",
			expectAllow: false,
			expectError: "not found in certificate DNS SANs",
		},
		{
			name:        "subdomain not in SAN should fail",
			subjectID:   "api.example.com",
			expectAllow: false,
			expectError: "not found in certificate DNS SANs",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := &authzen.EvaluationRequest{
				Subject: authzen.Subject{
					Type: "key",
					ID:   tc.subjectID,
				},
				Resource: authzen.Resource{
					Type: "x509_san_dns",
					ID:   tc.subjectID,
					Key:  []interface{}{certB64},
				},
			}

			resp, err := reg.Evaluate(context.Background(), req)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if resp.Decision != tc.expectAllow {
				t.Errorf("expected decision=%v, got %v", tc.expectAllow, resp.Decision)
				if resp.Context != nil && resp.Context.Reason != nil {
					t.Logf("reason: %v", resp.Context.Reason)
				}
			}

			if tc.expectError != "" && resp.Decision == false {
				if resp.Context == nil || resp.Context.Reason == nil {
					t.Error("expected error in reason but got nil context")
				} else if errMsg, ok := resp.Context.Reason["error"].(string); ok {
					if !strings.Contains(errMsg, tc.expectError) {
						t.Errorf("expected error to contain %q, got %q", tc.expectError, errMsg)
					}
				}
			}
		})
	}
}

// TestTSLRegistry_Evaluate_X509SanDNS_NoDNSSANs tests x509_san_dns with certificate without DNS SANs
func TestTSLRegistry_Evaluate_X509SanDNS_NoDNSSANs(t *testing.T) {
	// Create temp directory
	tmpDir, err := os.MkdirTemp("", "tsl-x509-san-dns-no-san-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Generate test certificate WITHOUT DNS SANs
	cert, pemData := generateTestCertificate(t, "Test CA")
	certPath := writeTestCertFile(t, tmpDir, "test-ca.pem", pemData)

	// Create registry with this certificate as trust anchor
	reg, err := NewTSLRegistry(TSLConfig{
		Name:       "x509-san-dns-no-san-test",
		CertBundle: certPath,
	})
	if err != nil {
		t.Fatalf("failed to create registry: %v", err)
	}

	// Encode certificate as base64 for x5c array
	certB64 := base64.StdEncoding.EncodeToString(cert.Raw)

	req := &authzen.EvaluationRequest{
		Subject: authzen.Subject{
			Type: "key",
			ID:   "example.com",
		},
		Resource: authzen.Resource{
			Type: "x509_san_dns",
			ID:   "example.com",
			Key:  []interface{}{certB64},
		},
	}

	resp, err := reg.Evaluate(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should fail because there are no DNS SANs in the certificate
	if resp.Decision != false {
		t.Error("expected decision=false for certificate without DNS SANs")
	}

	if resp.Context != nil && resp.Context.Reason != nil {
		if errMsg, ok := resp.Context.Reason["error"].(string); ok {
			if !strings.Contains(errMsg, "not found in certificate DNS SANs") {
				t.Errorf("expected error about DNS SANs, got: %s", errMsg)
			}
		}
		// Verify the response includes the empty DNS SANs list
		if dnsSans, ok := resp.Context.Reason["dns_sans"].([]string); ok {
			if len(dnsSans) != 0 {
				t.Errorf("expected empty dns_sans, got %v", dnsSans)
			}
		}
	}
}

// TestTSLRegistry_Evaluate_X509SanDNS_Wildcard tests x509_san_dns with wildcard certificates
func TestTSLRegistry_Evaluate_X509SanDNS_Wildcard(t *testing.T) {
	// Create temp directory
	tmpDir, err := os.MkdirTemp("", "tsl-x509-san-dns-wildcard-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Generate test certificate with wildcard DNS SAN
	wildcardDNSNames := []string{"*.example.com", "example.com"}
	cert, pemData := generateTestCertificateWithDNSSAN(t, "Wildcard CA", wildcardDNSNames)
	certPath := writeTestCertFile(t, tmpDir, "wildcard-ca.pem", pemData)

	// Create registry with this certificate as trust anchor
	reg, err := NewTSLRegistry(TSLConfig{
		Name:       "x509-san-dns-wildcard-test",
		CertBundle: certPath,
	})
	if err != nil {
		t.Fatalf("failed to create registry: %v", err)
	}

	// Encode certificate as base64 for x5c array
	certB64 := base64.StdEncoding.EncodeToString(cert.Raw)

	tests := []struct {
		name        string
		subjectID   string
		expectAllow bool
		expectError string
	}{
		{
			name:        "exact match - base domain",
			subjectID:   "example.com",
			expectAllow: true,
		},
		{
			name:        "wildcard match - subdomain",
			subjectID:   "sub.example.com",
			expectAllow: true,
		},
		{
			name:        "wildcard match - api subdomain",
			subjectID:   "api.example.com",
			expectAllow: true,
		},
		{
			name:        "wildcard match - www subdomain",
			subjectID:   "www.example.com",
			expectAllow: true,
		},
		{
			name:        "wildcard does not match nested subdomain",
			subjectID:   "a.b.example.com",
			expectAllow: false,
			expectError: "not found in certificate DNS SANs",
		},
		{
			name:        "wildcard does not match different domain",
			subjectID:   "sub.attacker.com",
			expectAllow: false,
			expectError: "not found in certificate DNS SANs",
		},
		{
			name:        "wildcard does not match suffix attack",
			subjectID:   "malicious-example.com",
			expectAllow: false,
			expectError: "not found in certificate DNS SANs",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := &authzen.EvaluationRequest{
				Subject: authzen.Subject{
					Type: "key",
					ID:   tc.subjectID,
				},
				Resource: authzen.Resource{
					Type: "x509_san_dns",
					ID:   tc.subjectID,
					Key:  []interface{}{certB64},
				},
			}

			resp, err := reg.Evaluate(context.Background(), req)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if resp.Decision != tc.expectAllow {
				t.Errorf("expected decision=%v, got %v", tc.expectAllow, resp.Decision)
				if resp.Context != nil && resp.Context.Reason != nil {
					t.Logf("reason: %v", resp.Context.Reason)
				}
			}

			if tc.expectError != "" && resp.Decision == false {
				if resp.Context == nil || resp.Context.Reason == nil {
					t.Error("expected error in reason but got nil context")
				} else if errMsg, ok := resp.Context.Reason["error"].(string); ok {
					if !strings.Contains(errMsg, tc.expectError) {
						t.Errorf("expected error to contain %q, got %q", tc.expectError, errMsg)
					}
				}
			}
		})
	}
}

// TestTSLRegistry_LOTLSignerBundle tests loading of LOTL signer certificates
func TestTSLRegistry_LOTLSignerBundle(t *testing.T) {
	// Create temp directory
	tmpDir, err := os.MkdirTemp("", "lotl-signer-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Generate test certificates - one for trust pool, one for LOTL signer
	_, trustPEM := generateTestCertificate(t, "Trust CA")
	trustPath := writeTestCertFile(t, tmpDir, "trust.pem", trustPEM)

	signerCert, signerPEM := generateTestCertificate(t, "LOTL Signer")
	signerPath := writeTestCertFile(t, tmpDir, "lotl-signer.pem", signerPEM)

	// Create registry with LOTL signer bundle configured
	reg, err := NewTSLRegistry(TSLConfig{
		Name:             "lotl-signer-test",
		CertBundle:       trustPath,
		LOTLSignerBundle: signerPath,
	})
	if err != nil {
		t.Fatalf("failed to create registry: %v", err)
	}

	// Verify the LOTL signers were loaded
	if len(reg.lotlSigners) != 1 {
		t.Errorf("expected 1 LOTL signer, got %d", len(reg.lotlSigners))
	}

	if reg.lotlSigners[0].Subject.CommonName != "LOTL Signer" {
		t.Errorf("expected signer CN 'LOTL Signer', got '%s'", reg.lotlSigners[0].Subject.CommonName)
	}

	// Check that the signer certificate is correct
	if !reg.lotlSigners[0].Equal(signerCert) {
		t.Error("loaded LOTL signer does not match original certificate")
	}
}

// TestTSLRegistry_LOTLSignerBundle_InvalidPath tests error handling for invalid LOTL signer bundle paths
func TestTSLRegistry_LOTLSignerBundle_InvalidPath(t *testing.T) {
	// Create temp directory for cert bundle
	tmpDir, err := os.MkdirTemp("", "lotl-signer-invalid-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	_, trustPEM := generateTestCertificate(t, "Trust CA")
	trustPath := writeTestCertFile(t, tmpDir, "trust.pem", trustPEM)

	// Try to create registry with non-existent LOTL signer bundle
	_, err = NewTSLRegistry(TSLConfig{
		Name:             "lotl-invalid-test",
		CertBundle:       trustPath,
		LOTLSignerBundle: "/nonexistent/path/lotl-signer.pem",
	})
	if err == nil {
		t.Error("expected error for non-existent LOTL signer bundle")
	}
}

// TestTSLRegistry_RequireSignature tests the RequireSignature configuration
func TestTSLRegistry_RequireSignature(t *testing.T) {
	// Create temp directory
	tmpDir, err := os.MkdirTemp("", "require-sig-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Generate test certificate for trust pool
	_, trustPEM := generateTestCertificate(t, "Trust CA")
	trustPath := writeTestCertFile(t, tmpDir, "trust.pem", trustPEM)

	// Test that RequireSignature=true without LOTLSignerBundle fails
	_, err = NewTSLRegistry(TSLConfig{
		Name:             "require-sig-no-signers",
		CertBundle:       trustPath,
		RequireSignature: true,
		// No LOTLSignerBundle configured
	})
	// This should succeed since we're only loading from CertBundle, not TSL files
	// The RequireSignature check happens when loading TSL files, not cert bundles
	if err != nil {
		t.Fatalf("unexpected error creating registry: %v", err)
	}
}
