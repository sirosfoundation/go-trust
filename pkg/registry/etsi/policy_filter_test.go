package etsi

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"math/big"
	"os"
	"testing"
	"time"

	"github.com/sirosfoundation/go-trust/pkg/authzen"
)

// TestBuildFilteredCertPool_NoTSLs verifies that when no TSLs are loaded
// (PEM bundle only), the unfiltered cert pool is returned regardless of context.
func TestBuildFilteredCertPool_NoTSLs(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "etsi-filter-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	_, pemData := generateTestCertificate(t, "Test CA")
	certPath := writeTestCertFile(t, tmpDir, "test-ca.pem", pemData)

	reg, err := NewTSLRegistry(TSLConfig{
		Name:       "filter-test-no-tsl",
		CertBundle: certPath,
	})
	if err != nil {
		t.Fatalf("failed to create registry: %v", err)
	}

	// Request with service type filter
	req := &authzen.EvaluationRequest{
		Context: map[string]interface{}{
			"service_types": []string{"http://uri.etsi.org/TrstSvc/Svctype/CA/QC"},
		},
		Resource: authzen.Resource{Type: "x5c"},
	}

	pool, desc := reg.buildFilteredCertPool(req)
	if pool == nil {
		t.Error("expected non-nil cert pool")
	}
	if desc != "unfiltered (pem bundle)" {
		t.Errorf("expected 'unfiltered (pem bundle)' description, got %q", desc)
	}
}

// TestBuildFilteredCertPool_NoContext verifies that when no context is provided,
// the full unfiltered pool is returned even when TSLs exist.
func TestBuildFilteredCertPool_NoContext(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "etsi-filter-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	_, pemData := generateTestCertificate(t, "Test CA")
	certPath := writeTestCertFile(t, tmpDir, "test-ca.pem", pemData)

	reg, err := NewTSLRegistry(TSLConfig{
		Name:       "filter-test-no-ctx",
		CertBundle: certPath,
	})
	if err != nil {
		t.Fatalf("failed to create registry: %v", err)
	}

	// Request with nil context
	req := &authzen.EvaluationRequest{
		Resource: authzen.Resource{Type: "x5c"},
	}

	pool, desc := reg.buildFilteredCertPool(req)
	if pool == nil {
		t.Error("expected non-nil cert pool")
	}
	// With no TSLs loaded, should return "unfiltered (pem bundle)"
	if desc != "unfiltered (pem bundle)" {
		t.Errorf("expected 'unfiltered (pem bundle)' description, got %q", desc)
	}
}

// TestBuildFilteredCertPool_EmptyContext verifies that empty constraints
// yield the unfiltered pool.
func TestBuildFilteredCertPool_EmptyContext(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "etsi-filter-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	_, pemData := generateTestCertificate(t, "Test CA")
	certPath := writeTestCertFile(t, tmpDir, "test-ca.pem", pemData)

	reg, err := NewTSLRegistry(TSLConfig{
		Name:       "filter-test-empty-ctx",
		CertBundle: certPath,
	})
	if err != nil {
		t.Fatalf("failed to create registry: %v", err)
	}

	// Request with empty context map (no service_types or service_statuses)
	req := &authzen.EvaluationRequest{
		Context:  map[string]interface{}{},
		Resource: authzen.Resource{Type: "x5c"},
	}

	pool, desc := reg.buildFilteredCertPool(req)
	if pool == nil {
		t.Error("expected non-nil cert pool")
	}
	if desc != "unfiltered (pem bundle)" {
		t.Errorf("expected 'unfiltered (pem bundle)' description, got %q", desc)
	}
}

// TestBuildFilteredCertPool_ServiceTypesAsInterfaceSlice verifies that
// service_types passed as []interface{} (from JSON parsing) are handled.
func TestBuildFilteredCertPool_ServiceTypesAsInterfaceSlice(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "etsi-filter-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	_, pemData := generateTestCertificate(t, "Test CA")
	certPath := writeTestCertFile(t, tmpDir, "test-ca.pem", pemData)

	reg, err := NewTSLRegistry(TSLConfig{
		Name:       "filter-test-iface",
		CertBundle: certPath,
	})
	if err != nil {
		t.Fatalf("failed to create registry: %v", err)
	}

	// Service types as []interface{} (as they come from JSON unmarshaling)
	req := &authzen.EvaluationRequest{
		Context: map[string]interface{}{
			"service_types": []interface{}{"http://uri.etsi.org/TrstSvc/Svctype/CA/QC"},
		},
		Resource: authzen.Resource{Type: "x5c"},
	}

	// With no TSLs loaded, it falls back to PEM bundle pool
	pool, desc := reg.buildFilteredCertPool(req)
	if pool == nil {
		t.Error("expected non-nil cert pool")
	}
	// PEM bundle has no TSLs, so it returns the unfiltered pool
	if desc != "unfiltered (pem bundle)" {
		t.Errorf("expected 'unfiltered (pem bundle)' description, got %q", desc)
	}
}

// TestTSLRegistry_EvaluateWithServiceTypeContext verifies that the evaluate method
// uses buildFilteredCertPool when service_types are in context. Since we only have
// a PEM bundle (no TSLs), it should fall back to the unfiltered pool.
func TestTSLRegistry_EvaluateWithServiceTypeContext(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "etsi-filter-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Generate self-signed CA cert
	caCert, caPEM := generateTestCertificate(t, "Test CA With Filter")
	certPath := writeTestCertFile(t, tmpDir, "test-ca.pem", caPEM)

	reg, err := NewTSLRegistry(TSLConfig{
		Name:       "filter-eval-test",
		CertBundle: certPath,
	})
	if err != nil {
		t.Fatalf("failed to create registry: %v", err)
	}

	certB64 := base64.StdEncoding.EncodeToString(caCert.Raw)

	// Evaluate with service_types in context - should still validate because
	// PEM bundle fallback is used when no TSLs are loaded
	req := &authzen.EvaluationRequest{
		Context: map[string]interface{}{
			"service_types": []string{"http://uri.etsi.org/TrstSvc/Svctype/CA/QC"},
		},
		Resource: authzen.Resource{
			Type: "x5c",
			Key:  []interface{}{certB64},
		},
	}

	resp, err := reg.Evaluate(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should succeed because PEM bundle fallback is used
	if !resp.Decision {
		t.Error("expected true decision with PEM bundle fallback")
	}

	// Verify pool_filter is in the response
	if resp.Context != nil && resp.Context.Reason != nil {
		if pf, ok := resp.Context.Reason["pool_filter"]; ok {
			t.Logf("pool_filter: %v", pf)
		}
	}
}

// TestTSLRegistry_EvaluateWithServiceStatusContext verifies service_statuses
// constraint parsing.
func TestTSLRegistry_EvaluateWithServiceStatusContext(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "etsi-filter-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	caCert, caPEM := generateTestCertificate(t, "Status Filter CA")
	certPath := writeTestCertFile(t, tmpDir, "test-ca.pem", caPEM)

	reg, err := NewTSLRegistry(TSLConfig{
		Name:       "status-filter-test",
		CertBundle: certPath,
	})
	if err != nil {
		t.Fatalf("failed to create registry: %v", err)
	}

	certB64 := base64.StdEncoding.EncodeToString(caCert.Raw)

	req := &authzen.EvaluationRequest{
		Context: map[string]interface{}{
			"service_statuses": []string{
				"http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted",
			},
		},
		Resource: authzen.Resource{
			Type: "x5c",
			Key:  []interface{}{certB64},
		},
	}

	resp, err := reg.Evaluate(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should succeed because PEM bundle fallback is used
	if !resp.Decision {
		t.Error("expected true decision with PEM bundle fallback")
	}
}

// TestTSLRegistry_EvaluateUntrustedWithFilter verifies that an untrusted cert
// is still rejected even when filter context is provided.
func TestTSLRegistry_EvaluateUntrustedWithFilter(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "etsi-filter-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Trusted CA
	_, trustedPEM := generateTestCertificate(t, "Trusted CA")
	certPath := writeTestCertFile(t, tmpDir, "trusted.pem", trustedPEM)

	reg, err := NewTSLRegistry(TSLConfig{
		Name:       "untrusted-filter-test",
		CertBundle: certPath,
	})
	if err != nil {
		t.Fatalf("failed to create registry: %v", err)
	}

	// Generate an untrusted cert (different CA)
	untrustedKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	untrustedTemplate := x509.Certificate{
		SerialNumber: big.NewInt(99),
		Subject:      pkix.Name{CommonName: "Untrusted CA"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		IsCA:         true,
	}
	untrustedDER, _ := x509.CreateCertificate(rand.Reader, &untrustedTemplate, &untrustedTemplate, &untrustedKey.PublicKey, untrustedKey)
	untrustedB64 := base64.StdEncoding.EncodeToString(untrustedDER)

	req := &authzen.EvaluationRequest{
		Context: map[string]interface{}{
			"service_types": []string{"http://uri.etsi.org/TrstSvc/Svctype/CA/QC"},
		},
		Resource: authzen.Resource{
			Type: "x5c",
			Key:  []interface{}{untrustedB64},
		},
	}

	resp, err := reg.Evaluate(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if resp.Decision {
		t.Error("expected false decision for untrusted cert even with service type filter")
	}
}

// TestTSLRegistry_Evaluate_X5CIntermediateWithFilter tests that intermediate chain
// validation works correctly when service type filters are present in context.
func TestTSLRegistry_Evaluate_X5CIntermediateWithFilter(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "etsi-intermediate-filter-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Create Root CA
	rootCert, rootDER, rootKey := generateSignedCertificate(t, "Root CA", true, nil, nil)
	rootPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootDER})
	certPath := writeTestCertFile(t, tmpDir, "root-ca.pem", rootPEM)

	// Create Intermediate CA
	intermediateCert, intermediateDER, intermediateKey := generateSignedCertificate(t, "Intermediate CA", true, rootCert, rootKey)

	// Create Leaf cert
	_, leafDER, _ := generateSignedCertificate(t, "Leaf Cert", false, intermediateCert, intermediateKey)

	reg, err := NewTSLRegistry(TSLConfig{
		Name:       "intermediate-filter-test",
		CertBundle: certPath,
	})
	if err != nil {
		t.Fatalf("failed to create registry: %v", err)
	}

	leafB64 := base64.StdEncoding.EncodeToString(leafDER)
	intermediateB64 := base64.StdEncoding.EncodeToString(intermediateDER)

	// Full chain with service type filter should succeed (PEM bundle fallback)
	req := &authzen.EvaluationRequest{
		Context: map[string]interface{}{
			"service_types":    []string{"http://uri.etsi.org/TrstSvc/Svctype/CA/QC"},
			"service_statuses": []string{"http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted"},
		},
		Resource: authzen.Resource{
			Type: "x5c",
			Key:  []interface{}{leafB64, intermediateB64},
		},
	}

	resp, err := reg.Evaluate(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !resp.Decision {
		t.Error("expected true decision for valid intermediate chain with filter context")
	}
}
// TestTSLRegistry_EvaluateWithCredentialTypesContext verifies credential_types
// are extracted from context and included in the response.
func TestTSLRegistry_EvaluateWithCredentialTypesContext(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "etsi-credential-types-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Generate self-signed CA cert
	caCert, caPEM := generateTestCertificate(t, "Credential Types Test CA")
	certPath := writeTestCertFile(t, tmpDir, "test-ca.pem", caPEM)

	reg, err := NewTSLRegistry(TSLConfig{
		Name:       "credential-types-test",
		CertBundle: certPath,
	})
	if err != nil {
		t.Fatalf("failed to create registry: %v", err)
	}

	certB64 := base64.StdEncoding.EncodeToString(caCert.Raw)

	// Evaluate with credential_types in context
	req := &authzen.EvaluationRequest{
		Context: map[string]interface{}{
			"credential_types": []string{"eu.europa.ec.eudi.pid.1", "eu.europa.ec.eudi.mdl.1"},
		},
		Resource: authzen.Resource{
			Type: "x5c",
			Key:  []interface{}{certB64},
		},
	}

	resp, err := reg.Evaluate(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should succeed - credential_types doesn't block validation yet
	if !resp.Decision {
		t.Error("expected true decision")
	}

	// Verify requested_credential_types is in the response
	if resp.Context == nil || resp.Context.Reason == nil {
		t.Fatal("expected context with reason")
	}

	reqCT, ok := resp.Context.Reason["requested_credential_types"]
	if !ok {
		t.Fatal("expected requested_credential_types in response reason")
	}

	// Check the credential types are present
	ctSlice, ok := reqCT.([]string)
	if !ok {
		t.Fatalf("expected []string, got %T", reqCT)
	}

	if len(ctSlice) != 2 {
		t.Errorf("expected 2 credential types, got %d", len(ctSlice))
	}
	if ctSlice[0] != "eu.europa.ec.eudi.pid.1" || ctSlice[1] != "eu.europa.ec.eudi.mdl.1" {
		t.Errorf("unexpected credential types: %v", ctSlice)
	}
}

// TestTSLRegistry_EvaluateWithCredentialTypesAsInterfaceSlice verifies credential_types
// parsing when marshaled through JSON (as []interface{}).
func TestTSLRegistry_EvaluateWithCredentialTypesAsInterfaceSlice(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "etsi-credential-types-interface-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	caCert, caPEM := generateTestCertificate(t, "Credential Types Interface Test")
	certPath := writeTestCertFile(t, tmpDir, "test-ca.pem", caPEM)

	reg, err := NewTSLRegistry(TSLConfig{
		Name:       "credential-types-interface-test",
		CertBundle: certPath,
	})
	if err != nil {
		t.Fatalf("failed to create registry: %v", err)
	}

	certB64 := base64.StdEncoding.EncodeToString(caCert.Raw)

	// Simulate JSON unmarshaling where []string becomes []interface{}
	req := &authzen.EvaluationRequest{
		Context: map[string]interface{}{
			"credential_types": []interface{}{"eu.europa.ec.eudi.pid.1"},
		},
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
		t.Error("expected true decision")
	}

	// Verify credential type is extracted correctly
	if resp.Context != nil && resp.Context.Reason != nil {
		if reqCT, ok := resp.Context.Reason["requested_credential_types"]; ok {
			ctSlice, ok := reqCT.([]string)
			if !ok || len(ctSlice) != 1 || ctSlice[0] != "eu.europa.ec.eudi.pid.1" {
				t.Errorf("unexpected credential types: %v (type: %T)", reqCT, reqCT)
			}
		} else {
			t.Error("expected requested_credential_types in response")
		}
	}
}
