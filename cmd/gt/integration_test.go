//go:build integration

// Package main provides integration tests for the go-trust (gt) server.
//
// Run with: go test -tags=integration -v ./cmd/gt/...
package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/sirosfoundation/g119612/pkg/logging"
	"github.com/sirosfoundation/go-trust/pkg/api"
	"github.com/sirosfoundation/go-trust/pkg/authzen"
	"github.com/sirosfoundation/go-trust/pkg/registry"
	"github.com/sirosfoundation/go-trust/pkg/registry/etsi"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testServer holds resources for an integration test server
type testServer struct {
	server     *http.Server
	baseURL    string
	client     *http.Client
	certBundle string
	trustedCAs []*x509.Certificate
	cleanup    func()
}

type testServerConfig struct {
	host           string
	certBundle     string
	generateCerts  bool
	mockRegistry   registry.TrustRegistry
	logLevel       logging.LogLevel
	triggerRefresh bool
}

func withCertBundle(path string) func(*testServerConfig) {
	return func(c *testServerConfig) { c.certBundle = path }
}

func withGeneratedCerts() func(*testServerConfig) {
	return func(c *testServerConfig) { c.generateCerts = true }
}

func withMockRegistry(r registry.TrustRegistry) func(*testServerConfig) {
	return func(c *testServerConfig) { c.mockRegistry = r }
}

func withLogLevel(level logging.LogLevel) func(*testServerConfig) {
	return func(c *testServerConfig) { c.logLevel = level }
}

func withRefresh() func(*testServerConfig) {
	return func(c *testServerConfig) { c.triggerRefresh = true }
}

// startTestServer creates and starts a test server with the given configuration
func startTestServer(t *testing.T, opts ...func(*testServerConfig)) *testServer {
	t.Helper()

	cfg := &testServerConfig{
		host:     "127.0.0.1",
		logLevel: logging.ErrorLevel,
	}
	for _, opt := range opts {
		opt(cfg)
	}

	// Find an available port
	listener, err := net.Listen("tcp", cfg.host+":0")
	require.NoError(t, err)
	port := listener.Addr().(*net.TCPAddr).Port
	listener.Close()

	// Set up test certificates if needed
	var certBundle string
	var trustedCAs []*x509.Certificate
	var cleanupFn func()

	if cfg.certBundle != "" {
		certBundle = cfg.certBundle
	} else if cfg.generateCerts {
		// Generate test CA and certificates
		tmpDir, err := os.MkdirTemp("", "gt-integration-test-*")
		require.NoError(t, err)

		certBundle = filepath.Join(tmpDir, "trusted-certs.pem")
		ca, caKey, err := generateTestCA()
		require.NoError(t, err)
		trustedCAs = append(trustedCAs, ca)

		// Also generate a leaf certificate signed by the CA for testing
		_, _ = caKey, ca // We'll use these if we need to generate leaf certs

		err = writeCertBundle(certBundle, trustedCAs)
		require.NoError(t, err)

		cleanupFn = func() { os.RemoveAll(tmpDir) }
	}

	// Configure and start server
	gin.SetMode(gin.TestMode)
	router := gin.New()

	logger := logging.NewLogger(cfg.logLevel)
	serverCtx := api.NewServerContext(logger)

	// Initialize registry manager
	registryMgr := registry.NewRegistryManager(registry.FirstMatch, 10*time.Second)

	if certBundle != "" {
		tslConfig := etsi.TSLConfig{
			Name:        "test-etsi",
			Description: "Test ETSI Registry",
			CertBundle:  certBundle,
		}
		tslRegistry, err := etsi.NewTSLRegistry(tslConfig)
		require.NoError(t, err)
		registryMgr.Register(tslRegistry)
	}

	// Add mock registry if configured
	if cfg.mockRegistry != nil {
		registryMgr.Register(cfg.mockRegistry)
	}

	serverCtx.RegistryManager = registryMgr
	serverCtx.BaseURL = fmt.Sprintf("http://%s:%d", cfg.host, port)

	// Trigger refresh if requested (simulates what happens after StartRefreshLoop runs)
	if cfg.triggerRefresh {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		err := registryMgr.Refresh(ctx)
		if err != nil {
			t.Logf("Registry refresh warning: %v", err)
		}
		serverCtx.Lock()
		serverCtx.LastProcessed = time.Now()
		serverCtx.Unlock()
	}

	// Initialize metrics
	metrics := api.NewMetrics()
	serverCtx.Metrics = metrics

	// Register all API routes (health, metrics, evaluation, etc.)
	api.RegisterHealthEndpoints(router, serverCtx)
	api.RegisterMetricsEndpoint(router, metrics)
	api.RegisterAPIRoutes(router, serverCtx)

	server := &http.Server{
		Addr:    fmt.Sprintf("%s:%d", cfg.host, port),
		Handler: router,
	}

	// Start server in background
	go func() {
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			t.Logf("Server error: %v", err)
		}
	}()

	// Wait for server to be ready
	baseURL := fmt.Sprintf("http://%s:%d", cfg.host, port)
	waitForServer(t, baseURL, 5*time.Second)

	ts := &testServer{
		server:     server,
		baseURL:    baseURL,
		client:     &http.Client{Timeout: 10 * time.Second},
		certBundle: certBundle,
		trustedCAs: trustedCAs,
		cleanup:    cleanupFn,
	}

	return ts
}

// Close shuts down the test server and cleans up resources
func (ts *testServer) Close(t *testing.T) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := ts.server.Shutdown(ctx); err != nil {
		t.Logf("Server shutdown error: %v", err)
	}
	if ts.cleanup != nil {
		ts.cleanup()
	}
}

// waitForServer polls the health endpoint until the server is ready
func waitForServer(t *testing.T, baseURL string, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		resp, err := http.Get(baseURL + "/healthz")
		if err == nil && resp.StatusCode == http.StatusOK {
			resp.Body.Close()
			return
		}
		if resp != nil {
			resp.Body.Close()
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("Server did not become ready within %v", timeout)
}

// generateTestCA creates a self-signed CA certificate for testing
func generateTestCA() (*x509.Certificate, *rsa.PrivateKey, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, err
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Test CA"},
			CommonName:   "Test CA",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return nil, nil, err
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, nil, err
	}

	return cert, privateKey, nil
}

// writeCertBundle writes certificates to a PEM file
func writeCertBundle(path string, certs []*x509.Certificate) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	for _, cert := range certs {
		if _, err := f.Write([]byte("-----BEGIN CERTIFICATE-----\n")); err != nil {
			return err
		}
		encoded := base64.StdEncoding.EncodeToString(cert.Raw)
		for i := 0; i < len(encoded); i += 64 {
			end := i + 64
			if end > len(encoded) {
				end = len(encoded)
			}
			if _, err := f.Write([]byte(encoded[i:end] + "\n")); err != nil {
				return err
			}
		}
		if _, err := f.Write([]byte("-----END CERTIFICATE-----\n")); err != nil {
			return err
		}
	}
	return nil
}

// =============================================================================
// Mock Registry for Testing
// =============================================================================

type acceptAllRegistry struct{}

func (r *acceptAllRegistry) Evaluate(ctx context.Context, req *authzen.EvaluationRequest) (*authzen.EvaluationResponse, error) {
	return &authzen.EvaluationResponse{
		Decision: true,
		Context: &authzen.EvaluationResponseContext{
			Reason: map[string]interface{}{
				"registry": "accept-all-mock",
				"message":  "Mock registry accepts all requests",
			},
		},
	}, nil
}

func (r *acceptAllRegistry) SupportedResourceTypes() []string {
	return []string{"x5c", "jwk"}
}

func (r *acceptAllRegistry) SupportsResolutionOnly() bool {
	return false
}

func (r *acceptAllRegistry) Info() registry.RegistryInfo {
	return registry.RegistryInfo{
		Name:        "accept-all-mock",
		Type:        "mock",
		Description: "Mock registry that accepts all requests",
	}
}

func (r *acceptAllRegistry) Healthy() bool {
	return true
}

func (r *acceptAllRegistry) Refresh(ctx context.Context) error {
	return nil
}

// =============================================================================
// Integration Tests
// =============================================================================

func TestIntegration_HealthEndpoint(t *testing.T) {
	ts := startTestServer(t)
	defer ts.Close(t)

	resp, err := ts.client.Get(ts.baseURL + "/healthz")
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	var result map[string]interface{}
	err = json.Unmarshal(body, &result)
	require.NoError(t, err)

	assert.Equal(t, "ok", result["status"])
}

func TestIntegration_ReadinessEndpoint(t *testing.T) {
	ts := startTestServer(t, withGeneratedCerts(), withRefresh())
	defer ts.Close(t)

	resp, err := ts.client.Get(ts.baseURL + "/readyz")
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	var result map[string]interface{}
	err = json.Unmarshal(body, &result)
	require.NoError(t, err)

	assert.Equal(t, "ready", result["status"])
}

func TestIntegration_ReadinessEndpoint_NotReady(t *testing.T) {
	// Test that a server without refresh reports not ready
	ts := startTestServer(t, withGeneratedCerts())
	defer ts.Close(t)

	resp, err := ts.client.Get(ts.baseURL + "/readyz")
	require.NoError(t, err)
	defer resp.Body.Close()

	// Should be 503 because registries haven't been refreshed
	assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	var result map[string]interface{}
	err = json.Unmarshal(body, &result)
	require.NoError(t, err)

	assert.Equal(t, "not_ready", result["status"])
}

func TestIntegration_ReadinessVerbose(t *testing.T) {
	ts := startTestServer(t, withGeneratedCerts(), withRefresh())
	defer ts.Close(t)

	resp, err := ts.client.Get(ts.baseURL + "/readyz?verbose=true")
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	var result map[string]interface{}
	err = json.Unmarshal(body, &result)
	require.NoError(t, err)

	assert.Equal(t, "ready", result["status"])
	// Verbose mode includes TSL registry information
	assert.Contains(t, result, "tsls")
	tsls, ok := result["tsls"].([]interface{})
	assert.True(t, ok, "tsls should be an array")
	assert.GreaterOrEqual(t, len(tsls), 1, "Should have at least one registry")
}

func TestIntegration_AuthZENDiscovery(t *testing.T) {
	ts := startTestServer(t)
	defer ts.Close(t)

	resp, err := ts.client.Get(ts.baseURL + "/.well-known/authzen-configuration")
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Contains(t, resp.Header.Get("Content-Type"), "application/json")

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	var discovery map[string]interface{}
	err = json.Unmarshal(body, &discovery)
	require.NoError(t, err)

	// Check required AuthZEN discovery fields
	assert.Contains(t, discovery, "policy_decision_point")
	assert.Contains(t, discovery, "access_evaluation_endpoint")

	// Verify the URLs are constructed correctly
	pdp := discovery["policy_decision_point"].(string)
	evalEndpoint := discovery["access_evaluation_endpoint"].(string)
	assert.Equal(t, ts.baseURL, pdp)
	assert.Equal(t, ts.baseURL+"/evaluation", evalEndpoint)
}

func TestIntegration_MetricsEndpoint(t *testing.T) {
	ts := startTestServer(t)
	defer ts.Close(t)

	resp, err := ts.client.Get(ts.baseURL + "/metrics")
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	// Should contain Prometheus metrics
	bodyStr := string(body)
	assert.Contains(t, bodyStr, "# HELP")
	assert.Contains(t, bodyStr, "# TYPE")
}

func TestIntegration_RegistriesEndpoint(t *testing.T) {
	ts := startTestServer(t, withGeneratedCerts())
	defer ts.Close(t)

	resp, err := ts.client.Get(ts.baseURL + "/registries")
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	var result map[string]interface{}
	err = json.Unmarshal(body, &result)
	require.NoError(t, err)

	// Check structure
	assert.Contains(t, result, "count")
	assert.Contains(t, result, "registries")
}

func TestIntegration_DeprecatedTSLsEndpoint(t *testing.T) {
	ts := startTestServer(t, withGeneratedCerts())
	defer ts.Close(t)

	// Legacy /tsls path should still work
	resp, err := ts.client.Get(ts.baseURL + "/tsls")
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	var result map[string]interface{}
	err = json.Unmarshal(body, &result)
	require.NoError(t, err)

	assert.Contains(t, result, "count")
	assert.Contains(t, result, "registries")

	// Verify deprecation signaling
	assert.Equal(t, "true", resp.Header.Get("Deprecation"))
	assert.Contains(t, resp.Header.Get("Link"), "/registries")
	assert.Contains(t, resp.Header.Get("X-API-Warn"), "/registries")
}

func TestIntegration_EvaluationEndpoint_NoBody(t *testing.T) {
	ts := startTestServer(t)
	defer ts.Close(t)

	resp, err := ts.client.Post(ts.baseURL+"/evaluation", "application/json", nil)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

func TestIntegration_EvaluationEndpoint_InvalidJSON(t *testing.T) {
	ts := startTestServer(t)
	defer ts.Close(t)

	resp, err := ts.client.Post(ts.baseURL+"/evaluation", "application/json",
		bytes.NewBufferString("{invalid json"))
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

func TestIntegration_EvaluationEndpoint_MissingSubject(t *testing.T) {
	ts := startTestServer(t, withGeneratedCerts())
	defer ts.Close(t)

	// A request without subject.type="key" or without subject.id
	// should return 200 but with decision=false (per AuthZEN Trust Registry Profile,
	// invalid requests are handled gracefully)
	reqBody := `{
		"subject": {
			"type": "invalid"
		},
		"resource": {
			"type": "x5c",
			"id": "test",
			"key": ["base64data"]
		},
		"action": {
			"name": "authenticate"
		}
	}`

	resp, err := ts.client.Post(ts.baseURL+"/evaluation", "application/json",
		bytes.NewBufferString(reqBody))
	require.NoError(t, err)
	defer resp.Body.Close()

	// The request is technically valid JSON but semantically invalid
	// per AuthZEN Trust Registry Profile. The server returns a decision
	// rather than an error.
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	var evalResp authzen.EvaluationResponse
	err = json.Unmarshal(body, &evalResp)
	require.NoError(t, err)

	// Invalid subject should result in a negative decision
	assert.False(t, evalResp.Decision, "Invalid request should result in decision=false")
}

func TestIntegration_EvaluationEndpoint_WithMockRegistry(t *testing.T) {
	// Create a mock registry that always accepts
	mock := &acceptAllRegistry{}
	ts := startTestServer(t, withMockRegistry(mock))
	defer ts.Close(t)

	// Per AuthZEN Trust Registry Profile:
	// - subject.type MUST be "key"
	// - subject.id is the name bound to the public key
	// - resource.type MUST be "jwk" or "x5c"
	// - resource.id MUST match subject.id
	// - resource.key contains the public key data
	req := authzen.EvaluationRequest{
		Subject: authzen.Subject{
			Type: "key",
			ID:   "test-subject",
		},
		Resource: authzen.Resource{
			Type: "x5c",
			ID:   "test-subject", // Must match subject.id
			Key:  []interface{}{"base64encodedcert"},
		},
		Action: &authzen.Action{
			Name: "authenticate",
		},
	}

	reqBody, err := json.Marshal(req)
	require.NoError(t, err)

	resp, err := ts.client.Post(ts.baseURL+"/evaluation", "application/json",
		bytes.NewBuffer(reqBody))
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	var evalResp authzen.EvaluationResponse
	err = json.Unmarshal(body, &evalResp)
	require.NoError(t, err)

	assert.True(t, evalResp.Decision, "Mock registry should accept all requests")
}

func TestIntegration_EvaluationEndpoint_WithRealCert(t *testing.T) {
	ts := startTestServer(t, withGeneratedCerts())
	defer ts.Close(t)

	// Generate a certificate signed by the test CA
	if len(ts.trustedCAs) == 0 {
		t.Skip("No trusted CAs available")
	}

	// Use base64 of the CA cert itself for testing
	certBase64 := base64.StdEncoding.EncodeToString(ts.trustedCAs[0].Raw)

	req := authzen.EvaluationRequest{
		Subject: authzen.Subject{
			Type: "key",
			ID:   "test-subject",
		},
		Resource: authzen.Resource{
			Type: "x5c",
			ID:   "test-subject",
			Key:  []interface{}{certBase64},
		},
		Action: &authzen.Action{
			Name: "authenticate",
		},
	}

	reqBody, err := json.Marshal(req)
	require.NoError(t, err)

	resp, err := ts.client.Post(ts.baseURL+"/evaluation", "application/json",
		bytes.NewBuffer(reqBody))
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	var evalResp authzen.EvaluationResponse
	err = json.Unmarshal(body, &evalResp)
	require.NoError(t, err)

	// The CA certificate should be trusted since it's in our bundle
	assert.True(t, evalResp.Decision, "CA certificate should be trusted")
}

func TestIntegration_EvaluationEndpoint_UntrustedCert(t *testing.T) {
	ts := startTestServer(t, withGeneratedCerts())
	defer ts.Close(t)

	// Generate an untrusted certificate
	untrustedCA, _, err := generateTestCA()
	require.NoError(t, err)

	certBase64 := base64.StdEncoding.EncodeToString(untrustedCA.Raw)

	req := authzen.EvaluationRequest{
		Subject: authzen.Subject{
			Type: "key",
			ID:   "untrusted-subject",
		},
		Resource: authzen.Resource{
			Type: "x5c",
			ID:   "untrusted-subject",
			Key:  []interface{}{certBase64},
		},
		Action: &authzen.Action{
			Name: "authenticate",
		},
	}

	reqBody, err := json.Marshal(req)
	require.NoError(t, err)

	resp, err := ts.client.Post(ts.baseURL+"/evaluation", "application/json",
		bytes.NewBuffer(reqBody))
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	var evalResp authzen.EvaluationResponse
	err = json.Unmarshal(body, &evalResp)
	require.NoError(t, err)

	// The untrusted certificate should NOT be trusted
	assert.False(t, evalResp.Decision, "Untrusted certificate should be rejected")
}

func TestIntegration_ConcurrentRequests(t *testing.T) {
	mock := &acceptAllRegistry{}
	ts := startTestServer(t, withMockRegistry(mock))
	defer ts.Close(t)

	numRequests := 50
	done := make(chan bool, numRequests)
	errors := make(chan error, numRequests)

	req := authzen.EvaluationRequest{
		Subject: authzen.Subject{
			Type: "key",
			ID:   "concurrent-test",
		},
		Resource: authzen.Resource{
			Type: "x5c",
			ID:   "concurrent-test",
			Key:  []interface{}{"base64cert"},
		},
		Action: &authzen.Action{
			Name: "authenticate",
		},
	}
	reqBody, err := json.Marshal(req)
	require.NoError(t, err)

	for i := 0; i < numRequests; i++ {
		go func(id int) {
			client := &http.Client{Timeout: 10 * time.Second}
			resp, err := client.Post(ts.baseURL+"/evaluation", "application/json",
				bytes.NewBuffer(reqBody))
			if err != nil {
				errors <- fmt.Errorf("request %d failed: %w", id, err)
				done <- false
				return
			}
			defer resp.Body.Close()

			if resp.StatusCode != http.StatusOK {
				errors <- fmt.Errorf("request %d got status %d", id, resp.StatusCode)
				done <- false
				return
			}
			done <- true
		}(i)
	}

	successCount := 0
	for i := 0; i < numRequests; i++ {
		select {
		case success := <-done:
			if success {
				successCount++
			}
		case err := <-errors:
			t.Logf("Error: %v", err)
		case <-time.After(30 * time.Second):
			t.Fatal("Timeout waiting for concurrent requests")
		}
	}

	assert.Equal(t, numRequests, successCount, "All concurrent requests should succeed")
}

func TestIntegration_ServerGracefulShutdown(t *testing.T) {
	ts := startTestServer(t)

	// Verify server is running
	resp, err := ts.client.Get(ts.baseURL + "/healthz")
	require.NoError(t, err)
	resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	// Gracefully shut down
	ts.Close(t)

	// Verify server is no longer responding
	_, err = ts.client.Get(ts.baseURL + "/healthz")
	assert.Error(t, err, "Server should not respond after shutdown")
}

// =============================================================================
// Test with Real TSL Data (Optional - requires test data)
// =============================================================================

// TestIntegration_WithRealTSLData tests loading and validating real EU Trust Service Lists.
// This test validates signature verification across multiple EU member state TSLs to ensure
// our XAdES signature validation implementation handles various signing patterns correctly.
func TestIntegration_WithRealTSLData(t *testing.T) {
	// Define test cases for different EU TSLs
	// Each TSL may have different signing patterns, certificate chains, and XML structures
	testCases := []struct {
		name        string
		filename    string
		description string
		expectError string // If non-empty, expect an error containing this string
	}{
		{
			name:        "Liechtenstein",
			filename:    "li-tsl.xml",
			description: "Small TSL with basic XAdES signature",
		},
		{
			name:        "Sweden",
			filename:    "se-tsl.xml",
			description: "Medium-sized TSL with Swedish trust services",
		},
		{
			name:        "Germany",
			filename:    "de-tsl.xml",
			description: "Large TSL with many trust service providers",
		},
		{
			name:        "France",
			filename:    "fr-tsl.xml",
			description: "Large TSL with French trust services",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			tslFile := filepath.Join("..", "..", "pkg", "registry", "etsi", "testdata", tc.filename)
			if _, err := os.Stat(tslFile); os.IsNotExist(err) {
				t.Skipf("TSL test data not available: %s", tc.filename)
			}

			// Start server with TSL file
			gin.SetMode(gin.TestMode)
			router := gin.New()

			logger := logging.NewLogger(logging.ErrorLevel)
			serverCtx := api.NewServerContext(logger)

			registryMgr := registry.NewRegistryManager(registry.FirstMatch, 10*time.Second)

			absPath, err := filepath.Abs(tslFile)
			require.NoError(t, err)

			tslConfig := etsi.TSLConfig{
				Name:        tc.name + "-TSL",
				Description: tc.description,
				TSLFiles:    []string{absPath},
			}
			tslRegistry, err := etsi.NewTSLRegistry(tslConfig)
			if err != nil {
				// Check if this is an expected error
				if tc.expectError != "" && strings.Contains(err.Error(), tc.expectError) {
					t.Skipf("Skipping %s TSL: expected error (unsupported algorithm): %v", tc.name, err)
					return
				}
				// TSL test data may have invalid signatures due to test data age/modifications
				t.Fatalf("Could not load TSL test data for %s (signature validation failed): %v", tc.name, err)
			}
			registryMgr.Register(tslRegistry)

			serverCtx.RegistryManager = registryMgr

			// Find available port
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			require.NoError(t, err)
			port := listener.Addr().(*net.TCPAddr).Port
			listener.Close()

			serverCtx.BaseURL = fmt.Sprintf("http://127.0.0.1:%d", port)
			api.RegisterHealthEndpoints(router, serverCtx)
			api.RegisterAPIRoutes(router, serverCtx)

			server := &http.Server{
				Addr:    fmt.Sprintf("127.0.0.1:%d", port),
				Handler: router,
			}

			go func() {
				if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
					t.Logf("Server error: %v", err)
				}
			}()

			baseURL := fmt.Sprintf("http://127.0.0.1:%d", port)
			waitForServer(t, baseURL, 5*time.Second)
			defer func() {
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				server.Shutdown(ctx)
			}()

			// Test the registries endpoint
			client := &http.Client{Timeout: 30 * time.Second}
			resp, err := client.Get(baseURL + "/registries")
			require.NoError(t, err)
			defer resp.Body.Close()

			assert.Equal(t, http.StatusOK, resp.StatusCode, "Registries endpoint should return 200 OK for %s", tc.name)

			body, err := io.ReadAll(resp.Body)
			require.NoError(t, err)

			var result map[string]interface{}
			err = json.Unmarshal(body, &result)
			require.NoError(t, err)

			// Should have loaded the TSL
			registries, ok := result["registries"].([]interface{})
			assert.True(t, ok, "registries should be an array")
			assert.GreaterOrEqual(t, len(registries), 1, "Should have at least one registry for %s", tc.name)

			t.Logf("Successfully loaded and validated %s TSL", tc.name)
		})
	}
}
