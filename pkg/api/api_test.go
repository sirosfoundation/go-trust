package api

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/sirosfoundation/g119612/pkg/logging"
	"github.com/sirosfoundation/go-trust/pkg/authzen"
	"github.com/sirosfoundation/go-trust/pkg/registry"
	"github.com/stretchr/testify/assert"
)

var testCertBase64 string
var testCertDER []byte
var testCert *x509.Certificate

// generateTestCertBase64 runs openssl to generate a self-signed cert and returns the base64-encoded DER string.
func generateTestCertBase64() (string, []byte, *x509.Certificate, error) {
	// Use unique temp files for key, cert, and der
	keyFile, err := os.CreateTemp("", "testkey-*.pem")
	if err != nil {
		return "", nil, nil, fmt.Errorf("failed to create temp key file: %w", err)
	}
	defer os.Remove(keyFile.Name())
	keyFile.Close()
	certFile, err := os.CreateTemp("", "testcert-*.pem")
	if err != nil {
		return "", nil, nil, fmt.Errorf("failed to create temp cert file: %w", err)
	}
	defer os.Remove(certFile.Name())
	certFile.Close()
	derFile, err := os.CreateTemp("", "testcert-*.der")
	if err != nil {
		return "", nil, nil, fmt.Errorf("failed to create temp der file: %w", err)
	}
	defer os.Remove(derFile.Name())
	derFile.Close()

	// Build the openssl command using the temp files
	opensslCmd := fmt.Sprintf("openssl req -x509 -newkey rsa:2048 -keyout %s -out %s -days 365 -nodes -subj '/CN=Test Cert' 2>/dev/null && openssl x509 -outform der -in %s -out %s 2>/dev/null && openssl base64 -in %s -A 2>/dev/null", keyFile.Name(), certFile.Name(), certFile.Name(), derFile.Name(), derFile.Name())
	cmd := exec.Command("bash", "-c", opensslCmd)
	var out bytes.Buffer
	cmd.Stdout = &out
	// Do not capture Stderr, as it is redirected in the shell command
	err = cmd.Run()
	output := out.String()
	if err != nil {
		// Print the OpenSSL output for debugging
		return "", nil, nil, fmt.Errorf("openssl error: %v\noutput: %s", err, output)
	}
	certBase64 := strings.TrimSpace(output)
	certDER, err := base64.StdEncoding.DecodeString(certBase64)
	if err != nil {
		return certBase64, nil, nil, fmt.Errorf("base64 decode error: %v\noutput: %s", err, output)
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return certBase64, certDER, nil, fmt.Errorf("parse cert error: %v\noutput: %s", err, output)
	}
	return certBase64, certDER, cert, nil
}

func init() {
	var err error
	testCertBase64, testCertDER, testCert, err = generateTestCertBase64()
	if err != nil {
		panic("failed to generate test cert: " + err.Error())
	}
}

func setupTestServer() (*gin.Engine, *ServerContext) {
	gin.SetMode(gin.TestMode)
	r := gin.Default()
	// Create a registry manager with a mock registry
	mgr := registry.NewRegistryManager(registry.FirstMatch, 10*time.Second)
	// Add a mock registry that accepts the test certificate
	mockReg := &mockTrustRegistry{
		certPool: x509.NewCertPool(),
	}
	mockReg.certPool.AddCert(testCert)
	mgr.Register(mockReg)

	serverCtx := &ServerContext{
		RegistryManager: mgr,
		Logger:          logging.DefaultLogger(),
		BaseURL:         "http://localhost:6001",
	}
	RegisterAPIRoutes(r, serverCtx)
	return r, serverCtx
}

// mockTrustRegistry is a test implementation for testing
type mockTrustRegistry struct {
	certPool *x509.CertPool
}

func (m *mockTrustRegistry) Evaluate(ctx context.Context, req *authzen.EvaluationRequest) (*authzen.EvaluationResponse, error) {
	// Parse the certificate from the request
	if req.Resource.Type == "x5c" {
		if len(req.Resource.Key) == 0 {
			return &authzen.EvaluationResponse{
				Decision: false,
				Context: &authzen.EvaluationResponseContext{
					Reason: map[string]interface{}{"error": "no certificates in key"},
				},
			}, nil
		}

		certB64, ok := req.Resource.Key[0].(string)
		if !ok {
			return &authzen.EvaluationResponse{
				Decision: false,
				Context: &authzen.EvaluationResponseContext{
					Reason: map[string]interface{}{"error": "invalid certificate format"},
				},
			}, nil
		}

		certDER, err := base64.StdEncoding.DecodeString(certB64)
		if err != nil {
			return &authzen.EvaluationResponse{
				Decision: false,
				Context: &authzen.EvaluationResponseContext{
					Reason: map[string]interface{}{"error": "invalid base64: " + err.Error()},
				},
			}, nil
		}

		cert, err := x509.ParseCertificate(certDER)
		if err != nil {
			return &authzen.EvaluationResponse{
				Decision: false,
				Context: &authzen.EvaluationResponseContext{
					Reason: map[string]interface{}{"error": "invalid certificate: " + err.Error()},
				},
			}, nil
		}

		if m.certPool == nil {
			return &authzen.EvaluationResponse{
				Decision: false,
				Context: &authzen.EvaluationResponseContext{
					Reason: map[string]interface{}{"error": "CertPool is nil"},
				},
			}, nil
		}

		opts := x509.VerifyOptions{Roots: m.certPool}
		_, err = cert.Verify(opts)
		if err != nil {
			return &authzen.EvaluationResponse{
				Decision: false,
				Context: &authzen.EvaluationResponseContext{
					Reason: map[string]interface{}{"error": err.Error()},
				},
			}, nil
		}

		return &authzen.EvaluationResponse{Decision: true}, nil
	}

	return &authzen.EvaluationResponse{
		Decision: false,
		Context: &authzen.EvaluationResponseContext{
			Reason: map[string]interface{}{"error": "unsupported resource type"},
		},
	}, nil
}

func (m *mockTrustRegistry) Refresh(ctx context.Context) error {
	return nil
}

func (m *mockTrustRegistry) SupportedResourceTypes() []string {
	return []string{"x5c", "jwk"}
}

func (m *mockTrustRegistry) SupportsResolutionOnly() bool {
	return false
}

func (m *mockTrustRegistry) Info() registry.RegistryInfo {
	return registry.RegistryInfo{
		Name:        "mock-registry",
		Type:        "mock",
		Description: "Mock registry for testing",
	}
}

func (m *mockTrustRegistry) Healthy() bool {
	return true
}

func TestStatusEndpoint(t *testing.T) {
	r, _ := setupTestServer()

	req, _ := http.NewRequest("GET", "/status", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	assert.Equal(t, 200, w.Code)
	assert.Contains(t, w.Body.String(), "registry_count")
}

func TestInfoEndpoint_Empty(t *testing.T) {
	r, _ := setupTestServer()
	req, _ := http.NewRequest("GET", "/info", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	assert.Equal(t, 200, w.Code)
	assert.Contains(t, w.Body.String(), "registries")
}

func TestInfoEndpoint_Registries(t *testing.T) {
	r, _ := setupTestServer()

	req, _ := http.NewRequest("GET", "/info", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	assert.Equal(t, 200, w.Code)
	body := w.Body.String()
	assert.Contains(t, body, "registries")
	assert.Contains(t, body, "mock-registry")
}

func TestWellKnownEndpoint(t *testing.T) {
	r, serverCtx := setupTestServer()

	// Set a base URL for the PDP
	serverCtx.Lock()
	serverCtx.BaseURL = "http://localhost:6001"
	serverCtx.Unlock()

	req, _ := http.NewRequest("GET", "/.well-known/authzen-configuration", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	assert.Equal(t, 200, w.Code)
	assert.Equal(t, "application/json; charset=utf-8", w.Header().Get("Content-Type"))

	body := w.Body.String()
	// Verify required fields according to AuthZEN spec Section 9.1
	assert.Contains(t, body, "policy_decision_point")
	assert.Contains(t, body, "access_evaluation_endpoint")
	assert.Contains(t, body, "http://localhost:6001")
	assert.Contains(t, body, "/evaluation")
}

func TestWellKnownEndpoint_ExternalURL(t *testing.T) {
	// Test with external URL (e.g., production deployment behind reverse proxy)
	_, serverCtx := setupTestServer()

	// Simulate setting external URL (like from --external-url flag or env var)
	externalURL := "https://pdp.example.com"
	serverCtx.Lock()
	serverCtx.BaseURL = externalURL
	serverCtx.Unlock()

	// Re-register routes with new BaseURL
	r2 := gin.New()
	RegisterAPIRoutes(r2, serverCtx)

	req, _ := http.NewRequest("GET", "/.well-known/authzen-configuration", nil)
	w := httptest.NewRecorder()
	r2.ServeHTTP(w, req)

	assert.Equal(t, 200, w.Code)
	body := w.Body.String()

	// Verify external URL is used
	assert.Contains(t, body, "https://pdp.example.com")
	assert.Contains(t, body, "https://pdp.example.com/evaluation")
	assert.NotContains(t, body, "localhost")
}

func TestAuthzenDecisionEndpoint(t *testing.T) {
	r, _ := setupTestServer()
	// AuthZEN Trust Registry Profile compliant request:
	// - subject.type must be "key"
	// - resource.type must be "x5c" or "jwk"
	// - resource.id must equal subject.id
	// - certificates in resource.key
	body := `{
	       "subject": {
		       "type": "key",
		       "id": "did:example:alice"
	       },
	       "resource": {
		       "type": "x5c",
		       "id": "did:example:alice",
		       "key": ["` + testCertBase64 + `"]
	       },
	       "action": {
		       "name": "http://ec.europa.eu/NS/wallet-provider"
	       }
       }`
	req, _ := http.NewRequest("POST", "/evaluation", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	assert.Equal(t, 200, w.Code)
	assert.Contains(t, w.Body.String(), `"decision":true`)
}

func TestAuthzenDecisionEndpoint_Errors(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r, _ := setupTestServer()

	// Malformed JSON
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/evaluation", strings.NewReader("{")))
	if w.Code != 400 {
		t.Errorf("Expected 400 for malformed JSON, got %d", w.Code)
	}

	// Valid JSON, but violates AuthZEN Trust Registry Profile validation
	// (subject.type is not "key")
	// Per AuthZEN spec, validation errors return 200 with decision=false
	body := `{"subject":{"type":"user","id":"alice"},"resource":{"type":"x5c","id":"alice","key":[]}}`
	w = httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/evaluation", strings.NewReader(body)))
	if w.Code != 200 {
		t.Errorf("Expected 200 for validation error (AuthZEN spec), got %d", w.Code)
	}
	var respValidation map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &respValidation)
	if respValidation["decision"] != false {
		t.Errorf("Expected decision=false for validation error, got %v", respValidation["decision"])
	}

	// Valid JSON, but resource.id != subject.id (validation error)
	// Per AuthZEN spec, validation errors return 200 with decision=false
	body = `{"subject":{"type":"key","id":"alice"},"resource":{"type":"x5c","id":"bob","key":["` + testCertBase64 + `"]}}`
	w = httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/evaluation", strings.NewReader(body)))
	if w.Code != 200 {
		t.Errorf("Expected 200 for resource.id != subject.id (AuthZEN spec), got %d", w.Code)
	}
	var respMismatch map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &respMismatch)
	if respMismatch["decision"] != false {
		t.Errorf("Expected decision=false for ID mismatch, got %v", respMismatch["decision"])
	}

	// Valid JSON, missing CertPool
	// Create a test server with a mock registry that has nil certPool
	gin.SetMode(gin.TestMode)
	r2 := gin.Default()
	mgr2 := registry.NewRegistryManager(registry.FirstMatch, 10*time.Second)
	mockReg2 := &mockTrustRegistry{certPool: nil}
	mgr2.Register(mockReg2)
	serverCtx2 := &ServerContext{
		RegistryManager: mgr2,
		Logger:          logging.DefaultLogger(),
		BaseURL:         "http://localhost:6001",
	}
	RegisterAPIRoutes(r2, serverCtx2)
	body = `{"subject":{"type":"key","id":"alice"},"resource":{"type":"x5c","id":"alice","key":["` + testCertBase64 + `"]}}`
	w = httptest.NewRecorder()
	r2.ServeHTTP(w, httptest.NewRequest("POST", "/evaluation", strings.NewReader(body)))
	responseBody := w.Body.String()
	// The error is now "no registry returned positive match" since the mock returns CertPool is nil error
	if !strings.Contains(responseBody, "CertPool is nil") && !strings.Contains(responseBody, "no registry returned positive match") {
		t.Errorf("Expected CertPool is nil or no registry returned positive match error, got %s", responseBody)
	}

	// Valid JSON, cert verification failure (garbage cert)
	garbageCert := base64.StdEncoding.EncodeToString([]byte("notacert"))
	body = fmt.Sprintf(`{"subject":{"type":"key","id":"alice"},"resource":{"type":"x5c","id":"alice","key":["%s"]}}`, garbageCert)
	w = httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/evaluation", strings.NewReader(body)))
	if !strings.Contains(w.Body.String(), "\"decision\":false") {
		t.Errorf("Expected decision:false for cert verification failure, got %s", w.Body.String())
	}
}

func TestBuildResponse(t *testing.T) {
	// Decision true: should return true and nil context
	resp := buildResponse(true, "")
	if !resp.Decision {
		t.Errorf("Expected Decision true, got false")
	}
	if resp.Context != nil {
		t.Errorf("Expected nil Context for true decision")
	}

	// Decision false: should return false and context with reason
	reason := "some error"
	resp = buildResponse(false, reason)
	if resp.Decision {
		t.Errorf("Expected Decision false, got true")
	}
	if resp.Context == nil {
		t.Errorf("Expected non-nil Context for false decision")
	} else {
		// Check that Reason contains the error
		reasonMap, ok := resp.Context.Reason["error"]
		if !ok || reasonMap != reason {
			t.Errorf("Expected Reason to contain error '%s', got '%v'", reason, reasonMap)
		}
	}

	// Decision false, empty reason
	resp = buildResponse(false, "")
	if resp.Decision {
		t.Errorf("Expected Decision false, got true")
	}
	if resp.Context == nil {
		t.Errorf("Expected non-nil Context for false decision with empty reason")
	}
}

func TestParseX5C_Errors(t *testing.T) {
	// Invalid base64
	props := map[string]interface{}{"x5c": []interface{}{">>notbase64<<"}}
	certs, err := parseX5C(props)
	if err == nil || certs != nil {
		t.Errorf("Expected error for invalid base64, got: %v", err)
	}

	// Malformed certificate (valid base64, but not a cert)
	props = map[string]interface{}{"x5c": []interface{}{base64.StdEncoding.EncodeToString([]byte("notacert"))}}
	certs, err = parseX5C(props)
	if err == nil || certs != nil {
		t.Errorf("Expected error for malformed cert, got: %v", err)
	}

	// x5c property is not a list
	props = map[string]interface{}{"x5c": "notalist"}
	certs, err = parseX5C(props)
	if err == nil || certs != nil {
		t.Errorf("Expected error for non-list x5c, got: %v", err)
	}

	// x5c entry is not a string
	props = map[string]interface{}{"x5c": []interface{}{1234}}
	certs, err = parseX5C(props)
	if err == nil || certs != nil {
		t.Errorf("Expected error for non-string x5c entry, got: %v", err)
	}

	// Nil props and missing x5c should not error, should return empty slice
	certs, err = parseX5C(nil)
	if err != nil || len(certs) != 0 {
		t.Errorf("Expected empty result for nil props, got: %v, %v", certs, err)
	}
	certs, err = parseX5C(map[string]interface{}{})
	if err != nil || len(certs) != 0 {
		t.Errorf("Expected empty result for missing x5c, got: %v, %v", certs, err)
	}
}

// TestRateLimiting_Integration verifies that rate limiting is applied when configured
func TestRateLimiting_Integration(t *testing.T) {
	gin.SetMode(gin.TestMode)

	// Create a server context with rate limiting enabled (strict limits for testing)
	logger := logging.NewLogger(logging.InfoLevel)
	serverCtx := NewServerContext(logger)
	mgr := registry.NewRegistryManager(registry.FirstMatch, 10*time.Second)
	mockReg := &mockTrustRegistry{certPool: x509.NewCertPool()}
	mgr.Register(mockReg)
	serverCtx.RegistryManager = mgr
	serverCtx.RateLimiter = NewRateLimiter(2, 2) // 2 req/sec, burst of 2

	// Create router and register routes
	router := gin.New()
	RegisterAPIRoutes(router, serverCtx)

	// Make requests from the same IP
	ip := "192.168.1.100"

	// First 2 requests should succeed (within burst)
	for i := 0; i < 2; i++ {
		req := httptest.NewRequest("GET", "/status", nil)
		req.RemoteAddr = ip + ":1234"
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		assert.Equal(t, 200, w.Code, "Request %d should succeed", i+1)
	}

	// Third request should be rate limited
	req := httptest.NewRequest("GET", "/status", nil)
	req.RemoteAddr = ip + ":1234"
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.Equal(t, 429, w.Code, "Request should be rate limited")
	assert.Contains(t, w.Body.String(), "rate limit exceeded")

	// Request from different IP should still work
	req2 := httptest.NewRequest("GET", "/status", nil)
	req2.RemoteAddr = "192.168.1.101:1234"
	w2 := httptest.NewRecorder()
	router.ServeHTTP(w2, req2)
	assert.Equal(t, 200, w2.Code, "Request from different IP should succeed")
}

// TestRateLimiting_Disabled verifies that rate limiting can be disabled
func TestRateLimiting_Disabled(t *testing.T) {
	gin.SetMode(gin.TestMode)

	// Create a server context WITHOUT rate limiting
	logger := logging.NewLogger(logging.InfoLevel)
	serverCtx := NewServerContext(logger)
	mgr := registry.NewRegistryManager(registry.FirstMatch, 10*time.Second)
	mockReg := &mockTrustRegistry{certPool: x509.NewCertPool()}
	mgr.Register(mockReg)
	serverCtx.RegistryManager = mgr
	serverCtx.RateLimiter = nil // No rate limiter

	// Create router and register routes
	router := gin.New()
	RegisterAPIRoutes(router, serverCtx)

	// Make many requests rapidly - all should succeed
	for i := 0; i < 10; i++ {
		req := httptest.NewRequest("GET", "/status", nil)
		req.RemoteAddr = "192.168.1.1:1234"
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		assert.Equal(t, 200, w.Code, "Request %d should succeed when rate limiting disabled", i+1)
	}
}

// TestParseX5CFromArray tests the parseX5CFromArray function
func TestParseX5CFromArray(t *testing.T) {
	tests := []struct {
		name    string
		key     []interface{}
		wantErr bool
		errMsg  string
	}{
		{
			name:    "empty key array",
			key:     []interface{}{},
			wantErr: true,
			errMsg:  "resource.key is empty",
		},
		{
			name:    "nil key array",
			key:     nil,
			wantErr: true,
			errMsg:  "resource.key is empty",
		},
		{
			name:    "non-string element",
			key:     []interface{}{123},
			wantErr: true,
			errMsg:  "resource.key[0] is not a string",
		},
		{
			name:    "invalid base64",
			key:     []interface{}{"not-valid-base64!!!"},
			wantErr: true,
			errMsg:  "failed to base64 decode",
		},
		{
			name:    "invalid certificate",
			key:     []interface{}{base64.StdEncoding.EncodeToString([]byte("not a certificate"))},
			wantErr: true,
			errMsg:  "failed to parse certificate",
		},
		{
			name:    "valid certificate",
			key:     []interface{}{testCertBase64},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			certs, err := parseX5CFromArray(tt.key)
			if tt.wantErr {
				assert.Error(t, err)
				if tt.errMsg != "" {
					assert.Contains(t, err.Error(), tt.errMsg)
				}
			} else {
				assert.NoError(t, err)
				assert.Len(t, certs, 1)
				assert.Equal(t, "Test Cert", certs[0].Subject.CommonName)
			}
		})
	}
}

// TestParseX5CFromJWK tests the parseX5CFromJWK function
func TestParseX5CFromJWK(t *testing.T) {
	tests := []struct {
		name    string
		key     []interface{}
		wantErr bool
		errMsg  string
	}{
		{
			name:    "empty key array",
			key:     []interface{}{},
			wantErr: true,
			errMsg:  "resource.key is empty",
		},
		{
			name:    "nil key array",
			key:     nil,
			wantErr: true,
			errMsg:  "resource.key is empty",
		},
		{
			name:    "non-map element",
			key:     []interface{}{"not a map"},
			wantErr: true,
			errMsg:  "resource.key[0] is not a JWK object (map)",
		},
		{
			name: "no x5c claim",
			key: []interface{}{
				map[string]interface{}{
					"kty": "RSA",
					"n":   "somevalue",
				},
			},
			wantErr: true,
			errMsg:  "JWK does not contain x5c claim",
		},
		{
			name: "x5c is not array",
			key: []interface{}{
				map[string]interface{}{
					"kty": "RSA",
					"x5c": "not an array",
				},
			},
			wantErr: true,
			errMsg:  "JWK x5c claim is not an array",
		},
		{
			name: "x5c element is not string",
			key: []interface{}{
				map[string]interface{}{
					"kty": "RSA",
					"x5c": []interface{}{123},
				},
			},
			wantErr: true,
			errMsg:  "JWK x5c[0] is not a string",
		},
		{
			name: "invalid base64 in x5c",
			key: []interface{}{
				map[string]interface{}{
					"kty": "RSA",
					"x5c": []interface{}{"not-valid-base64!!!"},
				},
			},
			wantErr: true,
			errMsg:  "failed to base64 decode JWK x5c[0]",
		},
		{
			name: "invalid certificate in x5c",
			key: []interface{}{
				map[string]interface{}{
					"kty": "RSA",
					"x5c": []interface{}{base64.StdEncoding.EncodeToString([]byte("not a cert"))},
				},
			},
			wantErr: true,
			errMsg:  "failed to parse certificate from JWK x5c[0]",
		},
		{
			name: "valid JWK with x5c",
			key: []interface{}{
				map[string]interface{}{
					"kty": "RSA",
					"x5c": []interface{}{testCertBase64},
				},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			certs, err := parseX5CFromJWK(tt.key)
			if tt.wantErr {
				assert.Error(t, err)
				if tt.errMsg != "" {
					assert.Contains(t, err.Error(), tt.errMsg)
				}
			} else {
				assert.NoError(t, err)
				assert.Len(t, certs, 1)
				assert.Equal(t, "Test Cert", certs[0].Subject.CommonName)
			}
		})
	}
}

// TestServerContext_WithLogger tests the WithLogger method
func TestServerContext_WithLogger(t *testing.T) {
	logger := logging.NewLogger(logging.DebugLevel)
	serverCtx := NewServerContext(logger)

	// Apply WithLogger method to create a new context with a different logger
	newLogger := logging.NewLogger(logging.InfoLevel)
	newCtx := serverCtx.WithLogger(newLogger)

	assert.NotNil(t, newCtx.Logger)
	assert.NotSame(t, serverCtx, newCtx, "WithLogger should return a new ServerContext")
}

// TestServerContext_WithLogger_NilLogger tests that WithLogger handles nil logger
func TestServerContext_WithLogger_NilLogger(t *testing.T) {
	logger := logging.NewLogger(logging.DebugLevel)
	serverCtx := NewServerContext(logger)

	// Pass nil logger - should use default
	newCtx := serverCtx.WithLogger(nil)

	assert.NotNil(t, newCtx.Logger, "WithLogger(nil) should use default logger")
}

// TestNewServerContext_DefaultValues tests NewServerContext default values
func TestNewServerContext_DefaultValues(t *testing.T) {
	logger := logging.NewLogger(logging.InfoLevel)
	serverCtx := NewServerContext(logger)

	assert.NotNil(t, serverCtx.Logger)
}

// TestNilRegistryManager tests evaluation when RegistryManager is nil
func TestNilRegistryManager(t *testing.T) {
	gin.SetMode(gin.TestMode)

	logger := logging.NewLogger(logging.InfoLevel)
	serverCtx := NewServerContext(logger)
	// RegistryManager is nil
	serverCtx.RegistryManager = nil

	router := gin.New()
	RegisterAPIRoutes(router, serverCtx)

	// Test the evaluation endpoint without RegistryManager - should return 500
	body := `{
		"subject": {
			"type": "key",
			"id": "did:example:test"
		},
		"resource": {
			"type": "x5c",
			"id": "did:example:test",
			"key": ["dGVzdA=="]
		}
	}`

	req := httptest.NewRequest("POST", "/evaluation", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, 500, w.Code)
	assert.Contains(t, w.Body.String(), "no registry manager")
}

// TestRegistriesHandler_EmptyRegistryManager tests RegistriesHandler when no ETSI registries exist
func TestRegistriesHandler_EmptyRegistryManager(t *testing.T) {
	gin.SetMode(gin.TestMode)

	logger := logging.NewLogger(logging.InfoLevel)
	serverCtx := NewServerContext(logger)

	// Create registry manager with non-ETSI registry
	mgr := registry.NewRegistryManager(registry.FirstMatch, 10*time.Second)
	mockReg := &mockTrustRegistry{certPool: x509.NewCertPool()}
	mgr.Register(mockReg)
	serverCtx.RegistryManager = mgr

	router := gin.New()
	RegisterAPIRoutes(router, serverCtx)

	req := httptest.NewRequest("GET", "/registries", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, 200, w.Code)
	// The response contains registry information
	assert.Contains(t, w.Body.String(), "registries")
}

// TestRegistriesHandler_NilRegistryManager tests RegistriesHandler when RegistryManager is nil
func TestRegistriesHandler_NilRegistryManager(t *testing.T) {
	gin.SetMode(gin.TestMode)

	logger := logging.NewLogger(logging.InfoLevel)
	serverCtx := NewServerContext(logger)
	serverCtx.RegistryManager = nil

	router := gin.New()
	RegisterAPIRoutes(router, serverCtx)

	req := httptest.NewRequest("GET", "/registries", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// When RegistryManager is nil, it returns 200 with empty registries
	assert.Equal(t, 200, w.Code)
	assert.Contains(t, w.Body.String(), "count")
}

// TestDeprecatedTSLsEndpoint tests that the legacy /tsls path still works and emits deprecation headers
func TestDeprecatedTSLsEndpoint(t *testing.T) {
	gin.SetMode(gin.TestMode)

	logger := logging.NewLogger(logging.InfoLevel)
	serverCtx := NewServerContext(logger)
	serverCtx.RegistryManager = nil

	router := gin.New()
	RegisterAPIRoutes(router, serverCtx)

	req := httptest.NewRequest("GET", "/tsls", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, 200, w.Code)
	assert.Contains(t, w.Body.String(), "count")

	// Verify deprecation signaling
	assert.Equal(t, "true", w.Header().Get("Deprecation"))
	assert.Contains(t, w.Header().Get("Link"), "/registries")
	assert.Contains(t, w.Header().Get("X-API-Warn"), "/registries")
}
