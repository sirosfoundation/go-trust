package issuerurl

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/sirosfoundation/go-trust/pkg/authzen"
)

func newTestRegistry(t *testing.T, server *httptest.Server) *Registry {
	t.Helper()
	cfg := &Config{
		Name:            "test-issuer-url",
		CacheTTL:        5 * time.Minute,
		HTTPTimeout:     5 * time.Second,
		AllowHTTP:       true,
		AllowPrivateIPs: true,
	}
	reg, err := New(cfg)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}
	return reg
}

func TestEvaluate_URLResolution_Success(t *testing.T) {
	issuerMetadata := map[string]interface{}{
		"credential_issuer": "https://issuer.example.com",
		"credential_configurations_supported": map[string]interface{}{
			"UniversityDegree": map[string]interface{}{
				"format": "vc+sd-jwt",
			},
		},
		"display": []interface{}{
			map[string]interface{}{
				"name":   "Example University",
				"locale": "en-US",
			},
		},
		"signed_metadata": "eyJhbGciOiJSUzI1NiJ9.test.signature",
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/.well-known/openid-credential-issuer" {
			t.Errorf("unexpected path: %s", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(issuerMetadata)
	}))
	defer server.Close()

	reg := newTestRegistry(t, server)

	req := &authzen.EvaluationRequest{
		Subject: authzen.Subject{
			Type: "url",
			ID:   server.URL,
		},
		Resource: authzen.Resource{
			Type: "resolution",
			ID:   server.URL,
		},
	}

	resp, err := reg.Evaluate(context.Background(), req)
	if err != nil {
		t.Fatalf("Evaluate() error: %v", err)
	}
	if !resp.Decision {
		t.Fatalf("Expected decision=true, got false: %v", resp.Context.Reason)
	}
	if resp.Context == nil || resp.Context.TrustMetadata == nil {
		t.Fatal("Expected trust_metadata in response")
	}

	// Verify trust_metadata is a parsed map
	parsed, ok := resp.Context.TrustMetadata.(map[string]interface{})
	if !ok {
		t.Fatalf("Expected map[string]interface{}, got %T", resp.Context.TrustMetadata)
	}
	if parsed["signed_metadata"] != "eyJhbGciOiJSUzI1NiJ9.test.signature" {
		t.Errorf("signed_metadata not preserved: got %v", parsed["signed_metadata"])
	}
	if parsed["credential_issuer"] != "https://issuer.example.com" {
		t.Errorf("credential_issuer missing: got %v", parsed["credential_issuer"])
	}

	// Verify reason fields
	reason := resp.Context.Reason
	if reason["resolution_only"] != true {
		t.Error("Expected resolution_only=true")
	}
}

func TestEvaluate_URLResolution_Cached(t *testing.T) {
	callCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"credential_issuer": "https://test.com"})
	}))
	defer server.Close()

	reg := newTestRegistry(t, server)

	req := &authzen.EvaluationRequest{
		Subject:  authzen.Subject{Type: "url", ID: server.URL},
		Resource: authzen.Resource{Type: "resolution", ID: server.URL},
	}

	// First call — fetches
	resp, _ := reg.Evaluate(context.Background(), req)
	if !resp.Decision {
		t.Fatal("First call should succeed")
	}

	// Second call — should be served from cache (no additional HTTP request)
	resp, _ = reg.Evaluate(context.Background(), req)
	if !resp.Decision {
		t.Fatal("Second call should succeed")
	}
	if callCount != 1 {
		t.Errorf("Expected 1 HTTP request, got %d", callCount)
	}
}

func TestEvaluate_RejectsNonURLSubject(t *testing.T) {
	reg := newTestRegistry(t, nil)

	req := &authzen.EvaluationRequest{
		Subject:  authzen.Subject{Type: "key", ID: "did:web:example.com"},
		Resource: authzen.Resource{Type: "resolution", ID: "did:web:example.com"},
	}

	resp, err := reg.Evaluate(context.Background(), req)
	if err != nil {
		t.Fatalf("Evaluate() error: %v", err)
	}
	if resp.Decision {
		t.Error("Expected decision=false for non-URL subject type")
	}
}

func TestEvaluate_RejectsNonResolutionRequest(t *testing.T) {
	reg := newTestRegistry(t, nil)

	req := &authzen.EvaluationRequest{
		Subject:  authzen.Subject{Type: "url", ID: "https://issuer.example.com"},
		Resource: authzen.Resource{Type: "x5c", ID: "https://issuer.example.com", Key: []interface{}{"cert"}},
	}

	resp, err := reg.Evaluate(context.Background(), req)
	if err != nil {
		t.Fatalf("Evaluate() error: %v", err)
	}
	if resp.Decision {
		t.Error("Expected decision=false for non-resolution request")
	}
}

func TestEvaluate_RejectsHTTP(t *testing.T) {
	cfg := &Config{
		Name:      "test",
		AllowHTTP: false,
	}
	reg, _ := New(cfg)

	req := &authzen.EvaluationRequest{
		Subject:  authzen.Subject{Type: "url", ID: "http://insecure.example.com"},
		Resource: authzen.Resource{Type: "resolution", ID: "http://insecure.example.com"},
	}

	resp, err := reg.Evaluate(context.Background(), req)
	if err != nil {
		t.Fatalf("Evaluate() error: %v", err)
	}
	if resp.Decision {
		t.Error("Expected decision=false for HTTP URL")
	}
}

func TestEvaluate_IssuerReturns404(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	reg := newTestRegistry(t, server)

	req := &authzen.EvaluationRequest{
		Subject:  authzen.Subject{Type: "url", ID: server.URL},
		Resource: authzen.Resource{Type: "resolution", ID: server.URL},
	}

	resp, err := reg.Evaluate(context.Background(), req)
	if err != nil {
		t.Fatalf("Evaluate() error: %v", err)
	}
	if resp.Decision {
		t.Error("Expected decision=false when issuer returns 404")
	}
}

func TestEvaluate_InvalidJSON(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte("not json"))
	}))
	defer server.Close()

	reg := newTestRegistry(t, server)

	req := &authzen.EvaluationRequest{
		Subject:  authzen.Subject{Type: "url", ID: server.URL},
		Resource: authzen.Resource{Type: "resolution", ID: server.URL},
	}

	resp, err := reg.Evaluate(context.Background(), req)
	if err != nil {
		t.Fatalf("Evaluate() error: %v", err)
	}
	if resp.Decision {
		t.Error("Expected decision=false for invalid JSON")
	}
}

func TestSupportsResolutionOnly(t *testing.T) {
	reg := newTestRegistry(t, nil)
	if !reg.SupportsResolutionOnly() {
		t.Error("Expected SupportsResolutionOnly() = true")
	}
}

func TestSupportedResourceTypes(t *testing.T) {
	reg := newTestRegistry(t, nil)
	types := reg.SupportedResourceTypes()
	if len(types) != 0 {
		t.Errorf("Expected empty SupportedResourceTypes, got %v", types)
	}
}

func TestInfo(t *testing.T) {
	reg := newTestRegistry(t, nil)
	info := reg.Info()
	if info.Type != "issuer_url" {
		t.Errorf("Expected type 'issuer_url', got %q", info.Type)
	}
	if !info.ResolutionOnly {
		t.Error("Expected ResolutionOnly=true in info")
	}
}


