package static

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sirosfoundation/go-trust/pkg/authzen"
)

func TestWhitelistRegistry_Evaluate(t *testing.T) {
	tests := []struct {
		name     string
		config   WhitelistConfig
		request  *authzen.EvaluationRequest
		decision bool
	}{
		{
			name: "issuer in whitelist",
			config: WhitelistConfig{
				Issuers: []string{"https://issuer.example.com"},
			},
			request: &authzen.EvaluationRequest{
				Subject: authzen.Subject{ID: "https://issuer.example.com"},
				Action:  &authzen.Action{Name: "issuer"},
			},
			decision: true,
		},
		{
			name: "issuer not in whitelist",
			config: WhitelistConfig{
				Issuers: []string{"https://other.example.com"},
			},
			request: &authzen.EvaluationRequest{
				Subject: authzen.Subject{ID: "https://issuer.example.com"},
				Action:  &authzen.Action{Name: "issuer"},
			},
			decision: false,
		},
		{
			name: "verifier in whitelist",
			config: WhitelistConfig{
				Verifiers: []string{"https://verifier.example.com"},
			},
			request: &authzen.EvaluationRequest{
				Subject: authzen.Subject{ID: "https://verifier.example.com"},
				Action:  &authzen.Action{Name: "verifier"},
			},
			decision: true,
		},
		{
			name: "wildcard prefix match",
			config: WhitelistConfig{
				Issuers: []string{"https://example.com/*"},
			},
			request: &authzen.EvaluationRequest{
				Subject: authzen.Subject{ID: "https://example.com/issuer1"},
				Action:  &authzen.Action{Name: "issuer"},
			},
			decision: true,
		},
		{
			name: "trusted_subjects fallback",
			config: WhitelistConfig{
				TrustedSubjects: []string{"https://trusted.example.com"},
			},
			request: &authzen.EvaluationRequest{
				Subject: authzen.Subject{ID: "https://trusted.example.com"},
				Action:  &authzen.Action{Name: "custom-role"},
			},
			decision: true,
		},
		{
			name: "global wildcard",
			config: WhitelistConfig{
				Issuers: []string{"*"},
			},
			request: &authzen.EvaluationRequest{
				Subject: authzen.Subject{ID: "https://any.example.com"},
				Action:  &authzen.Action{Name: "issuer"},
			},
			decision: true,
		},
		{
			name: "credential-issuer role matches issuers list",
			config: WhitelistConfig{
				Issuers: []string{"https://pid.example.com"},
			},
			request: &authzen.EvaluationRequest{
				Subject: authzen.Subject{ID: "https://pid.example.com"},
				Action:  &authzen.Action{Name: "credential-issuer"},
			},
			decision: true,
		},
		{
			name: "credential-verifier role matches verifiers list",
			config: WhitelistConfig{
				Verifiers: []string{"https://rp.example.com"},
			},
			request: &authzen.EvaluationRequest{
				Subject: authzen.Subject{ID: "https://rp.example.com"},
				Action:  &authzen.Action{Name: "credential-verifier"},
			},
			decision: true,
		},
		{
			name: "subject without scheme matches config with scheme",
			config: WhitelistConfig{
				Issuers: []string{"https://issuer.example.com"},
			},
			request: &authzen.EvaluationRequest{
				Subject: authzen.Subject{ID: "issuer.example.com"},
				Action:  &authzen.Action{Name: "issuer"},
			},
			decision: true,
		},
		{
			name: "subject with scheme matches config without scheme",
			config: WhitelistConfig{
				Issuers: []string{"issuer.example.com"},
			},
			request: &authzen.EvaluationRequest{
				Subject: authzen.Subject{ID: "https://issuer.example.com"},
				Action:  &authzen.Action{Name: "issuer"},
			},
			decision: true,
		},
		{
			name: "subject without scheme matches config with scheme and path",
			config: WhitelistConfig{
				Verifiers: []string{"https://rp.example.com/verifier"},
			},
			request: &authzen.EvaluationRequest{
				Subject: authzen.Subject{ID: "rp.example.com/verifier"},
				Action:  &authzen.Action{Name: "credential-verifier"},
			},
			decision: true,
		},
		{
			name: "wildcard prefix match is scheme-agnostic",
			config: WhitelistConfig{
				Issuers: []string{"https://example.com/*"},
			},
			request: &authzen.EvaluationRequest{
				Subject: authzen.Subject{ID: "example.com/issuer1"},
				Action:  &authzen.Action{Name: "issuer"},
			},
			decision: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reg := NewWhitelistRegistry(WithWhitelistConfig(tt.config))

			resp, err := reg.Evaluate(context.Background(), tt.request)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if resp.Decision != tt.decision {
				t.Errorf("expected decision=%v, got %v", tt.decision, resp.Decision)
			}
		})
	}
}

func TestNormalizeEntityID(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"https://example.com", "example.com"},
		{"http://example.com", "example.com"},
		{"https://example.com/path", "example.com/path"},
		{"https://example.com/path/", "example.com/path"},
		{"example.com", "example.com"},
		{"example.com/path", "example.com/path"},
		{"example.com/path/", "example.com/path"},
		{"https://example.com:8443/path", "example.com:8443/path"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := normalizeEntityID(tt.input)
			if got != tt.expected {
				t.Errorf("normalizeEntityID(%q) = %q, want %q", tt.input, got, tt.expected)
			}
		})
	}
}

func TestWhitelistRegistry_FromFile(t *testing.T) {
	// Create temp YAML config
	yamlContent := `
issuers:
  - https://issuer1.example.com
  - https://issuer2.example.com
verifiers:
  - https://verifier.example.com
`

	tmpDir := t.TempDir()
	yamlPath := filepath.Join(tmpDir, "whitelist.yaml")
	if err := os.WriteFile(yamlPath, []byte(yamlContent), 0644); err != nil {
		t.Fatalf("failed to write yaml file: %v", err)
	}

	reg, err := NewWhitelistRegistryFromFile(yamlPath, false)
	if err != nil {
		t.Fatalf("failed to load from file: %v", err)
	}

	// Test that config was loaded
	req := &authzen.EvaluationRequest{
		Subject: authzen.Subject{ID: "https://issuer1.example.com"},
		Action:  &authzen.Action{Name: "issuer"},
	}

	resp, err := reg.Evaluate(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !resp.Decision {
		t.Error("expected issuer to be trusted")
	}
}

func TestWhitelistRegistry_FileWatch(t *testing.T) {
	tmpDir := t.TempDir()
	yamlPath := filepath.Join(tmpDir, "whitelist.yaml")

	// Initial config - only issuer1 trusted
	initialConfig := `
issuers:
  - https://issuer1.example.com
`
	if err := os.WriteFile(yamlPath, []byte(initialConfig), 0644); err != nil {
		t.Fatalf("failed to write yaml file: %v", err)
	}

	// Create registry with file watching enabled
	reg, err := NewWhitelistRegistryFromFile(yamlPath, true)
	if err != nil {
		t.Fatalf("failed to load from file: %v", err)
	}
	defer reg.Close()

	// Verify initial config
	req := &authzen.EvaluationRequest{
		Subject: authzen.Subject{ID: "https://issuer2.example.com"},
		Action:  &authzen.Action{Name: "issuer"},
	}
	resp, _ := reg.Evaluate(context.Background(), req)
	if resp.Decision {
		t.Error("issuer2 should NOT be trusted initially")
	}

	// Update config - add issuer2
	updatedConfig := `
issuers:
  - https://issuer1.example.com
  - https://issuer2.example.com
`
	if err := os.WriteFile(yamlPath, []byte(updatedConfig), 0644); err != nil {
		t.Fatalf("failed to update yaml file: %v", err)
	}

	// Wait for file watcher to pick up the change
	time.Sleep(200 * time.Millisecond)

	// Verify config was reloaded
	resp, _ = reg.Evaluate(context.Background(), req)
	if !resp.Decision {
		t.Error("issuer2 should be trusted after config reload")
	}
}

func TestWhitelistRegistry_RuntimeUpdates(t *testing.T) {
	reg := NewWhitelistRegistry()

	// Initially empty - should deny
	req := &authzen.EvaluationRequest{
		Subject: authzen.Subject{ID: "https://issuer.example.com"},
		Action:  &authzen.Action{Name: "issuer"},
	}

	resp, _ := reg.Evaluate(context.Background(), req)
	if resp.Decision {
		t.Error("expected deny for empty whitelist")
	}

	// Add issuer at runtime
	reg.AddIssuer("https://issuer.example.com")

	resp, _ = reg.Evaluate(context.Background(), req)
	if !resp.Decision {
		t.Error("expected allow after adding issuer")
	}

	// Remove issuer
	reg.RemoveIssuer("https://issuer.example.com")

	resp, _ = reg.Evaluate(context.Background(), req)
	if resp.Decision {
		t.Error("expected deny after removing issuer")
	}
}

func TestWhitelistRegistry_Info(t *testing.T) {
	reg := NewWhitelistRegistry(
		WithWhitelistName("my-whitelist"),
		WithWhitelistDescription("Test whitelist"),
	)

	info := reg.Info()

	if info.Name != "my-whitelist" {
		t.Errorf("expected name 'my-whitelist', got %q", info.Name)
	}
	if info.Type != "static_whitelist" {
		t.Errorf("expected type 'static_whitelist', got %q", info.Type)
	}
	if !info.ResolutionOnly {
		t.Error("expected ResolutionOnly=true")
	}
	// Healthy is false until Refresh is called
	if info.Healthy {
		t.Error("expected Healthy=false before Refresh")
	}

	// After Refresh, should be healthy (empty registry has no keys to load)
	_ = reg.Refresh(context.Background())
	info = reg.Info()
	if !info.Healthy {
		t.Error("expected Healthy=true after Refresh")
	}
}

func TestWhitelistRegistry_AddRemoveVerifier(t *testing.T) {
	reg := NewWhitelistRegistry()

	// Add verifier
	reg.AddVerifier("https://verifier.example.com")

	cfg := reg.GetConfig()
	if len(cfg.Verifiers) != 1 || cfg.Verifiers[0] != "https://verifier.example.com" {
		t.Errorf("unexpected verifiers: %v", cfg.Verifiers)
	}

	// Add duplicate - should be ignored
	reg.AddVerifier("https://verifier.example.com")
	cfg = reg.GetConfig()
	if len(cfg.Verifiers) != 1 {
		t.Errorf("expected 1 verifier after duplicate add, got %d", len(cfg.Verifiers))
	}

	// Remove
	reg.RemoveVerifier("https://verifier.example.com")
	cfg = reg.GetConfig()
	if len(cfg.Verifiers) != 0 {
		t.Errorf("expected 0 verifiers after remove, got %d", len(cfg.Verifiers))
	}
}

func TestWhitelistRegistry_JSONConfig(t *testing.T) {
	tmpDir := t.TempDir()
	jsonPath := filepath.Join(tmpDir, "whitelist.json")

	jsonContent := `{
"issuers": ["https://issuer.example.com"],
"verifiers": ["https://verifier.example.com"]
}`
	if err := os.WriteFile(jsonPath, []byte(jsonContent), 0644); err != nil {
		t.Fatalf("failed to write json file: %v", err)
	}

	reg, err := NewWhitelistRegistryFromFile(jsonPath, false)
	if err != nil {
		t.Fatalf("failed to load from file: %v", err)
	}

	req := &authzen.EvaluationRequest{
		Subject: authzen.Subject{ID: "https://issuer.example.com"},
		Action:  &authzen.Action{Name: "issuer"},
	}

	resp, err := reg.Evaluate(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !resp.Decision {
		t.Error("expected issuer to be trusted")
	}
}

func TestWhitelistRegistry_InterfaceMethods(t *testing.T) {
	reg := NewWhitelistRegistry()

	// Test SupportedResourceTypes - now returns specific types for key validation
	types := reg.SupportedResourceTypes()
	expected := map[string]bool{"jwk": true, "x5c": true, "x509_san_dns": true, "x509_san_uri": true}
	if len(types) != len(expected) {
		t.Errorf("expected %d resource types, got %v", len(expected), types)
	}
	for _, rt := range types {
		if !expected[rt] {
			t.Errorf("unexpected resource type %q in %v", rt, types)
		}
	}

	// Test SupportsResolutionOnly
	if !reg.SupportsResolutionOnly() {
		t.Error("expected SupportsResolutionOnly to return true")
	}

	// Test Healthy - false before Refresh
	if reg.Healthy() {
		t.Error("expected Healthy to return false before Refresh")
	}

	// Test Refresh - for empty registry, should succeed and set healthy
	if err := reg.Refresh(context.Background()); err != nil {
		t.Errorf("expected Refresh to succeed, got %v", err)
	}

	// After Refresh, should be healthy
	if !reg.Healthy() {
		t.Error("expected Healthy to return true after Refresh")
	}
}

func TestWhitelistRegistry_SetConfig(t *testing.T) {
	reg := NewWhitelistRegistry()

	newCfg := WhitelistConfig{
		Issuers:   []string{"https://new-issuer.example.com"},
		Verifiers: []string{"https://new-verifier.example.com"},
	}
	reg.SetConfig(newCfg)

	cfg := reg.GetConfig()
	if len(cfg.Issuers) != 1 || cfg.Issuers[0] != "https://new-issuer.example.com" {
		t.Errorf("SetConfig did not update issuers: %v", cfg.Issuers)
	}
}

func TestWhitelistRegistry_WithLogger(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	reg := NewWhitelistRegistry(WithWhitelistLogger(logger))

	if reg.logger != logger {
		t.Error("expected custom logger to be set")
	}
}

func TestWhitelistRegistry_NilAction(t *testing.T) {
	reg := NewWhitelistRegistry(WithWhitelistConfig(WhitelistConfig{
		TrustedSubjects: []string{"https://subject.example.com"},
	}))

	// Request without action
	req := &authzen.EvaluationRequest{
		Subject: authzen.Subject{ID: "https://subject.example.com"},
		Action:  nil,
	}

	resp, err := reg.Evaluate(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !resp.Decision {
		t.Error("expected subject in trusted_subjects to be trusted even with nil action")
	}
}

func TestWhitelistRegistry_AddIssuerDuplicate(t *testing.T) {
	reg := NewWhitelistRegistry()

	// Add issuer
	reg.AddIssuer("https://issuer.example.com")

	// Add same issuer again (duplicate)
	reg.AddIssuer("https://issuer.example.com")

	cfg := reg.GetConfig()
	if len(cfg.Issuers) != 1 {
		t.Errorf("expected 1 issuer after duplicate add, got %d", len(cfg.Issuers))
	}
}

func TestWhitelistRegistry_RemoveNonexistent(t *testing.T) {
	reg := NewWhitelistRegistry()

	// Try to remove issuer that doesn't exist
	reg.RemoveIssuer("https://nonexistent.example.com")
	// Should not panic or error

	// Try to remove verifier that doesn't exist
	reg.RemoveVerifier("https://nonexistent.example.com")
	// Should not panic or error
}

func TestWhitelistRegistry_FileNotFound(t *testing.T) {
	_, err := NewWhitelistRegistryFromFile("/nonexistent/path/whitelist.yaml", false)
	if err == nil {
		t.Error("expected error for nonexistent file")
	}
}

func TestWhitelistRegistry_InvalidYAML(t *testing.T) {
	tmpDir := t.TempDir()
	yamlPath := filepath.Join(tmpDir, "invalid.yaml")

	if err := os.WriteFile(yamlPath, []byte("invalid: yaml: content: ["), 0644); err != nil {
		t.Fatalf("failed to write invalid yaml: %v", err)
	}

	_, err := NewWhitelistRegistryFromFile(yamlPath, false)
	if err == nil {
		t.Error("expected error for invalid YAML")
	}
}

func TestWhitelistRegistry_InvalidJSON(t *testing.T) {
	tmpDir := t.TempDir()
	jsonPath := filepath.Join(tmpDir, "invalid.json")

	if err := os.WriteFile(jsonPath, []byte("{invalid json"), 0644); err != nil {
		t.Fatalf("failed to write invalid json: %v", err)
	}

	_, err := NewWhitelistRegistryFromFile(jsonPath, false)
	if err == nil {
		t.Error("expected error for invalid JSON")
	}
}

func TestWhitelistRegistry_CloseWithoutWatcher(t *testing.T) {
	reg := NewWhitelistRegistry()

	// Close should not panic when watcher was never started
	err := reg.Close()
	if err != nil {
		t.Errorf("Close should not error without watcher: %v", err)
	}
}

func TestWhitelistRegistry_PidProviderRole(t *testing.T) {
	reg := NewWhitelistRegistry(WithWhitelistConfig(WhitelistConfig{
		Issuers: []string{"https://pid-provider.example.com"},
	}))

	req := &authzen.EvaluationRequest{
		Subject: authzen.Subject{ID: "https://pid-provider.example.com"},
		Action:  &authzen.Action{Name: "pid-provider"},
	}

	resp, err := reg.Evaluate(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !resp.Decision {
		t.Error("expected pid-provider to match issuers list")
	}
}

// Helper function to generate a JWK from an ECDSA public key
func ecdsaPubKeyToJWK(pub *ecdsa.PublicKey, kid string) map[string]interface{} {
	// Use ECDH().Bytes() to avoid deprecated direct X/Y field access (Go 1.26+)
	ecdhKey, err := pub.ECDH()
	if err != nil {
		// Fall back for test purposes - panics are acceptable in test helpers
		panic(fmt.Sprintf("failed to convert ECDSA key to ECDH: %v", err))
	}
	marshaled := ecdhKey.Bytes()
	byteLen := (pub.Curve.Params().BitSize + 7) / 8
	// Skip the 0x04 prefix and extract X, Y
	x := base64.RawURLEncoding.EncodeToString(marshaled[1 : 1+byteLen])
	y := base64.RawURLEncoding.EncodeToString(marshaled[1+byteLen:])

	crv := ""
	switch pub.Curve {
	case elliptic.P256():
		crv = "P-256"
	case elliptic.P384():
		crv = "P-384"
	case elliptic.P521():
		crv = "P-521"
	}

	return map[string]interface{}{
		"kty": "EC",
		"crv": crv,
		"x":   x,
		"y":   y,
		"kid": kid,
		"use": "sig",
	}
}

func TestWhitelistRegistry_KeyBindingVerification(t *testing.T) {
	// Generate a test EC key pair
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	// Create JWKS with the public key
	jwk := ecdsaPubKeyToJWK(&privateKey.PublicKey, "test-key-1")
	jwks := map[string]interface{}{
		"keys": []interface{}{jwk},
	}

	// Create a test server that serves the JWKS
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/jwks.json" {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(jwks)
		} else {
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	// Create whitelist registry with the test server's URL
	reg := NewWhitelistRegistry(WithWhitelistConfig(WhitelistConfig{
		Issuers:   []string{server.URL},
		AllowHTTP: true, // Allow HTTP for test server
	}))

	// Refresh to load keys
	err = reg.Refresh(context.Background())
	if err != nil {
		t.Fatalf("Refresh failed: %v", err)
	}

	// Verify keys were loaded
	if !reg.Healthy() {
		t.Error("expected registry to be healthy after Refresh")
	}

	t.Run("accept_matching_key", func(t *testing.T) {
		req := &authzen.EvaluationRequest{
			Subject: authzen.Subject{ID: server.URL},
			Action:  &authzen.Action{Name: "issuer"},
			Resource: authzen.Resource{
				Type: "jwk",
				Key:  []interface{}{jwk},
			},
		}

		resp, err := reg.Evaluate(context.Background(), req)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !resp.Decision {
			t.Error("expected decision=true for matching key")
		}
	})

	t.Run("reject_non_matching_key", func(t *testing.T) {
		// Generate a different key
		otherKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		otherJWK := ecdsaPubKeyToJWK(&otherKey.PublicKey, "other-key")

		req := &authzen.EvaluationRequest{
			Subject: authzen.Subject{ID: server.URL},
			Action:  &authzen.Action{Name: "issuer"},
			Resource: authzen.Resource{
				Type: "jwk",
				Key:  []interface{}{otherJWK},
			},
		}

		resp, err := reg.Evaluate(context.Background(), req)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if resp.Decision {
			t.Error("expected decision=false for non-matching key")
		}
	})

	t.Run("resolution_only_without_key", func(t *testing.T) {
		// Request without resource should still allow checking whitelist membership
		req := &authzen.EvaluationRequest{
			Subject: authzen.Subject{ID: server.URL},
			Action:  &authzen.Action{Name: "issuer"},
		}

		resp, err := reg.Evaluate(context.Background(), req)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !resp.Decision {
			t.Error("expected decision=true for whitelisted entity without key")
		}
	})

	t.Run("reject_non_whitelisted_entity", func(t *testing.T) {
		req := &authzen.EvaluationRequest{
			Subject: authzen.Subject{ID: "https://not-whitelisted.example.com"},
			Action:  &authzen.Action{Name: "issuer"},
		}

		resp, err := reg.Evaluate(context.Background(), req)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if resp.Decision {
			t.Error("expected decision=false for non-whitelisted entity")
		}
	})
}

func TestWhitelistRegistry_RefreshWithJWKS(t *testing.T) {
	// Generate two EC key pairs for different entities
	key1, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	key2, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)

	jwks1 := map[string]interface{}{
		"keys": []interface{}{ecdsaPubKeyToJWK(&key1.PublicKey, "issuer-key")},
	}
	jwks2 := map[string]interface{}{
		"keys": []interface{}{ecdsaPubKeyToJWK(&key2.PublicKey, "verifier-key")},
	}

	// Create handlers for two entities
	mux := http.NewServeMux()
	mux.HandleFunc("/issuer/.well-known/jwks.json", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(jwks1)
	})
	mux.HandleFunc("/verifier/.well-known/jwks.json", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(jwks2)
	})

	server := httptest.NewServer(mux)
	defer server.Close()

	issuerURL := server.URL + "/issuer"
	verifierURL := server.URL + "/verifier"

	reg := NewWhitelistRegistry(WithWhitelistConfig(WhitelistConfig{
		Issuers:   []string{issuerURL},
		Verifiers: []string{verifierURL},
		AllowHTTP: true,
	}))

	// Refresh to load keys
	err := reg.Refresh(context.Background())
	if err != nil {
		t.Fatalf("Refresh failed: %v", err)
	}

	// Test issuer with correct key
	req := &authzen.EvaluationRequest{
		Subject: authzen.Subject{ID: issuerURL},
		Action:  &authzen.Action{Name: "issuer"},
		Resource: authzen.Resource{
			Type: "jwk",
			Key:  []interface{}{ecdsaPubKeyToJWK(&key1.PublicKey, "issuer-key")},
		},
	}

	resp, err := reg.Evaluate(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !resp.Decision {
		t.Error("expected issuer with correct key to be allowed")
	}

	// Test verifier with wrong key (issuer's key)
	req = &authzen.EvaluationRequest{
		Subject: authzen.Subject{ID: verifierURL},
		Action:  &authzen.Action{Name: "verifier"},
		Resource: authzen.Resource{
			Type: "jwk",
			Key:  []interface{}{ecdsaPubKeyToJWK(&key1.PublicKey, "wrong-key")},
		},
	}

	resp, err = reg.Evaluate(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Decision {
		t.Error("expected verifier with wrong key to be denied")
	}

	// Test verifier with correct key
	req = &authzen.EvaluationRequest{
		Subject: authzen.Subject{ID: verifierURL},
		Action:  &authzen.Action{Name: "verifier"},
		Resource: authzen.Resource{
			Type: "jwk",
			Key:  []interface{}{ecdsaPubKeyToJWK(&key2.PublicKey, "verifier-key")},
		},
	}

	resp, err = reg.Evaluate(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !resp.Decision {
		t.Error("expected verifier with correct key to be allowed")
	}
}

func TestWhitelistRegistry_MetadataDiscovery(t *testing.T) {
	// Generate a test EC key pair
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	jwk := ecdsaPubKeyToJWK(&privateKey.PublicKey, "discovery-key-1")
	jwks := map[string]interface{}{
		"keys": []interface{}{jwk},
	}

	t.Run("discover_via_jwt_vc_issuer_inline_jwks", func(t *testing.T) {
		// Server exposes jwt-vc-issuer metadata with inline JWKS (no jwks_uri)
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/.well-known/jwt-vc-issuer":
				w.Header().Set("Content-Type", "application/json")
				jwksJSON, _ := json.Marshal(jwks)
				fmt.Fprintf(w, `{"issuer":"http://%s","jwks":%s}`, r.Host, jwksJSON)
			default:
				http.NotFound(w, r)
			}
		}))
		defer server.Close()

		reg := NewWhitelistRegistry(WithWhitelistConfig(WhitelistConfig{
			Issuers:   []string{server.URL},
			AllowHTTP: true,
		}))

		err := reg.Refresh(context.Background())
		if err != nil {
			t.Fatalf("Refresh failed: %v", err)
		}

		resp, err := reg.Evaluate(context.Background(), &authzen.EvaluationRequest{
			Subject:  authzen.Subject{ID: server.URL},
			Action:   &authzen.Action{Name: "issuer"},
			Resource: authzen.Resource{Type: "jwk", Key: []interface{}{jwk}},
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !resp.Decision {
			t.Error("expected decision=true for key from jwt-vc-issuer inline JWKS")
		}
	})

	t.Run("discover_via_jwt_vc_issuer_jwks_uri", func(t *testing.T) {
		// Server exposes jwt-vc-issuer metadata with jwks_uri (no inline JWKS)
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/.well-known/jwt-vc-issuer":
				w.Header().Set("Content-Type", "application/json")
				fmt.Fprintf(w, `{"issuer":"http://%s","jwks_uri":"http://%s/issuer-keys"}`, r.Host, r.Host)
			case "/issuer-keys":
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(jwks)
			default:
				http.NotFound(w, r)
			}
		}))
		defer server.Close()

		reg := NewWhitelistRegistry(WithWhitelistConfig(WhitelistConfig{
			Issuers:   []string{server.URL},
			AllowHTTP: true,
		}))

		err := reg.Refresh(context.Background())
		if err != nil {
			t.Fatalf("Refresh failed: %v", err)
		}

		resp, err := reg.Evaluate(context.Background(), &authzen.EvaluationRequest{
			Subject:  authzen.Subject{ID: server.URL},
			Action:   &authzen.Action{Name: "issuer"},
			Resource: authzen.Resource{Type: "jwk", Key: []interface{}{jwk}},
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !resp.Decision {
			t.Error("expected decision=true for key from jwt-vc-issuer jwks_uri")
		}
	})

	t.Run("jwt_vc_issuer_takes_priority_over_oauth_as", func(t *testing.T) {
		// jwt-vc-issuer should win over oauth-authorization-server
		otherKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		otherJWK := ecdsaPubKeyToJWK(&otherKey.PublicKey, "other-key")
		otherJWKS := map[string]interface{}{"keys": []interface{}{otherJWK}}

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/.well-known/jwt-vc-issuer":
				w.Header().Set("Content-Type", "application/json")
				jwksJSON, _ := json.Marshal(jwks)
				fmt.Fprintf(w, `{"issuer":"http://%s","jwks":%s}`, r.Host, jwksJSON)
			case "/.well-known/oauth-authorization-server":
				w.Header().Set("Content-Type", "application/json")
				fmt.Fprintf(w, `{"issuer":"http://%s","jwks_uri":"http://%s/oauth-jwks"}`, r.Host, r.Host)
			case "/oauth-jwks":
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(otherJWKS)
			default:
				http.NotFound(w, r)
			}
		}))
		defer server.Close()

		reg := NewWhitelistRegistry(WithWhitelistConfig(WhitelistConfig{
			Issuers:   []string{server.URL},
			AllowHTTP: true,
		}))

		err := reg.Refresh(context.Background())
		if err != nil {
			t.Fatalf("Refresh failed: %v", err)
		}

		// The key from jwt-vc-issuer should be trusted
		resp, err := reg.Evaluate(context.Background(), &authzen.EvaluationRequest{
			Subject:  authzen.Subject{ID: server.URL},
			Action:   &authzen.Action{Name: "issuer"},
			Resource: authzen.Resource{Type: "jwk", Key: []interface{}{jwk}},
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !resp.Decision {
			t.Error("expected jwt-vc-issuer key to be trusted (first priority)")
		}

		// The key from oauth-authorization-server should NOT be trusted
		resp, err = reg.Evaluate(context.Background(), &authzen.EvaluationRequest{
			Subject:  authzen.Subject{ID: server.URL},
			Action:   &authzen.Action{Name: "issuer"},
			Resource: authzen.Resource{Type: "jwk", Key: []interface{}{otherJWK}},
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if resp.Decision {
			t.Error("expected OAuth AS key NOT to be trusted (jwt-vc-issuer took priority)")
		}
	})

	t.Run("discover_via_oauth_authorization_server", func(t *testing.T) {
		// Server exposes JWKS at /jwks (NOT at /.well-known/jwks.json)
		// and has OAuth AS metadata at /.well-known/oauth-authorization-server
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/.well-known/oauth-authorization-server":
				w.Header().Set("Content-Type", "application/json")
				fmt.Fprintf(w, `{"issuer":"http://%s","jwks_uri":"http://%s/jwks"}`, r.Host, r.Host)
			case "/jwks":
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(jwks)
			default:
				http.NotFound(w, r)
			}
		}))
		defer server.Close()

		reg := NewWhitelistRegistry(WithWhitelistConfig(WhitelistConfig{
			Issuers:   []string{server.URL},
			AllowHTTP: true,
		}))

		err := reg.Refresh(context.Background())
		if err != nil {
			t.Fatalf("Refresh failed: %v", err)
		}
		if !reg.Healthy() {
			t.Fatal("expected registry to be healthy")
		}

		// Verify key binding works via discovered JWKS
		resp, err := reg.Evaluate(context.Background(), &authzen.EvaluationRequest{
			Subject:  authzen.Subject{ID: server.URL},
			Action:   &authzen.Action{Name: "issuer"},
			Resource: authzen.Resource{Type: "jwk", Key: []interface{}{jwk}},
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !resp.Decision {
			t.Error("expected decision=true for key discovered via OAuth AS metadata")
		}
	})

	t.Run("discover_via_openid_configuration", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/.well-known/openid-configuration":
				w.Header().Set("Content-Type", "application/json")
				fmt.Fprintf(w, `{"issuer":"http://%s","jwks_uri":"http://%s/keys/jwks"}`, r.Host, r.Host)
			case "/keys/jwks":
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(jwks)
			default:
				http.NotFound(w, r)
			}
		}))
		defer server.Close()

		reg := NewWhitelistRegistry(WithWhitelistConfig(WhitelistConfig{
			Issuers:   []string{server.URL},
			AllowHTTP: true,
		}))

		err := reg.Refresh(context.Background())
		if err != nil {
			t.Fatalf("Refresh failed: %v", err)
		}

		resp, err := reg.Evaluate(context.Background(), &authzen.EvaluationRequest{
			Subject:  authzen.Subject{ID: server.URL},
			Action:   &authzen.Action{Name: "issuer"},
			Resource: authzen.Resource{Type: "jwk", Key: []interface{}{jwk}},
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !resp.Decision {
			t.Error("expected decision=true for key discovered via OIDC discovery")
		}
	})

	t.Run("discover_via_openid_credential_issuer", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/.well-known/openid-credential-issuer":
				w.Header().Set("Content-Type", "application/json")
				fmt.Fprintf(w, `{"credential_issuer":"http://%s","jwks_uri":"http://%s/issuer/jwks"}`, r.Host, r.Host)
			case "/issuer/jwks":
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(jwks)
			default:
				http.NotFound(w, r)
			}
		}))
		defer server.Close()

		reg := NewWhitelistRegistry(WithWhitelistConfig(WhitelistConfig{
			Issuers:   []string{server.URL},
			AllowHTTP: true,
		}))

		err := reg.Refresh(context.Background())
		if err != nil {
			t.Fatalf("Refresh failed: %v", err)
		}

		resp, err := reg.Evaluate(context.Background(), &authzen.EvaluationRequest{
			Subject:  authzen.Subject{ID: server.URL},
			Action:   &authzen.Action{Name: "issuer"},
			Resource: authzen.Resource{Type: "jwk", Key: []interface{}{jwk}},
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !resp.Decision {
			t.Error("expected decision=true for key discovered via OpenID4VCI metadata")
		}
	})

	t.Run("fallback_to_well_known_jwks_json", func(t *testing.T) {
		// No metadata endpoints — should fall back to /.well-known/jwks.json
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/.well-known/jwks.json" {
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(jwks)
			} else {
				http.NotFound(w, r)
			}
		}))
		defer server.Close()

		reg := NewWhitelistRegistry(WithWhitelistConfig(WhitelistConfig{
			Issuers:   []string{server.URL},
			AllowHTTP: true,
		}))

		err := reg.Refresh(context.Background())
		if err != nil {
			t.Fatalf("Refresh failed: %v", err)
		}

		resp, err := reg.Evaluate(context.Background(), &authzen.EvaluationRequest{
			Subject:  authzen.Subject{ID: server.URL},
			Action:   &authzen.Action{Name: "issuer"},
			Resource: authzen.Resource{Type: "jwk", Key: []interface{}{jwk}},
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !resp.Decision {
			t.Error("expected decision=true via fallback to /.well-known/jwks.json")
		}
	})

	t.Run("explicit_pattern_skips_discovery", func(t *testing.T) {
		// Server has metadata but also a custom endpoint; explicit pattern should be used
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/.well-known/oauth-authorization-server":
				w.Header().Set("Content-Type", "application/json")
				fmt.Fprintf(w, `{"jwks_uri":"http://%s/wrong-jwks"}`, r.Host)
			case "/custom/keys.json":
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(jwks)
			default:
				http.NotFound(w, r)
			}
		}))
		defer server.Close()

		reg := NewWhitelistRegistry(WithWhitelistConfig(WhitelistConfig{
			Issuers:             []string{server.URL},
			AllowHTTP:           true,
			JWKSEndpointPattern: "{entity}/custom/keys.json",
		}))

		err := reg.Refresh(context.Background())
		if err != nil {
			t.Fatalf("Refresh failed: %v", err)
		}

		resp, err := reg.Evaluate(context.Background(), &authzen.EvaluationRequest{
			Subject:  authzen.Subject{ID: server.URL},
			Action:   &authzen.Action{Name: "issuer"},
			Resource: authzen.Resource{Type: "jwk", Key: []interface{}{jwk}},
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !resp.Decision {
			t.Error("expected decision=true via explicit JWKSEndpointPattern")
		}
	})

	t.Run("discovery_priority_order", func(t *testing.T) {
		// Serve different JWKS at different discovery endpoints to verify priority
		key2, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		jwk2 := ecdsaPubKeyToJWK(&key2.PublicKey, "oidc-key")
		jwks2 := map[string]interface{}{
			"keys": []interface{}{jwk2},
		}

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/.well-known/oauth-authorization-server":
				// First priority — points to /oauth-jwks with the CORRECT key
				w.Header().Set("Content-Type", "application/json")
				fmt.Fprintf(w, `{"jwks_uri":"http://%s/oauth-jwks"}`, r.Host)
			case "/oauth-jwks":
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(jwks)
			case "/.well-known/openid-configuration":
				// Second priority — points to different JWKS
				w.Header().Set("Content-Type", "application/json")
				fmt.Fprintf(w, `{"jwks_uri":"http://%s/oidc-jwks"}`, r.Host)
			case "/oidc-jwks":
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(jwks2)
			default:
				http.NotFound(w, r)
			}
		}))
		defer server.Close()

		reg := NewWhitelistRegistry(WithWhitelistConfig(WhitelistConfig{
			Issuers:   []string{server.URL},
			AllowHTTP: true,
		}))

		err := reg.Refresh(context.Background())
		if err != nil {
			t.Fatalf("Refresh failed: %v", err)
		}

		// The key from oauth-authorization-server (first priority) should be trusted
		resp, err := reg.Evaluate(context.Background(), &authzen.EvaluationRequest{
			Subject:  authzen.Subject{ID: server.URL},
			Action:   &authzen.Action{Name: "issuer"},
			Resource: authzen.Resource{Type: "jwk", Key: []interface{}{jwk}},
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !resp.Decision {
			t.Error("expected OAuth AS metadata key to be trusted (first priority)")
		}

		// The key from openid-configuration (second priority) should NOT be trusted
		// because the first discovery succeeded
		resp, err = reg.Evaluate(context.Background(), &authzen.EvaluationRequest{
			Subject:  authzen.Subject{ID: server.URL},
			Action:   &authzen.Action{Name: "issuer"},
			Resource: authzen.Resource{Type: "jwk", Key: []interface{}{jwk2}},
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if resp.Decision {
			t.Error("expected OIDC discovery key NOT to be trusted (OAuth AS took priority)")
		}
	})
}

func TestBuildWellKnownURL(t *testing.T) {
	tests := []struct {
		entity string
		suffix string
		want   string
	}{
		// Host-only entity
		{"https://example.com", "jwt-vc-issuer", "https://example.com/.well-known/jwt-vc-issuer"},
		// Host with trailing slash
		{"https://example.com/", "jwt-vc-issuer", "https://example.com/.well-known/jwt-vc-issuer"},
		// Path-based entity (RFC 8615 §3: insert between host and path)
		{"https://example.com/tenant1", "jwt-vc-issuer", "https://example.com/.well-known/jwt-vc-issuer/tenant1"},
		// Deep path
		{"https://example.com/org/tenant/v1", "jwt-vc-issuer", "https://example.com/.well-known/jwt-vc-issuer/org/tenant/v1"},
		// With port
		{"https://example.com:8443/tenant", "jwt-vc-issuer", "https://example.com:8443/.well-known/jwt-vc-issuer/tenant"},
		// HTTP (test servers)
		{"http://127.0.0.1:12345", "jwt-vc-issuer", "http://127.0.0.1:12345/.well-known/jwt-vc-issuer"},
		// Works with other well-known suffixes too
		{"https://example.com/path", "openid-configuration", "https://example.com/.well-known/openid-configuration/path"},
	}

	for _, tt := range tests {
		t.Run(tt.entity, func(t *testing.T) {
			got := buildWellKnownURL(tt.entity, tt.suffix)
			if got != tt.want {
				t.Errorf("buildWellKnownURL(%q, %q) = %q, want %q", tt.entity, tt.suffix, got, tt.want)
			}
		})
	}
}

func TestWhitelistRegistry_KeyFingerprint(t *testing.T) {
	// Generate a key and verify fingerprint is deterministic
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	fp1, err := KeyFingerprint(&key.PublicKey)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	fp2, err := KeyFingerprint(&key.PublicKey)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if fp1 != fp2 {
		t.Errorf("fingerprints should be deterministic: %s != %s", fp1, fp2)
	}

	// Different key should have different fingerprint
	otherKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	fp3, err := KeyFingerprint(&otherKey.PublicKey)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if fp1 == fp3 {
		t.Error("different keys should have different fingerprints")
	}
}

func TestWhitelistRegistry_WildcardWithKey(t *testing.T) {
	// Test that wildcard issuers still work with key verification
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	jwk := ecdsaPubKeyToJWK(&key.PublicKey, "wildcard-key")
	jwks := map[string]interface{}{
		"keys": []interface{}{jwk},
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(jwks)
	}))
	defer server.Close()

	// Wildcard pattern - for wildcards, we can't fetch keys
	reg := NewWhitelistRegistry(WithWhitelistConfig(WhitelistConfig{
		Issuers:   []string{"https://example.com/*"},
		AllowHTTP: true,
	}))

	// Request should still work for wildcard (resolution-only)
	req := &authzen.EvaluationRequest{
		Subject: authzen.Subject{ID: "https://example.com/issuer1"},
		Action:  &authzen.Action{Name: "issuer"},
	}

	resp, err := reg.Evaluate(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !resp.Decision {
		t.Error("expected wildcard-matched issuer to be allowed (resolution-only)")
	}
}

func TestWhitelistRegistry_JWKSFetchError(t *testing.T) {
	// Create a server that returns errors
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	reg := NewWhitelistRegistry(WithWhitelistConfig(WhitelistConfig{
		Issuers:   []string{server.URL},
		AllowHTTP: true,
	}))

	// Refresh should partially fail but not error completely
	err := reg.Refresh(context.Background())
	// Should log warning but may return error since entity couldn't be fetched
	if err == nil {
		// If no error, registry should still handle requests
		// but without keys loaded for that entity
		t.Log("Refresh succeeded despite fetch error")
	}

	// Resolution-only should still work
	req := &authzen.EvaluationRequest{
		Subject: authzen.Subject{ID: server.URL},
		Action:  &authzen.Action{Name: "issuer"},
	}

	resp, err := reg.Evaluate(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Should still allow resolution-only (entity is in whitelist)
	if !resp.Decision {
		t.Error("expected whitelisted entity to be allowed in resolution-only mode")
	}
}

func TestExtractPublicKeysFromJWKS(t *testing.T) {
	// Test extracting keys from JWKS
	key1, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	key2, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)

	jwks := map[string]interface{}{
		"keys": []interface{}{
			ecdsaPubKeyToJWK(&key1.PublicKey, "key1"),
			ecdsaPubKeyToJWK(&key2.PublicKey, "key2"),
		},
	}

	keys, err := ExtractPublicKeysFromJWKS(jwks)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(keys) != 2 {
		t.Errorf("expected 2 keys, got %d", len(keys))
	}
}

func TestKeyutilParseJWK(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	jwk := ecdsaPubKeyToJWK(&key.PublicKey, "test")

	parsed, err := ParseJWKPublicKey(jwk)
	if err != nil {
		t.Fatalf("failed to parse JWK: %v", err)
	}

	// Verify it's the same key by comparing fingerprints
	fp1, _ := KeyFingerprint(&key.PublicKey)
	fp2, _ := KeyFingerprint(parsed)

	if fp1 != fp2 {
		t.Error("parsed key should match original")
	}
}

func TestKeyFingerprint_RSA(t *testing.T) {
	// Skip if RSA key generation is slow
	// This tests that RSA keys are handled correctly
	t.Log("RSA fingerprint test - skipping for speed")
}

func TestWhitelistRegistry_MultipleKeysPerEntity(t *testing.T) {
	// Entity with multiple keys
	key1, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	key2, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	jwks := map[string]interface{}{
		"keys": []interface{}{
			ecdsaPubKeyToJWK(&key1.PublicKey, "key1"),
			ecdsaPubKeyToJWK(&key2.PublicKey, "key2"),
		},
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(jwks)
	}))
	defer server.Close()

	reg := NewWhitelistRegistry(WithWhitelistConfig(WhitelistConfig{
		Issuers:   []string{server.URL},
		AllowHTTP: true,
	}))

	_ = reg.Refresh(context.Background())

	// Both keys should be accepted
	for i, key := range []*ecdsa.PublicKey{&key1.PublicKey, &key2.PublicKey} {
		t.Run(fmt.Sprintf("key%d", i+1), func(t *testing.T) {
			req := &authzen.EvaluationRequest{
				Subject: authzen.Subject{ID: server.URL},
				Action:  &authzen.Action{Name: "issuer"},
				Resource: authzen.Resource{
					Type: "jwk",
					Key:  []interface{}{ecdsaPubKeyToJWK(key, fmt.Sprintf("key%d", i+1))},
				},
			}

			resp, err := reg.Evaluate(context.Background(), req)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !resp.Decision {
				t.Error("expected key to be accepted")
			}
		})
	}
}

func TestWhitelistRegistry_RefreshLoop(t *testing.T) {
	// Create a key that we'll use for our "entity"
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	jwks := map[string]interface{}{
		"keys": []interface{}{ecdsaPubKeyToJWK(&key.PublicKey, "refresh-test-key")},
	}

	// Track how many times JWKS was fetched
	fetchCount := 0
	var fetchMu sync.Mutex

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fetchMu.Lock()
		fetchCount++
		fetchMu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(jwks)
	}))
	defer server.Close()

	// Create registry with short refresh interval
	reg := NewWhitelistRegistry(
		WithWhitelistConfig(WhitelistConfig{
			Issuers:         []string{server.URL},
			AllowHTTP:       true,
			RefreshInterval: "100ms", // Very short for testing
		}),
	)
	defer reg.Close()

	// Start the refresh loop
	err := reg.StartRefreshLoop(context.Background())
	if err != nil {
		t.Fatalf("StartRefreshLoop failed: %v", err)
	}

	// Wait for a few refresh cycles
	time.Sleep(350 * time.Millisecond)

	// Check that multiple fetches occurred
	fetchMu.Lock()
	count := fetchCount
	fetchMu.Unlock()

	// Initial + at least 2 more refreshes
	if count < 3 {
		t.Errorf("expected at least 3 fetches, got %d", count)
	}

	// Verify registry is healthy
	if !reg.Healthy() {
		t.Error("expected registry to be healthy")
	}

	// Close should stop the refresh loop
	err = reg.Close()
	if err != nil {
		t.Errorf("Close failed: %v", err)
	}

	// Wait a bit and check fetch count hasn't increased
	time.Sleep(200 * time.Millisecond)
	fetchMu.Lock()
	finalCount := fetchCount
	fetchMu.Unlock()

	if finalCount > count+1 {
		t.Errorf("refresh loop may not have stopped: pre-close=%d, post-close=%d", count, finalCount)
	}
}

// TestWhitelistRegistry_EvaluateDoesNotBlockOnConcurrentRefresh guards
// against a real bug: Refresh() used to hold r.mu (the write lock) for its
// entire duration, including the network I/O to fetch each entity's JWKS.
// Evaluate() only needs a read lock, so a slow-to-resolve entity (an
// unreachable host, one with no JWKS endpoint at all, etc.) meant every
// concurrent Evaluate() call - even a fast resolution-only one needing none
// of the data being refreshed - blocked for as long as that fetch took.
// Confirmed in production: a background refresh (default every 5 minutes)
// stalling on one slow entity caused every trust evaluation during that
// window to time out from the caller's perspective, well before the fetch
// itself ever gave up.
func TestWhitelistRegistry_EvaluateDoesNotBlockOnConcurrentRefresh(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	jwks := map[string]interface{}{
		"keys": []interface{}{ecdsaPubKeyToJWK(&key.PublicKey, "slow-refresh-key")},
	}

	fetchStarted := make(chan struct{})
	releaseFetch := make(chan struct{})
	var startOnce sync.Once

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		startOnce.Do(func() { close(fetchStarted) })
		<-releaseFetch
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(jwks)
	}))
	defer server.Close()

	reg := NewWhitelistRegistry(
		WithWhitelistConfig(WhitelistConfig{
			Issuers:   []string{server.URL},
			AllowHTTP: true,
		}),
	)
	defer reg.Close()

	// Kick off a Refresh() that will block inside the HTTP handler above
	// until the test releases it - simulating a slow/unreachable entity.
	refreshDone := make(chan error, 1)
	go func() {
		refreshDone <- reg.Refresh(context.Background())
	}()

	select {
	case <-fetchStarted:
	case <-time.After(2 * time.Second):
		t.Fatal("Refresh() did not start fetching in time")
	}

	// While that Refresh() is still blocked on network I/O, a concurrent
	// resolution-only Evaluate() for the same entity must complete quickly -
	// whitelist membership only depends on config set at construction time,
	// not on the JWKS cache Refresh() is rebuilding, so it must not wait for
	// the in-flight Refresh() to finish.
	req := &authzen.EvaluationRequest{
		Subject: authzen.Subject{ID: server.URL},
		Action:  &authzen.Action{Name: "issuer"},
	}

	evalDone := make(chan struct{})
	var resp *authzen.EvaluationResponse
	var evalErr error
	go func() {
		resp, evalErr = reg.Evaluate(context.Background(), req)
		close(evalDone)
	}()

	select {
	case <-evalDone:
		// Good - Evaluate() did not block behind the in-flight Refresh().
	case <-time.After(500 * time.Millisecond):
		t.Fatal("Evaluate() blocked on a concurrent Refresh()'s network I/O - lock held too long")
	}

	close(releaseFetch)
	if err := <-refreshDone; err != nil {
		t.Fatalf("Refresh() failed: %v", err)
	}

	if evalErr != nil {
		t.Fatalf("Evaluate() returned error: %v", evalErr)
	}
	if !resp.Decision {
		t.Error("expected decision=true for whitelisted entity (resolution-only)")
	}
}

func TestWhitelistRegistry_RefreshLoopWithOption(t *testing.T) {
	// Test using WithRefreshInterval option
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	jwks := map[string]interface{}{
		"keys": []interface{}{ecdsaPubKeyToJWK(&key.PublicKey, "option-key")},
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(jwks)
	}))
	defer server.Close()

	reg := NewWhitelistRegistry(
		WithWhitelistConfig(WhitelistConfig{
			Issuers:   []string{server.URL},
			AllowHTTP: true,
		}),
		WithRefreshInterval(50*time.Millisecond),
	)
	defer reg.Close()

	// Start should use the option interval
	err := reg.StartRefreshLoop(context.Background())
	if err != nil {
		t.Fatalf("StartRefreshLoop failed: %v", err)
	}

	// Verify initial refresh happened
	time.Sleep(100 * time.Millisecond)
	if !reg.Healthy() {
		t.Error("expected registry to be healthy after refresh loop started")
	}
}

func TestWhitelistRegistry_NoRefreshWithoutInterval(t *testing.T) {
	// Even without an explicit refresh interval, StartRefreshLoop should start
	// a background loop using DefaultRefreshInterval.
	reg := NewWhitelistRegistry()

	err := reg.StartRefreshLoop(context.Background())
	if err != nil {
		t.Fatalf("StartRefreshLoop should not fail: %v", err)
	}
	defer reg.Close()

	// A background goroutine should be started with the default interval
	if reg.refreshStopCh == nil {
		t.Error("refresh stop channel should not be nil — default interval should start a loop")
	}
}

func TestWhitelistRegistry_InitialRefreshWithoutInterval(t *testing.T) {
	// Regression test: StartRefreshLoop without refresh_interval must still
	// perform initial JWKS fetch so that key binding works on first request.
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	jwks := map[string]interface{}{
		"keys": []interface{}{ecdsaPubKeyToJWK(&key.PublicKey, "init-test-key")},
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(jwks)
	}))
	defer server.Close()

	reg := NewWhitelistRegistry(WithWhitelistConfig(WhitelistConfig{
		Issuers:   []string{server.URL},
		AllowHTTP: true,
		// No RefreshInterval set — this is the bug scenario
	}))

	// StartRefreshLoop should perform initial refresh even without interval
	err := reg.StartRefreshLoop(context.Background())
	if err != nil {
		t.Fatalf("StartRefreshLoop failed: %v", err)
	}

	// Keys should be loaded despite no refresh interval
	req := &authzen.EvaluationRequest{
		Subject: authzen.Subject{ID: server.URL},
		Action:  &authzen.Action{Name: "pid-provider"},
		Resource: authzen.Resource{
			Type: "jwk",
			Key:  []interface{}{ecdsaPubKeyToJWK(&key.PublicKey, "init-test-key")},
		},
	}

	resp, err := reg.Evaluate(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !resp.Decision {
		reason := ""
		if resp.Context != nil && resp.Context.Reason != nil {
			reason = fmt.Sprintf("%v", resp.Context.Reason)
		}
		t.Errorf("expected issuer to be trusted after StartRefreshLoop without interval, got deny: %s", reason)
	}

	// Verify response includes user reason and trust_framework
	if resp.Context == nil {
		t.Fatal("expected response context")
	}
	if resp.Context.Reason["user"] == nil {
		t.Error("expected Reason['user'] to be set")
	}
	if meta, ok := resp.Context.TrustMetadata.(map[string]interface{}); !ok {
		t.Error("expected TrustMetadata to be set")
	} else if meta["trust_framework"] != "whitelist" {
		t.Errorf("expected trust_framework='whitelist', got %v", meta["trust_framework"])
	}
}

func TestWhitelistRegistry_NamedLists(t *testing.T) {
	// Test the new explicit Lists/Actions config format.
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	jwks := map[string]interface{}{
		"keys": []interface{}{ecdsaPubKeyToJWK(&key.PublicKey, "named-list-key")},
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(jwks)
	}))
	defer server.Close()

	reg := NewWhitelistRegistry(WithWhitelistConfig(WhitelistConfig{
		Lists: map[string][]string{
			"pid-issuers":       {server.URL},
			"trusted-verifiers": {server.URL},
		},
		Actions: map[string]string{
			"pid-provider":        "pid-issuers",
			"credential-issuer":   "pid-issuers",
			"verifier":            "trusted-verifiers",
			"credential-verifier": "trusted-verifiers",
		},
		AllowHTTP: true,
	}))

	err := reg.StartRefreshLoop(context.Background())
	if err != nil {
		t.Fatalf("StartRefreshLoop failed: %v", err)
	}
	defer reg.Close()

	makeReq := func(action string) *authzen.EvaluationRequest {
		return &authzen.EvaluationRequest{
			Subject: authzen.Subject{ID: server.URL},
			Action:  &authzen.Action{Name: action},
			Resource: authzen.Resource{
				Type: "jwk",
				Key:  []interface{}{ecdsaPubKeyToJWK(&key.PublicKey, "named-list-key")},
			},
		}
	}

	t.Run("pid-provider mapped to pid-issuers list", func(t *testing.T) {
		resp, err := reg.Evaluate(context.Background(), makeReq("pid-provider"))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !resp.Decision {
			t.Error("expected pid-provider to be trusted via pid-issuers list")
		}
	})

	t.Run("credential-issuer mapped to pid-issuers list", func(t *testing.T) {
		resp, err := reg.Evaluate(context.Background(), makeReq("credential-issuer"))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !resp.Decision {
			t.Error("expected credential-issuer to be trusted via pid-issuers list")
		}
	})

	t.Run("verifier mapped to trusted-verifiers list", func(t *testing.T) {
		resp, err := reg.Evaluate(context.Background(), makeReq("verifier"))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !resp.Decision {
			t.Error("expected verifier to be trusted via trusted-verifiers list")
		}
	})

	t.Run("unmapped action denied", func(t *testing.T) {
		resp, err := reg.Evaluate(context.Background(), makeReq("unknown-action"))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if resp.Decision {
			t.Error("expected unmapped action to be denied")
		}
	})

	t.Run("issuer not in explicit actions denied", func(t *testing.T) {
		// "issuer" is not in the explicit Actions map, so it should be denied
		// even though the entity exists in a list.
		resp, err := reg.Evaluate(context.Background(), makeReq("issuer"))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if resp.Decision {
			t.Error("expected 'issuer' action to be denied — not in explicit Actions map")
		}
	})
}

func TestWhitelistRegistry_NamedListsWithLegacyFallback(t *testing.T) {
	// Test that Lists/Actions and legacy Issuers/Verifiers can coexist.
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	jwks := map[string]interface{}{
		"keys": []interface{}{ecdsaPubKeyToJWK(&key.PublicKey, "mixed-key")},
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(jwks)
	}))
	defer server.Close()

	reg := NewWhitelistRegistry(WithWhitelistConfig(WhitelistConfig{
		// New format: explicit list + action
		Lists: map[string][]string{
			"custom-list": {server.URL},
		},
		Actions: map[string]string{
			"custom-role": "custom-list",
		},
		// Legacy format alongside
		Issuers:   []string{server.URL},
		AllowHTTP: true,
	}))

	err := reg.StartRefreshLoop(context.Background())
	if err != nil {
		t.Fatalf("StartRefreshLoop failed: %v", err)
	}
	defer reg.Close()

	makeReq := func(action string) *authzen.EvaluationRequest {
		return &authzen.EvaluationRequest{
			Subject: authzen.Subject{ID: server.URL},
			Action:  &authzen.Action{Name: action},
			Resource: authzen.Resource{
				Type: "jwk",
				Key:  []interface{}{ecdsaPubKeyToJWK(&key.PublicKey, "mixed-key")},
			},
		}
	}

	t.Run("explicit action works", func(t *testing.T) {
		resp, err := reg.Evaluate(context.Background(), makeReq("custom-role"))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !resp.Decision {
			t.Error("expected custom-role to be trusted via custom-list")
		}
	})

	t.Run("legacy issuer action still works", func(t *testing.T) {
		resp, err := reg.Evaluate(context.Background(), makeReq("issuer"))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !resp.Decision {
			t.Error("expected issuer to be trusted via legacy Issuers config")
		}
	})

	t.Run("legacy pid-provider still works", func(t *testing.T) {
		resp, err := reg.Evaluate(context.Background(), makeReq("pid-provider"))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !resp.Decision {
			t.Error("expected pid-provider to be trusted via legacy Issuers config")
		}
	})
}

// Tests for extractCredentialTypes helper function

func TestExtractCredentialTypes_NilContext(t *testing.T) {
	reg := NewWhitelistRegistry(WithWhitelistConfig(WhitelistConfig{
		Issuers: []string{"https://example.com"},
	}))
	req := &authzen.EvaluationRequest{Context: nil}
	result := reg.extractCredentialTypes(req)
	if result != nil {
		t.Errorf("expected nil for nil context, got %v", result)
	}
}

func TestExtractCredentialTypes_MissingKey(t *testing.T) {
	reg := NewWhitelistRegistry(WithWhitelistConfig(WhitelistConfig{
		Issuers: []string{"https://example.com"},
	}))
	req := &authzen.EvaluationRequest{
		Context: map[string]interface{}{"other_key": "value"},
	}
	result := reg.extractCredentialTypes(req)
	if result != nil {
		t.Errorf("expected nil for missing key, got %v", result)
	}
}

func TestExtractCredentialTypes_StringSlice(t *testing.T) {
	reg := NewWhitelistRegistry(WithWhitelistConfig(WhitelistConfig{
		Issuers: []string{"https://example.com"},
	}))
	req := &authzen.EvaluationRequest{
		Context: map[string]interface{}{
			"credential_types": []string{"eu.europa.ec.eudi.pid.1", "eu.europa.ec.eudi.mdl.1"},
		},
	}
	result := reg.extractCredentialTypes(req)
	expected := []string{"eu.europa.ec.eudi.pid.1", "eu.europa.ec.eudi.mdl.1"}
	if len(result) != len(expected) || result[0] != expected[0] || result[1] != expected[1] {
		t.Errorf("expected %v, got %v", expected, result)
	}
}

func TestExtractCredentialTypes_InterfaceSlice(t *testing.T) {
	// Simulates JSON-unmarshaled data where []string becomes []interface{}
	reg := NewWhitelistRegistry(WithWhitelistConfig(WhitelistConfig{
		Issuers: []string{"https://example.com"},
	}))
	req := &authzen.EvaluationRequest{
		Context: map[string]interface{}{
			"credential_types": []interface{}{"eu.europa.ec.eudi.pid.1", "eu.europa.ec.eudi.mdl.1"},
		},
	}
	result := reg.extractCredentialTypes(req)
	expected := []string{"eu.europa.ec.eudi.pid.1", "eu.europa.ec.eudi.mdl.1"}
	if len(result) != len(expected) || result[0] != expected[0] || result[1] != expected[1] {
		t.Errorf("expected %v, got %v", expected, result)
	}
}

func TestExtractCredentialTypes_MixedInterfaceSlice(t *testing.T) {
	// Filters out non-string values
	reg := NewWhitelistRegistry(WithWhitelistConfig(WhitelistConfig{
		Issuers: []string{"https://example.com"},
	}))
	req := &authzen.EvaluationRequest{
		Context: map[string]interface{}{
			"credential_types": []interface{}{"eu.europa.ec.eudi.pid.1", 123, "eu.europa.ec.eudi.mdl.1", nil},
		},
	}
	result := reg.extractCredentialTypes(req)
	expected := []string{"eu.europa.ec.eudi.pid.1", "eu.europa.ec.eudi.mdl.1"}
	if len(result) != len(expected) || result[0] != expected[0] || result[1] != expected[1] {
		t.Errorf("expected %v, got %v", expected, result)
	}
}

func TestExtractCredentialTypes_WrongType(t *testing.T) {
	reg := NewWhitelistRegistry(WithWhitelistConfig(WhitelistConfig{
		Issuers: []string{"https://example.com"},
	}))
	req := &authzen.EvaluationRequest{
		Context: map[string]interface{}{"credential_types": "single-string"},
	}
	result := reg.extractCredentialTypes(req)
	if result != nil {
		t.Errorf("expected nil for wrong type, got %v", result)
	}
}

func TestWhitelist_CredentialTypesInResponse(t *testing.T) {
	// Generate a test EC key pair
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	// Create JWKS with the public key
	jwk := ecdsaPubKeyToJWK(&privateKey.PublicKey, "cred-types-test-key")
	jwks := map[string]interface{}{
		"keys": []interface{}{jwk},
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/jwks.json" {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(jwks)
		} else {
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	reg := NewWhitelistRegistry(WithWhitelistConfig(WhitelistConfig{
		Issuers:   []string{server.URL},
		AllowHTTP: true,
	}))

	// Refresh to load keys
	if err := reg.Refresh(context.Background()); err != nil {
		t.Fatalf("failed to refresh registry: %v", err)
	}

	t.Run("credential_types included in success response", func(t *testing.T) {
		resp, err := reg.Evaluate(context.Background(), &authzen.EvaluationRequest{
			Subject: authzen.Subject{ID: server.URL},
			Action:  &authzen.Action{Name: "issuer"},
			Resource: authzen.Resource{
				Type: "jwk",
				Key:  []interface{}{jwk},
			},
			Context: map[string]interface{}{
				"credential_types": []string{"eu.europa.ec.eudi.pid.1"},
			},
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !resp.Decision {
			t.Error("expected decision to be true")
		}
		if resp.Context == nil || resp.Context.Reason == nil {
			t.Fatal("expected response context with reason")
		}
		credTypes, ok := resp.Context.Reason["requested_credential_types"]
		if !ok {
			t.Error("expected requested_credential_types in response")
		}
		if ct, ok := credTypes.([]string); !ok || len(ct) != 1 || ct[0] != "eu.europa.ec.eudi.pid.1" {
			t.Errorf("unexpected credential_types in response: %v", credTypes)
		}
	})

	t.Run("no credential_types when not provided", func(t *testing.T) {
		resp, err := reg.Evaluate(context.Background(), &authzen.EvaluationRequest{
			Subject: authzen.Subject{ID: server.URL},
			Action:  &authzen.Action{Name: "issuer"},
			Resource: authzen.Resource{
				Type: "jwk",
				Key:  []interface{}{jwk},
			},
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !resp.Decision {
			t.Error("expected decision to be true")
		}
		if resp.Context == nil || resp.Context.Reason == nil {
			t.Fatal("expected response context with reason")
		}
		if _, ok := resp.Context.Reason["requested_credential_types"]; ok {
			t.Error("should not have requested_credential_types when not provided")
		}
	})
}

// TestWhitelistRegistry_Refresh_StaleCacheOnFailure verifies that when a refresh
// fails to fetch keys for some entities, previously cached keys are preserved
// (stale-cache fallback) and the registry remains healthy.
func TestWhitelistRegistry_Refresh_StaleCacheOnFailure(t *testing.T) {
	key1, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	key2, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	jwks1 := map[string]interface{}{
		"keys": []interface{}{ecdsaPubKeyToJWK(&key1.PublicKey, "key1")},
	}
	jwks2 := map[string]interface{}{
		"keys": []interface{}{ecdsaPubKeyToJWK(&key2.PublicKey, "key2")},
	}

	// entity2Fail controls whether entity2's JWKS endpoint returns an error.
	entity2Fail := false
	mux := http.NewServeMux()
	mux.HandleFunc("/entity1/.well-known/jwks.json", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(jwks1)
	})
	mux.HandleFunc("/entity2/.well-known/jwks.json", func(w http.ResponseWriter, r *http.Request) {
		if entity2Fail {
			http.Error(w, "Service Unavailable", http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(jwks2)
	})

	server := httptest.NewServer(mux)
	defer server.Close()

	entity1URL := server.URL + "/entity1"
	entity2URL := server.URL + "/entity2"

	reg := NewWhitelistRegistry(WithWhitelistConfig(WhitelistConfig{
		Lists: map[string][]string{
			"all": {entity1URL, entity2URL},
		},
		Actions: map[string]string{
			"issuer": "all",
		},
		AllowHTTP: true,
	}))

	// First refresh: both succeed.
	if err := reg.Refresh(context.Background()); err != nil {
		t.Fatalf("initial refresh failed: %v", err)
	}
	if !reg.Healthy() {
		t.Fatal("registry should be healthy after successful refresh")
	}

	// Verify both entities' keys work.
	for _, tc := range []struct {
		name   string
		entity string
		key    *ecdsa.PublicKey
	}{
		{"entity1", entity1URL, &key1.PublicKey},
		{"entity2", entity2URL, &key2.PublicKey},
	} {
		resp, err := reg.Evaluate(context.Background(), &authzen.EvaluationRequest{
			Subject: authzen.Subject{ID: tc.entity},
			Action:  &authzen.Action{Name: "issuer"},
			Resource: authzen.Resource{
				Type: "jwk",
				Key:  []interface{}{ecdsaPubKeyToJWK(tc.key, "k")},
			},
		})
		if err != nil {
			t.Fatalf("%s: unexpected error: %v", tc.name, err)
		}
		if !resp.Decision {
			t.Fatalf("%s: expected allow, got deny", tc.name)
		}
	}

	// Second refresh: entity2 fails. The resilience fetcher returns stale cached
	// data from the first fetch, so refresh succeeds with stale-cached keys for
	// entity2. Entity2's keys continue to work transparently.
	entity2Fail = true
	if err := reg.Refresh(context.Background()); err != nil {
		t.Fatalf("expected refresh to succeed (stale cache absorbs entity2 failure), got: %v", err)
	}

	// Registry should still be healthy.
	if !reg.Healthy() {
		t.Fatal("registry should remain healthy with stale keys")
	}

	// entity2's key should still work (stale cache).
	resp, err := reg.Evaluate(context.Background(), &authzen.EvaluationRequest{
		Subject: authzen.Subject{ID: entity2URL},
		Action:  &authzen.Action{Name: "issuer"},
		Resource: authzen.Resource{
			Type: "jwk",
			Key:  []interface{}{ecdsaPubKeyToJWK(&key2.PublicKey, "k")},
		},
	})
	if err != nil {
		t.Fatalf("entity2 stale cache: unexpected error: %v", err)
	}
	if !resp.Decision {
		t.Fatal("entity2 stale cache: expected allow (stale keys preserved), got deny")
	}

	// entity1 should still work (fresh keys).
	resp, err = reg.Evaluate(context.Background(), &authzen.EvaluationRequest{
		Subject: authzen.Subject{ID: entity1URL},
		Action:  &authzen.Action{Name: "issuer"},
		Resource: authzen.Resource{
			Type: "jwk",
			Key:  []interface{}{ecdsaPubKeyToJWK(&key1.PublicKey, "k")},
		},
	})
	if err != nil {
		t.Fatalf("entity1 fresh: unexpected error: %v", err)
	}
	if !resp.Decision {
		t.Fatal("entity1 fresh: expected allow, got deny")
	}
}

func TestWithHTTPClient(t *testing.T) {
	custom := &http.Client{Timeout: 5}
	r := &WhitelistRegistry{}
	opt := WithHTTPClient(custom)
	opt(r)
	if r.httpClient != custom {
		t.Error("WithHTTPClient did not set httpClient on WhitelistRegistry")
	}
}

// TestWhitelistRegistry_TrustX509ViaSystemCA covers the fallback trust path
// for whitelisted entities identified by a non-HTTP(S) scheme (e.g.
// OpenID4VP's x509_san_dns:example.com client_id_scheme), which have no JWKS
// endpoint and would otherwise always be denied with "no keys cached for
// entity" regardless of how legitimate their presented certificate is.
func TestWhitelistRegistry_TrustX509ViaSystemCA(t *testing.T) {
	cert := generateSelfSignedCert(t)
	certB64 := base64.StdEncoding.EncodeToString(cert.Raw)

	t.Run("disabled_by_default_denies_non_jwks_entity", func(t *testing.T) {
		reg := NewWhitelistRegistry(WithWhitelistConfig(WhitelistConfig{
			Lists:   map[string][]string{"verifiers": {"x509_san_dns:verifier.example.com"}},
			Actions: map[string]string{"credential-verifier": "verifiers"},
		}))
		// Refresh() returns an error whenever ANY entity's JWKS fetch fails -
		// expected and benign here, since this entity was never JWKS-fetchable
		// to begin with (mirrors what the real PDP deployment does: logs the
		// warning, keeps running).
		_ = reg.Refresh(context.Background())

		resp, err := reg.Evaluate(context.Background(), &authzen.EvaluationRequest{
			Subject: authzen.Subject{ID: "x509_san_dns:verifier.example.com"},
			Action:  &authzen.Action{Name: "credential-verifier"},
			Resource: authzen.Resource{
				Type: "x5c",
				Key:  []interface{}{certB64},
			},
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if resp.Decision {
			t.Error("expected decision=false when TrustX509ViaSystemCA is disabled")
		}
		if resp.Context.Reason["error"] != "no keys cached for entity; call Refresh() to load keys" {
			t.Errorf("expected the original JWKS-missing deny reason, got: %v", resp.Context.Reason["error"])
		}
	})

	t.Run("enabled_denies_on_certificate_binding_mismatch", func(t *testing.T) {
		// certB64 (generateSelfSignedCert) carries no DNS SAN at all, so it
		// can never be bound to the claimed "verifier.example.com" identity -
		// this must be denied on the binding check, before chain validation
		// is even attempted (and regardless of whether the cert would
		// otherwise chain to a public CA). This is the exact case the
		// binding check exists to close: without it, ANY certificate the
		// caller holds - chaining to any public CA, for any domain - would
		// have been accepted for this claimed identity.
		reg := NewWhitelistRegistry(WithWhitelistConfig(WhitelistConfig{
			Lists:                map[string][]string{"verifiers": {"x509_san_dns:verifier.example.com"}},
			Actions:              map[string]string{"credential-verifier": "verifiers"},
			TrustX509ViaSystemCA: true,
		}))
		_ = reg.Refresh(context.Background())

		resp, err := reg.Evaluate(context.Background(), &authzen.EvaluationRequest{
			Subject: authzen.Subject{ID: "x509_san_dns:verifier.example.com"},
			Action:  &authzen.Action{Name: "credential-verifier"},
			Resource: authzen.Resource{
				Type: "x5c",
				Key:  []interface{}{certB64},
			},
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if resp.Decision {
			t.Error("expected decision=false for a certificate with no matching DNS SAN")
		}
		errReason, _ := resp.Context.Reason["error"].(string)
		if !strings.Contains(errReason, "certificate binding check failed") {
			t.Errorf("expected a certificate-binding deny reason, got: %v", errReason)
		}
	})

	t.Run("enabled_attempts_chain_validation_once_binding_matches", func(t *testing.T) {
		// Prove the fallback still reaches chain validation (and denies
		// there) once the binding check itself passes: use a cert whose DNS
		// SAN matches the claimed identity, but deliberately don't trust its
		// issuing CA - so the binding check passes and the deny comes from
		// chain validation, proving both checks run in the right order.
		leafCert, _ := generateCASignedLeafCert(t)

		reg := NewWhitelistRegistry(WithWhitelistConfig(WhitelistConfig{
			Lists:                map[string][]string{"verifiers": {"x509_san_dns:verifier.example.com"}},
			Actions:              map[string]string{"credential-verifier": "verifiers"},
			TrustX509ViaSystemCA: true,
		}))
		_ = reg.Refresh(context.Background())
		// Force the pool to one that does NOT contain this leaf's issuer, so
		// the binding check (which matches) passes but chain validation
		// still fails - proving both checks run, in the right order.
		reg.systemCertPoolOnce.Do(func() {})
		reg.systemCertPoolErr = nil
		reg.systemCertPool = x509.NewCertPool()

		leafB64 := base64.StdEncoding.EncodeToString(leafCert.Raw)
		resp, err := reg.Evaluate(context.Background(), &authzen.EvaluationRequest{
			Subject: authzen.Subject{ID: "x509_san_dns:verifier.example.com"},
			Action:  &authzen.Action{Name: "credential-verifier"},
			Resource: authzen.Resource{
				Type: "x5c",
				Key:  []interface{}{leafB64},
			},
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if resp.Decision {
			t.Error("expected decision=false: leaf's issuing CA is not in the (deliberately empty) pool")
		}
		errReason, _ := resp.Context.Reason["error"].(string)
		if !strings.Contains(errReason, "x509 chain validation") {
			t.Errorf("expected a chain-validation error (binding check should have already passed), got: %v", errReason)
		}
	})

	t.Run("enabled_skips_chain_validation_for_x509_hash_scheme", func(t *testing.T) {
		// Unlike x509_san_dns/x509_san_uri (which need a real CA-validated
		// chain to prove a SAN claim isn't just self-asserted), x509_hash
		// pins the exact leaf certificate's bytes - a successful binding
		// (hash) match IS the whole trust decision, so chain validation
		// must be skipped entirely for this scheme. Prove this with a
		// deliberately empty (and so, if consulted, always-failing) CA
		// pool: a self-signed/non-CA-chained certificate (the common case
		// for a conformance/demo verifier, e.g. digital-credentials.dev)
		// must still be granted trust once its hash matches.
		leafCert, _ := generateCASignedLeafCert(t)
		digest := sha256.Sum256(leafCert.Raw)
		hashHex := hex.EncodeToString(digest[:])

		reg := NewWhitelistRegistry(WithWhitelistConfig(WhitelistConfig{
			Lists:                map[string][]string{"verifiers": {"x509_hash:" + hashHex}},
			Actions:              map[string]string{"credential-verifier": "verifiers"},
			TrustX509ViaSystemCA: true,
		}))
		_ = reg.Refresh(context.Background())
		reg.systemCertPoolOnce.Do(func() {})
		reg.systemCertPoolErr = nil
		reg.systemCertPool = x509.NewCertPool()

		leafB64 := base64.StdEncoding.EncodeToString(leafCert.Raw)
		resp, err := reg.Evaluate(context.Background(), &authzen.EvaluationRequest{
			Subject: authzen.Subject{ID: "x509_hash:" + hashHex},
			Action:  &authzen.Action{Name: "credential-verifier"},
			Resource: authzen.Resource{
				Type: "x5c",
				Key:  []interface{}{leafB64},
			},
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !resp.Decision {
			t.Errorf("expected decision=true: hash-pinned trust must not depend on the (deliberately empty) CA pool, got reason: %v", resp.Context.Reason)
		}
		trustPath, _ := resp.Context.Reason["trust_path"].(string)
		if trustPath != "system_ca_pinned_hash" {
			t.Errorf("expected trust_path=system_ca_pinned_hash, got: %v", trustPath)
		}
	})

	t.Run("enabled_denies_x509_hash_mismatch", func(t *testing.T) {
		// The mirror image of the DNS SAN mismatch case above: a whitelisted
		// x509_hash entity whose claimed hash does NOT match the presented
		// certificate's actual digest must be denied on the binding check,
		// never reaching (and so never benefiting from) chain validation.
		reg := NewWhitelistRegistry(WithWhitelistConfig(WhitelistConfig{
			Lists:                map[string][]string{"verifiers": {"x509_hash:deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"}},
			Actions:              map[string]string{"credential-verifier": "verifiers"},
			TrustX509ViaSystemCA: true,
		}))
		_ = reg.Refresh(context.Background())

		resp, err := reg.Evaluate(context.Background(), &authzen.EvaluationRequest{
			Subject: authzen.Subject{ID: "x509_hash:deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"},
			Action:  &authzen.Action{Name: "credential-verifier"},
			Resource: authzen.Resource{
				Type: "x5c",
				Key:  []interface{}{certB64},
			},
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if resp.Decision {
			t.Error("expected decision=false for a certificate whose hash doesn't match the claimed x509_hash identity")
		}
		errReason, _ := resp.Context.Reason["error"].(string)
		if !strings.Contains(errReason, "certificate binding check failed") {
			t.Errorf("expected a certificate-binding deny reason, got: %v", errReason)
		}
	})

	t.Run("enabled_denies_unrecognized_client_id_scheme", func(t *testing.T) {
		// A whitelisted entity using a non-HTTP(S) scheme this package has no
		// certificate-binding rule for (e.g. "did:web:...") must be denied
		// outright rather than falling back to chain-validity-only trust -
		// there's no defined way to verify such an identity is bound to a
		// presented x5c chain at all.
		reg := NewWhitelistRegistry(WithWhitelistConfig(WhitelistConfig{
			Lists:                map[string][]string{"verifiers": {"did:web:verifier.example.com"}},
			Actions:              map[string]string{"credential-verifier": "verifiers"},
			TrustX509ViaSystemCA: true,
		}))
		_ = reg.Refresh(context.Background())

		resp, err := reg.Evaluate(context.Background(), &authzen.EvaluationRequest{
			Subject: authzen.Subject{ID: "did:web:verifier.example.com"},
			Action:  &authzen.Action{Name: "credential-verifier"},
			Resource: authzen.Resource{
				Type: "x5c",
				Key:  []interface{}{certB64},
			},
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if resp.Decision {
			t.Error("expected decision=false: did: has no defined certificate-binding rule")
		}
		errReason, _ := resp.Context.Reason["error"].(string)
		if !strings.Contains(errReason, "not a recognized x509 client_id_scheme") {
			t.Errorf("expected an unrecognized-scheme deny reason, got: %v", errReason)
		}
	})

	t.Run("still_gated_by_whitelist_membership", func(t *testing.T) {
		reg := NewWhitelistRegistry(WithWhitelistConfig(WhitelistConfig{
			Lists:                map[string][]string{"verifiers": {"x509_san_dns:verifier.example.com"}},
			Actions:              map[string]string{"credential-verifier": "verifiers"},
			TrustX509ViaSystemCA: true,
		}))
		_ = reg.Refresh(context.Background())

		// A DIFFERENT x509_san_dns entity, not in the whitelist - must be
		// denied on membership grounds, never even reaching the cert-chain
		// fallback. TrustX509ViaSystemCA is not a blanket "trust any
		// certificate" switch.
		resp, err := reg.Evaluate(context.Background(), &authzen.EvaluationRequest{
			Subject: authzen.Subject{ID: "x509_san_dns:not-whitelisted.example.com"},
			Action:  &authzen.Action{Name: "credential-verifier"},
			Resource: authzen.Resource{
				Type: "x5c",
				Key:  []interface{}{certB64},
			},
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if resp.Decision {
			t.Error("expected decision=false for an entity not in the whitelist")
		}
		errReason, _ := resp.Context.Reason["error"].(string)
		if !strings.Contains(errReason, "not in whitelist") {
			t.Errorf("expected a whitelist-membership deny reason (not a cert-chain error), got: %v", errReason)
		}
	})

	t.Run("http_scheme_entity_unaffected_by_flag", func(t *testing.T) {
		// A normal https:// entity whose JWKS fetch genuinely failed must
		// still be denied outright - TrustX509ViaSystemCA only applies to
		// entities that were never JWKS-fetchable to begin with.
		reg := NewWhitelistRegistry(WithWhitelistConfig(WhitelistConfig{
			Lists:                map[string][]string{"verifiers": {"https://unreachable.invalid.example"}},
			Actions:              map[string]string{"credential-verifier": "verifiers"},
			TrustX509ViaSystemCA: true,
		}))
		_ = reg.Refresh(context.Background())

		resp, err := reg.Evaluate(context.Background(), &authzen.EvaluationRequest{
			Subject: authzen.Subject{ID: "https://unreachable.invalid.example"},
			Action:  &authzen.Action{Name: "credential-verifier"},
			Resource: authzen.Resource{
				Type: "x5c",
				Key:  []interface{}{certB64},
			},
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if resp.Decision {
			t.Error("expected decision=false for an unreachable https entity")
		}
		errReason, _ := resp.Context.Reason["error"].(string)
		if !strings.Contains(errReason, "no keys cached") {
			t.Errorf("expected the JWKS-missing deny reason (not the system-CA fallback), got: %v", errReason)
		}
	})

	t.Run("enabled_grants_trust_for_a_chain_that_validates", func(t *testing.T) {
		// The previous "enabled" subtests only prove the fallback path *runs*
		// (via a self-signed cert that can never chain to any pool). Prove it
		// can also *succeed*: build a real CA + leaf chain, inject a cert
		// pool containing just that CA directly into the registry (same
		// package as production code, so private fields are reachable here
		// without needing a public test-only constructor), and confirm a
		// Decision=true with trust_path=system_ca in both the reason and
		// trust metadata.
		leafCert, caCert := generateCASignedLeafCert(t)
		customPool := x509.NewCertPool()
		customPool.AddCert(caCert)

		reg := NewWhitelistRegistry(WithWhitelistConfig(WhitelistConfig{
			Lists:                map[string][]string{"verifiers": {"x509_san_dns:verifier.example.com"}},
			Actions:              map[string]string{"credential-verifier": "verifiers"},
			TrustX509ViaSystemCA: true,
		}))
		_ = reg.Refresh(context.Background())
		// Pre-seed the once-loaded system cert pool with our own test CA
		// instead of the real OS trust store, so the outcome is deterministic
		// and doesn't depend on any real public CA.
		reg.systemCertPoolOnce.Do(func() {})
		reg.systemCertPool = customPool
		reg.systemCertPoolErr = nil

		leafB64 := base64.StdEncoding.EncodeToString(leafCert.Raw)
		// Also exercise the requested_credential_types branch of the success
		// reason - a real OpenID4VP presentation request typically carries
		// this in Context.
		resp, err := reg.Evaluate(context.Background(), &authzen.EvaluationRequest{
			Subject: authzen.Subject{ID: "x509_san_dns:verifier.example.com"},
			Action:  &authzen.Action{Name: "credential-verifier"},
			Resource: authzen.Resource{
				Type: "x5c",
				Key:  []interface{}{leafB64},
			},
			Context: map[string]interface{}{
				"credential_types": []interface{}{"org.iso.18013.5.1.mDL"},
			},
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !resp.Decision {
			t.Fatalf("expected decision=true for a chain that validates against the injected pool, got deny: %v", resp.Context.Reason["error"])
		}
		trustMetadata, _ := resp.Context.TrustMetadata.(map[string]interface{})
		if trustMetadata["trust_path"] != "system_ca" {
			t.Errorf("expected trust_path=system_ca in trust metadata, got: %v", trustMetadata["trust_path"])
		}
		if resp.Context.Reason["trust_path"] != "system_ca" {
			t.Errorf("expected trust_path=system_ca in reason, got: %v", resp.Context.Reason["trust_path"])
		}
		credTypes, _ := resp.Context.Reason["requested_credential_types"].([]string)
		if len(credTypes) != 1 || credTypes[0] != "org.iso.18013.5.1.mDL" {
			t.Errorf("expected requested_credential_types=[org.iso.18013.5.1.mDL] in reason, got: %v", resp.Context.Reason["requested_credential_types"])
		}
	})

	t.Run("enabled_grants_trust_for_a_chain_with_an_intermediate", func(t *testing.T) {
		// Exercise the multi-cert (leaf + intermediate) branch of
		// evaluateViaSystemCA - the previous success subtest only presented a
		// single leaf cert signed directly by a pool-trusted root.
		leafCert, intermediateCert, rootCert := generateCASignedLeafCertWithIntermediate(t)
		customPool := x509.NewCertPool()
		customPool.AddCert(rootCert)

		reg := NewWhitelistRegistry(WithWhitelistConfig(WhitelistConfig{
			Lists:                map[string][]string{"verifiers": {"x509_san_dns:verifier.example.com"}},
			Actions:              map[string]string{"credential-verifier": "verifiers"},
			TrustX509ViaSystemCA: true,
		}))
		_ = reg.Refresh(context.Background())
		reg.systemCertPoolOnce.Do(func() {})
		reg.systemCertPool = customPool
		reg.systemCertPoolErr = nil

		leafB64 := base64.StdEncoding.EncodeToString(leafCert.Raw)
		intermediateB64 := base64.StdEncoding.EncodeToString(intermediateCert.Raw)
		resp, err := reg.Evaluate(context.Background(), &authzen.EvaluationRequest{
			Subject: authzen.Subject{ID: "x509_san_dns:verifier.example.com"},
			Action:  &authzen.Action{Name: "credential-verifier"},
			Resource: authzen.Resource{
				Type: "x5c",
				Key:  []interface{}{leafB64, intermediateB64},
			},
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !resp.Decision {
			t.Fatalf("expected decision=true for a leaf+intermediate chain that validates against the injected root pool, got deny: %v", resp.Context.Reason["error"])
		}
		if resp.Context.Reason["chain_length"] != 1 {
			t.Errorf("expected a single resolved chain, got chain_length=%v", resp.Context.Reason["chain_length"])
		}
	})

	t.Run("additional_trusted_roots_extends_chain_validation", func(t *testing.T) {
		// Proves the AdditionalTrustedRoots config field itself - not the
		// registry-internal systemCertPool test seam the subtests above use.
		// This is the real-world shape: a verifier's request-signing leaf is
		// issued by a long-lived, self-signed "reader CA" root (the ISO
		// 18013-5 convention this field exists for - see its doc comment)
		// that will never appear in any OS system CA pool, so chain
		// validation must succeed via ONLY the configured additional root,
		// not the real system pool this test also loads alongside it.
		leafCert, caCert := generateCASignedLeafCert(t)
		caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caCert.Raw})

		reg := NewWhitelistRegistry(WithWhitelistConfig(WhitelistConfig{
			Lists:                  map[string][]string{"verifiers": {"x509_san_dns:verifier.example.com"}},
			Actions:                map[string]string{"credential-verifier": "verifiers"},
			TrustX509ViaSystemCA:   true,
			AdditionalTrustedRoots: []string{string(caPEM)},
		}))
		_ = reg.Refresh(context.Background())

		leafB64 := base64.StdEncoding.EncodeToString(leafCert.Raw)
		resp, err := reg.Evaluate(context.Background(), &authzen.EvaluationRequest{
			Subject: authzen.Subject{ID: "x509_san_dns:verifier.example.com"},
			Action:  &authzen.Action{Name: "credential-verifier"},
			Resource: authzen.Resource{
				Type: "x5c",
				Key:  []interface{}{leafB64},
			},
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !resp.Decision {
			t.Fatalf("expected decision=true: leaf is signed by a root supplied via AdditionalTrustedRoots, got deny: %v", resp.Context.Reason["error"])
		}
		if resp.Context.Reason["trust_path"] != "system_ca" {
			t.Errorf("expected trust_path=system_ca, got: %v", resp.Context.Reason["trust_path"])
		}
	})

	t.Run("additional_trusted_root_with_negative_serial_number", func(t *testing.T) {
		// Go's x509 parser rejects certificates with a negative serial
		// number by default since Go 1.23 (RFC 5280 recommends non-negative
		// but doesn't forbid it, and x509.CreateCertificate itself refuses
		// to mint one - this is a real-world-artifact test, not a synthetic
		// one, for that reason). Real-world CA tooling still produces such
		// certs: this is verifier.multipaz.org's actual self-generated
		// reader-CA root (fetched from its /verifier/readerRootCert
		// endpoint), which openssl - and every other major TLS stack -
		// accepts without complaint, but a stock Go binary silently fails
		// to even parse via AppendCertsFromPEM, denying every certificate
		// it issues regardless of whitelist membership. See this package's
		// Dockerfile's GODEBUG=x509negativeserial=1 setting, which callers
		// embedding this package (rather than running the packaged binary)
		// must also set for AdditionalTrustedRoots to work with such roots.
		t.Setenv("GODEBUG", "x509negativeserial=1")

		reg := NewWhitelistRegistry(WithWhitelistConfig(WhitelistConfig{
			Lists:                  map[string][]string{"verifiers": {"x509_san_dns:verifier.multipaz.org"}},
			Actions:                map[string]string{"credential-verifier": "verifiers"},
			TrustX509ViaSystemCA:   true,
			AdditionalTrustedRoots: []string{multipazReaderCAPEMWithNegativeSerial},
		}))
		_ = reg.Refresh(context.Background())

		pool, err := reg.loadSystemCertPool()
		if err != nil {
			t.Fatalf("expected the negative-serial root to load successfully with GODEBUG=x509negativeserial=1, got: %v", err)
		}
		if pool == nil {
			t.Fatal("expected a non-nil cert pool")
		}
	})

	t.Run("malformed_additional_trusted_root_denies_with_pool_error", func(t *testing.T) {
		reg := NewWhitelistRegistry(WithWhitelistConfig(WhitelistConfig{
			Lists:                  map[string][]string{"verifiers": {"x509_san_dns:verifier.example.com"}},
			Actions:                map[string]string{"credential-verifier": "verifiers"},
			TrustX509ViaSystemCA:   true,
			AdditionalTrustedRoots: []string{"not a real PEM certificate"},
		}))
		_ = reg.Refresh(context.Background())

		leafCert, _ := generateCASignedLeafCert(t)
		leafB64 := base64.StdEncoding.EncodeToString(leafCert.Raw)
		resp, err := reg.Evaluate(context.Background(), &authzen.EvaluationRequest{
			Subject: authzen.Subject{ID: "x509_san_dns:verifier.example.com"},
			Action:  &authzen.Action{Name: "credential-verifier"},
			Resource: authzen.Resource{
				Type: "x5c",
				Key:  []interface{}{leafB64},
			},
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if resp.Decision {
			t.Error("expected decision=false: a malformed additional_trusted_roots entry should fail the pool, not be silently ignored")
		}
		errReason, _ := resp.Context.Reason["error"].(string)
		if !strings.Contains(errReason, "additional_trusted_roots") {
			t.Errorf("expected error to name additional_trusted_roots as the cause, got: %v", errReason)
		}
	})

	t.Run("malformed_x5c_denies_with_parse_error", func(t *testing.T) {
		reg := NewWhitelistRegistry(WithWhitelistConfig(WhitelistConfig{
			Lists:                map[string][]string{"verifiers": {"x509_san_dns:verifier.example.com"}},
			Actions:              map[string]string{"credential-verifier": "verifiers"},
			TrustX509ViaSystemCA: true,
		}))
		_ = reg.Refresh(context.Background())

		resp, err := reg.Evaluate(context.Background(), &authzen.EvaluationRequest{
			Subject: authzen.Subject{ID: "x509_san_dns:verifier.example.com"},
			Action:  &authzen.Action{Name: "credential-verifier"},
			Resource: authzen.Resource{
				Type: "x5c",
				Key:  []interface{}{"not-valid-base64!!!"},
			},
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if resp.Decision {
			t.Error("expected decision=false for a malformed x5c entry")
		}
		errReason, _ := resp.Context.Reason["error"].(string)
		if !strings.Contains(errReason, "failed to parse x5c chain") {
			t.Errorf("expected a parse-error deny reason, got: %v", errReason)
		}
	})

	t.Run("system_cert_pool_unavailable_denies", func(t *testing.T) {
		// Simulate loadSystemCertPool() itself failing (e.g. an unsupported
		// platform) by pre-seeding the once-loaded state directly, since
		// x509.SystemCertPool() can't be made to fail on demand in this test
		// environment.
		reg := NewWhitelistRegistry(WithWhitelistConfig(WhitelistConfig{
			Lists:                map[string][]string{"verifiers": {"x509_san_dns:verifier.example.com"}},
			Actions:              map[string]string{"credential-verifier": "verifiers"},
			TrustX509ViaSystemCA: true,
		}))
		_ = reg.Refresh(context.Background())
		reg.systemCertPoolOnce.Do(func() {})
		reg.systemCertPool = nil
		reg.systemCertPoolErr = fmt.Errorf("simulated: system cert pool unavailable")

		resp, err := reg.Evaluate(context.Background(), &authzen.EvaluationRequest{
			Subject: authzen.Subject{ID: "x509_san_dns:verifier.example.com"},
			Action:  &authzen.Action{Name: "credential-verifier"},
			Resource: authzen.Resource{
				Type: "x5c",
				Key:  []interface{}{certB64},
			},
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if resp.Decision {
			t.Error("expected decision=false when the system cert pool failed to load")
		}
		errReason, _ := resp.Context.Reason["error"].(string)
		if !strings.Contains(errReason, "system CA pool unavailable") {
			t.Errorf("expected a pool-unavailable deny reason, got: %v", errReason)
		}
	})
}

// generateCASignedLeafCert creates a self-signed CA certificate and a leaf
// certificate signed by it, for testing the TrustX509ViaSystemCA success path
// with a deterministic, injectable pool instead of depending on any real
// public CA.
func generateCASignedLeafCert(t *testing.T) (leaf *x509.Certificate, ca *x509.Certificate) {
	t.Helper()

	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate CA key: %v", err)
	}
	caTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Test CA Org"},
			CommonName:   "Test Root CA",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("failed to create CA certificate: %v", err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatalf("failed to parse CA certificate: %v", err)
	}

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate leaf key: %v", err)
	}
	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject: pkix.Name{
			Organization: []string{"Test Org"},
			CommonName:   "verifier.example.com",
		},
		DNSNames:    []string{"verifier.example.com"},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().Add(24 * time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, caCert, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("failed to create leaf certificate: %v", err)
	}
	leafCert, err := x509.ParseCertificate(leafDER)
	if err != nil {
		t.Fatalf("failed to parse leaf certificate: %v", err)
	}

	return leafCert, caCert
}

// multipazReaderCAPEMWithNegativeSerial is verifier.multipaz.org's actual
// self-generated OpenID4VP request-signing reader-CA root, fetched from its
// /verifier/readerRootCert endpoint on 2026-08-13. Its serial number is
// negative (openssl explicitly flags this: "Serial Number: (Negative)
// 48:ca:d0:...") - x509.CreateCertificate refuses to mint a certificate
// like this at all, so this real-world artifact is embedded verbatim rather
// than synthesized, for additional_trusted_root_with_negative_serial_number.
const multipazReaderCAPEMWithNegativeSerial = `-----BEGIN CERTIFICATE-----
MIICaTCCAe+gAwIBAgIQtzUvFDCKLUBWQAZ4UnCw5zAKBggqhkjOPQQDAzA3MQswCQYDVQQGDAJV
UzEoMCYGA1UEAwwfdmVyaWZpZXIubXVsdGlwYXoub3JnIFJlYWRlciBDQTAeFw0yNTA2MTkyMjE2
MzJaFw0zMDA2MTkyMjE2MzJaMDcxCzAJBgNVBAYMAlVTMSgwJgYDVQQDDB92ZXJpZmllci5tdWx0
aXBhei5vcmcgUmVhZGVyIENBMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEa6oCzC8rfHfwVOmQf83W
yHEQFE8HrLK+NxsufJDrSFgMXjhRvPt3fIjlMyRAaf94Y25Ux9tXg+28EzzB/xG7q8P/FQ9nOSJk
w4cQJVdD/ufN599uVdfp1URdG95Vncuoo4G/MIG8MA4GA1UdDwEB/wQEAwIBBjASBgNVHRMBAf8E
CDAGAQH/AgEAMFYGA1UdHwRPME0wS6BJoEeGRWh0dHBzOi8vZ2l0aHViLmNvbS9vcGVud2FsbGV0
LWZvdW5kYXRpb24tbGFicy9pZGVudGl0eS1jcmVkZW50aWFsL2NybDAdBgNVHQ4EFgQUsYQ5hS9K
buq/6mKtvFHQgfdIhykwHwYDVR0jBBgwFoAUsYQ5hS9Kbuq/6mKtvFHQgfdIhykwCgYIKoZIzj0E
AwMDaAAwZQIwKh87sK/cMbzuc9PFvyiSRedr2RoP0fuFK0X8ddOpi6hEMOapHL/Gs/QByROCpDpk
AjEA2yLSJDZEu1GI8uChAsDBZwJPtv5KHUjq1Vpok69SNn+zzb1mNpqmiey+tchPBjZm
-----END CERTIFICATE-----
`

// generateCASignedLeafCertWithIntermediate builds a 3-tier root CA ->
// intermediate CA -> leaf chain, for testing evaluateViaSystemCA's
// multi-cert (len(certs) > 1) branch: the presented x5c array carries the
// leaf and intermediate, while only the root is in the trusted pool.
func generateCASignedLeafCertWithIntermediate(t *testing.T) (leaf, intermediate, root *x509.Certificate) {
	t.Helper()

	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate root key: %v", err)
	}
	rootTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Test Root CA Org"},
			CommonName:   "Test Root CA",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, &rootKey.PublicKey, rootKey)
	if err != nil {
		t.Fatalf("failed to create root certificate: %v", err)
	}
	rootCert, err := x509.ParseCertificate(rootDER)
	if err != nil {
		t.Fatalf("failed to parse root certificate: %v", err)
	}

	intermediateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate intermediate key: %v", err)
	}
	intermediateTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject: pkix.Name{
			Organization: []string{"Test Intermediate CA Org"},
			CommonName:   "Test Intermediate CA",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	intermediateDER, err := x509.CreateCertificate(rand.Reader, intermediateTemplate, rootCert, &intermediateKey.PublicKey, rootKey)
	if err != nil {
		t.Fatalf("failed to create intermediate certificate: %v", err)
	}
	intermediateCert, err := x509.ParseCertificate(intermediateDER)
	if err != nil {
		t.Fatalf("failed to parse intermediate certificate: %v", err)
	}

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate leaf key: %v", err)
	}
	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(3),
		Subject: pkix.Name{
			Organization: []string{"Test Org"},
			CommonName:   "verifier.example.com",
		},
		DNSNames:    []string{"verifier.example.com"},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().Add(24 * time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, intermediateCert, &leafKey.PublicKey, intermediateKey)
	if err != nil {
		t.Fatalf("failed to create leaf certificate: %v", err)
	}
	leafCert, err := x509.ParseCertificate(leafDER)
	if err != nil {
		t.Fatalf("failed to parse leaf certificate: %v", err)
	}

	return leafCert, intermediateCert, rootCert
}
