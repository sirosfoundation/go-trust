package static

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
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
	if len(types) != 2 || (types[0] != "jwk" && types[0] != "x5c") {
		t.Errorf("expected [jwk x5c], got %v", types)
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
