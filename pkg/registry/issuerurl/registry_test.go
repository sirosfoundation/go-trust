package issuerurl

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/sirosfoundation/go-trust/pkg/authzen"
)

func newTestRegistry(t *testing.T) *Registry {
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

// newTestKey returns a fresh ECDSA P-256 key pair and its public JWK.
func newTestKey(t *testing.T) (*ecdsa.PrivateKey, jose.JSONWebKey) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating ECDSA key: %v", err)
	}
	return priv, jose.JSONWebKey{Key: priv.Public(), Algorithm: string(jose.ES256), Use: "sig"}
}

// signClaims signs the given claims as a compact JWS (ES256).
func signClaims(t *testing.T, priv *ecdsa.PrivateKey, claims map[string]interface{}) string {
	t.Helper()
	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.ES256, Key: priv},
		(&jose.SignerOptions{}).WithType("JWT"),
	)
	if err != nil {
		t.Fatalf("creating signer: %v", err)
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("marshaling claims: %v", err)
	}
	jws, err := signer.Sign(payload)
	if err != nil {
		t.Fatalf("signing: %v", err)
	}
	compact, err := jws.CompactSerialize()
	if err != nil {
		t.Fatalf("serializing JWS: %v", err)
	}
	return compact
}

// inlineJWKS returns the JWKS map for the given public JWK.
func inlineJWKS(t *testing.T, pub jose.JSONWebKey) map[string]interface{} {
	t.Helper()
	b, err := json.Marshal(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{pub}})
	if err != nil {
		t.Fatalf("marshaling JWKS: %v", err)
	}
	var jwksMap map[string]interface{}
	if err := json.Unmarshal(b, &jwksMap); err != nil {
		t.Fatalf("unmarshaling JWKS: %v", err)
	}
	return jwksMap
}

func TestEvaluate_URLResolution_Success(t *testing.T) {
	priv, pub := newTestKey(t)

	// JWT payload is the authoritative metadata.
	jwtClaims := map[string]interface{}{
		"credential_issuer": "https://issuer.example.com",
		"credential_configurations_supported": map[string]interface{}{
			"UniversityDegree": map[string]interface{}{
				"format": "vc+sd-jwt",
			},
		},
	}
	token := signClaims(t, priv, jwtClaims)

	issuerMetadata := map[string]interface{}{
		"credential_issuer": "https://issuer.example.com",
		"display": []interface{}{
			map[string]interface{}{
				"name":   "Example University",
				"locale": "en-US",
			},
		},
		"jwks":            inlineJWKS(t, pub),
		"signed_metadata": token,
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

	reg := newTestRegistry(t)

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

	// Verify trust_metadata is a parsed map with JWT payload claims.
	parsed, ok := resp.Context.TrustMetadata.(map[string]interface{})
	if !ok {
		t.Fatalf("Expected map[string]interface{}, got %T", resp.Context.TrustMetadata)
	}
	if parsed["signed_metadata"] != token {
		t.Errorf("signed_metadata not preserved: got %v", parsed["signed_metadata"])
	}
	if parsed["credential_issuer"] != "https://issuer.example.com" {
		t.Errorf("credential_issuer missing: got %v", parsed["credential_issuer"])
	}
	if _, ok := parsed["credential_configurations_supported"]; !ok {
		t.Error("credential_configurations_supported not found in JWT payload claims")
	}

	// Verify reason fields.
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

	reg := newTestRegistry(t)

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
	reg := newTestRegistry(t)

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
	reg := newTestRegistry(t)

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

	reg := newTestRegistry(t)

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

	reg := newTestRegistry(t)

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
	reg := newTestRegistry(t)
	if !reg.SupportsResolutionOnly() {
		t.Error("Expected SupportsResolutionOnly() = true")
	}
}

func TestSupportedResourceTypes(t *testing.T) {
	reg := newTestRegistry(t)
	types := reg.SupportedResourceTypes()
	if len(types) != 0 {
		t.Errorf("Expected empty SupportedResourceTypes, got %v", types)
	}
}

func TestInfo(t *testing.T) {
	reg := newTestRegistry(t)
	info := reg.Info()
	if info.Type != "issuer_url" {
		t.Errorf("Expected type 'issuer_url', got %q", info.Type)
	}
	if !info.ResolutionOnly {
		t.Error("Expected ResolutionOnly=true in info")
	}
}