package didjwks

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/sirosfoundation/go-trust/pkg/authzen"
)

// --- Test JWKS ---

// sampleJWKS returns a JWKS with an EC P-256 signing key and an RSA encryption key.
func sampleJWKS() map[string]interface{} {
	return map[string]interface{}{
		"keys": []interface{}{
			map[string]interface{}{
				"kty": "EC",
				"crv": "P-256",
				"x":   "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
				"y":   "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0",
				"kid": "ec-key-1",
				"use": "sig",
			},
			map[string]interface{}{
				"kty": "RSA",
				"n":   "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
				"e":   "AQAB",
				"kid": "rsa-enc-1",
				"use": "enc",
			},
		},
	}
}

// ecSigningJWK returns just the EC signing key from sampleJWKS.
func ecSigningJWK() map[string]interface{} {
	return map[string]interface{}{
		"kty": "EC",
		"crv": "P-256",
		"x":   "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
		"y":   "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0",
	}
}

// rsaEncJWK returns just the RSA encryption key from sampleJWKS.
func rsaEncJWK() map[string]interface{} {
	return map[string]interface{}{
		"kty": "RSA",
		"n":   "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
		"e":   "AQAB",
	}
}

// --- Helper: create test server ---

func newJWKSServer(jwks map[string]interface{}) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(jwks)
	}))
}

// newRoutingServer serves JWKS at /well-known/jwks.json and OIDC discovery at /.well-known/openid-configuration.
func newRoutingServer(jwks map[string]interface{}, jwksPath string) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case jwksPath:
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(jwks)
		default:
			http.NotFound(w, r)
		}
	}))
}

func registryWith(server *httptest.Server) *Registry {
	reg, _ := NewRegistry(Config{
		AllowHTTP:            true,
		DisableOIDCDiscovery: true,
	})
	reg.SetHTTPClient(server.Client())
	return reg
}

// testDomain extracts the host:port from a test server URL, percent-encoding
// the port colon as %3A for use in did:jwks identifiers.
func testDomain(server *httptest.Server) string {
	addr := server.Listener.Addr().String()
	return strings.Replace(addr, ":", "%3A", 1)
}

// --- Tests: DID Parsing ---

func TestParseDID(t *testing.T) {
	tests := []struct {
		name       string
		did        string
		wantDomain string
		wantPath   string
		wantErr    bool
	}{
		{
			name:       "root DID",
			did:        "did:jwks:example.com",
			wantDomain: "example.com",
			wantPath:   "",
		},
		{
			name:       "DID with path",
			did:        "did:jwks:example.com:api:v1",
			wantDomain: "example.com",
			wantPath:   "api/v1",
		},
		{
			name:       "DID with port",
			did:        "did:jwks:example.com%3A8443",
			wantDomain: "example.com:8443",
			wantPath:   "",
		},
		{
			name:       "DID with port and path",
			did:        "did:jwks:example.com%3A8443:tenant:abc",
			wantDomain: "example.com:8443",
			wantPath:   "tenant/abc",
		},
		{
			name:    "empty method-specific ID",
			did:     "did:jwks:",
			wantErr: true,
		},
		{
			name:    "not a did:jwks",
			did:     "did:web:example.com",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			domain, path, err := parseDID(tt.did)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error, got domain=%q path=%q", domain, path)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if domain != tt.wantDomain {
				t.Errorf("domain = %q, want %q", domain, tt.wantDomain)
			}
			if path != tt.wantPath {
				t.Errorf("path = %q, want %q", path, tt.wantPath)
			}
		})
	}
}

func TestSplitFragment(t *testing.T) {
	tests := []struct {
		input        string
		wantBase     string
		wantFragment string
	}{
		{"did:jwks:example.com", "did:jwks:example.com", ""},
		{"did:jwks:example.com#key-1", "did:jwks:example.com", "key-1"},
		{"did:jwks:example.com:api#thumb", "did:jwks:example.com:api", "thumb"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			base, frag := splitFragment(tt.input)
			if base != tt.wantBase {
				t.Errorf("base = %q, want %q", base, tt.wantBase)
			}
			if frag != tt.wantFragment {
				t.Errorf("fragment = %q, want %q", frag, tt.wantFragment)
			}
		})
	}
}

// --- Tests: URL Construction ---

func TestBuildJWKSURL(t *testing.T) {
	tests := []struct {
		scheme string
		domain string
		path   string
		want   string
	}{
		{"https", "example.com", "", "https://example.com/.well-known/jwks.json"},
		{"https", "example.com", "api/v1", "https://example.com/api/v1/jwks.json"},
		{"http", "localhost:8080", "", "http://localhost:8080/.well-known/jwks.json"},
		{"https", "auth.example.com", "tenant123", "https://auth.example.com/tenant123/jwks.json"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			got := buildJWKSURL(tt.scheme, tt.domain, tt.path)
			if got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestBuildDiscoveryURL(t *testing.T) {
	tests := []struct {
		scheme string
		domain string
		path   string
		want   string
	}{
		{"https", "example.com", "", "https://example.com/.well-known/openid-configuration"},
		{"https", "example.com", "api/v1", "https://example.com/.well-known/openid-configuration/api/v1"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			got := buildDiscoveryURL(tt.scheme, tt.domain, tt.path)
			if got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}

// --- Tests: JWK Thumbprint ---

func TestJWKThumbprint(t *testing.T) {
	// Test with the EC key from the JWKS
	ecKey := ecSigningJWK()
	tp, err := jwkThumbprint(ecKey)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tp == "" {
		t.Fatal("thumbprint should not be empty")
	}

	// Thumbprint should be deterministic
	tp2, _ := jwkThumbprint(ecKey)
	if tp != tp2 {
		t.Errorf("thumbprint not deterministic: %q != %q", tp, tp2)
	}

	// Adding non-required fields should not change thumbprint
	ecKeyWithKid := map[string]interface{}{
		"kty": "EC",
		"crv": "P-256",
		"x":   "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
		"y":   "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0",
		"kid": "ec-key-1",
		"use": "sig",
	}
	tp3, err := jwkThumbprint(ecKeyWithKid)
	if err != nil {
		t.Fatalf("unexpected error with extra fields: %v", err)
	}
	if tp3 != tp {
		t.Errorf("thumbprint should ignore non-required fields: %q != %q", tp3, tp)
	}

	// RSA key thumbprint
	rsaKey := rsaEncJWK()
	rsaTP, err := jwkThumbprint(rsaKey)
	if err != nil {
		t.Fatalf("RSA thumbprint error: %v", err)
	}
	if rsaTP == "" {
		t.Fatal("RSA thumbprint should not be empty")
	}
	if rsaTP == tp {
		t.Error("RSA and EC thumbprints should differ")
	}

	// OKP key thumbprint
	okpKey := map[string]interface{}{
		"kty": "OKP",
		"crv": "Ed25519",
		"x":   "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo",
	}
	okpTP, err := jwkThumbprint(okpKey)
	if err != nil {
		t.Fatalf("OKP thumbprint error: %v", err)
	}
	if okpTP == "" {
		t.Fatal("OKP thumbprint should not be empty")
	}

	// Missing required member should fail
	_, err = jwkThumbprint(map[string]interface{}{"kty": "EC", "crv": "P-256", "x": "abc"})
	if err == nil {
		t.Error("expected error for missing required member 'y'")
	}

	// Missing kty should fail
	_, err = jwkThumbprint(map[string]interface{}{"crv": "P-256"})
	if err == nil {
		t.Error("expected error for missing kty")
	}
}

// --- Tests: DID Document Generation ---

func TestBuildDIDDocument(t *testing.T) {
	jwks := &JWKS{}
	raw := sampleJWKS()
	keysRaw := raw["keys"].([]interface{})
	for _, k := range keysRaw {
		jwks.Keys = append(jwks.Keys, k.(map[string]interface{}))
	}

	doc, err := buildDIDDocument("did:jwks:example.com", jwks)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if doc.ID != "did:jwks:example.com" {
		t.Errorf("ID = %q, want %q", doc.ID, "did:jwks:example.com")
	}

	if len(doc.VerificationMethod) != 2 {
		t.Fatalf("expected 2 verification methods, got %d", len(doc.VerificationMethod))
	}

	// EC key (use:sig) should be in authentication + assertionMethod
	if len(doc.Authentication) != 1 {
		t.Errorf("expected 1 authentication entry, got %d", len(doc.Authentication))
	}
	if len(doc.AssertionMethod) != 1 {
		t.Errorf("expected 1 assertionMethod entry, got %d", len(doc.AssertionMethod))
	}

	// RSA key (use:enc) should be in keyAgreement
	if len(doc.KeyAgreement) != 1 {
		t.Errorf("expected 1 keyAgreement entry, got %d", len(doc.KeyAgreement))
	}

	// Verify VM IDs contain thumbprints
	for _, vm := range doc.VerificationMethod {
		if vm.Type != "JsonWebKey" {
			t.Errorf("VM type = %q, want %q", vm.Type, "JsonWebKey")
		}
		if vm.Controller != "did:jwks:example.com" {
			t.Errorf("VM controller = %q, want %q", vm.Controller, "did:jwks:example.com")
		}
		if vm.Thumbprint == "" {
			t.Error("VM should have a thumbprint")
		}
		expectedID := fmt.Sprintf("did:jwks:example.com#%s", vm.Thumbprint)
		if vm.ID != expectedID {
			t.Errorf("VM ID = %q, want %q", vm.ID, expectedID)
		}
	}

	// EC key should have kid stored
	if doc.VerificationMethod[0].Kid != "ec-key-1" {
		t.Errorf("EC VM kid = %q, want %q", doc.VerificationMethod[0].Kid, "ec-key-1")
	}
}

// --- Tests: Full Evaluate ---

func TestEvaluateResolutionOnly(t *testing.T) {
	server := newRoutingServer(sampleJWKS(), "/.well-known/jwks.json")
	defer server.Close()

	reg := registryWith(server)
	domain := testDomain(server)

	req := &authzen.EvaluationRequest{
		Subject:  authzen.Subject{Type: "key", ID: fmt.Sprintf("did:jwks:%s", domain)},
		Resource: authzen.Resource{
			// No type or key = resolution-only
		},
	}

	resp, err := reg.Evaluate(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !resp.Decision {
		t.Fatalf("expected decision=true for resolution-only, got false (reason: %v)", resp.Context.Reason)
	}

	// Should have trust_metadata with DID document
	if resp.Context == nil || resp.Context.TrustMetadata == nil {
		t.Fatal("expected trust_metadata in response")
	}
	meta, ok := resp.Context.TrustMetadata.(map[string]interface{})
	if !ok {
		t.Fatal("trust_metadata should be a map")
	}
	if meta["id"] != fmt.Sprintf("did:jwks:%s", domain) {
		t.Errorf("trust_metadata.id = %v, want did:jwks:%s", meta["id"], domain)
	}
}

func TestEvaluateKeyMatch(t *testing.T) {
	server := newRoutingServer(sampleJWKS(), "/.well-known/jwks.json")
	defer server.Close()

	reg := registryWith(server)
	domain := testDomain(server)

	req := &authzen.EvaluationRequest{
		Subject: authzen.Subject{Type: "key", ID: fmt.Sprintf("did:jwks:%s", domain)},
		Resource: authzen.Resource{
			Type: "jwk",
			ID:   fmt.Sprintf("did:jwks:%s", domain),
			Key:  []interface{}{ecSigningJWK()},
		},
	}

	resp, err := reg.Evaluate(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !resp.Decision {
		t.Fatalf("expected decision=true, got false (reason: %v)", resp.Context.Reason)
	}
}

func TestEvaluateKeyNoMatch(t *testing.T) {
	server := newRoutingServer(sampleJWKS(), "/.well-known/jwks.json")
	defer server.Close()

	reg := registryWith(server)
	domain := testDomain(server)

	unknownKey := map[string]interface{}{
		"kty": "EC",
		"crv": "P-256",
		"x":   "WbbaSStuffThatDoesntMatchh",
		"y":   "WbbaSStuffThatDoesntMatchh",
	}

	req := &authzen.EvaluationRequest{
		Subject: authzen.Subject{Type: "key", ID: fmt.Sprintf("did:jwks:%s", domain)},
		Resource: authzen.Resource{
			Type: "jwk",
			ID:   fmt.Sprintf("did:jwks:%s", domain),
			Key:  []interface{}{unknownKey},
		},
	}

	resp, err := reg.Evaluate(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Decision {
		t.Fatal("expected decision=false for unknown key")
	}
}

func TestEvaluateFragmentMatchByKid(t *testing.T) {
	server := newRoutingServer(sampleJWKS(), "/.well-known/jwks.json")
	defer server.Close()

	reg := registryWith(server)
	domain := testDomain(server)

	req := &authzen.EvaluationRequest{
		Subject: authzen.Subject{Type: "key", ID: fmt.Sprintf("did:jwks:%s#ec-key-1", domain)},
		Resource: authzen.Resource{
			Type: "jwk",
			ID:   fmt.Sprintf("did:jwks:%s#ec-key-1", domain),
			Key:  []interface{}{ecSigningJWK()},
		},
	}

	resp, err := reg.Evaluate(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !resp.Decision {
		t.Fatalf("expected decision=true for kid fragment match, got false (reason: %v)", resp.Context.Reason)
	}
}

func TestEvaluateFragmentMatchByThumbprint(t *testing.T) {
	server := newRoutingServer(sampleJWKS(), "/.well-known/jwks.json")
	defer server.Close()

	reg := registryWith(server)
	domain := testDomain(server)

	// Compute the expected thumbprint for the EC key
	tp, err := jwkThumbprint(ecSigningJWK())
	if err != nil {
		t.Fatalf("computing thumbprint: %v", err)
	}

	req := &authzen.EvaluationRequest{
		Subject: authzen.Subject{Type: "key", ID: fmt.Sprintf("did:jwks:%s#%s", domain, tp)},
		Resource: authzen.Resource{
			Type: "jwk",
			ID:   fmt.Sprintf("did:jwks:%s#%s", domain, tp),
			Key:  []interface{}{ecSigningJWK()},
		},
	}

	resp, err := reg.Evaluate(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !resp.Decision {
		t.Fatalf("expected decision=true for thumbprint fragment match, got false (reason: %v)", resp.Context.Reason)
	}
}

func TestEvaluateFragmentWrongKid(t *testing.T) {
	server := newRoutingServer(sampleJWKS(), "/.well-known/jwks.json")
	defer server.Close()

	reg := registryWith(server)
	domain := testDomain(server)

	// EC key with RSA kid fragment — fragment match fails, but fallback key-material match succeeds
	req := &authzen.EvaluationRequest{
		Subject: authzen.Subject{Type: "key", ID: fmt.Sprintf("did:jwks:%s#rsa-enc-1", domain)},
		Resource: authzen.Resource{
			Type: "jwk",
			ID:   fmt.Sprintf("did:jwks:%s#rsa-enc-1", domain),
			Key:  []interface{}{ecSigningJWK()},
		},
	}

	resp, err := reg.Evaluate(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Fragment "rsa-enc-1" doesn't match EC key, but fallback key-material match finds it
	if !resp.Decision {
		t.Fatalf("expected decision=true via fallback key-material match, got false (reason: %v)", resp.Context.Reason)
	}
}

func TestEvaluateNotDIDJWKS(t *testing.T) {
	reg, _ := NewRegistry(Config{AllowHTTP: true})

	req := &authzen.EvaluationRequest{
		Subject:  authzen.Subject{Type: "key", ID: "did:web:example.com"},
		Resource: authzen.Resource{},
	}

	resp, err := reg.Evaluate(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Decision {
		t.Fatal("expected decision=false for non-did:jwks DID")
	}
}

func TestEvaluatePathDID(t *testing.T) {
	server := newRoutingServer(sampleJWKS(), "/api/v1/jwks.json")
	defer server.Close()

	reg := registryWith(server)
	domain := testDomain(server)

	// did:jwks:domain:api:v1 → https://{domain}/api/v1/jwks.json
	did := fmt.Sprintf("did:jwks:%s:api:v1", domain)
	req := &authzen.EvaluationRequest{
		Subject:  authzen.Subject{Type: "key", ID: did},
		Resource: authzen.Resource{},
	}

	resp, err := reg.Evaluate(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !resp.Decision {
		t.Fatalf("expected decision=true for path DID resolution, got false (reason: %v)", resp.Context.Reason)
	}
}

func TestEvaluateOIDCDiscoveryFallback(t *testing.T) {
	jwks := sampleJWKS()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprintf(w, `{"jwks_uri":"http://%s/custom/jwks"}`, r.Host)
		case "/custom/jwks":
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(jwks)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	// Enable OIDC discovery for this test
	reg, _ := NewRegistry(Config{
		AllowHTTP:            true,
		DisableOIDCDiscovery: false,
	})
	reg.SetHTTPClient(server.Client())

	domain := testDomain(server)
	req := &authzen.EvaluationRequest{
		Subject:  authzen.Subject{Type: "key", ID: fmt.Sprintf("did:jwks:%s", domain)},
		Resource: authzen.Resource{},
	}

	resp, err := reg.Evaluate(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !resp.Decision {
		t.Fatalf("expected decision=true via OIDC discovery fallback, got false (reason: %v)", resp.Context.Reason)
	}
}

// --- Tests: Policy Constraints ---

func TestEvaluateAllowedDomains(t *testing.T) {
	server := newRoutingServer(sampleJWKS(), "/.well-known/jwks.json")
	defer server.Close()

	reg := registryWith(server)
	domain := testDomain(server)
	// allowed_domains uses the actual host:port (with real colon), not DID-encoded
	rawDomain := server.Listener.Addr().String()

	// Allowed domain matches
	req := &authzen.EvaluationRequest{
		Subject:  authzen.Subject{Type: "key", ID: fmt.Sprintf("did:jwks:%s", domain)},
		Resource: authzen.Resource{},
		Context:  map[string]interface{}{"allowed_domains": []interface{}{rawDomain}},
	}
	resp, _ := reg.Evaluate(context.Background(), req)
	if !resp.Decision {
		t.Fatalf("expected allowed domain to succeed, got false (reason: %v)", resp.Context.Reason)
	}

	// Disallowed domain
	req.Context = map[string]interface{}{"allowed_domains": []interface{}{"other.com"}}
	resp, _ = reg.Evaluate(context.Background(), req)
	if resp.Decision {
		t.Fatal("expected disallowed domain to fail")
	}
}

// --- Tests: Interface Methods ---

func TestRegistryInterface(t *testing.T) {
	reg, err := NewRegistry(Config{})
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}

	if types := reg.SupportedResourceTypes(); len(types) != 1 || types[0] != "jwk" {
		t.Errorf("SupportedResourceTypes = %v, want [jwk]", types)
	}

	if !reg.SupportsResolutionOnly() {
		t.Error("expected SupportsResolutionOnly = true")
	}

	info := reg.Info()
	if info.Name != "didjwks-registry" {
		t.Errorf("Info.Name = %q, want %q", info.Name, "didjwks-registry")
	}
	if info.Type != "did:jwks" {
		t.Errorf("Info.Type = %q, want %q", info.Type, "did:jwks")
	}

	if !reg.Healthy() {
		t.Error("expected Healthy = true")
	}

	if err := reg.Refresh(context.Background()); err != nil {
		t.Errorf("Refresh: %v", err)
	}
}

func TestEvaluateEmptyJWKS(t *testing.T) {
	emptyJWKS := map[string]interface{}{"keys": []interface{}{}}
	server := newRoutingServer(emptyJWKS, "/.well-known/jwks.json")
	defer server.Close()

	reg := registryWith(server)
	domain := testDomain(server)

	req := &authzen.EvaluationRequest{
		Subject:  authzen.Subject{Type: "key", ID: fmt.Sprintf("did:jwks:%s", domain)},
		Resource: authzen.Resource{},
	}

	resp, err := reg.Evaluate(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Decision {
		t.Fatal("expected decision=false for empty JWKS")
	}
}

func TestEvaluateRSAKeyMatch(t *testing.T) {
	server := newRoutingServer(sampleJWKS(), "/.well-known/jwks.json")
	defer server.Close()

	reg := registryWith(server)
	domain := testDomain(server)

	req := &authzen.EvaluationRequest{
		Subject: authzen.Subject{Type: "key", ID: fmt.Sprintf("did:jwks:%s", domain)},
		Resource: authzen.Resource{
			Type: "jwk",
			ID:   fmt.Sprintf("did:jwks:%s", domain),
			Key:  []interface{}{rsaEncJWK()},
		},
	}

	resp, err := reg.Evaluate(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !resp.Decision {
		t.Fatalf("expected decision=true for RSA key match, got false (reason: %v)", resp.Context.Reason)
	}
}
