package issuermetadata

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
)

func newTestResolver(t *testing.T) *Resolver {
	t.Helper()
	r, err := New(Config{
		CacheTTL:        5 * time.Minute,
		HTTPTimeout:     5 * time.Second,
		AllowHTTP:       true,
		AllowPrivateIPs: true,
	})
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}
	return r
}

// newTestKey returns a fresh ECDSA P-256 key pair and its public JWK for test use.
func newTestKey(t *testing.T) (*ecdsa.PrivateKey, jose.JSONWebKey) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating ECDSA key: %v", err)
	}
	pubJWK := jose.JSONWebKey{Key: priv.Public(), Algorithm: string(jose.ES256), Use: "sig"}
	return priv, pubJWK
}

// signClaims signs the given claims as a compact JWS using ES256.
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

// inlineJWKS returns the JSON-marshaled JWKS containing just the given public JWK.
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

// TestResolve_NoSignedMetadata verifies that plain (unsigned) metadata is
// returned as-is when signed_metadata is absent.
func TestResolve_NoSignedMetadata(t *testing.T) {
	meta := map[string]interface{}{
		"credential_issuer": "https://issuer.example.com",
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/.well-known/openid-credential-issuer" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(meta) //nolint:errcheck
	}))
	defer server.Close()

	r := newTestResolver(t)
	got, err := r.Resolve(context.Background(), server.URL)
	if err != nil {
		t.Fatalf("Resolve() error: %v", err)
	}
	if got["credential_issuer"] != "https://issuer.example.com" {
		t.Errorf("credential_issuer: got %v", got["credential_issuer"])
	}
}

// TestResolve_SignedMetadata_InlineJWKS verifies that when signed_metadata is
// present with an inline JWKS, the JWT signature is validated and the JWT
// payload claims are returned as the authoritative metadata.
func TestResolve_SignedMetadata_InlineJWKS(t *testing.T) {
	priv, pub := newTestKey(t)

	// JWT claims are the authoritative metadata.
	jwtClaims := map[string]interface{}{
		"credential_issuer": "https://issuer.example.com",
		"credential_configurations_supported": map[string]interface{}{
			"UniversityDegree": map[string]interface{}{"format": "vc+sd-jwt"},
		},
	}
	token := signClaims(t, priv, jwtClaims)

	// Outer document includes the inline JWKS and signed_metadata.
	outer := map[string]interface{}{
		"credential_issuer": "https://issuer.example.com",
		"jwks":              inlineJWKS(t, pub),
		"signed_metadata":   token,
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/.well-known/openid-credential-issuer" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(outer) //nolint:errcheck
	}))
	defer server.Close()

	got, err := newTestResolver(t).Resolve(context.Background(), server.URL)
	if err != nil {
		t.Fatalf("Resolve() error: %v", err)
	}

	// Authoritative claim comes from the JWT payload.
	if got["credential_issuer"] != "https://issuer.example.com" {
		t.Errorf("credential_issuer from JWT claims: got %v", got["credential_issuer"])
	}
	// signed_metadata is preserved as the original compact JWS string.
	if got["signed_metadata"] != token {
		t.Errorf("signed_metadata not preserved: got %v", got["signed_metadata"])
	}
	// JWT payload claim is returned.
	if _, ok := got["credential_configurations_supported"]; !ok {
		t.Error("credential_configurations_supported not found in JWT payload claims")
	}
}

// TestResolve_SignedMetadata_JWKSURI verifies that when signed_metadata is
// present and the outer metadata only has jwks_uri (no inline jwks), the
// resolver fetches the JWKS, validates the signature, and returns JWT claims.
func TestResolve_SignedMetadata_JWKSURI(t *testing.T) {
	priv, pub := newTestKey(t)

	jwtClaims := map[string]interface{}{
		"credential_issuer": "https://issuer.example.com",
	}
	token := signClaims(t, priv, jwtClaims)

	jwksBody, err := json.Marshal(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{pub}})
	if err != nil {
		t.Fatalf("marshaling JWKS: %v", err)
	}

	var jwksServer *httptest.Server
	jwksServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(jwksBody) //nolint:errcheck
	}))
	defer jwksServer.Close()

	outer := map[string]interface{}{
		"credential_issuer": "https://issuer.example.com",
		"jwks_uri":          jwksServer.URL + "/jwks",
		"signed_metadata":   token,
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/.well-known/openid-credential-issuer" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(outer) //nolint:errcheck
	}))
	defer server.Close()

	got, err := newTestResolver(t).Resolve(context.Background(), server.URL)
	if err != nil {
		t.Fatalf("Resolve() error: %v", err)
	}
	if got["credential_issuer"] != "https://issuer.example.com" {
		t.Errorf("credential_issuer: got %v", got["credential_issuer"])
	}
	if got["signed_metadata"] != token {
		t.Errorf("signed_metadata not preserved: got %v", got["signed_metadata"])
	}
}

// TestResolve_SignedMetadata_InvalidSignature verifies that a signed_metadata
// JWT with a signature that does not match the JWKS is rejected with an error.
func TestResolve_SignedMetadata_InvalidSignature(t *testing.T) {
	priv, _ := newTestKey(t)
	_, differentPub := newTestKey(t) // a different key — wrong public key

	jwtClaims := map[string]interface{}{"credential_issuer": "https://issuer.example.com"}
	token := signClaims(t, priv, jwtClaims)

	outer := map[string]interface{}{
		"credential_issuer": "https://issuer.example.com",
		"jwks":              inlineJWKS(t, differentPub), // wrong key
		"signed_metadata":   token,
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/.well-known/openid-credential-issuer" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(outer) //nolint:errcheck
	}))
	defer server.Close()

	_, err := newTestResolver(t).Resolve(context.Background(), server.URL)
	if err == nil {
		t.Error("expected error for invalid signed_metadata signature, got nil")
	}
}

// TestResolve_SignedMetadata_NoJWKS verifies that when signed_metadata is
// present but the metadata has neither jwks nor jwks_uri, an error is returned.
func TestResolve_SignedMetadata_NoJWKS(t *testing.T) {
	priv, _ := newTestKey(t)
	token := signClaims(t, priv, map[string]interface{}{"credential_issuer": "https://issuer.example.com"})

	outer := map[string]interface{}{
		"credential_issuer": "https://issuer.example.com",
		"signed_metadata":   token,
		// no jwks or jwks_uri
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/.well-known/openid-credential-issuer" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(outer) //nolint:errcheck
	}))
	defer server.Close()

	_, err := newTestResolver(t).Resolve(context.Background(), server.URL)
	if err == nil {
		t.Error("expected error when signed_metadata present but no JWKS available, got nil")
	}
}

func TestResolve_Cached(t *testing.T) {
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"credential_issuer": "https://test.com"}) //nolint:errcheck
	}))
	defer server.Close()

	r := newTestResolver(t)

	if _, err := r.Resolve(context.Background(), server.URL); err != nil {
		t.Fatalf("first Resolve() error: %v", err)
	}
	if _, err := r.Resolve(context.Background(), server.URL); err != nil {
		t.Fatalf("second Resolve() error: %v", err)
	}
	if calls != 1 {
		t.Errorf("expected 1 HTTP request, got %d", calls)
	}
}

func TestResolve_TrailingSlashStripped(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"credential_issuer": "https://test.com"}) //nolint:errcheck
	}))
	defer server.Close()

	r := newTestResolver(t)
	// URL with trailing slash should work the same
	if _, err := r.Resolve(context.Background(), server.URL+"/"); err != nil {
		t.Fatalf("Resolve() with trailing slash error: %v", err)
	}
}

func TestResolve_RejectsHTTPByDefault(t *testing.T) {
	r, _ := New(Config{}) // AllowHTTP = false
	_, err := r.Resolve(context.Background(), "http://issuer.example.com")
	if err == nil {
		t.Error("expected error for HTTP URL, got nil")
	}
}

func TestResolve_RejectsNonHTTPScheme(t *testing.T) {
	r := newTestResolver(t)
	_, err := r.Resolve(context.Background(), "ftp://issuer.example.com")
	if err == nil {
		t.Error("expected error for ftp:// URL, got nil")
	}
}

func TestResolve_RejectsMissingHost(t *testing.T) {
	r := newTestResolver(t)
	_, err := r.Resolve(context.Background(), "https://")
	if err == nil {
		t.Error("expected error for URL without host, got nil")
	}
}

func TestResolve_RejectsInvalidJSON(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte("not json")) //nolint:errcheck
	}))
	defer server.Close()

	r := newTestResolver(t)
	_, err := r.Resolve(context.Background(), server.URL)
	if err == nil {
		t.Error("expected error for invalid JSON response")
	}
}

func TestResolve_RejectsNonOKStatus(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	r := newTestResolver(t)
	_, err := r.Resolve(context.Background(), server.URL)
	if err == nil {
		t.Error("expected error for HTTP 404 response")
	}
}

func TestResolve_CacheTTLExpiry(t *testing.T) {
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]int{"call": calls}) //nolint:errcheck
	}))
	defer server.Close()

	r, _ := New(Config{
		CacheTTL:        1 * time.Millisecond, // very short TTL
		HTTPTimeout:     5 * time.Second,
		AllowHTTP:       true,
		AllowPrivateIPs: true,
	})

	if _, err := r.Resolve(context.Background(), server.URL); err != nil {
		t.Fatalf("first Resolve() error: %v", err)
	}

	time.Sleep(5 * time.Millisecond) // let TTL expire

	if _, err := r.Resolve(context.Background(), server.URL); err != nil {
		t.Fatalf("second Resolve() error: %v", err)
	}

	if calls != 2 {
		t.Errorf("expected 2 HTTP requests after TTL expiry, got %d", calls)
	}
}
