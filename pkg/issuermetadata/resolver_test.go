package issuermetadata

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/sirosfoundation/go-trust/pkg/authzen"
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

// TestResolve_SignedMetadata_KIDSelection verifies that when the JWT header
// carries a kid, only the matching key in the JWKS is used for verification
// (the JWKS may contain additional keys for other purposes).
func TestResolve_SignedMetadata_KIDSelection(t *testing.T) {
	priv, pub := newTestKey(t)
	pub.KeyID = "sig-2024"
	_, unrelatedPub := newTestKey(t) // an unrelated key in the JWKS
	unrelatedPub.KeyID = "enc-2024"

	// Build JWKS with both keys; sign with the specific kid.
	b, err := json.Marshal(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{unrelatedPub, pub}})
	if err != nil {
		t.Fatalf("marshaling JWKS: %v", err)
	}
	var jwksMap map[string]interface{}
	if err := json.Unmarshal(b, &jwksMap); err != nil {
		t.Fatalf("unmarshaling JWKS: %v", err)
	}

	// Sign with the private key carrying kid="sig-2024".
	signingKey := jose.SigningKey{Algorithm: jose.ES256, Key: &jose.JSONWebKey{Key: priv, KeyID: "sig-2024"}}
	signer, err := jose.NewSigner(signingKey, (&jose.SignerOptions{}).WithType("JWT"))
	if err != nil {
		t.Fatalf("creating signer: %v", err)
	}
	payload, err := json.Marshal(map[string]interface{}{"credential_issuer": "https://issuer.example.com"})
	if err != nil {
		t.Fatalf("marshaling payload: %v", err)
	}
	jws, err := signer.Sign(payload)
	if err != nil {
		t.Fatalf("signing: %v", err)
	}
	token, err := jws.CompactSerialize()
	if err != nil {
		t.Fatalf("serializing: %v", err)
	}

	outer := map[string]interface{}{
		"credential_issuer": "https://issuer.example.com",
		"jwks":              jwksMap,
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

// mockTrustEvaluator implements TrustEvaluator for testing.
type mockTrustEvaluator struct {
	decision bool
	err      error
	requests []*authzen.EvaluationRequest
}

func (m *mockTrustEvaluator) Evaluate(_ context.Context, req *authzen.EvaluationRequest) (*authzen.EvaluationResponse, error) {
	m.requests = append(m.requests, req)
	if m.err != nil {
		return nil, m.err
	}
	resp := &authzen.EvaluationResponse{Decision: m.decision}
	if !m.decision {
		resp.Context = &authzen.EvaluationResponseContext{
			Reason: map[string]interface{}{"error": "not trusted"},
		}
	}
	return resp, nil
}

// newTestCert creates a self-signed X.509 certificate for the given key.
func newTestCert(t *testing.T, priv *ecdsa.PrivateKey) *x509.Certificate {
	t.Helper()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	derBytes, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("creating test certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(derBytes)
	if err != nil {
		t.Fatalf("parsing test certificate: %v", err)
	}
	return cert
}

// signClaimsWithX5C signs claims as a compact JWS with x5c header.
func signClaimsWithX5C(t *testing.T, priv *ecdsa.PrivateKey, certs []*x509.Certificate, typ string, claims map[string]interface{}) string {
	t.Helper()
	opts := &jose.SignerOptions{}
	if typ != "" {
		opts = opts.WithType(jose.ContentType(typ))
	}
	// Add x5c header
	b64Certs := make([]interface{}, len(certs))
	for i, cert := range certs {
		b64Certs[i] = base64.StdEncoding.EncodeToString(cert.Raw)
	}
	opts = opts.WithHeader("x5c", b64Certs)

	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.ES256, Key: priv},
		opts,
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

// TestResolveWithInfo_Validated_SignedMetadata verifies that ResolveWithInfo
// reports Validated=true when signed_metadata is present, valid, and a
// TrustEvaluator is configured that approves the signer.
func TestResolveWithInfo_Validated_SignedMetadata(t *testing.T) {
	priv, pub := newTestKey(t)
	jwtClaims := map[string]interface{}{
		"credential_issuer": "https://issuer.example.com",
	}
	token := signClaims(t, priv, jwtClaims)

	outer := map[string]interface{}{
		"credential_issuer": "https://issuer.example.com",
		"jwks":              inlineJWKS(t, pub),
		"signed_metadata":   token,
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(outer) //nolint:errcheck
	}))
	defer server.Close()

	evaluator := &mockTrustEvaluator{decision: true}
	resolver, _ := New(Config{
		AllowHTTP:       true,
		AllowPrivateIPs: true,
		TrustEvaluator:  evaluator,
	})
	result, err := resolver.ResolveWithInfo(context.Background(), server.URL)
	if err != nil {
		t.Fatalf("ResolveWithInfo() error: %v", err)
	}
	if !result.Validated {
		t.Error("expected Validated=true for signed_metadata response with TrustEvaluator")
	}
}

// TestResolveWithInfo_NotValidated_SignedWithoutEvaluator verifies that
// Validated=false when signed_metadata is present but no TrustEvaluator is configured.
func TestResolveWithInfo_NotValidated_SignedWithoutEvaluator(t *testing.T) {
	priv, pub := newTestKey(t)
	jwtClaims := map[string]interface{}{
		"credential_issuer": "https://issuer.example.com",
	}
	token := signClaims(t, priv, jwtClaims)

	outer := map[string]interface{}{
		"credential_issuer": "https://issuer.example.com",
		"jwks":              inlineJWKS(t, pub),
		"signed_metadata":   token,
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(outer) //nolint:errcheck
	}))
	defer server.Close()

	result, err := newTestResolver(t).ResolveWithInfo(context.Background(), server.URL)
	if err != nil {
		t.Fatalf("ResolveWithInfo() error: %v", err)
	}
	if result.Validated {
		t.Error("expected Validated=false for signed_metadata without TrustEvaluator")
	}
}

// TestResolveWithInfo_NotValidated_UnsignedJSON verifies that ResolveWithInfo
// reports Validated=false for plain unsigned JSON.
func TestResolveWithInfo_NotValidated_UnsignedJSON(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"credential_issuer": "https://test.com"}) //nolint:errcheck
	}))
	defer server.Close()

	result, err := newTestResolver(t).ResolveWithInfo(context.Background(), server.URL)
	if err != nil {
		t.Fatalf("ResolveWithInfo() error: %v", err)
	}
	if result.Validated {
		t.Error("expected Validated=false for unsigned JSON response")
	}
}

// TestResolve_ApplicationJWT_WithX5C tests the application/jwt Content-Type
// response path with x5c certificate chain in the JOSE header.
func TestResolve_ApplicationJWT_WithX5C(t *testing.T) {
	priv, _ := newTestKey(t)
	cert := newTestCert(t, priv)

	evaluator := &mockTrustEvaluator{decision: true}

	// We need the server URL for the sub claim, so create server first with a handler
	// that will be set after we know the URL.
	var token string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/jwt")
		w.Write([]byte(token)) //nolint:errcheck
	}))
	defer server.Close()

	// Now create the token with sub matching the test server URL
	claims := map[string]interface{}{
		"credential_issuer": server.URL,
		"sub":               server.URL,
		"iat":               time.Now().Unix(),
	}
	token = signClaimsWithX5C(t, priv, []*x509.Certificate{cert}, "openidvci-issuer-metadata+jwt", claims)

	resolver, err := New(Config{
		CacheTTL:        5 * time.Minute,
		HTTPTimeout:     5 * time.Second,
		AllowHTTP:       true,
		AllowPrivateIPs: true,
		TrustEvaluator:  evaluator,
	})
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}

	result, err := resolver.ResolveWithInfo(context.Background(), server.URL)
	if err != nil {
		t.Fatalf("ResolveWithInfo() error: %v", err)
	}
	if !result.Validated {
		t.Error("expected Validated=true for application/jwt response")
	}
	if result.Metadata["sub"] != server.URL {
		t.Errorf("expected sub=%q, got %v", server.URL, result.Metadata["sub"])
	}

	// Verify trust evaluator was called with x5c
	if len(evaluator.requests) != 1 {
		t.Fatalf("expected 1 trust evaluation request, got %d", len(evaluator.requests))
	}
	req := evaluator.requests[0]
	if req.Resource.Type != "x5c" {
		t.Errorf("expected resource.type=x5c, got %q", req.Resource.Type)
	}
	if req.Action == nil || req.Action.Name != "credential-issuer" {
		t.Error("expected action.name=credential-issuer")
	}
}

// TestResolve_ApplicationJWT_TrustEvaluatorRejects tests that when the trust
// evaluator rejects the signer, the metadata is not returned.
func TestResolve_ApplicationJWT_TrustEvaluatorRejects(t *testing.T) {
	priv, _ := newTestKey(t)
	cert := newTestCert(t, priv)

	evaluator := &mockTrustEvaluator{decision: false}

	var token string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/jwt")
		w.Write([]byte(token)) //nolint:errcheck
	}))
	defer server.Close()

	claims := map[string]interface{}{
		"credential_issuer": server.URL,
		"sub":               server.URL,
		"iat":               time.Now().Unix(),
	}
	token = signClaimsWithX5C(t, priv, []*x509.Certificate{cert}, "openidvci-issuer-metadata+jwt", claims)

	resolver, _ := New(Config{
		CacheTTL:        5 * time.Minute,
		HTTPTimeout:     5 * time.Second,
		AllowHTTP:       true,
		AllowPrivateIPs: true,
		TrustEvaluator:  evaluator,
	})

	_, err := resolver.Resolve(context.Background(), server.URL)
	if err == nil {
		t.Error("expected error when trust evaluator rejects signer")
	}
	if !strings.Contains(err.Error(), "not trusted") {
		t.Errorf("expected 'not trusted' in error, got: %v", err)
	}
}

// TestResolve_ApplicationJWT_WrongTyp tests that a JWT with wrong typ header is rejected.
func TestResolve_ApplicationJWT_WrongTyp(t *testing.T) {
	priv, _ := newTestKey(t)
	cert := newTestCert(t, priv)

	issuerURL := "https://issuer.example.com"
	claims := map[string]interface{}{
		"credential_issuer": issuerURL,
		"sub":               issuerURL,
		"iat":               time.Now().Unix(),
	}
	// Wrong typ
	token := signClaimsWithX5C(t, priv, []*x509.Certificate{cert}, "JWT", claims)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/jwt")
		w.Write([]byte(token)) //nolint:errcheck
	}))
	defer server.Close()

	resolver, _ := New(Config{
		AllowHTTP:       true,
		AllowPrivateIPs: true,
	})

	_, err := resolver.Resolve(context.Background(), server.URL)
	if err == nil {
		t.Error("expected error for wrong typ header")
	}
	if !strings.Contains(err.Error(), "openidvci-issuer-metadata+jwt") {
		t.Errorf("expected typ error message, got: %v", err)
	}
}

// TestResolve_ApplicationJWT_MissingSub tests that a JWT without sub claim is rejected.
func TestResolve_ApplicationJWT_MissingSub(t *testing.T) {
	priv, _ := newTestKey(t)
	cert := newTestCert(t, priv)

	claims := map[string]interface{}{
		"credential_issuer": "https://issuer.example.com",
		// missing "sub"
		"iat": time.Now().Unix(),
	}
	token := signClaimsWithX5C(t, priv, []*x509.Certificate{cert}, "openidvci-issuer-metadata+jwt", claims)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/jwt")
		w.Write([]byte(token)) //nolint:errcheck
	}))
	defer server.Close()

	resolver, _ := New(Config{AllowHTTP: true, AllowPrivateIPs: true})
	_, err := resolver.Resolve(context.Background(), server.URL)
	if err == nil {
		t.Error("expected error for missing sub claim")
	}
}

// TestResolve_ApplicationJWT_SubMismatch tests that a JWT with sub not matching issuer URL is rejected.
func TestResolve_ApplicationJWT_SubMismatch(t *testing.T) {
	priv, _ := newTestKey(t)
	cert := newTestCert(t, priv)

	claims := map[string]interface{}{
		"credential_issuer": "https://issuer.example.com",
		"sub":               "https://different.example.com",
		"iat":               time.Now().Unix(),
	}
	token := signClaimsWithX5C(t, priv, []*x509.Certificate{cert}, "openidvci-issuer-metadata+jwt", claims)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/jwt")
		w.Write([]byte(token)) //nolint:errcheck
	}))
	defer server.Close()

	resolver, _ := New(Config{AllowHTTP: true, AllowPrivateIPs: true})
	_, err := resolver.Resolve(context.Background(), server.URL)
	if err == nil {
		t.Error("expected error for sub mismatch")
	}
	if !strings.Contains(err.Error(), "does not match") {
		t.Errorf("expected sub mismatch error, got: %v", err)
	}
}

// TestResolve_ApplicationJWT_MissingIat tests that a JWT without iat claim is rejected.
func TestResolve_ApplicationJWT_MissingIat(t *testing.T) {
	priv, _ := newTestKey(t)
	cert := newTestCert(t, priv)

	claims := map[string]interface{}{
		"credential_issuer": "https://issuer.example.com",
		"sub":               "https://issuer.example.com",
		// missing "iat"
	}
	token := signClaimsWithX5C(t, priv, []*x509.Certificate{cert}, "openidvci-issuer-metadata+jwt", claims)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/jwt")
		w.Write([]byte(token)) //nolint:errcheck
	}))
	defer server.Close()

	resolver, _ := New(Config{AllowHTTP: true, AllowPrivateIPs: true})
	_, err := resolver.Resolve(context.Background(), server.URL)
	if err == nil {
		t.Error("expected error for missing iat claim")
	}
}

// TestResolve_SignedMetadata_TrustEvaluatorCalled verifies that the trust evaluator
// is called for the legacy signed_metadata field in JSON responses.
func TestResolve_SignedMetadata_TrustEvaluatorCalled(t *testing.T) {
	priv, pub := newTestKey(t)
	jwtClaims := map[string]interface{}{
		"credential_issuer": "https://issuer.example.com",
	}
	token := signClaims(t, priv, jwtClaims)

	outer := map[string]interface{}{
		"credential_issuer": "https://issuer.example.com",
		"jwks":              inlineJWKS(t, pub),
		"signed_metadata":   token,
	}

	evaluator := &mockTrustEvaluator{decision: true}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(outer) //nolint:errcheck
	}))
	defer server.Close()

	resolver, _ := New(Config{
		AllowHTTP:       true,
		AllowPrivateIPs: true,
		TrustEvaluator:  evaluator,
	})

	_, err := resolver.Resolve(context.Background(), server.URL)
	if err != nil {
		t.Fatalf("Resolve() error: %v", err)
	}

	// Trust evaluator should have been called with jwk type
	// (legacy signed_metadata uses JWKS keys, not x5c)
	if len(evaluator.requests) != 1 {
		t.Fatalf("expected 1 trust evaluation request, got %d", len(evaluator.requests))
	}
	req := evaluator.requests[0]
	if req.Resource.Type != "jwk" {
		t.Errorf("expected resource.type=jwk, got %q", req.Resource.Type)
	}
}

// TestResolve_SignedMetadata_TrustEvaluatorRejects verifies that when the trust
// evaluator rejects the signer of signed_metadata, an error is returned.
func TestResolve_SignedMetadata_TrustEvaluatorRejects(t *testing.T) {
	priv, pub := newTestKey(t)
	token := signClaims(t, priv, map[string]interface{}{
		"credential_issuer": "https://issuer.example.com",
	})

	outer := map[string]interface{}{
		"credential_issuer": "https://issuer.example.com",
		"jwks":              inlineJWKS(t, pub),
		"signed_metadata":   token,
	}

	evaluator := &mockTrustEvaluator{decision: false}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(outer) //nolint:errcheck
	}))
	defer server.Close()

	resolver, _ := New(Config{
		AllowHTTP:       true,
		AllowPrivateIPs: true,
		TrustEvaluator:  evaluator,
	})

	_, err := resolver.Resolve(context.Background(), server.URL)
	if err == nil {
		t.Error("expected error when trust evaluator rejects signer")
	}
}

// TestResolve_AcceptHeader verifies the Accept header is sent correctly.
func TestResolve_AcceptHeader(t *testing.T) {
	var acceptHeader string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		acceptHeader = r.Header.Get("Accept")
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"credential_issuer": "https://test.com"}) //nolint:errcheck
	}))
	defer server.Close()

	resolver, _ := New(Config{AllowHTTP: true, AllowPrivateIPs: true})
	resolver.Resolve(context.Background(), server.URL) //nolint:errcheck

	if !strings.Contains(acceptHeader, "application/jwt") {
		t.Errorf("expected Accept header to include application/jwt, got %q", acceptHeader)
	}
	if !strings.Contains(acceptHeader, "application/json") {
		t.Errorf("expected Accept header to include application/json, got %q", acceptHeader)
	}
}

// TestResolve_UnsupportedContentType verifies that unsupported Content-Types are rejected.
func TestResolve_UnsupportedContentType(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, "<html>not metadata</html>")
	}))
	defer server.Close()

	resolver, _ := New(Config{AllowHTTP: true, AllowPrivateIPs: true})
	_, err := resolver.Resolve(context.Background(), server.URL)
	if err == nil {
		t.Error("expected error for unsupported Content-Type")
	}
	if !strings.Contains(err.Error(), "unsupported Content-Type") {
		t.Errorf("expected Content-Type error, got: %v", err)
	}
}

// TestResolve_TrustEvaluatorError verifies that trust evaluator errors propagate.
func TestResolve_TrustEvaluatorError(t *testing.T) {
	priv, pub := newTestKey(t)
	token := signClaims(t, priv, map[string]interface{}{
		"credential_issuer": "https://issuer.example.com",
	})

	outer := map[string]interface{}{
		"credential_issuer": "https://issuer.example.com",
		"jwks":              inlineJWKS(t, pub),
		"signed_metadata":   token,
	}

	evaluator := &mockTrustEvaluator{err: fmt.Errorf("trust engine unavailable")}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(outer) //nolint:errcheck
	}))
	defer server.Close()

	resolver, _ := New(Config{
		AllowHTTP:       true,
		AllowPrivateIPs: true,
		TrustEvaluator:  evaluator,
	})

	_, err := resolver.Resolve(context.Background(), server.URL)
	if err == nil {
		t.Error("expected error when trust evaluator returns error")
	}
	if !strings.Contains(err.Error(), "trust engine unavailable") {
		t.Errorf("expected propagated error, got: %v", err)
	}
}
