package lote

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/sirosfoundation/g119612/pkg/etsi119602"
	"github.com/sirosfoundation/go-trust/pkg/authzen"
	"github.com/sirosfoundation/go-trust/pkg/registry/rpcert"
)

// ─── key / cert helpers ─────────────────────────────────────────────────────

func newECKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	return k
}

func selfSignedCert(t *testing.T, key *ecdsa.PrivateKey, cn string, notAfter time.Time) *x509.Certificate {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(42),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return cert
}

// compactJWS builds an ES256 compact JWS with an x5c header carrying signerCert.
func compactJWS(t *testing.T, signerKey *ecdsa.PrivateKey, signerCert *x509.Certificate, payload []byte) string {
	t.Helper()
	headerJSON, err := json.Marshal(map[string]interface{}{
		"alg": "ES256",
		"x5c": []string{base64.StdEncoding.EncodeToString(signerCert.Raw)},
	})
	require.NoError(t, err)

	hB64 := base64.RawURLEncoding.EncodeToString(headerJSON)
	pB64 := base64.RawURLEncoding.EncodeToString(payload)
	signingInput := hB64 + "." + pB64

	digest := sha256.Sum256([]byte(signingInput))
	r, s, err := ecdsa.Sign(rand.Reader, signerKey, digest[:])
	require.NoError(t, err)

	n := (signerKey.Curve.Params().BitSize + 7) / 8
	sig := make([]byte, 2*n)
	r.FillBytes(sig[:n])
	s.FillBytes(sig[n:])

	return hB64 + "." + pB64 + "." + base64.RawURLEncoding.EncodeToString(sig)
}

// tamperedJWS replaces the payload in a compact JWS without re-signing.
func tamperedJWS(token, newPayload string) string {
	parts := splitDots(token)
	parts[1] = base64.RawURLEncoding.EncodeToString([]byte(newPayload))
	return parts[0] + "." + parts[1] + "." + parts[2]
}

func splitDots(s string) [3]string {
	var out [3]string
	first := indexByte(s, '.')
	last := lastIndexByte(s, '.')
	out[0] = s[:first]
	out[1] = s[first+1 : last]
	out[2] = s[last+1:]
	return out
}

func indexByte(s string, c byte) int {
	for i := range s {
		if s[i] == c {
			return i
		}
	}
	return -1
}

func lastIndexByte(s string, c byte) int {
	for i := len(s) - 1; i >= 0; i-- {
		if s[i] == c {
			return i
		}
	}
	return -1
}

// ─── VerifyLoTESignature ────────────────────────────────────────────────────

func TestVerifyLoTESignature_NilRootsSkips(t *testing.T) {
	cert, err := VerifyLoTESignature(context.Background(), []byte("anything"), nil, time.Now())
	require.NoError(t, err)
	assert.Nil(t, cert, "nil roots must skip verification and return nil")
}

func TestVerifyLoTESignature_MissingX5C(t *testing.T) {
	roots := x509.NewCertPool()
	hJSON, _ := json.Marshal(map[string]interface{}{"alg": "ES256"}) // no x5c
	h := base64.RawURLEncoding.EncodeToString(hJSON)
	p := base64.RawURLEncoding.EncodeToString([]byte("{}"))
	s := base64.RawURLEncoding.EncodeToString([]byte("sig"))
	_, err := VerifyLoTESignature(context.Background(), []byte(h+"."+p+"."+s), roots, time.Now())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "x5c")
}

func TestVerifyLoTESignature_ValidSignature(t *testing.T) {
	key := newECKey(t)
	cert := selfSignedCert(t, key, "LoTE Signer", time.Now().Add(time.Hour))
	token := compactJWS(t, key, cert, []byte(`{"test":true}`))

	roots := x509.NewCertPool()
	roots.AddCert(cert)

	signer, err := VerifyLoTESignature(context.Background(), []byte(token), roots, time.Now())
	require.NoError(t, err)
	require.NotNil(t, signer)
	assert.Equal(t, "LoTE Signer", signer.Subject.CommonName)
}

func TestVerifyLoTESignature_TamperedPayload(t *testing.T) {
	key := newECKey(t)
	cert := selfSignedCert(t, key, "LoTE Signer", time.Now().Add(time.Hour))
	token := compactJWS(t, key, cert, []byte(`{"original":true}`))
	bad := tamperedJWS(token, `{"tampered":true}`)

	roots := x509.NewCertPool()
	roots.AddCert(cert)

	_, err := VerifyLoTESignature(context.Background(), []byte(bad), roots, time.Now())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "signature")
}

func TestVerifyLoTESignature_UntrustedSigner(t *testing.T) {
	key := newECKey(t)
	cert := selfSignedCert(t, key, "Unknown", time.Now().Add(time.Hour))
	token := compactJWS(t, key, cert, []byte(`{}`))

	roots := x509.NewCertPool() // empty — cert not trusted

	_, err := VerifyLoTESignature(context.Background(), []byte(token), roots, time.Now())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "chain")
}

// ─── LoTETrustAnchorProvider ─────────────────────────────────────────────────

func TestNilTrustAnchorProvider(t *testing.T) {
	p := NilTrustAnchorProvider{}
	pool, err := p.TrustAnchors(context.Background())
	require.NoError(t, err)
	assert.Nil(t, pool)
}

func TestStaticTrustAnchorProvider_NonNil(t *testing.T) {
	pool := x509.NewCertPool()
	p := NewStaticTrustAnchorProvider(pool)
	got, err := p.TrustAnchors(context.Background())
	require.NoError(t, err)
	assert.Equal(t, pool, got)
}

func TestStaticTrustAnchorProvider_Nil(t *testing.T) {
	p := NewStaticTrustAnchorProvider(nil)
	got, err := p.TrustAnchors(context.Background())
	require.NoError(t, err)
	assert.Nil(t, got)
}

// ─── fetchRawSource ──────────────────────────────────────────────────────────

func TestFetchRawSource_HTTP200(t *testing.T) {
	want := []byte(`{"lote":"data"}`)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write(want)
	}))
	defer srv.Close()

	got, err := fetchRawSource(srv.URL, 5*time.Second)
	require.NoError(t, err)
	assert.Equal(t, want, got)
}

func TestFetchRawSource_HTTP404(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	_, err := fetchRawSource(srv.URL, 5*time.Second)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "404")
}

func TestFetchRawSource_LocalFile(t *testing.T) {
	content := []byte(`{"lote":"file"}`)
	f, err := os.CreateTemp("", "lote-*.json")
	require.NoError(t, err)
	defer os.Remove(f.Name())
	_, _ = f.Write(content)
	f.Close()

	got, err := fetchRawSource(f.Name(), 5*time.Second)
	require.NoError(t, err)
	assert.Equal(t, content, got)
}

// ─── parseX5CChainRaw ────────────────────────────────────────────────────────

func TestParseX5CChainRaw_Empty(t *testing.T) {
	_, _, err := parseX5CChainRaw(nil)
	assert.Error(t, err)
}

func TestParseX5CChainRaw_InvalidBase64(t *testing.T) {
	_, _, err := parseX5CChainRaw([]string{"not!valid%%base64"})
	assert.Error(t, err)
}

func TestParseX5CChainRaw_SingleCert(t *testing.T) {
	key := newECKey(t)
	cert := selfSignedCert(t, key, "leaf", time.Now().Add(time.Hour))
	b64 := base64.StdEncoding.EncodeToString(cert.Raw)

	leaf, ints, err := parseX5CChainRaw([]string{b64})
	require.NoError(t, err)
	assert.Equal(t, "leaf", leaf.Subject.CommonName)
	assert.NotNil(t, ints)
}

// ─── TrustAnchorProvider error propagates through New() ─────────────────────

func TestNew_TrustAnchorProviderError(t *testing.T) {
	// Use a file-based source so the LoTE content is always valid.
	path := writeEmptyLoTE(t)

	cfg := Config{
		Sources:             []string{path},
		TrustAnchorProvider: &failingTAProvider{},
	}
	_, err := New(cfg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "trust anchors")
}

type failingTAProvider struct{}

func (f *failingTAProvider) TrustAnchors(_ context.Context) (*x509.CertPool, error) {
	return nil, fmt.Errorf("simulated trust anchor failure")
}

// ─── National Register fallback (Phase 3) ────────────────────────────────────

func TestEvaluate_RegisterFallback_Grants(t *testing.T) {
	path := writeEmptyLoTE(t)
	rc := &stubRegisterClient{result: &rpcert.RPEntitlements{
		RPIdentifier:       "https://example.com/rp",
		RegistrationStatus: rpcert.StatusRegistered,
	}}
	r, err := New(Config{Sources: []string{path}, RegisterClient: rc})
	require.NoError(t, err)

	resp, err := r.Evaluate(context.Background(), &authzen.EvaluationRequest{
		Subject:  authzen.Subject{ID: "https://example.com/rp"},
		Resource: authzen.Resource{Type: "jwk"},
	})
	require.NoError(t, err)
	assert.True(t, resp.Decision)
	assert.Contains(t, resp.Context.Reason["admin"], "National Register fallback")
}

func TestEvaluate_RegisterFallback_Denies_WhenRegisterFails(t *testing.T) {
	path := writeEmptyLoTE(t)
	rc := &stubRegisterClient{err: fmt.Errorf("register unavailable")}
	r, err := New(Config{Sources: []string{path}, RegisterClient: rc})
	require.NoError(t, err)

	resp, err := r.Evaluate(context.Background(), &authzen.EvaluationRequest{
		Subject:  authzen.Subject{ID: "https://example.com/unknown"},
		Resource: authzen.Resource{Type: "jwk"},
	})
	require.NoError(t, err)
	assert.False(t, resp.Decision)
}

func TestEvaluate_RegisterFallback_NotCalledWhenEntityInLoTE(t *testing.T) {
	lote := minimalLoTE("EU", etsi119602.TrustedEntity{
		TrustedEntityInformation: etsi119602.TrustedEntityInformation{
			TEInformationURI: []etsi119602.NonEmptyMultiLangURI{{Lang: "en", URIValue: "https://example.com/rp"}},
		},
	})
	path := writeLoTE(t, t.TempDir(), "lote.json", lote)

	rc := &stubRegisterClient{}
	r, err := New(Config{Sources: []string{path}, RegisterClient: rc})
	require.NoError(t, err)

	r.Evaluate(context.Background(), &authzen.EvaluationRequest{
		Subject:  authzen.Subject{ID: "https://example.com/rp"},
		Resource: authzen.Resource{Type: "jwk"},
	})
	assert.False(t, rc.called, "register must NOT be consulted when entity is already in LoTE")
}

// ─── LoTE server / entity helpers ────────────────────────────────────────────

type stubRegisterClient struct {
	result *rpcert.RPEntitlements
	err    error
	called bool
}

func (s *stubRegisterClient) LookupRP(_ context.Context, _ string) (*rpcert.RPEntitlements, error) {
	s.called = true
	return s.result, s.err
}
func (s *stubRegisterClient) Healthy() bool { return true }

// writeEmptyLoTE writes a LoTE with no entities to a temp file and returns the path.
func writeEmptyLoTE(t *testing.T) string {
	t.Helper()
	lote := minimalLoTE("EU")
	return writeLoTE(t, t.TempDir(), "lote.json", lote)
}

// loTEServer is kept for the TrustAnchorProvider error test (it doesn't need
// a valid LoTE body since the error fires before the body is parsed).
func loTEServer(t *testing.T, territory, loTEType string, _ []interface{}) *httptest.Server {
	t.Helper()
	// Return an HTTP server that responds with a minimal valid JSON; used
	// only to supply a network-accessible URL — callers that need real LoTE
	// data should use writeEmptyLoTE / writeLoTE instead.
	body := map[string]interface{}{
		"LoTE": map[string]interface{}{
			"ListAndSchemeInformation": map[string]interface{}{
				"SchemeTerritory": territory,
				"LoTEType":        loTEType,
			},
			"TrustedEntitiesList": []interface{}{},
		},
	}
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(body)
	}))
}

// Suppress unused-import error for json/httptest when loTEServer is the only user.
var _ = errors.New
