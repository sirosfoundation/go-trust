package lote

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/sirosfoundation/g119612/pkg/etsi119602"
	"github.com/sirosfoundation/go-trust/pkg/authzen"
)

// jwsFixture holds a test CA that issues JWS signer certificates, so tests can
// produce signed LoTE/LoTL documents on disk.
type jwsFixture struct {
	t     *testing.T
	dir   string
	roots *x509.CertPool
	ca    *x509.Certificate
	caKey *ecdsa.PrivateKey
}

func newJWSFixture(t *testing.T) *jwsFixture {
	t.Helper()
	caCert, caKey := generateTestCA(t)
	f := &jwsFixture{t: t, dir: t.TempDir(), roots: x509.NewCertPool(), ca: caCert, caKey: caKey}
	f.roots.AddCert(caCert)
	return f
}

// signedFile signs payload with a fresh CA-issued leaf and writes the compact
// JWS to disk.
func (f *jwsFixture) signedFile(name string, payload []byte) string {
	f.t.Helper()
	leafKey := newECKey(f.t)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: "LoTE Signer"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, f.ca, &leafKey.PublicKey, f.caKey)
	require.NoError(f.t, err)
	leaf, err := x509.ParseCertificate(der)
	require.NoError(f.t, err)
	p := filepath.Join(f.dir, name)
	require.NoError(f.t, os.WriteFile(p, []byte(compactJWS(f.t, leafKey, leaf, payload)), 0o600))
	return p
}

func (f *jwsFixture) lote(name string, id string) string {
	data, err := minimalLoTE("SE", simpleEntity(id)).Marshal()
	require.NoError(f.t, err)
	return f.signedFile(name, data)
}

func (f *jwsFixture) lotl(name string, ptrs ...etsi119602.OtherLoTEPointer) string {
	l := &etsi119602.ListOfTrustedLists{
		ListAndSchemeInformation: etsi119602.ListAndSchemeInformation{
			LoTEVersionIdentifier: 1,
			SchemeTerritory:       "EU",
			LoTEType:              etsi119602.LoTLTypeEU,
			SchemeOperatorName:    etsi119602.NameSet{{Lang: "en", Value: "EU"}},
			ListIssueDateTime:     "2026-01-01T00:00:00Z",
			NextUpdate:            "2027-01-01T00:00:00Z",
			PointersToOtherLoTE:   ptrs,
		},
	}
	data, err := l.MarshalLoTL()
	require.NoError(f.t, err)
	return f.signedFile(name, data)
}

func (f *jwsFixture) provider() LoTETrustAnchorProvider { return NewStaticTrustAnchorProvider(f.roots) }

func evaluates(t *testing.T, r *Registry, id string) bool {
	t.Helper()
	resp, err := r.Evaluate(context.Background(), &authzen.EvaluationRequest{
		Subject:  authzen.Subject{Type: "key", ID: id},
		Resource: authzen.Resource{ID: id},
	})
	require.NoError(t, err)
	return resp.Decision
}

// tamperFile swaps the payload of a compact JWS on disk without re-signing.
func tamperFile(t *testing.T, path string) {
	t.Helper()
	b, err := os.ReadFile(path)
	require.NoError(t, err)
	out := tamperedJWS(string(b), `{"LoTE":{"ListAndSchemeInformation":{"LoTEVersionIdentifier":1},"TrustedEntitiesList":[]}}`)
	require.NoError(t, os.WriteFile(path, []byte(out), 0o600))
}

func TestVerifyJWS_DirectSource_Valid(t *testing.T) {
	f := newJWSFixture(t)
	src := f.lote("se.jws", "https://signed.example.com")

	reg, err := New(Config{Sources: []string{src}, VerifyJWS: true, TrustAnchorProvider: f.provider()})
	require.NoError(t, err)
	assert.True(t, evaluates(t, reg, "https://signed.example.com"))
}

func TestVerifyJWS_DirectSource_BadSignature(t *testing.T) {
	f := newJWSFixture(t)
	src := f.lote("se.jws", "https://signed.example.com")
	tamperFile(t, src)

	_, err := New(Config{Sources: []string{src}, VerifyJWS: true, TrustAnchorProvider: f.provider()})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "signature verification failed")
}

func TestVerifyJWS_DirectSource_UnsignedRejected(t *testing.T) {
	f := newJWSFixture(t)
	path := writeLoTE(t, f.dir, "plain.json", minimalLoTE("SE", simpleEntity("https://x.example.com")))

	_, err := New(Config{Sources: []string{path}, VerifyJWS: true, TrustAnchorProvider: f.provider()})
	require.Error(t, err)
}

func TestVerifyJWS_UntrustedSigner(t *testing.T) {
	f := newJWSFixture(t)
	src := f.lote("se.jws", "https://signed.example.com")
	other := newJWSFixture(t) // different CA

	_, err := New(Config{Sources: []string{src}, VerifyJWS: true, TrustAnchorProvider: other.provider()})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "signature verification failed")
}

func TestVerifyJWS_WithoutAnchorsRefuses(t *testing.T) {
	f := newJWSFixture(t)
	src := f.lote("se.jws", "https://signed.example.com")

	t.Run("nil provider", func(t *testing.T) {
		_, err := New(Config{Sources: []string{src}, VerifyJWS: true})
		require.ErrorIs(t, err, ErrVerifyJWSNoAnchors)
	})
	t.Run("provider yields nil pool", func(t *testing.T) {
		_, err := New(Config{Sources: []string{src}, VerifyJWS: true, TrustAnchorProvider: NilTrustAnchorProvider{}})
		require.ErrorIs(t, err, ErrVerifyJWSNoAnchors)
	})
}

func TestVerifyJWS_DefaultUnchanged(t *testing.T) {
	// Verification off and no anchors: unsigned plain documents still load.
	dir := t.TempDir()
	path := writeLoTE(t, dir, "plain.json", minimalLoTE("SE", simpleEntity("https://plain.example.com")))
	reg, err := New(Config{Sources: []string{path}})
	require.NoError(t, err)
	assert.True(t, evaluates(t, reg, "https://plain.example.com"))
}

func TestVerifyJWS_AnchorsImplyVerification(t *testing.T) {
	// VerifyJWS false but anchors configured: configured anchors are never
	// silently ignored, so an unsigned document is rejected.
	f := newJWSFixture(t)
	path := writeLoTE(t, f.dir, "plain.json", minimalLoTE("SE", simpleEntity("https://plain.example.com")))
	_, err := New(Config{Sources: []string{path}, TrustAnchorProvider: f.provider()})
	require.Error(t, err)
}

func TestVerifyJWS_LoTL_Resolved(t *testing.T) {
	f := newJWSFixture(t)
	a := f.lote("a.jws", "https://a.example.com")
	b := f.lote("b.jws", "https://b.example.com")
	nested := f.lotl("nested.jws", lotlPointer(b, etsi119602.LoTETypePIDProviders, "SE"))
	top := f.lotl("top.jws",
		lotlPointer(a, etsi119602.LoTETypePIDProviders, "SE"),
		lotlPointer(nested, etsi119602.LoTLTypeEU, "EU"))

	reg, err := New(Config{LoTLSources: []string{top}, VerifyJWS: true, TrustAnchorProvider: f.provider()})
	require.NoError(t, err)
	assert.True(t, evaluates(t, reg, "https://a.example.com"))
	assert.True(t, evaluates(t, reg, "https://b.example.com"), "LoTE behind a nested LoTL must load")
}

func TestVerifyJWS_LoTL_TamperedPointerTargetSkipped(t *testing.T) {
	f := newJWSFixture(t)
	good := f.lote("good.jws", "https://good.example.com")
	bad := f.lote("bad.jws", "https://bad.example.com")
	tamperFile(t, bad)
	top := f.lotl("top.jws",
		lotlPointer(good, etsi119602.LoTETypePIDProviders, "SE"),
		lotlPointer(bad, etsi119602.LoTETypePIDProviders, "SE"))

	reg, err := New(Config{LoTLSources: []string{top}, VerifyJWS: true, TrustAnchorProvider: f.provider()})
	require.NoError(t, err)
	assert.True(t, evaluates(t, reg, "https://good.example.com"))
	assert.False(t, evaluates(t, reg, "https://bad.example.com"), "unverified LoTE must contribute nothing")
}

func TestVerifyJWS_LoTL_UnsignedPointerTargetSkipped(t *testing.T) {
	f := newJWSFixture(t)
	plain := writeLoTE(t, f.dir, "plain.json", minimalLoTE("SE", simpleEntity("https://plain.example.com")))
	top := f.lotl("top.jws", lotlPointer(plain, etsi119602.LoTETypePIDProviders, "SE"))

	reg, err := New(Config{LoTLSources: []string{top}, VerifyJWS: true, TrustAnchorProvider: f.provider()})
	require.NoError(t, err)
	assert.False(t, evaluates(t, reg, "https://plain.example.com"))
}

func TestVerifyJWS_LoTL_TamperedLoTLFails(t *testing.T) {
	f := newJWSFixture(t)
	a := f.lote("a.jws", "https://a.example.com")
	top := f.lotl("top.jws", lotlPointer(a, etsi119602.LoTETypePIDProviders, "SE"))
	tamperFile(t, top)

	_, err := New(Config{LoTLSources: []string{top}, VerifyJWS: true, TrustAnchorProvider: f.provider()})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "signature verification failed")
}

func TestVerifyJWS_LoTL_UnsignedLoTLFails(t *testing.T) {
	f := newJWSFixture(t)
	a := f.lote("a.jws", "https://a.example.com")
	l := &etsi119602.ListOfTrustedLists{
		ListAndSchemeInformation: etsi119602.ListAndSchemeInformation{
			LoTEVersionIdentifier: 1,
			LoTEType:              etsi119602.LoTLTypeEU,
			SchemeOperatorName:    etsi119602.NameSet{{Lang: "en", Value: "EU"}},
			PointersToOtherLoTE:   []etsi119602.OtherLoTEPointer{lotlPointer(a, etsi119602.LoTETypePIDProviders, "SE")},
		},
	}
	top := writeLoTL(t, f.dir, "plain-lotl.json", l)

	_, err := New(Config{LoTLSources: []string{top}, VerifyJWS: true, TrustAnchorProvider: f.provider()})
	require.Error(t, err)
}

func TestVerifyJWS_LoTL_NestedTamperedLoTLSkipped(t *testing.T) {
	f := newJWSFixture(t)
	good := f.lote("good.jws", "https://good.example.com")
	b := f.lote("b.jws", "https://b.example.com")
	nested := f.lotl("nested.jws", lotlPointer(b, etsi119602.LoTETypePIDProviders, "SE"))
	tamperFile(t, nested)
	top := f.lotl("top.jws",
		lotlPointer(good, etsi119602.LoTETypePIDProviders, "SE"),
		lotlPointer(nested, etsi119602.LoTLTypeEU, "EU"))

	reg, err := New(Config{LoTLSources: []string{top}, VerifyJWS: true, TrustAnchorProvider: f.provider()})
	require.NoError(t, err)
	assert.True(t, evaluates(t, reg, "https://good.example.com"))
	assert.False(t, evaluates(t, reg, "https://b.example.com"))
}

// --- LoadTrustAnchorBundle ---

func writePEM(t *testing.T, path string, certs ...*x509.Certificate) {
	t.Helper()
	var out []byte
	for _, c := range certs {
		out = append(out, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})...)
	}
	require.NoError(t, os.WriteFile(path, out, 0o600))
}

func TestLoadTrustAnchorBundle(t *testing.T) {
	dir := t.TempDir()
	ca, _ := generateTestCA(t)

	t.Run("ok", func(t *testing.T) {
		p := filepath.Join(dir, "ok.pem")
		writePEM(t, p, ca)
		prov, err := LoadTrustAnchorBundle(p)
		require.NoError(t, err)
		pool, err := prov.TrustAnchors(context.Background())
		require.NoError(t, err)
		assert.NotNil(t, pool)
	})
	t.Run("missing file", func(t *testing.T) {
		_, err := LoadTrustAnchorBundle(filepath.Join(dir, "nope.pem"))
		require.Error(t, err)
	})
	t.Run("no certificates", func(t *testing.T) {
		p := filepath.Join(dir, "empty.pem")
		require.NoError(t, os.WriteFile(p, []byte("not pem"), 0o600))
		_, err := LoadTrustAnchorBundle(p)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "no certificates")
	})
	t.Run("corrupt certificate", func(t *testing.T) {
		p := filepath.Join(dir, "bad.pem")
		bad := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("garbage")})
		require.NoError(t, os.WriteFile(p, bad, 0o600))
		_, err := LoadTrustAnchorBundle(p)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid certificate")
	})
}
