package registry

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// signRawJOSE signs signingInput with the key in the JOSE r||s form.
func signRawJOSE(t *testing.T, key *ecdsa.PrivateKey, h crypto.Hash, signingInput []byte) []byte {
	t.Helper()
	hh := h.New()
	hh.Write(signingInput)
	digest := hh.Sum(nil)
	r, s, err := ecdsa.Sign(rand.Reader, key, digest)
	require.NoError(t, err)
	keyBytes := (key.Curve.Params().BitSize + 7) / 8
	sig := make([]byte, 2*keyBytes)
	r.FillBytes(sig[:keyBytes])
	s.FillBytes(sig[keyBytes:])
	return sig
}

func TestVerifyWRPRC_MalformedTokenShapes(t *testing.T) {
	_, validator := mintTestWRPRCToken(t, nil)

	for name, token := range map[string]string{
		"empty":           "",
		"two parts":       "a.b",
		"four parts":      "a.b.c.d",
		"bad header b64":  "!!!.payload.sig",
		"header not json": base64.RawURLEncoding.EncodeToString([]byte("not json")) + ".c2ln",
	} {
		t.Run(name, func(t *testing.T) {
			_, err := validator.VerifyWRPRC(context.Background(), []byte(token))
			require.Error(t, err)
		})
	}
}

func TestVerifyWRPRC_NilRootsFailsClosed(t *testing.T) {
	verifier := NewAnchoredWRPRCVerifier(nil)
	_, err := verifier.VerifyWRPRC(context.Background(), []byte("a.b.c"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no registrar trust anchors")
}

func TestVerifyWRPRC_WrongTypRefused(t *testing.T) {
	// A well-formed JWS with the WRONG typ: the media type identifies the
	// document (GEN-5.2.2-01) and the wrong one is refused.
	tok, v := mintTestWRPRCTokenWithTyp(t, "some-other-typ", nil)
	_, err := v.VerifyWRPRC(context.Background(), []byte(tok))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unexpected JWS typ")
	// The correctly-typed one passes the same verifier's shape checks.
	token, validator := mintTestWRPRCToken(t, nil)
	_, err = validator.VerifyWRPRC(context.Background(), []byte(token))
	assert.NoError(t, err)
}

func TestVerifyWRPRC_MissingAndMalformedX5C(t *testing.T) {
	// No x5c at all.
	tok, v := mintTestWRPRCTokenWithTyp(t, "rc-wrp+jwt", nil)
	tokNoX5C := stripX5C(t, tok, true)
	_, err := v.VerifyWRPRC(context.Background(), []byte(tokNoX5C))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "missing x5c")

	// x5c entries that are not certificates.
	tokBadB64 := replaceX5C(t, tok, "!!!not-base64!!!")
	_, err = v.VerifyWRPRC(context.Background(), []byte(tokBadB64))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "base64 decode failed")

	tokBadDER := replaceX5C(t, tok, base64.StdEncoding.EncodeToString([]byte("not a certificate")))
	_, err = v.VerifyWRPRC(context.Background(), []byte(tokBadDER))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "parse failed")

	// A valid x5c that does not anchor in the configured roots.
	_, other := mintTestWRPRCToken(t, nil)
	tokForeign, _ := mintTestWRPRCTokenWithTyp(t, "rc-wrp+jwt", nil)
	_, err = other.VerifyWRPRC(context.Background(), []byte(tokForeign))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "does not anchor")
}

func TestVerifyJWSSignature_AlgorithmBranches(t *testing.T) {
	input := []byte("the signing input")

	// RS256/PS256: an RSA registrar key.
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	digest := sha256.Sum256(input)
	rs256Sig, err := rsa.SignPKCS1v15(rand.Reader, rsaKey, crypto.SHA256, digest[:])
	require.NoError(t, err)
	assert.NoError(t, VerifyJWSSignature("RS256", &rsaKey.PublicKey, input, rs256Sig))
	assert.Error(t, VerifyJWSSignature("RS256", &rsaKey.PublicKey, input, []byte("bad length")))

	// RFC 7518 §3.5: salt length = hash length for PS*.
	pssOpts := &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: crypto.SHA256}
	ps256Sig, err := rsa.SignPSS(rand.Reader, rsaKey, crypto.SHA256, digest[:], pssOpts)
	require.NoError(t, err)
	assert.NoError(t, VerifyJWSSignature("PS256", &rsaKey.PublicKey, input, ps256Sig))

	// The RSA families refuse an ECDSA key, and vice versa.
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	ecSig := signRawJOSE(t, ecKey, crypto.SHA256, input)
	assert.Error(t, VerifyJWSSignature("RS256", &ecKey.PublicKey, input, ecSig))
	assert.Error(t, VerifyJWSSignature("ES256", &rsaKey.PublicKey, input, rs256Sig))

	// The ES family across its hash/curve pairings.
	p384Key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)
	p521Key, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	require.NoError(t, err)
	assert.NoError(t, VerifyJWSSignature("ES384", &p384Key.PublicKey, input, signRawJOSE(t, p384Key, crypto.SHA384, input)))
	assert.NoError(t, VerifyJWSSignature("ES512", &p521Key.PublicKey, input, signRawJOSE(t, p521Key, crypto.SHA512, input)))
	// A bad signature under the right key and curve.
	assert.Error(t, VerifyJWSSignature("ES256", &ecKey.PublicKey, input, make([]byte, 64)))

	// HMAC and unknown algorithms: no symmetric MACs, no invention.
	assert.Error(t, VerifyJWSSignature("HS256", &ecKey.PublicKey, input, ecSig))
	assert.Error(t, VerifyJWSSignature("future-alg", &ecKey.PublicKey, input, ecSig))
}

func TestMintWRPRCSignature_UnsupportedAlgorithm(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	_, err = mintWRPRCSignature(key, "HS256", []byte("x"))
	require.Error(t, err)
}

// mintWRPRCSignature signs the JWS signing input in the JOSE format
// (test-only helper): r || s fixed-width big-endian per RFC 7518 §3.4.
func mintWRPRCSignature(key *ecdsa.PrivateKey, alg string, signingInput []byte) ([]byte, error) {
	var h crypto.Hash
	switch alg {
	case "ES256":
		h = crypto.SHA256
	default:
		return nil, fmt.Errorf("test helper: unsupported algorithm %q", alg)
	}
	hh := h.New()
	hh.Write(signingInput)
	digest := hh.Sum(nil)
	r, s, err := ecdsa.Sign(rand.Reader, key, digest)
	if err != nil {
		return nil, err
	}
	keyBytes := (elliptic.P256().Params().BitSize + 7) / 8
	sig := make([]byte, 2*keyBytes)
	r.FillBytes(sig[:keyBytes])
	s.FillBytes(sig[keyBytes:])
	return sig, nil
}

// ---- helpers ---------------------------------------------------------------

// mintTestWRPRCToken mints a WRPRC-shaped token signed by a fresh registrar
// CA and returns it with a verifier anchored to that CA. claims may be nil
// for the default minimal payload.
func mintTestWRPRCToken(t *testing.T, claims map[string]interface{}) (string, WRPRCVerifier) {
	t.Helper()
	return mintTestWRPRCTokenWithTyp(t, "rc-wrp+jwt", claims)
}

func mintTestWRPRCTokenWithTyp(t *testing.T, typ string, claims map[string]interface{}) (string, WRPRCVerifier) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(42),
		Subject:               pkix.Name{Organization: []string{"Registrar CA"}, CommonName: "registrar.example"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)
	caCert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	pool := x509.NewCertPool()
	pool.AddCert(caCert)

	if claims == nil {
		now := time.Now()
		claims = map[string]interface{}{
			"name":         "Fronted RP GmbH",
			"sub":          "LEIXG-FRONTED",
			"entitlements": []string{"urn:example:entitlement:non-qeaa-provider"},
			"iat":          now.Add(-time.Hour).Unix(),
			"exp":          now.Add(30 * 24 * time.Hour).Unix(),
		}
	}
	header := map[string]interface{}{
		"typ": typ,
		"alg": "ES256",
		"x5c": []string{base64.StdEncoding.EncodeToString(caCert.Raw)},
	}
	hdrJSON, err := json.Marshal(header)
	require.NoError(t, err)
	hdrB64 := base64.RawURLEncoding.EncodeToString(hdrJSON)
	payJSON, err := json.Marshal(claims)
	require.NoError(t, err)
	payB64 := base64.RawURLEncoding.EncodeToString(payJSON)
	signingInput := hdrB64 + "." + payB64
	sig, err := mintWRPRCSignature(key, "ES256", []byte(signingInput))
	require.NoError(t, err)
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig), NewAnchoredWRPRCVerifier(pool)
}

func split3(t *testing.T, token string) []string {
	t.Helper()
	parts := make([]string, 0, 3)
	start := 0
	for i, c := range token {
		if c == '.' {
			parts = append(parts, token[start:i])
			start = i + 1
		}
	}
	parts = append(parts, token[start:])
	return parts
}

// stripX5C / replaceX5C rebuild the token's header with the x5c member
// removed or replaced, re-signing with a fresh dummy signature (the header
// changes make the original signature invalid, which is irrelevant for these
// shape-error cases — the errors fire before signature verification).
func stripX5C(t *testing.T, token string, drop bool) string {
	t.Helper()
	parts := split3(t, token)
	var header map[string]interface{}
	err := json.Unmarshal(b64Decode(t, parts[0]), &header)
	require.NoError(t, err)
	if drop {
		delete(header, "x5c")
	}
	hdrJSON, err := json.Marshal(header)
	require.NoError(t, err)
	return base64.RawURLEncoding.EncodeToString(hdrJSON) + "." + parts[1] + "." + parts[2]
}

func replaceX5C(t *testing.T, token, value string) string {
	t.Helper()
	parts := split3(t, token)
	var header map[string]interface{}
	err := json.Unmarshal(b64Decode(t, parts[0]), &header)
	require.NoError(t, err)
	header["x5c"] = []string{value}
	hdrJSON, err := json.Marshal(header)
	require.NoError(t, err)
	return base64.RawURLEncoding.EncodeToString(hdrJSON) + "." + parts[1] + "." + parts[2]
}

func b64Decode(t *testing.T, s string) []byte {
	t.Helper()
	raw, err := base64.RawURLEncoding.DecodeString(s)
	require.NoError(t, err)
	return raw
}
