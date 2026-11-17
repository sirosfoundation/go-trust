package etsi

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
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mintUnknownRegistrarWRPRC mints a well-formed WRPRC signed by a CA that is
// NOT any configured registrar — the token every scoped pool must refuse.
func mintUnknownRegistrarWRPRC(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(42),
		Subject:               pkix.Name{Organization: []string{"Unknown Registrar"}, CommonName: "rogue.example"},
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

	now := time.Now()
	header := map[string]interface{}{
		"typ": "rc-wrp+jwt",
		"alg": "ES256",
		"x5c": []string{base64.StdEncoding.EncodeToString(caCert.Raw)},
	}
	hdrJSON, err := json.Marshal(header)
	require.NoError(t, err)
	hdrB64 := base64.RawURLEncoding.EncodeToString(hdrJSON)
	payload := map[string]interface{}{
		"name":         "Fronted RP GmbH",
		"sub":          "LEIXG-FRONTED",
		"entitlements": []string{"urn:example:entitlement:non-qeaa-provider"},
		"iat":          now.Add(-time.Hour).Unix(),
		"exp":          now.Add(30 * 24 * time.Hour).Unix(),
	}
	payJSON, err := json.Marshal(payload)
	require.NoError(t, err)
	payB64 := base64.RawURLEncoding.EncodeToString(payJSON)
	signingInput := hdrB64 + "." + payB64
	digest := sha256.Sum256([]byte(signingInput))
	r, s, err := ecdsa.Sign(rand.Reader, key, digest[:])
	require.NoError(t, err)
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig)
}

// TestWRPRCVerifier_RegistrarScopedBranches pins the TSL-side scoping: the
// WRPRC anchors come only from services of the configured types, and neither
// an unconfigured registry nor a PEM bundle without TSLs ever yields anchors.
func TestWRPRCVerifier_RegistrarScopedBranches(t *testing.T) {
	const eaaType = "http://uri.etsi.org/TrstSvc/EAA"
	const snapshot = "../../../testdata/webuild-wp4/idunion-eaa.xml"
	const unknownType = "https://no-such-service-type.example/"

	// Unconfigured: nil, a presented WRPRC fails closed.
	reg, err := NewTSLRegistry(TSLConfig{
		Name:       "wrprc-unconfigured",
		TSLFiles:   []string{snapshot},
		AllowStale: true,
	})
	require.NoError(t, err)
	assert.Nil(t, reg.wrprcVerifier())

	// Configured types with the loaded TSL: a real verifier over exactly
	// those services' certificates — and an unknown registrar fails it.
	scoped, err := NewTSLRegistry(TSLConfig{
		Name:              "wrprc-scoped",
		TSLFiles:          []string{snapshot},
		AllowStale:        true,
		WRPRCServiceTypes: []string{eaaType},
	})
	require.NoError(t, err)
	verifier := scoped.wrprcVerifier()
	require.NotNil(t, verifier)
	_, err = verifier.VerifyWRPRC(context.Background(), []byte(mintUnknownRegistrarWRPRC(t)))
	assert.Error(t, err, "an unknown registrar must not anchor in the EAA-services pool")

	// A type no service carries: the pool is empty and every WRPRC fails.
	empty, err := NewTSLRegistry(TSLConfig{
		Name:              "wrprc-empty-type",
		TSLFiles:          []string{snapshot},
		AllowStale:        true,
		WRPRCServiceTypes: []string{unknownType},
	})
	require.NoError(t, err)
	verifier = empty.wrprcVerifier()
	require.NotNil(t, verifier)
	_, err = verifier.VerifyWRPRC(context.Background(), []byte(mintUnknownRegistrarWRPRC(t)))
	assert.Error(t, err)

	// Configured but no TSLs at all (a PEM bundle only): never the bundle —
	// nil, fail closed.
	tmpDir := t.TempDir()
	pemPath := filepath.Join(tmpDir, "ca.pem")
	require.NoError(t, os.WriteFile(pemPath, exportTestPEM(t), 0o600))
	bundleOnly, err := NewTSLRegistry(TSLConfig{
		Name:              "wrprc-bundle-only",
		CertBundle:        pemPath,
		WRPRCServiceTypes: []string{eaaType},
	})
	require.NoError(t, err)
	assert.Nil(t, bundleOnly.wrprcVerifier())
}

// exportTestPEM keeps the fixture helper local: the shared test helpers of
// the external test package are not visible here.
func exportTestPEM(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Bundle CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}
