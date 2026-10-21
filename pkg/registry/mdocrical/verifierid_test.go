package mdocrical

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"github.com/sirosfoundation/go-trust/pkg/authzen"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEvaluate_VerifierIDs(t *testing.T) {
	ricalRoot, ricalRootKey := generateCA(t, "Test RICAL Root")
	signerCert, signerKey := generateLeaf(t, ricalRoot, ricalRootKey, "Test RICAL Signer", 2)
	readerCA, readerCAKey := generateCA(t, "Test Reader CA")

	readerKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	leafDER, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{
		SerialNumber: big.NewInt(3), Subject: pkix.Name{CommonName: "Test Reader"},
		DNSNames:  []string{"reader.example.com"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}, readerCA, &readerKey.PublicKey, readerCAKey)
	require.NoError(t, err)
	readerLeaf, err := x509.ParseCertificate(leafDER)
	require.NoError(t, err)

	body := buildSignedRical(t, &RICAL{
		Version: "1.0", Provider: "test-provider", Date: time.Now().UTC().Format(time.RFC3339),
		Type: "org.iso.18013.5.1.reader_authentication",
		CertificateInfos: []RICALCertificateInfo{{
			Certificate: readerCA.Raw, SerialNumber: readerCA.SerialNumber, SKI: readerCA.SubjectKeyId, IsTrustAnchor: true,
		}},
	}, signerCert, signerKey)
	mock := newMockRicalServer(t, body)
	defer mock.Close()
	reg, err := New(&Config{
		RicalProviderURL: mock.URL(), RicalRootCertificatePEM: certPEM(ricalRoot),
		AllowHTTP: true, AllowPrivateIPs: true,
	})
	require.NoError(t, err)

	untrustedCA, untrustedKey := generateCA(t, "Other CA")
	badLeaf, _ := generateLeaf(t, untrustedCA, untrustedKey, "Impostor", 9)

	req := func(clientID string, types []string, leaf *x509.Certificate, chain ...*x509.Certificate) *authzen.EvaluationRequest {
		keys := []interface{}{certBase64(leaf)}
		for _, c := range chain {
			keys = append(keys, certBase64(c))
		}
		ctx := map[string]interface{}{}
		if types != nil {
			ctx[authzen.VerifierIDsPolicyContextKey] = types
		}
		return &authzen.EvaluationRequest{
			Subject:  authzen.Subject{ID: clientID},
			Resource: authzen.Resource{Type: "x5c", Key: keys},
			Context:  ctx,
		}
	}
	dns := []string{"x509_san_dns"}

	t.Run("trusted reader chain, bound client_id: dns id", func(t *testing.T) {
		resp, err := reg.Evaluate(context.Background(), req("x509_san_dns:reader.example.com", dns, readerLeaf, readerCA))
		require.NoError(t, err)
		require.True(t, resp.Decision)
		assert.Equal(t, []authzen.VerifierID{{Type: "x509_san_dns", ID: "reader.example.com", Basis: "client-id-binding"}}, resp.Context.VerifierIDs)
	})
	t.Run("policy off: none", func(t *testing.T) {
		resp, err := reg.Evaluate(context.Background(), req("x509_san_dns:reader.example.com", nil, readerLeaf, readerCA))
		require.NoError(t, err)
		require.True(t, resp.Decision)
		assert.Empty(t, resp.Context.VerifierIDs)
	})
	t.Run("client_id not a SAN of the reader certificate: allowed, no id", func(t *testing.T) {
		resp, err := reg.Evaluate(context.Background(), req("x509_san_dns:other.example.com", dns, readerLeaf, readerCA))
		require.NoError(t, err)
		require.True(t, resp.Decision)
		assert.Empty(t, resp.Context.VerifierIDs)
	})
	t.Run("brokered request: no dns id", func(t *testing.T) {
		r := req("x509_san_dns:reader.example.com", dns, readerLeaf, readerCA)
		r.Context["intermediary_x5c"] = []string{"MIIB"}
		resp, err := reg.Evaluate(context.Background(), r)
		require.NoError(t, err)
		require.True(t, resp.Decision)
		assert.Empty(t, resp.Context.VerifierIDs)
	})
	t.Run("untrusted chain: deny, no id", func(t *testing.T) {
		resp, err := reg.Evaluate(context.Background(), req("x509_san_dns:reader.example.com", dns, badLeaf, untrustedCA))
		require.NoError(t, err)
		require.False(t, resp.Decision)
		assert.Empty(t, resp.Context.VerifierIDs)
	})
}
