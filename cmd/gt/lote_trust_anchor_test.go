package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/sirosfoundation/go-trust/pkg/config"
	"github.com/sirosfoundation/go-trust/pkg/registry/lote"
)

func writeCAPEM(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(t.TempDir(), "anchors.pem")
	if err := os.WriteFile(p, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestApplyLoTETrustAnchors(t *testing.T) {
	t.Run("bundle sets provider", func(t *testing.T) {
		var out lote.Config
		err := applyLoTETrustAnchors(&config.LoTERegistryConfig{VerifyJWS: true, TrustAnchorBundle: writeCAPEM(t)}, &out)
		if err != nil || out.TrustAnchorProvider == nil {
			t.Fatalf("err=%v provider=%v, want provider set", err, out.TrustAnchorProvider)
		}
	})
	t.Run("verify_jws without bundle refused", func(t *testing.T) {
		var out lote.Config
		err := applyLoTETrustAnchors(&config.LoTERegistryConfig{VerifyJWS: true}, &out)
		if !errors.Is(err, lote.ErrVerifyJWSNoAnchors) {
			t.Fatalf("err = %v, want ErrVerifyJWSNoAnchors", err)
		}
	})
	t.Run("default leaves provider nil", func(t *testing.T) {
		var out lote.Config
		if err := applyLoTETrustAnchors(&config.LoTERegistryConfig{}, &out); err != nil || out.TrustAnchorProvider != nil {
			t.Fatalf("err=%v provider=%v, want nil/nil", err, out.TrustAnchorProvider)
		}
	})
	t.Run("unreadable bundle is an error", func(t *testing.T) {
		var out lote.Config
		if err := applyLoTETrustAnchors(&config.LoTERegistryConfig{TrustAnchorBundle: "/nonexistent/anchors.pem"}, &out); err == nil {
			t.Fatal("want error")
		}
	})
}
