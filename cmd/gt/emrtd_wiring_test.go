package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/sirosfoundation/g119612/pkg/logging"
	"github.com/sirosfoundation/go-trust/pkg/authzen"
	"github.com/sirosfoundation/go-trust/pkg/config"
	"github.com/sirosfoundation/go-trust/pkg/registry"
	"github.com/sirosfoundation/go-trust/pkg/registry/emrtd"
)

type testCert struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

func mkCert(t *testing.T, cn string, parent *testCert, ca bool, pathLenZero bool) *testCert {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: cn, Country: []string{"SE"}, Organization: []string{"Test"}},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		BasicConstraintsValid: true,
		IsCA:                  ca,
	}
	if ca {
		tmpl.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageCRLSign
		tmpl.MaxPathLen, tmpl.MaxPathLenZero = 0, pathLenZero
		if !pathLenZero {
			tmpl.MaxPathLen = -1
		}
	} else {
		tmpl.KeyUsage = x509.KeyUsageDigitalSignature
	}
	signer, issuer := key, tmpl
	if parent != nil {
		signer, issuer = parent.key, parent.cert
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, issuer, &key.PublicKey, signer)
	if err != nil {
		t.Fatal(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return &testCert{cert: c, key: key}
}

// TestConfigureEMRTDRegistryFromConfig drives the real startup functions with
// a temporary anchor tree: enabled/disabled registration, and a DSC evaluated
// through the configured manager with the configured policy (including the
// emrtd path-length setting).
func TestConfigureEMRTDRegistryFromConfig(t *testing.T) {
	root := mkCert(t, "CSCA Test", nil, true, true) // pathLenConstraint=0
	link := mkCert(t, "CSCA Test Successor", root, true, false)
	dsc := mkCert(t, "DSC Test", link, false, false)

	anchors := t.TempDir()
	if err := os.MkdirAll(filepath.Join(anchors, "SWE"), 0o755); err != nil {
		t.Fatal(err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: root.cert.Raw})
	if err := os.WriteFile(filepath.Join(anchors, "SWE", "root.pem"), pemBytes, 0o644); err != nil {
		t.Fatal(err)
	}

	build := func(enabled bool, emrtdPolicy *config.EMRTDPolicyConfig) *registry.RegistryManager {
		cfg := &config.Config{}
		cfg.Registries.EMRTD = &config.EMRTDRegistryConfig{Enabled: enabled, Name: "emrtd-csca", AnchorsDir: anchors}
		cfg.Policies.Policies = map[string]*config.PolicyConfig{
			emrtd.ActionName: {
				Registries:  []string{"emrtd-csca"},
				Constraints: &config.PolicyConstraintsConfig{RequireKeyBinding: true, AllowedKeyTypes: []string{"x5c"}},
				EMRTD:       emrtdPolicy,
			},
		}
		mgr := registry.NewRegistryManager(registry.FirstMatch, 10*time.Second)
		configureRegistriesFromConfig(cfg, mgr, logging.SilentLogger())
		configurePoliciesFromConfig(cfg, mgr, logging.SilentLogger())
		t.Cleanup(func() {
			if r := mgr.GetRegistry("emrtd-csca"); r != nil {
				if c, ok := r.(interface{ Close() error }); ok {
					_ = c.Close()
				}
			}
		})
		return mgr
	}
	eval := func(mgr *registry.RegistryManager) bool {
		t.Helper()
		b64 := func(c *testCert) interface{} { return base64.StdEncoding.EncodeToString(c.cert.Raw) }
		resp, err := mgr.Evaluate(context.Background(), &authzen.EvaluationRequest{
			Subject:  authzen.Subject{Type: "key", ID: "SWE"},
			Resource: authzen.Resource{Type: "x5c", ID: "SWE", Key: []interface{}{b64(dsc), b64(link)}},
			Action:   &authzen.Action{Name: emrtd.ActionName},
		})
		if err != nil {
			t.Fatalf("Evaluate: %v", err)
		}
		return resp.Decision
	}

	t.Run("disabled registers nothing", func(t *testing.T) {
		mgr := build(false, nil)
		if mgr.GetRegistry("emrtd-csca") != nil {
			t.Fatal("disabled emrtd registry was registered")
		}
		if eval(mgr) {
			t.Fatal("a DSC was trusted with no emrtd registry")
		}
	})
	t.Run("enabled registers and evaluates", func(t *testing.T) {
		mgr := build(true, nil)
		if mgr.GetRegistry("emrtd-csca") == nil {
			t.Fatal("enabled emrtd registry was not registered")
		}
		if !eval(mgr) {
			t.Fatal("DSC via link to a pathLen=0 CSCA must be allowed by default")
		}
	})
	t.Run("policy path_len_mode enforce reaches the registry", func(t *testing.T) {
		mgr := build(true, &config.EMRTDPolicyConfig{PathLenMode: "enforce"})
		if eval(mgr) {
			t.Fatal("enforce must deny a link under a pathLen=0 CSCA")
		}
	})
	t.Run("policy path_len_override reaches the registry", func(t *testing.T) {
		one := 1
		mgr := build(true, &config.EMRTDPolicyConfig{PathLenOverride: &one})
		if !eval(mgr) {
			t.Fatal("override 1 must allow one link certificate")
		}
	})
}
