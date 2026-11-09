package main

import (
	"context"
	"crypto/rand"
	"crypto/x509"
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

// TestConfigureEMRTDCRLPolicyFromConfig checks that the crl_* policy keys travel
// from the config file through the manager to the registry: without them a
// stale CRL is not a denial, with require-current it is, a client cannot
// switch the requirement off, and a current CRL restores the allow.
func TestConfigureEMRTDCRLPolicyFromConfig(t *testing.T) {
	root := mkCert(t, "CSCA Test", nil, true, false)
	dsc := mkCert(t, "DSC Test", root, false, false)

	anchors, crls := t.TempDir(), t.TempDir()
	for _, d := range []string{filepath.Join(anchors, "SWE"), filepath.Join(crls, "SWE")} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(anchors, "SWE", "root.pem"),
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: root.cert.Raw}), 0o644); err != nil {
		t.Fatal(err)
	}
	writeCRL := func(this, next time.Time) {
		der, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
			Number: big.NewInt(1), ThisUpdate: this, NextUpdate: next,
		}, root.cert, root.key)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(crls, "SWE", "a.crl"), der, 0o644); err != nil {
			t.Fatal(err)
		}
	}

	build := func(p *config.EMRTDPolicyConfig) *registry.RegistryManager {
		cfg := &config.Config{}
		cfg.Registries.EMRTD = &config.EMRTDRegistryConfig{Enabled: true, Name: "emrtd-csca", AnchorsDir: anchors, CRLsDir: crls}
		cfg.Policies.Policies = map[string]*config.PolicyConfig{
			emrtd.ActionName: {
				Registries:  []string{"emrtd-csca"},
				Constraints: &config.PolicyConstraintsConfig{RequireKeyBinding: true, AllowedKeyTypes: []string{"x5c"}},
				EMRTD:       p,
			},
		}
		mgr := registry.NewRegistryManager(registry.FirstMatch, 10*time.Second)
		collectors := configureRegistriesFromConfig(cfg, mgr, logging.SilentLogger())
		if len(collectors) != 1 {
			t.Fatalf("configureRegistriesFromConfig returned %d collectors, want the eMRTD registry's", len(collectors))
		}
		configurePoliciesFromConfig(cfg, mgr, logging.SilentLogger())
		t.Cleanup(func() {
			if c, ok := mgr.GetRegistry("emrtd-csca").(interface{ Close() error }); ok {
				_ = c.Close()
			}
		})
		return mgr
	}
	eval := func(mgr *registry.RegistryManager, clientCtx map[string]interface{}) (bool, interface{}) {
		t.Helper()
		resp, err := mgr.Evaluate(context.Background(), &authzen.EvaluationRequest{
			Subject:  authzen.Subject{Type: "key", ID: "SWE"},
			Resource: authzen.Resource{Type: "x5c", ID: "SWE", Key: []interface{}{base64.StdEncoding.EncodeToString(dsc.cert.Raw)}},
			Action:   &authzen.Action{Name: emrtd.ActionName},
			Context:  clientCtx,
		})
		if err != nil {
			t.Fatalf("Evaluate: %v", err)
		}
		if resp.Context != nil {
			return resp.Decision, resp.Context.Reason["code"]
		}
		return resp.Decision, nil
	}

	now := time.Now()
	writeCRL(now.Add(-72*time.Hour), now.Add(-24*time.Hour)) // stale
	requireCurrent := &config.EMRTDPolicyConfig{CRLMode: "require-current"}

	if ok, code := eval(build(nil), nil); !ok {
		t.Fatalf("default policy must allow with a stale CRL: %v", code)
	}
	if ok, code := eval(build(requireCurrent), nil); ok || code != emrtd.CodeCRLStale {
		t.Fatalf("require-current with a stale CRL = %v %v, want deny %s", ok, code, emrtd.CodeCRLStale)
	}
	if ok, code := eval(build(requireCurrent), map[string]interface{}{"emrtd_crl_mode": "best-effort"}); ok || code != emrtd.CodeCRLStale {
		t.Fatalf("client-supplied crl mode weakened the policy: %v %v", ok, code)
	}
	exempt := &config.EMRTDPolicyConfig{CRLMode: "require-current", CRLExemptCountries: []string{"SWE"}}
	if ok, code := eval(build(exempt), nil); !ok {
		t.Fatalf("an exempt country must be allowed: %v", code)
	}
	writeCRL(now.Add(-time.Hour), now.Add(24*time.Hour)) // current
	if ok, code := eval(build(requireCurrent), nil); !ok {
		t.Fatalf("require-current with a current CRL denied: %v", code)
	}
	tooOld := &config.EMRTDPolicyConfig{CRLMode: "require-current", CRLMaxAge: "30m"}
	if ok, code := eval(build(tooOld), nil); ok || code != emrtd.CodeCRLStale {
		t.Fatalf("crl_max_age 30m with a 1h-old CRL = %v %v, want deny", ok, code)
	}
}
