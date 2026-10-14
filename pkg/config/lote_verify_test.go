package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestValidate_LoTEVerifyJWS(t *testing.T) {
	cases := []struct {
		name    string
		lote    *LoTERegistryConfig
		wantErr bool
	}{
		{"verify without anchors refused", &LoTERegistryConfig{Enabled: true, Sources: []string{"x"}, VerifyJWS: true}, true},
		{"verify with anchors ok", &LoTERegistryConfig{Enabled: true, Sources: []string{"x"}, VerifyJWS: true, TrustAnchorBundle: "/etc/anchors.pem"}, false},
		{"default (off, no anchors) ok", &LoTERegistryConfig{Enabled: true, Sources: []string{"x"}}, false},
		{"anchors only ok", &LoTERegistryConfig{Enabled: true, Sources: []string{"x"}, TrustAnchorBundle: "/etc/anchors.pem"}, false},
		{"disabled registry not validated", &LoTERegistryConfig{Enabled: false, VerifyJWS: true}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := DefaultConfig()
			cfg.Registries.LoTE = tc.lote
			err := cfg.Validate()
			if tc.wantErr {
				if err == nil || !strings.Contains(err.Error(), "trust_anchor_bundle") {
					t.Fatalf("Validate() = %v, want trust_anchor_bundle error", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("Validate() = %v, want nil", err)
			}
		})
	}
}

func TestLoadConfig_LoTETrustAnchorBundle(t *testing.T) {
	path := filepath.Join(t.TempDir(), "c.yaml")
	y := "registries:\n  lote:\n    enabled: true\n    sources: [a.json]\n    verify_jws: true\n    trust_anchor_bundle: /etc/anchors.pem\n"
	if err := os.WriteFile(path, []byte(y), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	l := cfg.Registries.LoTE
	if l == nil || !l.VerifyJWS || l.TrustAnchorBundle != "/etc/anchors.pem" {
		t.Fatalf("lote config = %+v", l)
	}
}
