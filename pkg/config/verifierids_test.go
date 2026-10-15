package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestValidateReturnVerifierIDs(t *testing.T) {
	cases := []struct {
		name    string
		c       *PolicyConstraintsConfig
		wantErr string
	}{
		{"absent", nil, ""},
		{"default off", &PolicyConstraintsConfig{}, ""},
		{"all supported", &PolicyConstraintsConfig{ReturnVerifierIDs: []string{"semantic", "x509_san_dns", "x509_san_uri", "decentralized_identifier", "openid_federation"}}, ""},
		{"unknown", &PolicyConstraintsConfig{ReturnVerifierIDs: []string{"semantic", "sematic"}}, `"sematic"`},
		{"deferred type is not accepted yet", &PolicyConstraintsConfig{ReturnVerifierIDs: []string{"did_scid"}}, `"did_scid"`},
		{"wrong case", &PolicyConstraintsConfig{ReturnVerifierIDs: []string{"DNS"}}, `"DNS"`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := DefaultConfig()
			cfg.Policies.Policies = map[string]*PolicyConfig{"rp": {Constraints: tc.c}}
			err := cfg.Validate()
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("Validate() = %v, want nil", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) || !strings.Contains(err.Error(), `policy "rp"`) {
				t.Fatalf("Validate() = %v, want error naming the policy and containing %s", err, tc.wantErr)
			}
		})
	}
}

func TestLoadConfigReturnVerifierIDs(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	content := `
policies:
  policies:
    rp:
      constraints:
        return_verifier_ids: [semantic, x509_san_dns]
`
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	got := cfg.Policies.Policies["rp"].Constraints.ReturnVerifierIDs
	if len(got) != 2 || got[0] != "semantic" || got[1] != "x509_san_dns" {
		t.Fatalf("return_verifier_ids = %v", got)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
}
