package main

import (
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/sirosfoundation/g119612/pkg/logging"
	"github.com/sirosfoundation/go-trust/pkg/config"
	"github.com/sirosfoundation/go-trust/pkg/registry"
)

// yamlKeys returns the yaml key of every exported field of a struct type,
// indexed by field name.
func yamlKeys(t *testing.T, typ reflect.Type) map[string]string {
	t.Helper()
	keys := make(map[string]string, typ.NumField())
	for i := 0; i < typ.NumField(); i++ {
		f := typ.Field(i)
		tag := f.Tag.Get("yaml")
		if tag == "" {
			t.Fatalf("%s.%s has no yaml tag", typ.Name(), f.Name)
		}
		keys[f.Name] = strings.Split(tag, ",")[0]
	}
	return keys
}

// TestPolicyConfigCoversEveryConstraint pins the invariant that issue #176 was
// filed about: a constraint implemented in pkg/registry with no counterpart in
// pkg/config cannot be configured at all, and the operator gets no warning,
// because config is decoded with a non-strict yaml.Unmarshal — a key with no
// field to land in is discarded rather than rejected.
//
// The failure mode is silence, so the only thing that catches it is a test.
func TestPolicyConfigCoversEveryConstraint(t *testing.T) {
	cases := []struct {
		name       string
		constraint reflect.Type
		cfg        reflect.Type
	}{
		{"ETSI", reflect.TypeOf(registry.ETSIPolicyConstraints{}), reflect.TypeOf(config.ETSIPolicyConfig{})},
		{"OIDFed", reflect.TypeOf(registry.OIDFedPolicyConstraints{}), reflect.TypeOf(config.OIDFedPolicyConfig{})},
		{"Constraints", reflect.TypeOf(registry.PolicyConstraints{}), reflect.TypeOf(config.PolicyConstraintsConfig{})},
		{"DID", reflect.TypeOf(registry.DIDPolicyConstraints{}), reflect.TypeOf(config.DIDPolicyConfig{})},
		{"MDOCIACA", reflect.TypeOf(registry.MDOCIACAPolicyConstraints{}), reflect.TypeOf(config.MDOCIACAPolicyConfig{})},
		{"FIDOMDS3", reflect.TypeOf(registry.FIDOMDS3PolicyConstraints{}), reflect.TypeOf(config.FIDOMDS3PolicyConfig{})},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			constraintKeys := yamlKeys(t, tc.constraint)
			cfgKeys := yamlKeys(t, tc.cfg)

			for field, key := range constraintKeys {
				cfgKey, ok := cfgKeys[field]
				if !ok {
					t.Errorf("%s.%s has no counterpart in %s; it can never be set from config.yaml",
						tc.constraint.Name(), field, tc.cfg.Name())
					continue
				}
				if cfgKey != key {
					t.Errorf("%s.%s yaml key is %q but %s.%s uses %q; the config key would not reach the constraint",
						tc.cfg.Name(), field, cfgKey, tc.constraint.Name(), field, key)
				}
			}

			// The mirror image: a config key with nowhere to go parses fine and
			// is then dropped by the translation in configurePoliciesFromConfig.
			for field := range cfgKeys {
				if _, ok := constraintKeys[field]; !ok {
					t.Errorf("%s.%s has no counterpart in %s; the key parses and is then discarded",
						tc.cfg.Name(), field, tc.constraint.Name())
				}
			}
		})
	}
}

// TestConfigurePoliciesFromConfigCopiesEveryField is the behavioural half:
// struct parity is worthless if the hand-written translation in
// configurePoliciesFromConfig forgets to copy a field. Every field is set to a
// distinguishable non-zero value, so a forgotten one shows up as a zero value.
func TestConfigurePoliciesFromConfigCopiesEveryField(t *testing.T) {
	cfg := &config.Config{}
	cfg.Policies.Policies = map[string]*config.PolicyConfig{
		"credential-verifier": &config.PolicyConfig{
			Description: "every constraint set",
			Registries:  []string{"etsi"},
			Constraints: &config.PolicyConstraintsConfig{
				AllowedKeyTypes:   []string{"x5c"},
				RequireKeyBinding: true,
			},
			ETSI: &config.ETSIPolicyConfig{
				ServiceTypes:           []string{"http://uri.etsi.org/TrstSvc/Svctype/CA/QC"},
				ServiceStatuses:        []string{"http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted"},
				Countries:              []string{"SE"},
				CredentialTypes:        []string{"eu.europa.ec.eudi.pid.1"},
				RequiredCertPolicyOIDs: []string{"0.4.0.194112.1.0"},
				ExtractRPIdentity:      true,
				AllowedAttributes:      []string{"family_name", "given_name"},
				StrictEntitlementCheck: true,
				AllowIntermediaries:    true,
			},
			OIDFed: &config.OIDFedPolicyConfig{
				RequiredTrustMarks: []string{"https://trust.example/tm"},
				EntityTypes:        []string{"openid_relying_party"},
				MaxChainDepth:      4,
				CredentialTypeTrustMarks: map[string][]string{
					"eu.europa.ec.eudi.pid.1": {"https://trust.example/pid"},
				},
			},
		},
	}

	mgr := registry.NewRegistryManager(registry.FirstMatch, 10*time.Second)
	configurePoliciesFromConfig(cfg, mgr, logging.SilentLogger())

	pm := mgr.GetPolicyManager()
	if pm == nil {
		t.Fatal("no policy manager was installed")
	}
	policy := pm.GetPolicy("credential-verifier")
	if policy == nil {
		t.Fatal("policy credential-verifier was not registered")
	}

	assertNoZeroFields(t, "PolicyConstraints", reflect.ValueOf(policy.Constraints))
	if policy.ETSI == nil {
		t.Fatal("ETSI constraints were not converted")
	}
	assertNoZeroFields(t, "ETSIPolicyConstraints", reflect.ValueOf(*policy.ETSI))
	if policy.OIDFed == nil {
		t.Fatal("OIDFed constraints were not converted")
	}
	assertNoZeroFields(t, "OIDFedPolicyConstraints", reflect.ValueOf(*policy.OIDFed))

	// Spot-check values, not just non-zeroness, so a field copied from the
	// wrong source would still be caught.
	if !policy.Constraints.RequireKeyBinding {
		t.Error("RequireKeyBinding was not copied")
	}
	if got := policy.ETSI.AllowedAttributes; len(got) != 2 || got[0] != "family_name" {
		t.Errorf("AllowedAttributes = %v, want [family_name given_name]", got)
	}
	if got := policy.OIDFed.CredentialTypeTrustMarks["eu.europa.ec.eudi.pid.1"]; len(got) != 1 {
		t.Errorf("CredentialTypeTrustMarks = %v, want one entry", policy.OIDFed.CredentialTypeTrustMarks)
	}
}

func assertNoZeroFields(t *testing.T, name string, v reflect.Value) {
	t.Helper()
	for i := 0; i < v.NumField(); i++ {
		if v.Field(i).IsZero() {
			t.Errorf("%s.%s is the zero value; configurePoliciesFromConfig did not copy it",
				name, v.Type().Field(i).Name)
		}
	}
}

// Fail-closed must take effect even before any policy is defined, so an
// operator can enable it ahead of rolling out new action policies.
func TestConfigurePolicies_FailClosedWithoutPolicies(t *testing.T) {
	cfg := &config.Config{}
	cfg.Policies.FailClosedOnUnknownAction = true
	if !policiesConfigured(cfg) {
		t.Fatal("startup would skip policy configuration for a fail-closed-only config")
	}
	if policiesConfigured(&config.Config{}) || policiesConfigured(nil) {
		t.Fatal("empty config must not enable policy handling")
	}

	mgr := registry.NewRegistryManager(registry.FirstMatch, 10*time.Second)
	configurePoliciesFromConfig(cfg, mgr, logging.SilentLogger())

	pm := mgr.GetPolicyManager()
	if pm == nil {
		t.Fatal("policy manager not installed")
	}
	if !pm.FailClosedOnUnknownAction() {
		t.Fatal("fail-closed not applied")
	}
}
