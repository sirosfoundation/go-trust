package main

import (
	"path/filepath"
	"strings"
	"testing"
)

// parseConfigPackage parses the real pkg/config, so these tests fail when the
// config structs and the generator drift apart rather than when a fixture does.
func parseConfigPackage(t *testing.T) *Registry {
	t.Helper()
	reg := NewRegistry()
	if err := reg.ParseDir(filepath.Join("..", "..", "..", "pkg", "config")); err != nil {
		t.Fatalf("ParseDir: %v", err)
	}
	return reg
}

func flattenedPaths(t *testing.T) map[string]FieldDoc {
	t.Helper()
	reg := parseConfigPackage(t)
	sections := buildSections(reg, "Config", map[string]string{})
	paths := make(map[string]FieldDoc)
	for _, sec := range sections {
		for _, f := range sec.Fields {
			paths[f.YAMLPath] = f
		}
	}
	return paths
}

// TestPolicyConstraintsAreDocumented is the regression test for the gap that
// left every policy constraint out of docs/CONFIGURATION.md: PolicyConfig is
// reached only through `map[string]*PolicyConfig`, and the generator used to
// treat any map as an opaque leaf. The whole of the policy configuration
// surface rendered as a single cell reading "map[string]*PolicyConfig
// (object)" — no error, just a reference that quietly documented nothing.
func TestPolicyConstraintsAreDocumented(t *testing.T) {
	paths := flattenedPaths(t)

	// One per constraint group, including the six ETSI enrichment keys that
	// were unreachable from config until #177.
	want := []string{
		"policies.policies.<name>.description",
		"policies.policies.<name>.registries",
		"policies.policies.<name>.constraints.allowed_key_types",
		"policies.policies.<name>.constraints.require_key_binding",
		"policies.policies.<name>.etsi.service_types",
		"policies.policies.<name>.etsi.credential_types",
		"policies.policies.<name>.etsi.required_cert_policy_oids",
		"policies.policies.<name>.etsi.extract_rp_identity",
		"policies.policies.<name>.etsi.allowed_attributes",
		"policies.policies.<name>.etsi.strict_entitlement_check",
		"policies.policies.<name>.etsi.allow_intermediaries",
		"policies.policies.<name>.oidfed.required_trust_marks",
		"policies.policies.<name>.oidfed.credential_type_trust_marks",
		"policies.policies.<name>.did.allowed_domains",
		"policies.policies.<name>.mdociaca.issuer_allowlist",
		"policies.policies.<name>.fidomds3.allowed_aaguids",
	}

	for _, path := range want {
		if _, ok := paths[path]; !ok {
			t.Errorf("%s is absent from the generated reference", path)
		}
	}
}

// TestDocumentedFieldsCarryDescriptions guards the other half: a path that
// exists but has an empty description documents nothing useful.
func TestDocumentedFieldsCarryDescriptions(t *testing.T) {
	for path, doc := range flattenedPaths(t) {
		if !strings.HasPrefix(path, "policies.policies.<name>.") {
			continue
		}
		if strings.TrimSpace(doc.Description) == "" {
			t.Errorf("%s has no description; add a doc comment to the config field", path)
		}
	}
}

// TestResolveMapElemTypeName pins the narrow contract: string-keyed maps of
// structs unwrap, everything else stays a leaf.
func TestResolveMapElemTypeName(t *testing.T) {
	reg := parseConfigPackage(t)

	policies := reg.Lookup("PoliciesConfig")
	if policies == nil {
		t.Fatal("PoliciesConfig not found")
	}
	var found bool
	for _, f := range policies.Fields {
		if f.YAMLTag != "policies" {
			continue
		}
		found = true
		if f.TypeName != "" {
			t.Errorf("TypeName = %q, want empty: a map is not a direct struct reference", f.TypeName)
		}
		if f.ElemType != "PolicyConfig" {
			t.Errorf("ElemType = %q, want PolicyConfig", f.ElemType)
		}
	}
	if !found {
		t.Fatal("PoliciesConfig has no field tagged `policies`")
	}

	// A map of non-structs must not be unwrapped — there is nothing to recurse
	// into, and a <name> placeholder row would be noise.
	etsi := reg.Lookup("OIDFedPolicyConfig")
	if etsi == nil {
		t.Fatal("OIDFedPolicyConfig not found")
	}
	for _, f := range etsi.Fields {
		if f.YAMLTag == "credential_type_trust_marks" && f.ElemType != "" {
			t.Errorf("ElemType = %q for map[string][]string, want empty", f.ElemType)
		}
	}
}
