package rpcert

import (
	"testing"
)

func TestParseDCQLQuery_Basic(t *testing.T) {
	raw := map[string]interface{}{
		"credentials": []interface{}{
			map[string]interface{}{
				"id":     "pid",
				"format": "vc+sd-jwt",
				"meta": map[string]interface{}{
					"vct_values": []interface{}{"eu.europa.ec.eudi.pid.1"},
				},
				"claims": []interface{}{
					map[string]interface{}{"path": []interface{}{"family_name"}},
					map[string]interface{}{"path": []interface{}{"given_name"}},
					map[string]interface{}{"path": []interface{}{"age_over_18"}},
				},
			},
		},
	}

	q := ParseDCQLQuery(raw)
	if q == nil {
		t.Fatal("expected non-nil query")
	}
	if len(q.Credentials) != 1 {
		t.Fatalf("expected 1 credential, got %d", len(q.Credentials))
	}
	cred := q.Credentials[0]
	if cred.ID != "pid" {
		t.Errorf("expected id=pid, got %s", cred.ID)
	}
	if cred.Format != "vc+sd-jwt" {
		t.Errorf("expected format=vc+sd-jwt, got %s", cred.Format)
	}
	if len(cred.Claims) != 3 {
		t.Fatalf("expected 3 claims, got %d", len(cred.Claims))
	}
	expectedPaths := []string{"family_name", "given_name", "age_over_18"}
	for i, claim := range cred.Claims {
		if len(claim.Path) != 1 || claim.Path[0] != expectedPaths[i] {
			t.Errorf("claim %d: expected path [%s], got %v", i, expectedPaths[i], claim.Path)
		}
	}
}

func TestParseDCQLQuery_NestedPaths(t *testing.T) {
	raw := map[string]interface{}{
		"credentials": []interface{}{
			map[string]interface{}{
				"id":     "pid",
				"format": "vc+sd-jwt",
				"claims": []interface{}{
					map[string]interface{}{"path": []interface{}{"address", "street_address"}},
					map[string]interface{}{"path": []interface{}{"address", "locality"}},
					map[string]interface{}{"path": []interface{}{"family_name"}},
				},
			},
		},
	}

	q := ParseDCQLQuery(raw)
	names := q.ExtractRequestedClaimNames()

	// "address" should only appear once despite two nested claims
	if len(names) != 2 {
		t.Fatalf("expected 2 unique claim names, got %d: %v", len(names), names)
	}
	expected := map[string]bool{"address": true, "family_name": true}
	for _, n := range names {
		if !expected[n] {
			t.Errorf("unexpected claim name: %s", n)
		}
	}
}

func TestParseDCQLQuery_MultipleCredentials(t *testing.T) {
	raw := map[string]interface{}{
		"credentials": []interface{}{
			map[string]interface{}{
				"id":     "pid",
				"format": "vc+sd-jwt",
				"claims": []interface{}{
					map[string]interface{}{"path": []interface{}{"family_name"}},
				},
			},
			map[string]interface{}{
				"id":     "mdl",
				"format": "mso_mdoc",
				"claims": []interface{}{
					map[string]interface{}{"path": []interface{}{"driving_privileges"}},
				},
			},
		},
	}

	q := ParseDCQLQuery(raw)
	names := q.ExtractRequestedClaimNames()
	if len(names) != 2 {
		t.Fatalf("expected 2 claim names, got %d: %v", len(names), names)
	}
}

func TestParseDCQLQuery_Nil(t *testing.T) {
	if q := ParseDCQLQuery(nil); q != nil {
		t.Error("expected nil for nil input")
	}
	if q := ParseDCQLQuery("not a map"); q != nil {
		t.Error("expected nil for string input")
	}
}

func TestParseDCQLQuery_Empty(t *testing.T) {
	q := ParseDCQLQuery(map[string]interface{}{})
	if q == nil {
		t.Fatal("expected non-nil query")
	}
	names := q.ExtractRequestedClaimNames()
	if len(names) != 0 {
		t.Errorf("expected 0 claim names, got %d", len(names))
	}
}

func TestParseDCQLQuery_NoClaims(t *testing.T) {
	raw := map[string]interface{}{
		"credentials": []interface{}{
			map[string]interface{}{
				"id":     "pid",
				"format": "vc+sd-jwt",
			},
		},
	}
	q := ParseDCQLQuery(raw)
	names := q.ExtractRequestedClaimNames()
	if len(names) != 0 {
		t.Errorf("expected 0 claim names, got %d", len(names))
	}
}

func TestDetectOverRequest_WithDCQLClaimNames(t *testing.T) {
	// Simulate: DCQL claims extracted as flat list, compared against entitlements
	entitlements := &RPEntitlements{
		AllowedAttributes: []string{"family_name", "given_name", "birthdate"},
	}

	// RP requests family_name + age_over_18 (not entitled)
	result := DetectOverRequest(entitlements, []string{"family_name", "age_over_18"})
	if !result.IsOverRequest {
		t.Error("expected over-request")
	}
	if len(result.OverRequested) != 1 || result.OverRequested[0] != "age_over_18" {
		t.Errorf("expected [age_over_18] over-requested, got %v", result.OverRequested)
	}
}
