package didweb

import (
	"testing"
	"time"

	"github.com/sirosfoundation/go-trust/pkg/authzen"
)

// TestRequiredVerificationMethods enforces policies.<n>.did.required_verification_methods:
// every listed type must appear among verificationMethod[].type (exact match).
func TestRequiredVerificationMethods(t *testing.T) {
	reg, err := NewDIDWebRegistry(Config{Description: "test-vm"})
	if err != nil {
		t.Fatal(err)
	}
	doc := &DIDDocument{
		ID: "did:web:example.com",
		VerificationMethod: []VerificationMethod{
			{ID: "did:web:example.com#k1", Type: "JsonWebKey2020"},
			{ID: "did:web:example.com#k2", Type: "Multikey"},
		},
	}

	tests := []struct {
		name        string
		required    []string
		expectAllow bool
	}{
		{"all present", []string{"JsonWebKey2020", "Multikey"}, true},
		{"single present", []string{"Multikey"}, true},
		{"missing type", []string{"Ed25519VerificationKey2020"}, false},
		{"partially present set", []string{"JsonWebKey2020", "Ed25519VerificationKey2020"}, false},
		{"case sensitive", []string{"jsonwebkey2020"}, false},
		{"unset", nil, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctx := map[string]interface{}{}
			if tc.required != nil {
				ctx["required_verification_methods"] = tc.required
			}
			req := &authzen.EvaluationRequest{Subject: authzen.Subject{ID: "did:web:example.com"}, Context: ctx}
			resp := reg.checkPolicyConstraints(req, doc, "did:web:example.com", time.Now())
			if tc.expectAllow {
				if resp != nil {
					t.Fatalf("expected allow (nil), got deny: %v", resp.Context.Reason)
				}
				return
			}
			if resp == nil || resp.Decision {
				t.Fatal("expected deny response")
			}
			reason := resp.Context.Reason
			if _, ok := reason["required_verification_methods"]; !ok {
				t.Errorf("reason missing required_verification_methods: %v", reason)
			}
			if _, ok := reason["resolution_ms"]; !ok {
				t.Errorf("reason missing resolution_ms: %v", reason)
			}
		})
	}

	// Only the top-level verificationMethod array counts.
	t.Run("document without verification methods denies", func(t *testing.T) {
		req := &authzen.EvaluationRequest{Context: map[string]interface{}{
			"required_verification_methods": []interface{}{"Multikey"},
		}}
		resp := reg.checkPolicyConstraints(req, &DIDDocument{ID: "did:web:example.com"}, "did:web:example.com", time.Now())
		if resp == nil || resp.Decision {
			t.Fatal("expected deny for document without verification methods")
		}
	})
}
