package didjwks

import (
	"testing"
	"time"

	"github.com/sirosfoundation/go-trust/pkg/authzen"
)

// TestRequiredVerificationMethodsEnforced checks that the registry enforces
// did.required_verification_methods (all listed types must be present).
// The matching rules themselves are covered in pkg/registry.
func TestRequiredVerificationMethodsEnforced(t *testing.T) {
	doc := &DIDDocument{
		ID: "did:example:1",
		VerificationMethod: []VerificationMethod{
			{ID: "did:example:1#k1", Type: "JsonWebKey2020"},
			{ID: "did:example:1#k2", Type: "Multikey"},
		},
	}
	for _, tc := range []struct {
		name     string
		required []string
		deny     bool
	}{
		{"all present", []string{"JsonWebKey2020", "Multikey"}, false},
		{"missing type", []string{"Ed25519VerificationKey2020"}, true},
		{"partially present", []string{"JsonWebKey2020", "Ed25519VerificationKey2020"}, true},
		{"unset", nil, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := map[string]interface{}{}
			if tc.required != nil {
				ctx["required_verification_methods"] = tc.required
			}
			req := &authzen.EvaluationRequest{Subject: authzen.Subject{ID: "did:example:1"}, Context: ctx}
			resp := checkPolicyConstraints(req, doc, "example.com", time.Now())
			if tc.deny != (resp != nil && !resp.Decision) {
				t.Fatalf("deny=%v, got response %+v", tc.deny, resp)
			}
		})
	}
}
