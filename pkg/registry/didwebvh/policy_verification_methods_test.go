package didwebvh

import (
	"testing"
	"time"

	"github.com/sirosfoundation/go-trust/pkg/authzen"
	"github.com/sirosfoundation/go-trust/pkg/registry"
)

// TestRequiredVerificationMethodsEnforced checks that this registry enforces
// did.required_verification_methods. Matching rules are covered in pkg/registry.
func TestRequiredVerificationMethodsEnforced(t *testing.T) {
	reg, err := NewDIDWebVHRegistry(Config{Description: "test-vm"})
	if err != nil {
		t.Fatal(err)
	}
	err = registry.CheckRequiredVerificationMethodsEnforcement(
		func(ctx map[string]interface{}, vmTypes []string) *authzen.EvaluationResponse {
			doc := &DIDDocument{ID: "did:example:1"}
			for _, vt := range vmTypes {
				doc.VerificationMethod = append(doc.VerificationMethod, VerificationMethod{Type: vt})
			}
			req := &authzen.EvaluationRequest{Subject: authzen.Subject{ID: "did:example:1"}, Context: ctx}
			return reg.checkPolicyConstraints(req, doc, "did:webvh:SCID:example.com", time.Now())
		})
	if err != nil {
		t.Fatal(err)
	}
}
