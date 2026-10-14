package didjwks

import (
	"testing"
	"time"

	"github.com/sirosfoundation/go-trust/pkg/authzen"
	"github.com/sirosfoundation/go-trust/pkg/registry"
)

// TestRequiredVerificationMethodsEnforced checks that this registry enforces
// did.required_verification_methods. Matching rules are covered in pkg/registry.
func TestRequiredVerificationMethodsEnforced(t *testing.T) {
	newVM := func(typ string) VerificationMethod { return VerificationMethod{Type: typ} }
	evaluate := func(ctx map[string]interface{}, vms []VerificationMethod) *authzen.EvaluationResponse {
		return checkPolicyConstraints(&authzen.EvaluationRequest{Context: ctx}, &DIDDocument{VerificationMethod: vms}, "example.com", time.Now())
	}
	if err := registry.CheckRequiredVerificationMethodsEnforcement(newVM, evaluate); err != nil {
		t.Fatal(err)
	}
}
