package didjwks

import (
	"context"
	"fmt"
	"testing"

	"github.com/sirosfoundation/go-trust/pkg/authzen"
)

func TestEvaluateVerifierIDs(t *testing.T) {
	server := newRoutingServer(sampleJWKS(), "/.well-known/jwks.json")
	defer server.Close()

	reg := registryWith(server)
	did := fmt.Sprintf("did:jwks:%s", testDomain(server))

	req := func(ctx map[string]interface{}, withKey bool) *authzen.EvaluationRequest {
		rq := &authzen.EvaluationRequest{
			Subject:  authzen.Subject{Type: "key", ID: did + "#frag"},
			Resource: authzen.Resource{ID: did},
			Context:  ctx,
		}
		if withKey {
			rq.Resource.Type = "jwk"
			rq.Resource.Key = []interface{}{ecSigningJWK()}
		}
		return rq
	}
	enabled := map[string]interface{}{authzen.VerifierIDsPolicyContextKey: []string{"did"}}

	// The fragment names a verification method that is not in the document, so
	// use the bare DID for the matching case.
	rq := req(enabled, true)
	rq.Subject.ID = did
	resp, err := reg.Evaluate(context.Background(), rq)
	if err != nil {
		t.Fatal(err)
	}
	if !resp.Decision {
		t.Fatalf("expected allow: %v", resp.Context.Reason)
	}
	want := []authzen.VerifierID{{Type: "did", ID: did, Basis: "did-resolution"}}
	if len(resp.Context.VerifierIDs) != 1 || resp.Context.VerifierIDs[0] != want[0] {
		t.Fatalf("verifier_ids = %v, want %v", resp.Context.VerifierIDs, want)
	}

	// Policy off, and resolution-only: nothing.
	rq = req(nil, true)
	rq.Subject.ID = did
	if resp, _ = reg.Evaluate(context.Background(), rq); len(resp.Context.VerifierIDs) != 0 {
		t.Fatalf("policy off must emit nothing, got %v", resp.Context.VerifierIDs)
	}
	rq = req(enabled, false)
	rq.Subject.ID = did
	if resp, _ = reg.Evaluate(context.Background(), rq); !resp.Decision || len(resp.Context.VerifierIDs) != 0 {
		t.Fatalf("resolution-only must emit nothing, got %v", resp.Context.VerifierIDs)
	}
}
