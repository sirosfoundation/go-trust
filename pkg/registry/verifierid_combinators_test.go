package registry

import (
	"context"
	"testing"
	"time"

	"github.com/sirosfoundation/go-trust/pkg/authzen"
	"github.com/sirosfoundation/go-trust/pkg/registry/rpcert"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// vidStub is a registry that answers with a fixed decision and fixed verifier
// identifiers, standing in for any registry that emits them.
type vidStub struct {
	name     string
	decision bool
	ids      []authzen.VerifierID
}

func (s *vidStub) Evaluate(context.Context, *authzen.EvaluationRequest) (*authzen.EvaluationResponse, error) {
	resp := &authzen.EvaluationResponse{Decision: s.decision, Context: &authzen.EvaluationResponseContext{
		Reason: map[string]interface{}{"stub": s.name},
	}}
	// A deny carrying identifiers must never leak them through a combinator.
	resp.Context.VerifierIDs = s.ids
	return resp, nil
}
func (s *vidStub) SupportedResourceTypes() []string { return []string{"x5c"} }
func (s *vidStub) SupportsResolutionOnly() bool     { return false }
func (s *vidStub) Info() RegistryInfo               { return RegistryInfo{Name: s.name, Type: "stub", Healthy: true} }
func (s *vidStub) Healthy() bool                    { return true }
func (s *vidStub) Refresh(context.Context) error    { return nil }

func dnsID(v string) authzen.VerifierID {
	return authzen.VerifierID{Type: authzen.VerifierIDTypeDNS, ID: v, Basis: authzen.VerifierIDBasisClientIDBinding}
}

func semID(v string) authzen.VerifierID {
	return authzen.VerifierID{Type: authzen.VerifierIDTypeSemantic, ID: v, Basis: authzen.VerifierIDBasisX5CChain}
}

func stubReq() *authzen.EvaluationRequest {
	return &authzen.EvaluationRequest{
		Subject:  authzen.Subject{Type: "key", ID: "https://rp.example.com"},
		Resource: authzen.Resource{Type: "x5c", ID: "https://rp.example.com", Key: []interface{}{"x"}},
		Action:   &authzen.Action{Name: "verifier"},
	}
}

func evalWith(t *testing.T, strategy ResolutionStrategy, regs ...TrustRegistry) *authzen.EvaluationResponse {
	t.Helper()
	mgr := NewRegistryManager(strategy, 5*time.Second)
	for _, r := range regs {
		mgr.Register(r)
	}
	pm := NewPolicyManager()
	require.NoError(t, pm.RegisterPolicy(&Policy{Name: "verifier", Constraints: PolicyConstraints{ReturnVerifierIDs: []string{"x509_san_dns", "semantic"}}}))
	mgr.SetPolicyManager(pm)
	resp, err := mgr.Evaluate(context.Background(), stubReq())
	require.NoError(t, err)
	return resp
}

func idList(resp *authzen.EvaluationResponse) []authzen.VerifierID {
	if resp == nil || resp.Context == nil {
		return nil
	}
	return resp.Context.VerifierIDs
}

// Every strategy carries verifier_ids from the positive registries through.
func TestStrategies_CarryVerifierIDs(t *testing.T) {
	for _, strategy := range []ResolutionStrategy{FirstMatch, Sequential, AllRegistries, BestMatch} {
		t.Run(string(strategy), func(t *testing.T) {
			resp := evalWith(t, strategy,
				&vidStub{name: "a", decision: true, ids: []authzen.VerifierID{dnsID("rp.example.com")}})
			require.True(t, resp.Decision, "%+v", resp.Context)
			assert.Equal(t, []authzen.VerifierID{dnsID("rp.example.com")}, idList(resp))
		})
		t.Run(string(strategy)+"/deny_carries_nothing", func(t *testing.T) {
			resp := evalWith(t, strategy,
				&vidStub{name: "a", decision: false, ids: []authzen.VerifierID{dnsID("rp.example.com")}})
			require.False(t, resp.Decision)
			assert.Empty(t, idList(resp))
		})
	}
}

// all / best_match aggregate: identifiers of every positive registry are merged,
// deduplicated and stably ordered; a denying registry contributes nothing.
func TestStrategies_AggregateVerifierIDs(t *testing.T) {
	for _, strategy := range []ResolutionStrategy{AllRegistries, BestMatch} {
		t.Run(string(strategy), func(t *testing.T) {
			resp := evalWith(t, strategy,
				&vidStub{name: "a", decision: true, ids: []authzen.VerifierID{dnsID("rp.example.com"), semID("semantic_id:VATSE-1")}},
				&vidStub{name: "b", decision: true, ids: []authzen.VerifierID{dnsID("rp.example.com")}}, // duplicate
				&vidStub{name: "c", decision: false, ids: []authzen.VerifierID{dnsID("evil.example.com")}},
			)
			require.True(t, resp.Decision)
			assert.Equal(t, []authzen.VerifierID{semID("semantic_id:VATSE-1"), dnsID("rp.example.com")}, idList(resp))
		})
	}
	// Nobody positive: the aggregate denies and carries none.
	resp := evalWith(t, AllRegistries, &vidStub{name: "c", decision: false, ids: []authzen.VerifierID{dnsID("x.example.com")}})
	assert.False(t, resp.Decision)
	assert.Empty(t, idList(resp))
}

func TestComposite_CarriesVerifierIDs(t *testing.T) {
	yes := func(name, id string) TrustRegistry {
		return &vidStub{name: name, decision: true, ids: []authzen.VerifierID{dnsID(id)}}
	}
	no := func(name, id string) TrustRegistry {
		return &vidStub{name: name, decision: false, ids: []authzen.VerifierID{dnsID(id)}}
	}
	tests := []struct {
		name      string
		op        LogicOperator
		threshold int
		children  []TrustRegistry
		allow     bool
		want      []authzen.VerifierID
	}{
		{"AND all agree", LogicAND, 0, []TrustRegistry{yes("a", "a.example"), yes("b", "b.example")}, true,
			[]authzen.VerifierID{dnsID("a.example"), dnsID("b.example")}},
		{"AND one denies: deny, none", LogicAND, 0, []TrustRegistry{yes("a", "a.example"), no("b", "b.example")}, false, nil},
		{"OR only the agreeing child", LogicOR, 0, []TrustRegistry{yes("a", "a.example"), no("b", "b.example")}, true,
			[]authzen.VerifierID{dnsID("a.example")}},
		{"OR none agree", LogicOR, 0, []TrustRegistry{no("a", "a.example")}, false, nil},
		{"MAJORITY met", LogicMAJORITY, 0, []TrustRegistry{yes("a", "a.example"), yes("b", "b.example"), no("c", "c.example")}, true,
			[]authzen.VerifierID{dnsID("a.example"), dnsID("b.example")}},
		{"MAJORITY not met", LogicMAJORITY, 0, []TrustRegistry{yes("a", "a.example"), no("b", "b.example"), no("c", "c.example")}, false, nil},
		{"QUORUM met", LogicQUORUM, 2, []TrustRegistry{yes("a", "a.example"), yes("b", "a.example"), no("c", "c.example")}, true,
			[]authzen.VerifierID{dnsID("a.example")}},
		{"QUORUM not met", LogicQUORUM, 2, []TrustRegistry{yes("a", "a.example"), no("b", "b.example")}, false, nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c := NewCompositeRegistryWithOptions("c", tc.op, tc.children, WithThreshold(max(tc.threshold, 1)))
			resp, err := c.Evaluate(context.Background(), stubReq())
			require.NoError(t, err)
			assert.Equal(t, tc.allow, resp.Decision)
			assert.Equal(t, tc.want, idList(resp))
		})
	}
}

func TestMergeVerifierIDs_Guards(t *testing.T) {
	child := &authzen.EvaluationResponse{Decision: true, Context: &authzen.EvaluationResponseContext{VerifierIDs: []authzen.VerifierID{dnsID("a.example")}}}
	// A deny aggregate takes nothing, a nil/contextless/denied child gives nothing.
	deny := &authzen.EvaluationResponse{Decision: false}
	mergeVerifierIDs(deny, []*authzen.EvaluationResponse{child})
	assert.Nil(t, deny.Context)
	mergeVerifierIDs(nil, []*authzen.EvaluationResponse{child})
	allow := &authzen.EvaluationResponse{Decision: true}
	mergeVerifierIDs(allow, []*authzen.EvaluationResponse{nil, {Decision: true}, {Decision: false, Context: child.Context}})
	assert.Nil(t, allow.Context)
}

func TestAddVerifierIDs(t *testing.T) {
	enabled := vidReq("x509_san_dns:rp.example.com", []string{"x509_san_dns"}, nil)
	ids := []authzen.VerifierID{dnsID("rp.example.com"), semID("semantic_id:X")}

	allow := &authzen.EvaluationResponse{Decision: true}
	AddVerifierIDs(allow, enabled, ids)
	assert.Equal(t, []authzen.VerifierID{dnsID("rp.example.com")}, idList(allow), "type the policy did not enable is dropped")

	deny := &authzen.EvaluationResponse{Decision: false}
	AddVerifierIDs(deny, enabled, ids)
	assert.Empty(t, idList(deny), "never on a deny")

	off := &authzen.EvaluationResponse{Decision: true}
	AddVerifierIDs(off, vidReq("x509_san_dns:rp.example.com", nil, nil), ids)
	assert.Empty(t, idList(off), "policy off")
}

// DeriveCertVerifierIDs is the single derivation shared by whitelist,
// system_cert_pool and mdoc_rical. One negative per omission rule.
func TestDeriveCertVerifierIDs(t *testing.T) {
	full := makeVIDCert(t, vidCertOpts{orgID: "VATSE-556000000101", policy: rpcert.OIDNCPLegalPerson, dns: []string{"rp.example.com"}, uris: []string{"https://rp.example.com/id"}})
	wild := makeVIDCert(t, vidCertOpts{orgID: "VATSE-556000000101", policy: rpcert.OIDNCPLegalPerson, dns: []string{"*.example.com"}})
	both := []string{"semantic", "x509_san_dns", "x509_san_uri"}

	tests := []struct {
		name      string
		subject   string
		types     []string
		extra     map[string]interface{}
		leaf      bool // false: nil leaf
		wild      bool
		validated bool
		want      map[string]string // type -> id
	}{
		{"validated chain: dns + semantic", "x509_san_dns:rp.example.com", both, nil, true, false, true,
			map[string]string{"x509_san_dns": "rp.example.com", "semantic": "semantic_id:VATSE-556000000101"}},
		{"pinned key (chain not validated): semantic omitted", "x509_san_dns:rp.example.com", both, nil, true, false, false,
			map[string]string{"x509_san_dns": "rp.example.com"}},
		{"canonical form: upper case client_id gives lower case", "x509_san_dns:RP.Example.COM", both, nil, true, false, true,
			map[string]string{"x509_san_dns": "rp.example.com", "semantic": "semantic_id:VATSE-556000000101"}},
		{"trailing dot does not bind: omitted", "x509_san_dns:rp.example.com.", both, nil, true, false, true,
			map[string]string{"semantic": "semantic_id:VATSE-556000000101"}},
		{"uri is byte-for-byte", "x509_san_uri:https://rp.example.com/id", both, nil, true, false, true,
			map[string]string{"x509_san_uri": "https://rp.example.com/id", "semantic": "semantic_id:VATSE-556000000101"}},
		{"client_id not a SAN of the leaf", "x509_san_dns:other.example.com", both, nil, true, false, true,
			map[string]string{"semantic": "semantic_id:VATSE-556000000101"}},
		{"wildcard SAN binds but names many hosts: omitted", "x509_san_dns:host.example.com", both, nil, true, true, true,
			map[string]string{"semantic": "semantic_id:VATSE-556000000101"}},
		{"wildcard client_id: omitted", "x509_san_dns:*.example.com", both, nil, true, true, true,
			map[string]string{"semantic": "semantic_id:VATSE-556000000101"}},
		{"brokered (intermediary) request: dns omitted, semantic kept", "x509_san_dns:rp.example.com", both,
			map[string]interface{}{"intermediary_x5c": []string{"MIIB"}}, true, false, true,
			map[string]string{"semantic": "semantic_id:VATSE-556000000101"}},
		{"brokered, pinned key: nothing at all", "x509_san_dns:rp.example.com", both,
			map[string]interface{}{"intermediary_x5c": []string{"MIIB"}}, true, false, false, nil},
		{"policy enables only dns", "x509_san_dns:rp.example.com", []string{"x509_san_dns"}, nil, true, false, true,
			map[string]string{"x509_san_dns": "rp.example.com"}},
		{"policy off", "x509_san_dns:rp.example.com", nil, nil, true, false, true, nil},
		{"hash scheme has no identifier", "x509_hash:abcd", both, nil, true, false, false, nil},
		{"https client_id has no SAN claim", "https://rp.example.com", []string{"x509_san_dns"}, nil, true, false, true, nil},
		{"nil leaf", "x509_san_dns:rp.example.com", both, nil, false, false, true, nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := vidReq(tc.subject, tc.types, tc.extra)
			leaf := full
			if tc.wild {
				leaf = wild
			}
			if !tc.leaf {
				leaf = nil
			}
			got := idsOf(DeriveCertVerifierIDs(req, leaf, tc.validated))
			want := tc.want
			gotMap := map[string]string{}
			for k, v := range got {
				gotMap[k] = v.ID
			}
			if want == nil {
				want = map[string]string{}
			}
			assert.Equal(t, want, gotMap)
		})
	}
	assert.Nil(t, DeriveCertVerifierIDs(nil, full, true))
}
