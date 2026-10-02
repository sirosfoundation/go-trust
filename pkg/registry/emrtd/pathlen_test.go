package emrtd

import (
	"context"
	"testing"
	"time"

	"github.com/sirosfoundation/go-trust/pkg/registry"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func intp(n int) *int { return &n }

// pathLenFixture builds old CSCA (anchor, pathLen=0) -> link -> new CSCA -> DSC.
// selfIssued gives the link certificate the new CSCA's own name (same DN as
// the certificate it re-certifies), otherwise the link is named like the old
// CSCA's successor and signed by a differently named issuer.
type pathLenFixture struct {
	anchor *node
	link   *node
	dsc    *node
}

func newPathLenFixture(t *testing.T, anchorPathLen *int, linkSelfIssued bool) pathLenFixture {
	t.Helper()
	as := cscaSpec("CSCA old", "SE")
	as.pathLen = anchorPathLen
	anchor := issue(t, as, newKey(t, kindP256), nil)

	newKP := newKey(t, kindP256)
	ls := cscaSpec("CSCA new", "SE")
	if linkSelfIssued {
		ls = cscaSpec("CSCA old", "SE") // same DN as its issuer: self-issued
	}
	link := issue(t, ls, newKP, anchor)
	dsc := newDSC(t, kindP256, link, "SE")
	return pathLenFixture{anchor: anchor, link: link, dsc: dsc}
}

func pathLenCtx(mode string, override *int) map[string]interface{} {
	c := map[string]interface{}{}
	if mode != "" {
		c[ctxPathLenMode] = mode
	}
	if override != nil {
		c[ctxPathLenOverride] = *override
	}
	return c
}

func TestEvaluate_PathLen(t *testing.T) {
	cases := []struct {
		name       string
		anchorPL   *int
		selfIssued bool
		mode       string
		override   *int
		wantAllow  bool
	}{
		{"default ignores pathLen=0 with a link cert", intp(0), false, "", nil, true},
		{"explicit ignore ignores pathLen=0", intp(0), false, "ignore", nil, true},
		{"enforce denies pathLen=0 with a link cert", intp(0), false, "enforce", nil, false},
		{"enforce allows pathLen=1 with a link cert", intp(1), false, "enforce", nil, true},
		{"enforce with no pathLen is unlimited", nil, false, "enforce", nil, true},
		{"enforce allows pathLen=0 when link is self-issued", intp(0), true, "enforce", nil, true},
		{"override 1 allows a pathLen=0 anchor with one link cert", intp(0), false, "", intp(1), true},
		{"override 0 denies the same chain", intp(0), false, "", intp(0), false},
		{"override 0 denies even when certs have no pathLen", nil, false, "enforce", intp(0), false},
		{"override 0 allows self-issued link", nil, true, "", intp(0), true},
		{"override replaces a stricter own value", intp(0), false, "enforce", intp(2), true},
		{"override replaces a looser own value", intp(5), false, "enforce", intp(0), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newPathLenFixture(t, tc.anchorPL, tc.selfIssued)
			r := newReg(t, map[string][]*node{"SWE": {f.anchor}})
			resp := eval(t, r, req("SWE", []*node{f.dsc, f.link}, pathLenCtx(tc.mode, tc.override)))
			if tc.wantAllow {
				require.True(t, resp.Decision, "%v", resp.Context.Reason)
				return
			}
			requireDeny(t, resp, CodeChainInvalid)
			assert.Contains(t, resp.Context.Reason["error"], "non-self-issued intermediate")
		})
	}
}

func TestEvaluate_PathLen_LinkCertOwnConstraint(t *testing.T) {
	// anchor -> link1 (pathLen=0) -> link2 -> DSC: link1 may not have link2 below it.
	anchor := newCSCA(t, kindP256, "Root", "SE")
	s1 := cscaSpec("Link 1", "SE")
	s1.pathLen = intp(0)
	link1 := issue(t, s1, newKey(t, kindP256), anchor)
	link2 := issue(t, cscaSpec("Link 2", "SE"), newKey(t, kindP256), link1)
	dsc := newDSC(t, kindP256, link2, "SE")
	r := newReg(t, map[string][]*node{"SWE": {anchor}})
	chain := []*node{dsc, link2, link1}

	require.True(t, eval(t, r, req("SWE", chain, nil)).Decision)
	requireDeny(t, eval(t, r, req("SWE", chain, pathLenCtx("enforce", nil))), CodeChainInvalid)
	// The anchor has two non-self-issued intermediates below it, so the
	// override must be at least 2.
	require.True(t, eval(t, r, req("SWE", chain, pathLenCtx("", intp(2)))).Decision)
	requireDeny(t, eval(t, r, req("SWE", chain, pathLenCtx("", intp(1)))), CodeChainInvalid)
}

func TestEvaluate_PathLen_DSCAnchoredDirectlyNeverCounts(t *testing.T) {
	// A DSC directly under a pathLen=0 CSCA has no intermediates: fine even with override 0.
	csca := newCSCA(t, kindP256, "CSCA", "SE")
	dsc := newDSC(t, kindP256, csca, "SE")
	r := newReg(t, map[string][]*node{"SWE": {csca}})
	require.True(t, eval(t, r, req("SWE", []*node{dsc}, pathLenCtx("", intp(0)))).Decision)
}

func TestEvaluate_PathLen_AlternatePathAccepted(t *testing.T) {
	// Two anchors with the same name and key: one pathLen=0 (path denied), one
	// unlimited. Enforcement must not stop the search at the first failing path.
	f := newPathLenFixture(t, intp(0), false)
	as := cscaSpec("CSCA old", "SE")
	second := issue(t, as, f.anchor.key, nil)
	r := newReg(t, map[string][]*node{"SWE": {f.anchor, second}})
	resp := eval(t, r, req("SWE", []*node{f.dsc, f.link}, pathLenCtx("enforce", nil)))
	require.True(t, resp.Decision, "%v", resp.Context.Reason)
}

func TestPathLenFromContext(t *testing.T) {
	ok := []struct {
		name string
		ctx  map[string]interface{}
		want pathLenPolicy
	}{
		{"nil", nil, pathLenPolicy{}},
		{"ignore", map[string]interface{}{ctxPathLenMode: "ignore"}, pathLenPolicy{}},
		{"empty mode", map[string]interface{}{ctxPathLenMode: ""}, pathLenPolicy{}},
		{"enforce", map[string]interface{}{ctxPathLenMode: "enforce"}, pathLenPolicy{enforce: true}},
		{"nil values", map[string]interface{}{ctxPathLenMode: nil, ctxPathLenOverride: nil}, pathLenPolicy{}},
		{"override int", map[string]interface{}{ctxPathLenOverride: 2}, pathLenPolicy{enforce: true, override: 2, hasOver: true}},
		{"override int64", map[string]interface{}{ctxPathLenOverride: int64(0)}, pathLenPolicy{enforce: true, hasOver: true}},
		{"override float64", map[string]interface{}{ctxPathLenOverride: float64(3)}, pathLenPolicy{enforce: true, override: 3, hasOver: true}},
	}
	for _, tc := range ok {
		t.Run(tc.name, func(t *testing.T) {
			got, err := pathLenFromContext(tc.ctx)
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
	bad := map[string]map[string]interface{}{
		"unknown mode":    {ctxPathLenMode: "strict"},
		"mode not string": {ctxPathLenMode: true},
		"negative":        {ctxPathLenOverride: -1},
		"fractional":      {ctxPathLenOverride: 1.5},
		"wrong type":      {ctxPathLenOverride: "1"},
	}
	for name, c := range bad {
		t.Run("rejects "+name, func(t *testing.T) {
			_, err := pathLenFromContext(c)
			require.Error(t, err)
		})
	}
}

func TestEvaluate_PathLen_MalformedControlDenied(t *testing.T) {
	f := newPathLenFixture(t, intp(0), false)
	r := newReg(t, map[string][]*node{"SWE": {f.anchor}})
	requireDeny(t, eval(t, r, req("SWE", []*node{f.dsc, f.link}, map[string]interface{}{ctxPathLenMode: "strict"})), CodeMalformedRequest)
}

// TestPathLen_ThroughManager drives the real manager: the setting comes from
// the policy, a client cannot set or weaken it, and a policy without an emrtd
// block leaves the default behaviour whatever the client sends.
func TestPathLen_ThroughManager(t *testing.T) {
	f := newPathLenFixture(t, intp(0), false)
	r := newReg(t, map[string][]*node{"SWE": {f.anchor}})

	run := func(t *testing.T, policy *registry.EMRTDPolicyConstraints, clientCtx map[string]interface{}) bool {
		t.Helper()
		mgr := registry.NewRegistryManager(registry.FirstMatch, 5*time.Second)
		mgr.Register(r)
		pm := registry.NewPolicyManager()
		pm.RegisterPolicy(&registry.Policy{Name: ActionName, Registries: []string{r.Info().Name}, EMRTD: policy})
		mgr.SetPolicyManager(pm)
		resp, err := mgr.Evaluate(context.Background(), req("SWE", []*node{f.dsc, f.link}, clientCtx))
		require.NoError(t, err)
		return resp.Decision
	}

	assert.True(t, run(t, nil, nil), "no emrtd block: default ignore")
	assert.False(t, run(t, &registry.EMRTDPolicyConstraints{PathLenMode: "enforce"}, nil), "policy enforce")
	assert.True(t, run(t, &registry.EMRTDPolicyConstraints{PathLenOverride: intp(1)}, nil), "policy override 1")
	assert.False(t, run(t, &registry.EMRTDPolicyConstraints{PathLenOverride: intp(0)}, nil), "policy override 0")

	// Client cannot weaken a policy that enforces...
	assert.False(t, run(t, &registry.EMRTDPolicyConstraints{PathLenMode: "enforce"},
		map[string]interface{}{ctxPathLenMode: "ignore", ctxPathLenOverride: 5}), "client weaken mode/override")
	assert.False(t, run(t, &registry.EMRTDPolicyConstraints{PathLenOverride: intp(0)},
		map[string]interface{}{ctxPathLenOverride: 9}), "client raise override")
	// ...nor impose enforcement where the policy has none.
	assert.True(t, run(t, nil, map[string]interface{}{ctxPathLenMode: "enforce"}), "client enforce without policy")
	assert.True(t, run(t, &registry.EMRTDPolicyConstraints{},
		map[string]interface{}{ctxPathLenOverride: 0}), "client override with empty emrtd block")
}
