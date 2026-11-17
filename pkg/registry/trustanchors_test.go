package registry

import (
	"context"
	"testing"
	"time"

	"github.com/sirosfoundation/go-trust/pkg/authzen"
)

func TestTrustAnchorTTL(t *testing.T) {
	now := time.Date(2026, 11, 16, 12, 0, 0, 0, time.UTC)
	rfc := func(d time.Duration) string { return now.Add(d).Format(time.RFC3339) }
	cases := []struct {
		name               string
		nextUpdate, notAft string
		want               time.Duration
		ok                 bool
	}{
		{"no nextUpdate: 24h default", "", "", 24 * time.Hour, true},
		{"time to nextUpdate", rfc(3 * time.Hour), "", 3 * time.Hour, true},
		{"overdue nextUpdate: retry", rfc(-time.Hour), rfc(48 * time.Hour), OverdueTrustAnchorTTL, true},
		{"clamped to notAfter", rfc(10 * time.Hour), rfc(2 * time.Hour), 2 * time.Hour, true},
		{"default clamped to notAfter", "", rfc(time.Hour), time.Hour, true},
		{"retry clamped to notAfter", rfc(-time.Hour), rfc(5 * time.Minute), 5 * time.Minute, true},
		{"expired list offers nothing", "", rfc(-time.Second), 0, false},
		{"unparseable nextUpdate offers nothing", "tomorrow", "", 0, false},
		{"unparseable notAfter offers nothing", "", "never", 0, false},
		{"offset-free nextUpdate offers nothing", "2026-11-17T00:00:00", "", 0, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := TrustAnchorTTL(now, tc.nextUpdate, tc.notAft)
			if ok != tc.ok || got != tc.want {
				t.Errorf("got (%v, %v), want (%v, %v)", got, ok, tc.want, tc.ok)
			}
		})
	}
}

func TestBuildTrustAnchorSet(t *testing.T) {
	now := time.Now()
	a := authzen.TrustAnchor{X5C: "AAA"}
	set, ok := BuildTrustAnchorSet(now, "r", authzen.TrustAnchorTypeVICAL, "", "", "", []authzen.TrustAnchor{a})
	if !ok || set.TTLSeconds != int64(DefaultTrustAnchorTTL/time.Second) || set.Version == "" || set.Excluded != 0 {
		t.Fatalf("unexpected set: %+v ok=%v", set, ok)
	}
	again, _ := BuildTrustAnchorSet(now, "r", authzen.TrustAnchorTypeVICAL, "", "", "", []authzen.TrustAnchor{a})
	other, _ := BuildTrustAnchorSet(now, "r", authzen.TrustAnchorTypeVICAL, "", "", "", []authzen.TrustAnchor{{X5C: "BBB"}})
	if set.Version != again.Version || set.Version == other.Version {
		t.Errorf("version must follow the content: %s %s %s", set.Version, again.Version, other.Version)
	}
	if _, ok := BuildTrustAnchorSet(now, "r", "vical", "", "", "", nil); ok {
		t.Error("an empty list is not offered")
	}
	many := make([]authzen.TrustAnchor, MaxTrustAnchors+5)
	for i := range many {
		many[i] = a
	}
	set, _ = BuildTrustAnchorSet(now, "r", "vical", "", "", "", many)
	if len(set.Anchors) != MaxTrustAnchors || set.Excluded != 5 {
		t.Errorf("anchors=%d excluded=%d", len(set.Anchors), set.Excluded)
	}
}

func reqWithTypes(types ...string) *authzen.EvaluationRequest {
	ctx := map[string]interface{}{}
	if len(types) > 0 {
		ctx[authzen.TrustAnchorsPolicyContextKey] = types
	}
	return &authzen.EvaluationRequest{Subject: authzen.Subject{Type: "key", ID: "iaca"}, Context: ctx}
}

func TestAddTrustAnchorSet_FailsClosed(t *testing.T) {
	set := authzen.TrustAnchorSet{Registry: "iaca", Type: "vical", Anchors: []authzen.TrustAnchor{{X5C: "A"}}}
	pos := func() *authzen.EvaluationResponse { return &authzen.EvaluationResponse{Decision: true} }

	if r := pos(); func() bool { AddTrustAnchorSet(r, reqWithTypes(), set); return r.Context != nil }() {
		t.Error("policy did not enable the member: nothing may be added")
	}
	if r := pos(); func() bool { AddTrustAnchorSet(r, reqWithTypes("rical"), set); return r.Context != nil }() {
		t.Error("a different type was enabled: nothing may be added")
	}
	if r := (&authzen.EvaluationResponse{}); func() bool { AddTrustAnchorSet(r, reqWithTypes("vical"), set); return r.Context != nil }() {
		t.Error("a denial never carries anchors")
	}
	r := pos()
	AddTrustAnchorSet(r, reqWithTypes("vical"), set)
	AddTrustAnchorSet(r, reqWithTypes("vical"), set)
	if len(r.Context.TrustAnchors) != 1 {
		t.Errorf("want one entry, got %d", len(r.Context.TrustAnchors))
	}
}

func TestMergeTrustAnchors_PositiveChildrenOnly(t *testing.T) {
	mk := func(decision bool, reg, typ string) *authzen.EvaluationResponse {
		return &authzen.EvaluationResponse{Decision: decision, Context: &authzen.EvaluationResponseContext{
			TrustAnchors: []authzen.TrustAnchorSet{{Registry: reg, Type: typ, Anchors: []authzen.TrustAnchor{{X5C: "A"}}}},
		}}
	}
	resp := &authzen.EvaluationResponse{Decision: true}
	mergeTrustAnchors(resp, []*authzen.EvaluationResponse{mk(true, "z", "vical"), mk(false, "denied", "vical"), mk(true, "a", "rical"), mk(true, "z", "vical"), nil})
	got := resp.Context.TrustAnchors
	if len(got) != 2 || got[0].Type != "rical" || got[1].Registry != "z" {
		t.Errorf("unexpected merge: %+v", got)
	}
	neg := &authzen.EvaluationResponse{}
	mergeTrustAnchors(neg, []*authzen.EvaluationResponse{mk(true, "a", "vical")})
	if neg.Context != nil {
		t.Error("a negative aggregate carries no anchors")
	}
}

func TestTrustAnchorResolutionTarget(t *testing.T) {
	req := reqWithTypes("vical")
	if !TrustAnchorResolutionTarget(req, "iaca", "vical") {
		t.Error("enabled type naming the registry is a preload")
	}
	if TrustAnchorResolutionTarget(req, "other", "vical") {
		t.Error("subject.id must name the registry")
	}
	if TrustAnchorResolutionTarget(req, "iaca", "rical") {
		t.Error("type not enabled")
	}
	req.Resource = authzen.Resource{Type: "x5c", Key: []interface{}{"x"}}
	if TrustAnchorResolutionTarget(req, "iaca", "vical") {
		t.Error("a full evaluation is not a preload")
	}
}

func TestPolicyConstraintsValidate_TrustAnchors(t *testing.T) {
	if err := (PolicyConstraints{ReturnTrustAnchors: []string{"vical", "rical"}}).Validate(); err != nil {
		t.Error(err)
	}
	if err := (PolicyConstraints{ReturnTrustAnchors: []string{"lote"}}).Validate(); err == nil {
		t.Error("unknown type must be rejected")
	}
}

// An aggregate waits for its slowest child, and the client counts ttl_seconds
// from receipt: the merge must shrink the ttl by the time already spent and
// drop a set that has run out.
func TestMergeTrustAnchors_RecomputesTTLFromDeadline(t *testing.T) {
	now := time.Now()
	child := func(registry string, left time.Duration) *authzen.EvaluationResponse {
		return &authzen.EvaluationResponse{Decision: true, Context: &authzen.EvaluationResponseContext{
			TrustAnchors: []authzen.TrustAnchorSet{{
				Registry: registry, Type: authzen.TrustAnchorTypeVICAL, TTLSeconds: 600,
				ExpiresAt: now.Add(left), Anchors: []authzen.TrustAnchor{{X5C: "x"}},
			}},
		}}
	}
	resp := &authzen.EvaluationResponse{Decision: true}
	mergeTrustAnchors(resp, []*authzen.EvaluationResponse{child("fresh", 100*time.Second), child("spent", -time.Second), child("nearly", 500*time.Millisecond)})
	sets := resp.Context.TrustAnchors
	if len(sets) != 1 || sets[0].Registry != "fresh" {
		t.Fatalf("expired and sub-second sets must be dropped: %+v", sets)
	}
	if sets[0].TTLSeconds > 100 || sets[0].TTLSeconds < 98 {
		t.Errorf("ttl_seconds=%d, want about 100 (the deadline), not the child's 600", sets[0].TTLSeconds)
	}
}

// Only OR composites export anchors: a client holding one child's list cannot
// reproduce an AND, majority or quorum requirement.
func TestComposite_TrustAnchorsOnlyUnderOR(t *testing.T) {
	req := &authzen.EvaluationRequest{
		Subject:  authzen.Subject{Type: "key", ID: "x"},
		Resource: authzen.Resource{Type: "x5c", ID: "x"},
		Context:  map[string]interface{}{authzen.TrustAnchorsPolicyContextKey: []string{"vical"}},
	}
	child := func(name string) TrustRegistry {
		return &anchorRegistry{&mockRegistry{name: name, resourceTypes: []string{"x5c"}, healthy: true}}
	}
	for _, op := range []LogicOperator{LogicOR, LogicAND, LogicMAJORITY} {
		c := NewCompositeRegistry("c", op, child("a"), child("b"))
		resp, err := c.Evaluate(context.Background(), req)
		if err != nil || !resp.Decision {
			t.Fatalf("%s: %v %+v", op, err, resp)
		}
		got := 0
		if resp.Context != nil {
			got = len(resp.Context.TrustAnchors)
		}
		if (op == LogicOR) != (got > 0) {
			t.Errorf("%s: %d sets exported", op, got)
		}
	}
}
