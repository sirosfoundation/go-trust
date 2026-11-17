package registry

import "github.com/sirosfoundation/go-trust/pkg/authzen"

// mergeDisplayName carries a child registry's display_name (#249) onto an
// aggregated response. The strategies that combine several registries build a
// fresh context out of the children's results, so without this the name is
// dropped before it reaches the wallet even when exactly one registry named
// the trust subject.
//
// Only an unambiguous name travels. When the agreeing children carry more than
// one distinct name the aggregate has no single subject to label, so it stays
// unnamed: display_name overrides the verifier's own label downstream, and
// presenting one of several disagreeing names would suppress the right one.
// Absence is a supported outcome — the wallet falls back to its own label
// chain — and a name only a denying child carried never travels at all,
// because children is the set that agreed with the decision.
func mergeDisplayName(resp *authzen.EvaluationResponse, children []*authzen.EvaluationResponse) {
	if resp == nil || !resp.Decision {
		return
	}

	name := ""
	for _, c := range children {
		if c == nil || !c.Decision || c.Context == nil || c.Context.DisplayName == "" {
			continue
		}
		if name != "" && c.Context.DisplayName != name {
			return
		}
		name = c.Context.DisplayName
	}
	if name == "" {
		return
	}

	if resp.Context == nil {
		resp.Context = &authzen.EvaluationResponseContext{}
	}
	resp.Context.DisplayName = name
}
