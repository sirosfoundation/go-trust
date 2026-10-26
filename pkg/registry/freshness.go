package registry

import (
	"time"

	"github.com/sirosfoundation/go-trust/pkg/authzen"
)

// Freshness describes how current a registry's data is. A zero field means
// unknown or not applicable.
type Freshness struct {
	// AsOf is when the data was last loaded.
	AsOf time.Time
	// NextUpdate is when the source says it will next be replaced.
	NextUpdate time.Time
}

// FreshnessReporter is implemented by registries that know how fresh their data
// is. It is optional: a registry without it is reported with no as_of and no
// next_update, which a caller must read as "unknown".
type FreshnessReporter interface {
	Freshness() Freshness
}

// ParseSourceTime parses a timestamp from a trust-data source (ETSI
// dateTime, VICAL/RICAL tdate). An empty or unparseable value yields the zero
// time, i.e. "unknown": freshness must never be invented.
func ParseSourceTime(s string) time.Time {
	if s == "" {
		return time.Time{}
	}
	for _, layout := range []string{time.RFC3339Nano, time.RFC3339, "2006-01-02T15:04:05", "2006-01-02"} {
		if t, err := time.Parse(layout, s); err == nil {
			return t.UTC()
		}
	}
	return time.Time{}
}

// EarliestKnown returns the earliest of the times, or the zero time (unknown)
// when there are none or any of them is unknown. A registry that holds several
// lists can decide from any of them, so it is only as fresh as its
// soonest-expiring list, and unknown if any list is.
func EarliestKnown(times ...time.Time) time.Time {
	var earliest time.Time
	for _, t := range times {
		if t.IsZero() {
			return time.Time{}
		}
		if earliest.IsZero() || t.Before(earliest) {
			earliest = t
		}
	}
	return earliest
}

// collectTrustData appends one TrustData entry per leaf registry under reg.
// A composite contributes its children, not itself.
func collectTrustData(reg TrustRegistry, out []authzen.TrustData) []authzen.TrustData {
	if c, ok := reg.(*CompositeRegistry); ok {
		for _, child := range c.registries {
			out = collectTrustData(child, out)
		}
		return out
	}
	td := authzen.TrustData{Registry: reg.Info().Name}
	if fr, ok := reg.(FreshnessReporter); ok {
		f := fr.Freshness()
		if !f.AsOf.IsZero() {
			td.AsOf = f.AsOf.UTC().Format(time.RFC3339)
		}
		if !f.NextUpdate.IsZero() {
			td.NextUpdate = f.NextUpdate.UTC().Format(time.RFC3339)
		}
	}
	return append(out, td)
}

// trustDataSnapshot returns the current freshness of every registry in regs.
func trustDataSnapshot(regs []TrustRegistry) []authzen.TrustData {
	var data []authzen.TrustData
	for _, r := range regs {
		data = collectTrustData(r, data)
	}
	return data
}

// attachTrustData returns a copy of resp whose context carries the freshness of
// every registry that could have contributed to the decision. The copy matters:
// registries may hand back a response they also keep.
//
// before and after are snapshots taken around the evaluation. A registry may
// reload while it is being evaluated, and its freshness is read outside its own
// lock, so an entry is only reported when both snapshots agree; otherwise the
// data the decision used cannot be told apart from the data now loaded, and the
// entry carries no as_of or next_update (unknown).
//
// The set is the policy-filtered applicable registries, not only those that
// answered first. For a first-match allow that can name a registry that was not
// reached, which only makes the reported bound earlier, never later.
func attachTrustData(resp *authzen.EvaluationResponse, before, after []authzen.TrustData) *authzen.EvaluationResponse {
	if resp == nil || len(after) == 0 {
		return resp
	}
	data := make([]authzen.TrustData, len(after))
	for i, a := range after {
		data[i] = a
		if len(before) != len(after) || before[i] != a {
			data[i] = authzen.TrustData{Registry: a.Registry}
		}
	}
	out := *resp
	var ctx authzen.EvaluationResponseContext
	if resp.Context != nil {
		ctx = *resp.Context
	}
	ctx.TrustData = data
	out.Context = &ctx
	return &out
}
