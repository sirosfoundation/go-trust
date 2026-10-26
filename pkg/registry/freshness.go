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
// dateTime, VICAL/RICAL tdate). The value must carry an explicit UTC offset
// (RFC 3339). An empty, unparseable or offset-free value yields the zero time,
// i.e. "unknown": freshness must never be invented, and assuming a zone for an
// offset-free value could report a deadline later than the source meant.
func ParseSourceTime(s string) time.Time {
	t, err := time.Parse(time.RFC3339Nano, s) // also accepts RFC 3339 without fractional seconds
	if err != nil {
		return time.Time{}
	}
	return t.UTC()
}

// CachedFreshness builds the Freshness of a list fetched at fetchedAt and held
// for ttl. The nextUpdate string is unknown unless it parses (see
// ParseSourceTime). Once the cache has outlived ttl the next evaluation must
// refetch; if that fails the registry keeps the old list and denies, and the
// denial can flip as soon as fetching recovers, so an expired cache reports
// nothing.
func CachedFreshness(fetchedAt time.Time, ttl time.Duration, nextUpdate string) Freshness {
	if ttl > 0 && time.Since(fetchedAt) >= ttl {
		return Freshness{}
	}
	return Freshness{AsOf: fetchedAt, NextUpdate: ParseSourceTime(nextUpdate)}
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

// trustDatum is one registry's freshness at a point in time. The times keep
// full precision so two snapshots are compared exactly, not as the rounded
// strings sent on the wire.
type trustDatum struct {
	name       string
	asOf, next time.Time
}

func (d trustDatum) same(o trustDatum) bool {
	return d.name == o.name && d.asOf.Equal(o.asOf) && d.next.Equal(o.next)
}

// collectTrustData appends one entry per leaf registry under reg. A composite
// contributes its children, not itself.
func collectTrustData(reg TrustRegistry, out []trustDatum) []trustDatum {
	if c, ok := reg.(*CompositeRegistry); ok {
		for _, child := range c.registries {
			out = collectTrustData(child, out)
		}
		return out
	}
	d := trustDatum{name: reg.Info().Name}
	if fr, ok := reg.(FreshnessReporter); ok {
		f := fr.Freshness()
		d.asOf, d.next = f.AsOf, f.NextUpdate
	}
	return append(out, d)
}

// trustDataSnapshot returns the current freshness of every registry in regs.
func trustDataSnapshot(regs []TrustRegistry) []trustDatum {
	var data []trustDatum
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
func attachTrustData(resp *authzen.EvaluationResponse, before, after []trustDatum) *authzen.EvaluationResponse {
	if resp == nil || len(after) == 0 {
		return resp
	}
	data := make([]authzen.TrustData, len(after))
	for i, a := range after {
		data[i] = authzen.TrustData{Registry: a.name}
		if len(before) != len(after) || !before[i].same(a) {
			continue
		}
		if !a.asOf.IsZero() {
			data[i].AsOf = a.asOf.UTC().Format(time.RFC3339)
		}
		if !a.next.IsZero() {
			data[i].NextUpdate = a.next.UTC().Format(time.RFC3339)
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
