package mdocrical

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestFreshness(t *testing.T) {
	assert.True(t, (&Registry{}).Freshness().AsOf.IsZero(), "nothing fetched yet is unknown")

	fetched := time.Date(2026, 10, 19, 12, 0, 0, 0, time.UTC)
	r := &Registry{cache: &cachedRical{rical: &RICAL{NextUpdate: "2026-10-26T00:00:00Z"}, fetchedAt: fetched}}
	f := r.Freshness()
	assert.True(t, f.AsOf.Equal(fetched))
	assert.True(t, f.NextUpdate.Equal(time.Date(2026, 10, 26, 0, 0, 0, 0, time.UTC)))

	r = &Registry{cache: &cachedRical{rical: &RICAL{}, fetchedAt: fetched}}
	assert.True(t, r.Freshness().NextUpdate.IsZero(), "RICAL without nextUpdate has no bound")
}
