package mdocrical

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestFreshness(t *testing.T) {
	assert.True(t, (&Registry{config: &Config{CacheTTL: time.Hour}}).Freshness().AsOf.IsZero(), "nothing fetched yet is unknown")

	fetched := time.Now().Add(-time.Minute)
	r := &Registry{config: &Config{CacheTTL: time.Hour}, cache: &cachedRical{rical: &RICAL{NextUpdate: "2026-10-26T00:00:00Z"}, fetchedAt: fetched}}
	f := r.Freshness()
	assert.True(t, f.AsOf.Equal(fetched))
	assert.True(t, f.NextUpdate.Equal(time.Date(2026, 10, 26, 0, 0, 0, 0, time.UTC)))

	r = &Registry{config: &Config{CacheTTL: time.Hour}, cache: &cachedRical{rical: &RICAL{}, fetchedAt: fetched}}
	assert.True(t, r.Freshness().NextUpdate.IsZero(), "RICAL without nextUpdate has no bound")
}

// Once the cache has outlived its TTL the next evaluation refetches. If that
// fails the old list stays and the denial can flip when fetching recovers, so
// the old list's dates must not be reported.
func TestFreshness_ExpiredCacheIsUnknown(t *testing.T) {
	fetched := time.Now().Add(-2 * time.Hour)
	r := &Registry{config: &Config{CacheTTL: time.Hour}, cache: &cachedRical{rical: &RICAL{NextUpdate: "2099-01-01T00:00:00Z"}, fetchedAt: fetched}}
	f := r.Freshness()
	assert.True(t, f.AsOf.IsZero())
	assert.True(t, f.NextUpdate.IsZero())
}
