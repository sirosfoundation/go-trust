package vical

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestFreshness(t *testing.T) {
	assert.True(t, (&Registry{config: &Config{CacheTTL: time.Hour}}).Freshness().AsOf.IsZero(), "nothing fetched yet is unknown")

	fetched := time.Now().Add(-time.Minute)
	r := &Registry{config: &Config{CacheTTL: time.Hour}, cache: &cachedVical{vical: &VICAL{NextUpdate: "2026-10-26T00:00:00Z"}, fetchedAt: fetched}}
	f := r.Freshness()
	assert.True(t, f.AsOf.Equal(fetched))
	assert.True(t, f.NextUpdate.Equal(time.Date(2026, 10, 26, 0, 0, 0, 0, time.UTC)))

	r = &Registry{config: &Config{CacheTTL: time.Hour}, cache: &cachedVical{vical: &VICAL{}, fetchedAt: fetched}}
	assert.True(t, r.Freshness().NextUpdate.IsZero(), "VICAL without nextUpdate has no bound")
}

// Once the cache has outlived its TTL the next evaluation refetches. If that
// fails the old list stays and the denial can flip when fetching recovers, so
// the old list's dates must not be reported.
func TestFreshness_ExpiredCacheIsUnknown(t *testing.T) {
	fetched := time.Now().Add(-2 * time.Hour)
	r := &Registry{config: &Config{CacheTTL: time.Hour}, cache: &cachedVical{vical: &VICAL{NextUpdate: "2099-01-01T00:00:00Z"}, fetchedAt: fetched}}
	f := r.Freshness()
	assert.True(t, f.AsOf.IsZero())
	assert.True(t, f.NextUpdate.IsZero())
}

// The registry treats a cache as fresh only while time since fetch < CacheTTL,
// so a negative TTL means every evaluation refetches: never fresh.
func TestFreshness_NonPositiveTTLIsUnknown(t *testing.T) {
	for _, ttl := range []time.Duration{0, -time.Hour} {
		r := &Registry{config: &Config{CacheTTL: ttl}, cache: &cachedVical{vical: &VICAL{NextUpdate: "2099-01-01T00:00:00Z"}, fetchedAt: time.Now()}}
		assert.True(t, r.Freshness().NextUpdate.IsZero(), "ttl %v", ttl)
	}
}
