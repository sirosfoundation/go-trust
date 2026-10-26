package lote

import (
	"testing"
	"time"

	"github.com/sirosfoundation/g119612/pkg/etsi119602"
	"github.com/stretchr/testify/assert"
)

func loteWithNextUpdate(dt string) *etsi119602.ListOfTrustedEntities {
	l := &etsi119602.ListOfTrustedEntities{}
	l.ListAndSchemeInformation.NextUpdate = dt
	return l
}

func TestFreshness(t *testing.T) {
	updated := time.Date(2026, 10, 19, 12, 0, 0, 0, time.UTC)

	r := &Registry{lastUpdated: updated, lotes: []*etsi119602.ListOfTrustedEntities{
		loteWithNextUpdate("2026-11-01T00:00:00Z"),
		loteWithNextUpdate("2026-10-26T00:00:00Z"),
		loteWithNextUpdate(""),
		nil,
	}}
	f := r.Freshness()
	assert.True(t, f.AsOf.Equal(updated))
	assert.True(t, f.NextUpdate.IsZero(), "one undated LoTE makes the registry's NextUpdate unknown")

	r = &Registry{lastUpdated: updated, lotes: []*etsi119602.ListOfTrustedEntities{
		loteWithNextUpdate("2026-11-01T00:00:00Z"),
		loteWithNextUpdate("2026-10-26T00:00:00Z"),
		nil,
	}}
	assert.True(t, r.Freshness().NextUpdate.Equal(time.Date(2026, 10, 26, 0, 0, 0, 0, time.UTC)))

	assert.True(t, (&Registry{lastUpdated: updated}).Freshness().NextUpdate.IsZero())
}
