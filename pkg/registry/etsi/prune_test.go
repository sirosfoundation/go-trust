package etsi

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/sirosfoundation/g119612/pkg/etsi119612"
)

func tslWithNextUpdate(source, next string) *etsi119612.TSL {
	tsl := &etsi119612.TSL{Source: source}
	tsl.StatusList.TslSchemeInformation = &etsi119612.TSLSchemeInformationType{
		TslNextUpdate: &etsi119612.NextUpdateType{DateTime: next},
	}
	return tsl
}

// A stale referenced TSL must also leave the Referenced list of the TSLs that
// point to it, or filtered evaluation would still trust its certificates.
func TestPrune_RemovesStaleReferences(t *testing.T) {
	now := time.Date(2026, 12, 1, 0, 0, 0, 0, time.UTC)
	r := &TSLRegistry{config: TSLConfig{Now: func() time.Time { return now }}}

	fresh := tslWithNextUpdate("fresh", "2027-01-01T00:00:00Z")
	stale := tslWithNextUpdate("stale", "2026-11-01T00:00:00Z")
	parent := tslWithNextUpdate("parent", "2027-01-01T00:00:00Z")
	parent.Referenced = []*etsi119612.TSL{fresh, stale}

	got := r.prune(parent)
	if assert.NotNil(t, got) && assert.Len(t, got.Referenced, 1) {
		assert.Equal(t, "fresh", got.Referenced[0].Source)
	}
	assert.Len(t, parent.Referenced, 2, "the loaded TSL must not be modified in place")

	assert.Nil(t, r.prune(stale))

	parent.Referenced = nil
	assert.Equal(t, time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC), earliestDeadline([]*etsi119612.TSL{parent, fresh}))
}
