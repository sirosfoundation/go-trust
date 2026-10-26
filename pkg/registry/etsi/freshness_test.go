package etsi

import (
	"testing"
	"time"

	"github.com/sirosfoundation/g119612/pkg/etsi119612"
	"github.com/stretchr/testify/assert"
)

func tslWithNextUpdate(dt string) *etsi119612.TSL {
	tsl := &etsi119612.TSL{}
	tsl.StatusList.TslSchemeInformation = &etsi119612.TSLSchemeInformationType{}
	if dt != "" {
		tsl.StatusList.TslSchemeInformation.TslNextUpdate = &etsi119612.NextUpdateType{DateTime: dt}
	}
	return tsl
}

func TestFreshness(t *testing.T) {
	loaded := time.Date(2026, 10, 19, 12, 0, 0, 0, time.UTC)

	r := &TSLRegistry{loadedAt: loaded, tsls: []*etsi119612.TSL{
		tslWithNextUpdate("2026-11-01T00:00:00Z"),
		tslWithNextUpdate("2026-10-26T00:00:00Z"),
		tslWithNextUpdate(""),
		nil,
	}}
	f := r.Freshness()
	assert.True(t, f.AsOf.Equal(loaded))
	assert.True(t, f.NextUpdate.IsZero(), "one undated TSL makes the registry's NextUpdate unknown")

	r = &TSLRegistry{loadedAt: loaded, tsls: []*etsi119612.TSL{
		tslWithNextUpdate("2026-11-01T00:00:00Z"),
		tslWithNextUpdate("2026-10-26T00:00:00Z"),
		nil,
	}}
	assert.True(t, r.Freshness().NextUpdate.Equal(time.Date(2026, 10, 26, 0, 0, 0, 0, time.UTC)),
		"the registry is only as fresh as its soonest-expiring TSL")

	r = &TSLRegistry{loadedAt: loaded, tsls: []*etsi119612.TSL{tslWithNextUpdate("not a date"), tslWithNextUpdate("2026-10-26T00:00:00Z")}}
	assert.True(t, r.Freshness().NextUpdate.IsZero(), "an unparseable date is unknown")

	assert.True(t, (&TSLRegistry{loadedAt: loaded}).Freshness().NextUpdate.IsZero(), "no TSLs: no bound")
}

func TestFreshness_UnknownWithPEMBundle(t *testing.T) {
	loaded := time.Date(2026, 10, 19, 12, 0, 0, 0, time.UTC)
	tsls := []*etsi119612.TSL{tslWithNextUpdate("2026-10-26T00:00:00Z")}

	r := &TSLRegistry{loadedAt: loaded, tsls: tsls}
	assert.False(t, r.Freshness().NextUpdate.IsZero())

	// A bundle certificate can authorise a decision without any TSL.
	r = &TSLRegistry{loadedAt: loaded, tsls: tsls, config: TSLConfig{CertBundle: "/etc/ca.pem"}}
	f := r.Freshness()
	assert.True(t, f.NextUpdate.IsZero())
	assert.True(t, f.AsOf.Equal(loaded))
}
