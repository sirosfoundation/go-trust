package etsi

import (
	"crypto/x509"
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

// A fresh TSL that is only reachable through a lapsed list is not trusted.
func TestReachable_NeedsCurrentAncestors(t *testing.T) {
	now := time.Date(2026, 12, 1, 0, 0, 0, 0, time.UTC)
	r := &TSLRegistry{config: TSLConfig{Now: func() time.Time { return now }}}

	leaf := tslWithNextUpdate("leaf", "2027-01-01T00:00:00Z")
	mid := tslWithNextUpdate("mid", "2026-11-01T00:00:00Z") // lapsed
	mid.Referenced = []*etsi119612.TSL{leaf}
	root := tslWithNextUpdate("root", "2027-01-01T00:00:00Z")
	root.Referenced = []*etsi119612.TSL{mid}

	got := r.reachable(root)
	if assert.Len(t, got, 1) {
		assert.Equal(t, "root", got[0].Source)
	}

	mid.Referenced = []*etsi119612.TSL{leaf}
	mid.StatusList.TslSchemeInformation.TslNextUpdate.DateTime = "2027-01-01T00:00:00Z"
	assert.Len(t, r.reachable(root), 3)

	root.StatusList.TslSchemeInformation.TslNextUpdate.DateTime = "2026-11-01T00:00:00Z"
	assert.Empty(t, r.reachable(root), "a lapsed root takes its descendants with it")

	// A reference cycle terminates.
	root.StatusList.TslSchemeInformation.TslNextUpdate.DateTime = "2027-01-01T00:00:00Z"
	leaf.Referenced = []*etsi119612.TSL{root}
	assert.Len(t, r.reachable(root), 3)
}

// PEM bundle anchors keep counting, and keep the registry healthy, after every
// TSL has lapsed.
func TestExpireStale_KeepsBundleCount(t *testing.T) {
	now := time.Date(2026, 12, 1, 0, 0, 0, 0, time.UTC)
	root := tslWithNextUpdate("root", "2026-12-02T00:00:00Z")
	r := &TSLRegistry{
		config:      TSLConfig{Now: func() time.Time { return now }},
		certPool:    x509.NewCertPool(),
		bundlePool:  x509.NewCertPool(),
		bundleCount: 2,
		certCount:   2,
		tsls:        []*etsi119612.TSL{root},
		roots:       []*etsi119612.TSL{root},
		nextExpiry:  time.Date(2026, 12, 2, 0, 0, 0, 0, time.UTC),
		healthy:     true,
	}
	now = now.Add(48 * time.Hour)
	r.expireStale()
	assert.Equal(t, 2, r.CertificateCount())
	assert.Zero(t, r.TSLCount())
	assert.True(t, r.Healthy())
}
