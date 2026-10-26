package lote

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/sirosfoundation/g119612/pkg/etsi119602"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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

func lotlWithPointers(nextUpdate string, ptrs ...etsi119602.OtherLoTEPointer) *etsi119602.ListOfTrustedLists {
	return &etsi119602.ListOfTrustedLists{
		ListAndSchemeInformation: etsi119602.ListAndSchemeInformation{
			LoTEVersionIdentifier: 1,
			SchemeTerritory:       "EU",
			LoTEType:              etsi119602.LoTLTypeEU,
			SchemeOperatorName:    etsi119602.NameSet{{Lang: "en", Value: "EU Commission"}},
			ListIssueDateTime:     "2026-01-01T00:00:00Z",
			NextUpdate:            nextUpdate,
			PointersToOtherLoTE:   ptrs,
		},
	}
}

// The LoTL, and any nested LoTL, decides which LoTEs are loaded, so their
// deadlines bound the registry as well as the child LoTEs' own.
func TestFreshness_IncludesFollowedLoTLs(t *testing.T) {
	dir := t.TempDir()
	child := minimalLoTE("SE", simpleEntity("https://se-pid.example.com"))
	child.ListAndSchemeInformation.NextUpdate = "2027-06-01T00:00:00Z"
	childPath := writeLoTE(t, dir, "child.json", child)

	nested := writeLoTL(t, dir, "nested.json", lotlWithPointers("2026-12-01T00:00:00Z",
		lotlPointer(childPath, etsi119602.LoTETypePIDProviders, "SE")))
	top := func(nextUpdate string) string {
		return writeLoTL(t, dir, "top-"+nextUpdate+".json", lotlWithPointers(nextUpdate,
			lotlPointer(nested, etsi119602.LoTLTypeEU, "EU")))
	}

	t.Run("earliest of parent, nested and LoTE", func(t *testing.T) {
		r, err := New(Config{LoTLSources: []string{top("2026-11-01T00:00:00Z")}})
		require.NoError(t, err)
		assert.True(t, r.Freshness().NextUpdate.Equal(time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)),
			"parent due before the child must not be hidden by the child's later date")
	})
	t.Run("nested LoTL earlier than parent", func(t *testing.T) {
		r, err := New(Config{LoTLSources: []string{top("2027-03-01T00:00:00Z")}})
		require.NoError(t, err)
		assert.True(t, r.Freshness().NextUpdate.Equal(time.Date(2026, 12, 1, 0, 0, 0, 0, time.UTC)))
	})
	t.Run("undated parent is unknown", func(t *testing.T) {
		r, err := New(Config{LoTLSources: []string{top("")}})
		require.NoError(t, err)
		assert.True(t, r.Freshness().NextUpdate.IsZero())
	})
}

func TestFreshness_UnknownWithNationalRegisterFallback(t *testing.T) {
	dir := t.TempDir()
	l := minimalLoTE("SE", simpleEntity("https://se.example.com"))
	l.ListAndSchemeInformation.NextUpdate = "2027-06-01T00:00:00Z"
	path := writeLoTE(t, dir, "l.json", l)

	r, err := New(Config{Sources: []string{path}})
	require.NoError(t, err)
	assert.False(t, r.Freshness().NextUpdate.IsZero(), "without the fallback the LoTE date applies")

	r, err = New(Config{Sources: []string{path}, RegisterClient: &stubRegisterClient{}})
	require.NoError(t, err)
	f := r.Freshness()
	assert.True(t, f.NextUpdate.IsZero(), "register data has no freshness contract")
	assert.False(t, f.AsOf.IsZero())
}

// A pointer target that fails to load leaves its entities out of the registry;
// a denial for one of them can flip when fetching recovers.
func TestFreshness_UnknownWhenPointerTargetFailsToLoad(t *testing.T) {
	dir := t.TempDir()
	child := minimalLoTE("SE", simpleEntity("https://se-pid.example.com"))
	child.ListAndSchemeInformation.NextUpdate = "2099-06-01T00:00:00Z"
	childPath := writeLoTE(t, dir, "child.json", child)

	good := lotlWithPointers("2099-01-01T00:00:00Z", lotlPointer(childPath, etsi119602.LoTETypePIDProviders, "SE"))
	r, err := New(Config{LoTLSources: []string{writeLoTL(t, dir, "good.json", good)}})
	require.NoError(t, err)
	assert.False(t, r.Freshness().NextUpdate.IsZero())

	bad := lotlWithPointers("2099-01-01T00:00:00Z",
		lotlPointer(childPath, etsi119602.LoTETypePIDProviders, "SE"),
		lotlPointer(filepath.Join(dir, "missing.json"), etsi119602.LoTETypePIDProviders, "DE"))
	r, err = New(Config{LoTLSources: []string{writeLoTL(t, dir, "bad.json", bad)}})
	require.NoError(t, err)
	assert.True(t, r.Freshness().NextUpdate.IsZero())
}
