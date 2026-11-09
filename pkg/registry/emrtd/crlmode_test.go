package emrtd

import (
	"crypto/x509"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// crlAt builds a CRL signed by signer under signer's own name with the given
// validity window, revoking the given certificates.
func crlAt(t *testing.T, signer *node, this, next time.Time, revoked ...*node) []byte {
	t.Helper()
	var entries []x509.RevocationListEntry
	for _, n := range revoked {
		entries = append(entries, x509.RevocationListEntry{SerialNumber: n.cert.SerialNumber, RevocationTime: t2020})
	}
	der, err := x509.CreateRevocationList(testRand{}, &x509.RevocationList{
		Number: big.NewInt(1), ThisUpdate: this, NextUpdate: next, RevokedCertificateEntries: entries,
	}, signer.cert, signer.key.ec)
	require.NoError(t, err)
	return der
}

// regWithCRLs loads the anchors and writes each CRL under crls_dir/<country>.
func regWithCRLs(t *testing.T, anchors map[string][]*node, crls map[string][][]byte) *Registry {
	t.Helper()
	ad, cd := t.TempDir(), t.TempDir()
	writeAnchors(t, ad, anchors)
	for country, list := range crls {
		require.NoError(t, os.MkdirAll(filepath.Join(cd, country), 0o755))
		for i, b := range list {
			require.NoError(t, os.WriteFile(filepath.Join(cd, country, string(rune('a'+i))+".crl"), b, 0o644))
		}
	}
	r, err := New(Config{AnchorsDir: ad, CRLsDir: cd, Logger: quietLogger(), Now: func() time.Time { return tNow }})
	require.NoError(t, err)
	t.Cleanup(func() { _ = r.Close() })
	return r
}

func crlCtx(extra map[string]interface{}) map[string]interface{} {
	c := map[string]interface{}{ctxCRLMode: CRLModeRequireCurrent}
	for k, v := range extra {
		c[k] = v
	}
	return c
}

func TestEvaluate_CRLRequireCurrent(t *testing.T) {
	csca := newCSCA(t, kindP256, "CSCA", "SE")
	dsc := newDSC(t, kindP256, csca, "SE")
	stranger := newCSCA(t, kindP256, "CSCA", "SE") // same name, key not anchored
	otherName := newCSCA(t, kindP256, "Other CSCA", "SE")

	fresh := crlAt(t, csca, tNow.Add(-24*time.Hour), tNow.Add(24*time.Hour))
	stale := crlAt(t, csca, tNow.Add(-72*time.Hour), tNow.Add(-24*time.Hour))
	old := crlAt(t, csca, tNow.Add(-10*24*time.Hour), tNow.Add(24*time.Hour)) // not past nextUpdate, but old
	anchors := map[string][]*node{"SWE": {csca}}

	type tc struct {
		name string
		crls [][]byte
		ctx  map[string]interface{}
		want string // "" = allow
	}
	for _, c := range []tc{
		{"default mode, no CRL: allowed (unchanged)", nil, nil, ""},
		{"default mode, stale CRL: allowed (unchanged)", [][]byte{stale}, nil, ""},
		{"explicit best-effort, no CRL: allowed", nil, map[string]interface{}{ctxCRLMode: CRLModeBestEffort}, ""},
		{"require-current, current CRL: allowed", [][]byte{fresh}, crlCtx(nil), ""},
		{"require-current, no CRL: unavailable", nil, crlCtx(nil), CodeCRLUnavailable},
		{"require-current, stale CRL: stale", [][]byte{stale}, crlCtx(nil), CodeCRLStale},
		{"require-current, stale and current CRL: allowed", [][]byte{stale, fresh}, crlCtx(nil), ""},
		{"max age exceeded: stale", [][]byte{old}, crlCtx(map[string]interface{}{ctxCRLMaxAge: "168h"}), CodeCRLStale},
		{"within max age: allowed", [][]byte{old}, crlCtx(map[string]interface{}{ctxCRLMaxAge: "240h"}), ""},
		{"no max age: nextUpdate only", [][]byte{old}, crlCtx(nil), ""},
		{"CRL not signed by the issuer is not coverage", [][]byte{crlAt(t, stranger, tNow.Add(-time.Hour), tNow.Add(time.Hour))}, crlCtx(nil), CodeCRLUnavailable},
		{"CRL of another issuer name is not coverage", [][]byte{crlAt(t, otherName, tNow.Add(-time.Hour), tNow.Add(time.Hour))}, crlCtx(nil), CodeCRLUnavailable},
		{"CRL from the future is not current", [][]byte{crlAt(t, csca, tNow.Add(time.Hour), tNow.Add(48*time.Hour))}, crlCtx(nil), CodeCRLStale},
		{"revoked beats stale", [][]byte{crlAt(t, csca, tNow.Add(-72*time.Hour), tNow.Add(-24*time.Hour), dsc)}, crlCtx(nil), CodeRevoked},
		{"revoked beats unavailable-free current", [][]byte{crlAt(t, csca, tNow.Add(-time.Hour), tNow.Add(time.Hour), dsc)}, crlCtx(nil), CodeRevoked},
	} {
		t.Run(c.name, func(t *testing.T) {
			crls := map[string][][]byte{}
			if c.crls != nil {
				crls["SWE"] = c.crls
			}
			r := regWithCRLs(t, anchors, crls)
			resp := eval(t, r, req("SWE", []*node{dsc}, c.ctx))
			if c.want == "" {
				require.True(t, resp.Decision, "%v", resp.Context.Reason)
				return
			}
			requireDeny(t, resp, c.want)
		})
	}
}

func TestEvaluate_CRLRequireCurrent_EveryIssuerOnPath(t *testing.T) {
	// anchor -> link -> DSC: the link's CRL covers the DSC, the anchor's CRL
	// covers the link. Both must be current.
	f := newPathLenFixture(t, nil, false)
	chain := []*node{f.dsc, f.link}
	fresh := func(signer *node) []byte { return crlAt(t, signer, tNow.Add(-time.Hour), tNow.Add(time.Hour)) }
	stale := func(signer *node) []byte { return crlAt(t, signer, tNow.Add(-48*time.Hour), tNow.Add(-24*time.Hour)) }
	anchors := map[string][]*node{"SWE": {f.anchor}}

	t.Run("both current", func(t *testing.T) {
		r := regWithCRLs(t, anchors, map[string][][]byte{"SWE": {fresh(f.link), fresh(f.anchor)}})
		require.True(t, eval(t, r, req("SWE", chain, crlCtx(nil))).Decision)
	})
	t.Run("only the DSC issuer has a CRL", func(t *testing.T) {
		r := regWithCRLs(t, anchors, map[string][][]byte{"SWE": {fresh(f.link)}})
		resp := eval(t, r, req("SWE", chain, crlCtx(nil)))
		requireDeny(t, resp, CodeCRLUnavailable)
		assert.Contains(t, resp.Context.Reason["error"], "CSCA old")
	})
	t.Run("link issuer CRL stale", func(t *testing.T) {
		r := regWithCRLs(t, anchors, map[string][][]byte{"SWE": {fresh(f.link), stale(f.anchor)}})
		requireDeny(t, eval(t, r, req("SWE", chain, crlCtx(nil))), CodeCRLStale)
	})
	t.Run("best-effort ignores the missing one", func(t *testing.T) {
		r := regWithCRLs(t, anchors, map[string][][]byte{"SWE": {fresh(f.link)}})
		require.True(t, eval(t, r, req("SWE", chain, nil)).Decision)
	})
}

func TestEvaluate_CRLRequireCurrent_CountryScope(t *testing.T) {
	cscaSE := newCSCA(t, kindP256, "CSCA", "SE")
	dscSE := newDSC(t, kindP256, cscaSE, "SE")
	cscaDE := newCSCA(t, kindP256, "CSCA", "DE")
	dscDE := newDSC(t, kindP256, cscaDE, "DE")
	r := newReg(t, map[string][]*node{"SWE": {cscaSE}, "DEU": {cscaDE}}) // no CRLs at all

	list := func(c ...string) []interface{} {
		out := make([]interface{}, len(c))
		for i, s := range c {
			out[i] = s
		}
		return out
	}
	t.Run("everywhere by default", func(t *testing.T) {
		requireDeny(t, eval(t, r, req("SWE", []*node{dscSE}, crlCtx(nil))), CodeCRLUnavailable)
		requireDeny(t, eval(t, r, req("DEU", []*node{dscDE}, crlCtx(nil))), CodeCRLUnavailable)
	})
	t.Run("crl_countries limits the requirement", func(t *testing.T) {
		ctx := crlCtx(map[string]interface{}{ctxCRLCountries: list("SWE")})
		requireDeny(t, eval(t, r, req("SWE", []*node{dscSE}, ctx)), CodeCRLUnavailable)
		require.True(t, eval(t, r, req("DEU", []*node{dscDE}, ctx)).Decision)
	})
	t.Run("crl_exempt_countries exempts", func(t *testing.T) {
		ctx := crlCtx(map[string]interface{}{ctxCRLExemptCountries: []string{"DEU"}})
		requireDeny(t, eval(t, r, req("SWE", []*node{dscSE}, ctx)), CodeCRLUnavailable)
		require.True(t, eval(t, r, req("DEU", []*node{dscDE}, ctx)).Decision)
	})
}

func TestEvaluate_CRLContextMalformed(t *testing.T) {
	csca := newCSCA(t, kindP256, "CSCA", "SE")
	dsc := newDSC(t, kindP256, csca, "SE")
	r := newReg(t, map[string][]*node{"SWE": {csca}})
	for name, ctx := range map[string]map[string]interface{}{
		"mode not a string":     {ctxCRLMode: 1},
		"unknown mode":          {ctxCRLMode: "strict"},
		"wrong case":            {ctxCRLMode: "Require-Current"},
		"max age not a string":  crlCtx(map[string]interface{}{ctxCRLMaxAge: 168}),
		"max age not parseable": crlCtx(map[string]interface{}{ctxCRLMaxAge: "a week"}),
		"max age negative":      crlCtx(map[string]interface{}{ctxCRLMaxAge: "-1h"}),
		"countries not a list":  crlCtx(map[string]interface{}{ctxCRLCountries: "SWE"}),
		"exempt not strings":    crlCtx(map[string]interface{}{ctxCRLExemptCountries: []interface{}{1}}),
	} {
		t.Run(name, func(t *testing.T) {
			// A malformed control must deny, never fall back to best-effort
			// (which would allow this document signer).
			requireDeny(t, eval(t, r, req("SWE", []*node{dsc}, ctx)), CodeMalformedRequest)
		})
	}
}

func TestCRLCollector(t *testing.T) {
	csca := newCSCA(t, kindP256, "CSCA", "SE")
	r := regWithCRLs(t, map[string][]*node{"SWE": {csca}}, map[string][][]byte{"SWE": {
		crlAt(t, csca, tNow.Add(-48*time.Hour), tNow.Add(-24*time.Hour)),
		crlAt(t, csca, tNow.Add(-6*time.Hour), tNow.Add(18*time.Hour)),
	}})
	want := `
# HELP go_trust_emrtd_crl_age_seconds Seconds since thisUpdate of the newest loaded CRL per issuing state
# TYPE go_trust_emrtd_crl_age_seconds gauge
go_trust_emrtd_crl_age_seconds{country="SWE"} 21600
# HELP go_trust_emrtd_crl_count Number of loaded CRLs per issuing state
# TYPE go_trust_emrtd_crl_count gauge
go_trust_emrtd_crl_count{country="SWE"} 2
# HELP go_trust_emrtd_crl_next_update_timestamp_seconds Unix time of the latest nextUpdate among the loaded CRLs per issuing state (0 if none sets one)
# TYPE go_trust_emrtd_crl_next_update_timestamp_seconds gauge
go_trust_emrtd_crl_next_update_timestamp_seconds{country="SWE"} ` + itoa(tNow.Add(18*time.Hour).Unix()) + `
`
	require.NoError(t, testutil.CollectAndCompare(r.Collector(), strings.NewReader(want)))

	// A registry without CRLs exports nothing rather than zeros.
	require.Zero(t, testutil.CollectAndCount(newReg(t, map[string][]*node{"SWE": {csca}}).Collector()))
}

func itoa(n int64) string { return big.NewInt(n).String() }
