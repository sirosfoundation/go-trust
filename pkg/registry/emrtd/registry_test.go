package emrtd

import (
	"bytes"
	"context"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"log/slog"
	"math/big"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/sirosfoundation/go-trust/pkg/authzen"
	"github.com/sirosfoundation/go-trust/pkg/registry"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newReg(t *testing.T, anchors map[string][]*node) *Registry {
	t.Helper()
	root := t.TempDir()
	writeAnchors(t, root, anchors)
	r, err := New(Config{AnchorsDir: root, Logger: quietLogger(), Now: func() time.Time { return tNow }})
	require.NoError(t, err)
	t.Cleanup(func() { _ = r.Close() })
	return r
}

func req(country string, chain []*node, ctx map[string]interface{}) *authzen.EvaluationRequest {
	keys := make([]interface{}, len(chain))
	for i, n := range chain {
		keys[i] = n.b64()
	}
	return &authzen.EvaluationRequest{
		Subject:  authzen.Subject{Type: "key", ID: country},
		Resource: authzen.Resource{Type: "x5c", ID: country, Key: keys},
		Action:   &authzen.Action{Name: ActionName},
		Context:  ctx,
	}
}

func eval(t *testing.T, r *Registry, rq *authzen.EvaluationRequest) *authzen.EvaluationResponse {
	t.Helper()
	resp, err := r.Evaluate(context.Background(), rq)
	require.NoError(t, err)
	require.NotNil(t, resp.Context)
	return resp
}

func code(resp *authzen.EvaluationResponse) string {
	c, _ := resp.Context.Reason["code"].(string)
	return c
}

func requireDeny(t *testing.T, resp *authzen.EvaluationResponse, want string) {
	t.Helper()
	require.False(t, resp.Decision, "expected deny %s, got allow: %v", want, resp.Context.Reason)
	assert.Equal(t, want, code(resp), "%v", resp.Context.Reason["error"])
	admin, ok := resp.Context.Reason["admin"].(map[string]interface{})
	require.True(t, ok)
	assert.Equal(t, want, admin["code"])
}

func TestEvaluate_Allow_KeyTypes(t *testing.T) {
	for _, tc := range []struct {
		name    string
		country string
		a2      string
		ca, dsc keyKind
	}{
		{"p256", "SWE", "SE", kindP256, kindP256},
		{"brainpool", "DEU", "DE", kindBrainpool256, kindBrainpool256},
		{"rsa-pss", "NLD", "NL", kindRSAPSS, kindRSAPSS},
		{"brainpool CSCA, p256 DSC", "FRA", "FR", kindBrainpool256, kindP256},
		{"rsa-pss CSCA, p256 DSC", "ESP", "ES", kindRSAPSS, kindP256},
	} {
		t.Run(tc.name, func(t *testing.T) {
			csca := newCSCA(t, tc.ca, "CSCA "+tc.country, tc.a2)
			dsc := newDSC(t, tc.dsc, csca, tc.a2)
			r := newReg(t, map[string][]*node{tc.country: {csca}})

			resp := eval(t, r, req(tc.country, []*node{dsc}, nil))
			require.True(t, resp.Decision, "%v", resp.Context.Reason)
			admin := resp.Context.Reason["admin"].(map[string]interface{})
			assert.Equal(t, fingerprint(csca.cert), admin["csca_sha256"])
			assert.Equal(t, fingerprint(dsc.cert), admin["dsc_sha256"])
			assert.Equal(t, csca.cert.Subject.String(), admin["csca_subject"])
			assert.Equal(t, tc.country, admin["country"])
		})
	}
}

// A brainpool subject key under an RSA-PSS signature is parsed by
// go-cryptoutil into a skeleton certificate; it must be refused explicitly.
func TestEvaluate_SkeletonCertificateRefused(t *testing.T) {
	csca := newCSCA(t, kindRSAPSS, "CSCA", "ES")
	dsc := newDSC(t, kindBrainpool256, csca, "ES")
	r := newReg(t, map[string][]*node{"ESP": {csca}})
	requireDeny(t, eval(t, r, req("ESP", []*node{dsc}, nil)), CodeMalformedRequest)

	// the same combination as an anchor is skipped at load time
	root := t.TempDir()
	writeAnchors(t, root, map[string][]*node{"ESP": {dsc}})
	r2, err := New(Config{AnchorsDir: root, Logger: quietLogger()})
	require.NoError(t, err)
	assert.Empty(t, r2.Countries())
}

func TestEvaluate_LinkCertificates(t *testing.T) {
	oldCSCA := newCSCA(t, kindP256, "CSCA old", "SE")
	newKeyPair := newKey(t, kindBrainpool256)
	rolled := issue(t, cscaSpec("CSCA new", "SE"), newKeyPair, nil)
	link := issue(t, cscaSpec("CSCA new", "SE"), newKeyPair, oldCSCA) // same key+name, signed by old CSCA
	dsc := newDSC(t, kindBrainpool256, rolled, "SE")

	t.Run("link cert in extras chains to old CSCA anchor", func(t *testing.T) {
		r := newReg(t, map[string][]*node{"SWE": {oldCSCA}})
		resp := eval(t, r, req("SWE", []*node{dsc, link}, nil))
		require.True(t, resp.Decision, "%v", resp.Context.Reason)
		admin := resp.Context.Reason["admin"].(map[string]interface{})
		assert.Equal(t, fingerprint(oldCSCA.cert), admin["csca_sha256"])
		assert.Equal(t, []string{fingerprint(link.cert)}, admin["link_sha256"])
	})
	t.Run("without the link cert the old anchor does not vouch", func(t *testing.T) {
		r := newReg(t, map[string][]*node{"SWE": {oldCSCA}})
		requireDeny(t, eval(t, r, req("SWE", []*node{dsc}, nil)), CodeNoAnchor)
	})
	t.Run("link cert as anchor", func(t *testing.T) {
		r := newReg(t, map[string][]*node{"SWE": {oldCSCA, link}})
		resp := eval(t, r, req("SWE", []*node{dsc}, nil))
		require.True(t, resp.Decision, "%v", resp.Context.Reason)
	})
	t.Run("extras in any order, unrelated extras ignored", func(t *testing.T) {
		other := newCSCA(t, kindP256, "Other", "SE")
		r := newReg(t, map[string][]*node{"SWE": {oldCSCA}})
		resp := eval(t, r, req("SWE", []*node{dsc, other, link}, nil))
		require.True(t, resp.Decision, "%v", resp.Context.Reason)
	})
	t.Run("link cert without CA basicConstraints is refused", func(t *testing.T) {
		badSpec := cscaSpec("CSCA new", "SE")
		badSpec.ca = false
		badLink := issue(t, badSpec, newKeyPair, oldCSCA)
		r := newReg(t, map[string][]*node{"SWE": {oldCSCA}})
		requireDeny(t, eval(t, r, req("SWE", []*node{dsc, badLink}, nil)), CodeChainInvalid)
	})
	t.Run("link cert whose keyUsage lacks keyCertSign is refused", func(t *testing.T) {
		badSpec := cscaSpec("CSCA new", "SE")
		badSpec.usage = usageDigitalSignature
		badLink := issue(t, badSpec, newKeyPair, oldCSCA)
		r := newReg(t, map[string][]*node{"SWE": {oldCSCA}})
		requireDeny(t, eval(t, r, req("SWE", []*node{dsc, badLink}, nil)), CodeChainInvalid)
	})
	t.Run("expired link cert at signing time", func(t *testing.T) {
		s := cscaSpec("CSCA new", "SE")
		s.notAfter = t2012
		oldLink := issue(t, s, newKeyPair, oldCSCA)
		r := newReg(t, map[string][]*node{"SWE": {oldCSCA}})
		requireDeny(t, eval(t, r, req("SWE", []*node{dsc, oldLink}, nil)), CodeExpired)
	})
}

func TestEvaluate_Country(t *testing.T) {
	sweCSCA := newCSCA(t, kindP256, "CSCA SE", "SE")
	deuCSCA := newCSCA(t, kindP256, "CSCA DE", "DE")
	sweDSC := newDSC(t, kindP256, sweCSCA, "SE")
	r := newReg(t, map[string][]*node{"SWE": {sweCSCA}, "DEU": {deuCSCA}})

	t.Run("DSC subject C disagrees with claimed state", func(t *testing.T) {
		requireDeny(t, eval(t, r, req("DEU", []*node{sweDSC}, nil)), CodeCountryMismatch)
	})
	t.Run("DSC without C chains to another state's anchor", func(t *testing.T) {
		noC := issue(t, dscSpec("DSC", ""), newKey(t, kindP256), sweCSCA)
		resp := eval(t, r, req("DEU", []*node{noC}, nil))
		requireDeny(t, resp, CodeCountryMismatch)
		// and without a C it is fine for the right state (documented leniency)
		require.True(t, eval(t, r, req("SWE", []*node{noC}, nil)).Decision)
	})
	t.Run("unknown country", func(t *testing.T) {
		for _, id := range []string{"ZZZ", "SE", "", "D", "swedenx"} {
			requireDeny(t, eval(t, r, req(id, []*node{sweDSC}, nil)), CodeUnknownCountry)
		}
	})
	t.Run("valid code but no anchors loaded", func(t *testing.T) {
		requireDeny(t, eval(t, r, req("FRA", []*node{sweDSC}, nil)), CodeUnknownCountry)
	})
	t.Run("lower case subject id is accepted", func(t *testing.T) {
		require.True(t, eval(t, r, req("swe", []*node{sweDSC}, nil)).Decision)
	})
	t.Run("same name, forged key under the anchor's subject", func(t *testing.T) {
		fake := issue(t, cscaSpec("CSCA SE", "SE"), newKey(t, kindP256), nil)
		dsc := newDSC(t, kindP256, fake, "SE")
		requireDeny(t, eval(t, r, req("SWE", []*node{dsc}, nil)), CodeChainInvalid)
	})
}

func TestEvaluate_SigningTime(t *testing.T) {
	csca := newCSCA(t, kindP256, "CSCA", "SE")
	s := dscSpec("DSC old", "SE")
	s.notBefore, s.notAfter = t2010, t2012
	oldDSC := issue(t, s, newKey(t, kindP256), csca)
	r := newReg(t, map[string][]*node{"SWE": {csca}})

	for _, tc := range []struct {
		name string
		ctx  map[string]interface{}
		want string // "" = allow
	}{
		{"valid at signing time", map[string]interface{}{"signing_time": "2011-06-01T00:00:00Z"}, ""},
		{"valid with offset form", map[string]interface{}{"signing_time": "2011-06-01T02:00:00+02:00"}, ""},
		{"expired at now (omitted)", nil, CodeExpired},
		{"expired at now (nil value)", map[string]interface{}{"signing_time": nil}, CodeExpired},
		{"expired at signing time", map[string]interface{}{"signing_time": "2013-01-01T00:00:00Z"}, CodeExpired},
		{"not yet valid at signing time", map[string]interface{}{"signing_time": "2009-01-01T00:00:00Z"}, CodeNotYetValid},
		{"malformed string", map[string]interface{}{"signing_time": "yesterday"}, CodeMalformedRequest},
		{"date only", map[string]interface{}{"signing_time": "2011-06-01"}, CodeMalformedRequest},
		{"empty string", map[string]interface{}{"signing_time": ""}, CodeMalformedRequest},
		{"comma fractional seconds", map[string]interface{}{"signing_time": "2011-06-01T00:00:00,5Z"}, CodeMalformedRequest},
		{"period fractional seconds", map[string]interface{}{"signing_time": "2011-06-01T00:00:00.5Z"}, ""},
		{"number", map[string]interface{}{"signing_time": 1306886400}, CodeMalformedRequest},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resp := eval(t, r, req("SWE", []*node{oldDSC}, tc.ctx))
			if tc.want == "" {
				require.True(t, resp.Decision, "%v", resp.Context.Reason)
				return
			}
			requireDeny(t, resp, tc.want)
		})
	}

	t.Run("CSCA not yet valid at signing time", func(t *testing.T) {
		cs := cscaSpec("CSCA young", "SE")
		cs.notBefore = time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
		young := issue(t, cs, newKey(t, kindP256), nil)
		ds := dscSpec("DSC", "SE")
		ds.notBefore = cs.notBefore
		d := issue(t, ds, newKey(t, kindP256), young)
		rr := newReg(t, map[string][]*node{"SWE": {young}})
		requireDeny(t, eval(t, rr, req("SWE", []*node{d}, map[string]interface{}{"signing_time": "2026-01-01T00:00:00Z"})), CodeNotYetValid)
	})
}

func TestEvaluate_KeyUsage(t *testing.T) {
	csca := newCSCA(t, kindP256, "CSCA", "SE")
	r := newReg(t, map[string][]*node{"SWE": {csca}})

	for _, tc := range []struct {
		name  string
		usage byte
		ok    bool
	}{
		{"digitalSignature", usageDigitalSignature, true},
		{"digitalSignature+nonRepudiation", usageDigitalSignature | 0x40, true},
		{"no keyUsage extension (lenient)", 0, true},
		{"keyCertSign only", 0x04, false},
		{"nonRepudiation only", 0x40, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := dscSpec("DSC", "SE")
			s.usage = tc.usage
			dsc := issue(t, s, newKey(t, kindP256), csca)
			resp := eval(t, r, req("SWE", []*node{dsc}, nil))
			if tc.ok {
				require.True(t, resp.Decision, "%v", resp.Context.Reason)
			} else {
				requireDeny(t, resp, CodeBadKeyUsage)
			}
		})
	}

	t.Run("CSCA presented as the DSC", func(t *testing.T) {
		// Anchored self-signed CSCA has no issuer among the anchors other than
		// itself, which is excluded: it cannot vouch for itself.
		requireDeny(t, eval(t, r, req("SWE", []*node{csca}, nil)), CodeNoAnchor)
	})
}

func TestEvaluate_UntrustedExtras(t *testing.T) {
	realCSCA := newCSCA(t, kindP256, "CSCA SE", "SE")
	r := newReg(t, map[string][]*node{"SWE": {realCSCA}})

	t.Run("attacker self-signed CSCA passed in resource.key", func(t *testing.T) {
		evil := newCSCA(t, kindP256, "CSCA SE Evil", "SE")
		dsc := newDSC(t, kindP256, evil, "SE")
		requireDeny(t, eval(t, r, req("SWE", []*node{dsc, evil}, nil)), CodeNoAnchor)
	})
	t.Run("attacker CSCA reusing the real subject name", func(t *testing.T) {
		evil := issue(t, cscaSpec("CSCA SE", "SE"), newKey(t, kindBrainpool256), nil)
		dsc := newDSC(t, kindBrainpool256, evil, "SE")
		requireDeny(t, eval(t, r, req("SWE", []*node{dsc, evil}, nil)), CodeChainInvalid)
	})
	t.Run("attacker CSCA duplicated many times", func(t *testing.T) {
		evil := newCSCA(t, kindP256, "CSCA SE Evil", "SE")
		dsc := newDSC(t, kindP256, evil, "SE")
		chain := []*node{dsc}
		for i := 0; i < 10; i++ {
			chain = append(chain, evil)
		}
		requireDeny(t, eval(t, r, req("SWE", chain, nil)), CodeNoAnchor)
	})
	t.Run("the real anchor in extras is not needed and not special", func(t *testing.T) {
		dsc := newDSC(t, kindP256, realCSCA, "SE")
		require.True(t, eval(t, r, req("SWE", []*node{dsc, realCSCA}, nil)).Decision)
	})
	t.Run("attacker intermediate signed by nobody trusted", func(t *testing.T) {
		evilRoot := newCSCA(t, kindP256, "Evil Root", "SE")
		evilMid := issue(t, cscaSpec("Evil Mid", "SE"), newKey(t, kindP256), evilRoot)
		dsc := newDSC(t, kindP256, evilMid, "SE")
		requireDeny(t, eval(t, r, req("SWE", []*node{dsc, evilMid, evilRoot}, nil)), CodeNoAnchor)
	})
}

func TestEvaluate_ChainDepthLimit(t *testing.T) {
	root := newCSCA(t, kindP256, "Root", "SE")
	parent := root
	var mids []*node
	for i := 0; i < 6; i++ {
		m := issue(t, cscaSpec(fmt.Sprintf("Mid %d", i), "SE"), newKey(t, kindP256), parent)
		mids = append(mids, m)
		parent = m
	}
	dsc := newDSC(t, kindP256, parent, "SE")
	chain := []*node{dsc}
	for i := len(mids) - 1; i >= 0; i-- {
		chain = append(chain, mids[i])
	}
	r := newReg(t, map[string][]*node{"SWE": {root}})
	requireDeny(t, eval(t, r, req("SWE", chain, nil)), CodeNoAnchor)
}

func TestEvaluate_MalformedRequests(t *testing.T) {
	csca := newCSCA(t, kindP256, "CSCA", "SE")
	dsc := newDSC(t, kindP256, csca, "SE")
	r := newReg(t, map[string][]*node{"SWE": {csca}})
	good := func() *authzen.EvaluationRequest { return req("SWE", []*node{dsc}, nil) }

	for _, tc := range []struct {
		name string
		mut  func(*authzen.EvaluationRequest)
	}{
		{"no action", func(q *authzen.EvaluationRequest) { q.Action = nil }},
		{"wrong action", func(q *authzen.EvaluationRequest) { q.Action = &authzen.Action{Name: "credential-issuer"} }},
		{"wrong resource type", func(q *authzen.EvaluationRequest) { q.Resource.Type = "jwk" }},
		{"nil key", func(q *authzen.EvaluationRequest) { q.Resource.Key = nil }},
		{"empty key", func(q *authzen.EvaluationRequest) { q.Resource.Key = []interface{}{} }},
		{"non-string entry", func(q *authzen.EvaluationRequest) { q.Resource.Key = []interface{}{42} }},
		{"bad base64", func(q *authzen.EvaluationRequest) { q.Resource.Key = []interface{}{"!!!"} }},
		{"not a certificate", func(q *authzen.EvaluationRequest) { q.Resource.Key = []interface{}{"AAAA"} }},
		{"malformed extra", func(q *authzen.EvaluationRequest) { q.Resource.Key = []interface{}{dsc.b64(), "AAAA"} }},
		{"too many certificates", func(q *authzen.EvaluationRequest) {
			k := make([]interface{}, maxRequestCerts+1)
			for i := range k {
				k[i] = dsc.b64()
			}
			q.Resource.Key = k
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			q := good()
			tc.mut(q)
			requireDeny(t, eval(t, r, q), CodeMalformedRequest)
		})
	}

	t.Run("[]string key accepted by the parser", func(t *testing.T) {
		certs, err := r.parseChain([]string{dsc.b64()})
		require.NoError(t, err)
		assert.Len(t, certs, 1)
		_, err = r.parseChain("abc")
		assert.Error(t, err)
	})
}

func TestEvaluate_Revocation(t *testing.T) {
	csca := newCSCA(t, kindP256, "CSCA", "SE")
	dsc := newDSC(t, kindP256, csca, "SE")
	good := newDSC(t, kindP256, csca, "SE")

	mkCRL := func(t *testing.T, issuer *node, revoked ...*node) []byte {
		t.Helper()
		var entries []x509.RevocationListEntry
		for _, n := range revoked {
			entries = append(entries, x509.RevocationListEntry{SerialNumber: n.cert.SerialNumber, RevocationTime: t2020})
		}
		der, err := x509.CreateRevocationList(testRand{}, &x509.RevocationList{
			Number:                    big.NewInt(1),
			ThisUpdate:                t2020,
			NextUpdate:                t2020.Add(24 * time.Hour), // long stale at tNow
			RevokedCertificateEntries: entries,
		}, issuer.cert, issuer.key.ec)
		require.NoError(t, err)
		return der
	}
	build := func(t *testing.T, crlBytes map[string][]byte) *Registry {
		anchors, crls := t.TempDir(), t.TempDir()
		writeAnchors(t, anchors, map[string][]*node{"SWE": {csca}})
		require.NoError(t, os.MkdirAll(filepath.Join(crls, "SWE"), 0o755))
		for n, b := range crlBytes {
			require.NoError(t, os.WriteFile(filepath.Join(crls, "SWE", n), b, 0o644))
		}
		r, err := New(Config{AnchorsDir: anchors, CRLsDir: crls, Logger: quietLogger(), Now: func() time.Time { return tNow }})
		require.NoError(t, err)
		t.Cleanup(func() { _ = r.Close() })
		return r
	}

	t.Run("revoked DSC (DER), stale CRL still counts", func(t *testing.T) {
		r := build(t, map[string][]byte{"a.crl": mkCRL(t, csca, dsc)})
		requireDeny(t, eval(t, r, req("SWE", []*node{dsc}, nil)), CodeRevoked)
		require.True(t, eval(t, r, req("SWE", []*node{good}, nil)).Decision)
	})
	t.Run("revoked DSC (PEM)", func(t *testing.T) {
		der := mkCRL(t, csca, dsc)
		r := build(t, map[string][]byte{"a.crl": pemBytes("X509 CRL", der)})
		requireDeny(t, eval(t, r, req("SWE", []*node{dsc}, nil)), CodeRevoked)
	})
	t.Run("revocation regardless of signing time before revocation date", func(t *testing.T) {
		// Valid since 2010, revoked (per the CRL entry) on 2020-01-01; the
		// document was signed in 2019, before the revocation date, and is still
		// denied: staleness or dates never un-revoke a certificate.
		ds := dscSpec("DSC early", "SE")
		ds.notBefore, ds.notAfter = t2010, t2040
		early := issue(t, ds, newKey(t, kindP256), csca)
		r := build(t, map[string][]byte{"a.crl": mkCRL(t, csca, early)})
		requireDeny(t, eval(t, r, req("SWE", []*node{early}, map[string]interface{}{"signing_time": "2019-06-01T00:00:00Z"})), CodeRevoked)
	})
	t.Run("every PEM block in a CRL file is used (appended list not dropped)", func(t *testing.T) {
		second := newDSC(t, kindP256, csca, "SE")
		first := pemBytes("X509 CRL", mkCRL(t, csca, dsc))
		appended := pemBytes("X509 CRL", mkCRL(t, csca, second))
		r := build(t, map[string][]byte{"a.crl": append(append([]byte{}, first...), appended...)})
		requireDeny(t, eval(t, r, req("SWE", []*node{dsc}, nil)), CodeRevoked)
		requireDeny(t, eval(t, r, req("SWE", []*node{second}, nil)), CodeRevoked)
		require.True(t, eval(t, r, req("SWE", []*node{good}, nil)).Decision)
	})
	t.Run("junk or a malformed block between PEM CRLs is refused, not skipped", func(t *testing.T) {
		second := newDSC(t, kindP256, csca, "SE")
		first := pemBytes("X509 CRL", mkCRL(t, csca, dsc))
		appended := pemBytes("X509 CRL", mkCRL(t, csca, second))
		malformed := []byte("-----BEGIN X509 CRL-----\n!!!not base64!!!\n-----END X509 CRL-----\n")
		for name, data := range map[string][]byte{
			"junk between":      append(append(append([]byte{}, first...), []byte("junk\n")...), appended...),
			"malformed between": append(append(append([]byte{}, first...), malformed...), appended...),
			"malformed first":   append(append([]byte{}, malformed...), appended...),
		} {
			anchors, crls := t.TempDir(), t.TempDir()
			writeAnchors(t, anchors, map[string][]*node{"SWE": {csca}})
			require.NoError(t, os.MkdirAll(filepath.Join(crls, "SWE"), 0o755))
			require.NoError(t, os.WriteFile(filepath.Join(crls, "SWE", "a.crl"), data, 0o644))
			_, err := New(Config{AnchorsDir: anchors, CRLsDir: crls, Logger: quietLogger()})
			require.Errorf(t, err, "%s", name)
		}
	})
	t.Run("trailing junk after the last PEM CRL is refused", func(t *testing.T) {
		anchors, crls := t.TempDir(), t.TempDir()
		writeAnchors(t, anchors, map[string][]*node{"SWE": {csca}})
		require.NoError(t, os.MkdirAll(filepath.Join(crls, "SWE"), 0o755))
		data := append(pemBytes("X509 CRL", mkCRL(t, csca, dsc)), []byte("\nappended junk that is not PEM\n")...)
		require.NoError(t, os.WriteFile(filepath.Join(crls, "SWE", "a.crl"), data, 0o644))
		_, err := New(Config{AnchorsDir: anchors, CRLsDir: crls, Logger: quietLogger()})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "malformed PEM data")
	})
	t.Run("CRL signed by someone else is ignored", func(t *testing.T) {
		other := newCSCA(t, kindP256, "CSCA", "SE") // same DN, different key
		r := build(t, map[string][]byte{"a.crl": mkCRL(t, other, dsc)})
		require.True(t, eval(t, r, req("SWE", []*node{dsc}, nil)).Decision)
	})
	t.Run("CRL for a different issuer name is ignored", func(t *testing.T) {
		other := newCSCA(t, kindP256, "Some other CA", "SE")
		r := build(t, map[string][]byte{"a.crl": mkCRL(t, other, dsc)})
		require.True(t, eval(t, r, req("SWE", []*node{dsc}, nil)).Decision)
	})
	t.Run("revoked link certificate", func(t *testing.T) {
		kp := newKey(t, kindP256)
		newRoot := issue(t, cscaSpec("CSCA new", "SE"), kp, nil)
		link := issue(t, cscaSpec("CSCA new", "SE"), kp, csca)
		d := newDSC(t, kindP256, newRoot, "SE")
		r := build(t, map[string][]byte{"a.crl": mkCRL(t, csca, link)})
		requireDeny(t, eval(t, r, req("SWE", []*node{d, link}, nil)), CodeRevoked)
	})
	t.Run("CRL filed under the wrong country is refused at load", func(t *testing.T) {
		anchors, crls := t.TempDir(), t.TempDir()
		writeAnchors(t, anchors, map[string][]*node{"SWE": {csca}})
		require.NoError(t, os.MkdirAll(filepath.Join(crls, "DEU"), 0o755)) // issuer is C=SE
		require.NoError(t, os.WriteFile(filepath.Join(crls, "DEU", "a.crl"), mkCRL(t, csca, dsc), 0o644))
		_, err := New(Config{AnchorsDir: anchors, CRLsDir: crls, Logger: quietLogger()})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "filed under DEU")
	})
	t.Run("indirect CRL is refused at load", func(t *testing.T) {
		mk := func(idp []byte) error {
			der, err := x509.CreateRevocationList(testRand{}, &x509.RevocationList{
				Number: big.NewInt(1), ThisUpdate: t2020, NextUpdate: t2040,
				ExtraExtensions: []pkix.Extension{{Id: oidIssuingDistPoint, Critical: true, Value: idp}},
			}, csca.cert, csca.key.ec)
			require.NoError(t, err)
			anchors, crls := t.TempDir(), t.TempDir()
			writeAnchors(t, anchors, map[string][]*node{"SWE": {csca}})
			require.NoError(t, os.MkdirAll(filepath.Join(crls, "SWE"), 0o755))
			require.NoError(t, os.WriteFile(filepath.Join(crls, "SWE", "i.crl"), der, 0o644))
			_, err = New(Config{AnchorsDir: anchors, CRLsDir: crls, Logger: quietLogger()})
			return err
		}
		// IDP ::= SEQUENCE { onlyContainsUserCerts [1] TRUE, indirectCRL [4] TRUE }
		err := mk([]byte{0x30, 0x06, 0x81, 0x01, 0xff, 0x84, 0x01, 0xff})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "indirect CRL")
		// indirectCRL [4] FALSE, and a direct IDP without it, are fine
		require.NoError(t, mk([]byte{0x30, 0x03, 0x84, 0x01, 0x00}))
		require.NoError(t, mk([]byte{0x30, 0x03, 0x81, 0x01, 0xff}))
		// malformed IDP fails closed
		err = mk([]byte{0x04, 0x00})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "issuingDistributionPoint")
		err = mk([]byte{0x30, 0x04, 0x84, 0x02, 0xff, 0xff})
		require.Error(t, err)
		// duplicate [4] elements, FALSE then TRUE and TRUE then FALSE, are refused
		require.Error(t, mk([]byte{0x30, 0x06, 0x84, 0x01, 0x00, 0x84, 0x01, 0xff}))
		require.Error(t, mk([]byte{0x30, 0x06, 0x84, 0x01, 0xff, 0x84, 0x01, 0x00}))
	})
	t.Run("CRLs under a non-country directory name are refused, not dropped", func(t *testing.T) {
		anchors, crls := t.TempDir(), t.TempDir()
		writeAnchors(t, anchors, map[string][]*node{"SWE": {csca}})
		require.NoError(t, os.MkdirAll(filepath.Join(crls, "swe"), 0o755)) // lower case: not an alpha-3 code
		require.NoError(t, os.WriteFile(filepath.Join(crls, "swe", "a.crl"), mkCRL(t, csca, dsc), 0o644))
		_, err := New(Config{AnchorsDir: anchors, CRLsDir: crls, Logger: quietLogger()})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "not an ISO 3166-1 alpha-3")
	})
	t.Run("a CRL replaced by a directory fails the reload and keeps the previous CRLs", func(t *testing.T) {
		anchors, crls := t.TempDir(), t.TempDir()
		writeAnchors(t, anchors, map[string][]*node{"SWE": {csca}})
		require.NoError(t, os.MkdirAll(filepath.Join(crls, "SWE"), 0o755))
		crlPath := filepath.Join(crls, "SWE", "a.crl")
		require.NoError(t, os.WriteFile(crlPath, mkCRL(t, csca, dsc), 0o644))
		r, err := New(Config{AnchorsDir: anchors, CRLsDir: crls, Logger: quietLogger(), Now: func() time.Time { return tNow }})
		require.NoError(t, err)
		t.Cleanup(func() { _ = r.Close() })
		requireDeny(t, eval(t, r, req("SWE", []*node{dsc}, nil)), CodeRevoked)

		require.NoError(t, os.Remove(crlPath))
		require.NoError(t, os.Mkdir(crlPath, 0o755)) // "a.crl" is now a directory
		require.Error(t, r.Refresh(context.Background()))
		requireDeny(t, eval(t, r, req("SWE", []*node{dsc}, nil)), CodeRevoked) // still revoked
	})
	t.Run("delta CRL is refused at load (a base may be missing)", func(t *testing.T) {
		val, err := asn1.Marshal(big.NewInt(1)) // BaseCRLNumber
		require.NoError(t, err)
		der, err := x509.CreateRevocationList(testRand{}, &x509.RevocationList{
			Number:          big.NewInt(2),
			ThisUpdate:      t2020,
			NextUpdate:      t2020.Add(24 * time.Hour),
			ExtraExtensions: []pkix.Extension{{Id: oidDeltaCRLIndicator, Critical: true, Value: val}},
		}, csca.cert, csca.key.ec)
		require.NoError(t, err)
		anchors, crls := t.TempDir(), t.TempDir()
		writeAnchors(t, anchors, map[string][]*node{"SWE": {csca}})
		require.NoError(t, os.MkdirAll(filepath.Join(crls, "SWE"), 0o755))
		require.NoError(t, os.WriteFile(filepath.Join(crls, "SWE", "delta.crl"), der, 0o644))
		_, err = New(Config{AnchorsDir: anchors, CRLsDir: crls, Logger: quietLogger()})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "delta CRL")
	})
	t.Run("unparseable CRL fails registry load (cannot verify => refuse)", func(t *testing.T) {
		anchors, crls := t.TempDir(), t.TempDir()
		writeAnchors(t, anchors, map[string][]*node{"SWE": {csca}})
		require.NoError(t, os.MkdirAll(filepath.Join(crls, "SWE"), 0o755))
		require.NoError(t, os.WriteFile(filepath.Join(crls, "SWE", "bad.crl"), []byte("garbage"), 0o644))
		_, err := New(Config{AnchorsDir: anchors, CRLsDir: crls, Logger: quietLogger()})
		require.Error(t, err)
	})
	t.Run("crls_dir missing fails load", func(t *testing.T) {
		anchors := t.TempDir()
		writeAnchors(t, anchors, map[string][]*node{"SWE": {csca}})
		_, err := New(Config{AnchorsDir: anchors, CRLsDir: filepath.Join(anchors, "nope"), Logger: quietLogger()})
		require.Error(t, err)
	})
	t.Run("non-country CRL dirs and stray files are ignored", func(t *testing.T) {
		anchors, crls := t.TempDir(), t.TempDir()
		writeAnchors(t, anchors, map[string][]*node{"SWE": {csca}})
		require.NoError(t, os.MkdirAll(filepath.Join(crls, "junk"), 0o755))
		require.NoError(t, os.MkdirAll(filepath.Join(crls, "SWE", "subdir"), 0o755))
		r, err := New(Config{AnchorsDir: anchors, CRLsDir: crls, Logger: quietLogger(), Now: func() time.Time { return tNow }})
		require.NoError(t, err)
		require.True(t, eval(t, r, req("SWE", []*node{dsc}, nil)).Decision)
	})
}

func TestAnchorLoading(t *testing.T) {
	good := newCSCA(t, kindP256, "CSCA SE", "SE")
	wrongC := newCSCA(t, kindP256, "CSCA claims DE", "DE")
	noC := issue(t, cscaSpec("CSCA no C", ""), newKey(t, kindP256), nil)
	bp := newCSCA(t, kindBrainpool256, "CSCA SE bp", "SE")

	root := t.TempDir()
	writeAnchors(t, root, map[string][]*node{
		"SWE":  {good, wrongC, noC, bp, good}, // wrongC/noC must be skipped, good deduped
		"XXX":  {good},                        // not an ISO code
		"sweD": {good},
	})
	require.NoError(t, os.WriteFile(filepath.Join(root, "SWE", "garbage.pem"), []byte("not pem"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(root, "SWE", "notes.txt"), good.pem(), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(root, "stray-file"), []byte("x"), 0o644))
	// A single file with two certificates loads both.
	require.NoError(t, os.WriteFile(filepath.Join(root, "SWE", "bundle.pem"), append(good.pem(), bp.pem()...), 0o644))

	r, err := New(Config{AnchorsDir: root, Logger: quietLogger(), Name: "x", Description: "d"})
	require.NoError(t, err)
	t.Cleanup(func() { _ = r.Close() })

	assert.ElementsMatch(t, []string{"SWE"}, r.Countries())
	info := r.Info()
	assert.Equal(t, "x", info.Name)
	assert.Equal(t, "emrtd", info.Type)
	assert.ElementsMatch(t, []string{fingerprint(good.cert), fingerprint(bp.cert)}, info.TrustAnchors)
	assert.True(t, r.Healthy())
	assert.Equal(t, []string{"x5c"}, r.SupportedResourceTypes())
	assert.False(t, r.SupportsResolutionOnly())
	assert.NoError(t, r.Refresh(context.Background()))
}

func TestNewErrors(t *testing.T) {
	_, err := New(Config{})
	require.Error(t, err)
	_, err = New(Config{AnchorsDir: filepath.Join(t.TempDir(), "missing")})
	require.Error(t, err)

	// empty anchors dir is allowed (and denies everything)
	r, err := New(Config{AnchorsDir: t.TempDir(), Logger: quietLogger()})
	require.NoError(t, err)
	csca := newCSCA(t, kindP256, "CSCA", "SE")
	requireDeny(t, eval(t, r, req("SWE", []*node{newDSC(t, kindP256, csca, "SE")}, nil)), CodeUnknownCountry)
	require.NoError(t, r.Close())
	require.NoError(t, r.Close()) // idempotent
}

func TestCandidatesDirNeverLoaded(t *testing.T) {
	real := newCSCA(t, kindP256, "CSCA", "SE")
	pending := newCSCA(t, kindP256, "CSCA pending", "SE")
	repo := t.TempDir()
	writeAnchors(t, filepath.Join(repo, "anchors"), map[string][]*node{"SWE": {real}})
	writeAnchors(t, filepath.Join(repo, "candidates"), map[string][]*node{"SWE": {pending}})
	writeAnchors(t, filepath.Join(repo, "revoked"), map[string][]*node{"SWE": {pending}})

	r, err := New(Config{AnchorsDir: filepath.Join(repo, "anchors"), Logger: quietLogger(), Now: func() time.Time { return tNow }})
	require.NoError(t, err)
	t.Cleanup(func() { _ = r.Close() })

	dsc := newDSC(t, kindP256, pending, "SE")
	requireDeny(t, eval(t, r, req("SWE", []*node{dsc, pending}, nil)), CodeNoAnchor)
	assert.Len(t, r.Info().TrustAnchors, 1)

	// Misconfiguration guard: pointing at the repo root would make every
	// top-level dir (anchors, candidates...) an invalid country dir, so
	// nothing is loaded rather than candidates being trusted.
	bad, err := New(Config{AnchorsDir: repo, Logger: quietLogger()})
	require.NoError(t, err)
	assert.Empty(t, bad.Countries())
}

func TestRefreshAndWatch(t *testing.T) {
	csca := newCSCA(t, kindP256, "CSCA", "SE")
	dsc := newDSC(t, kindP256, csca, "SE")
	root := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(root, "SWE"), 0o755))

	r, err := New(Config{AnchorsDir: root, Watch: true, ReloadDebounce: 20 * time.Millisecond, Logger: quietLogger(), Now: func() time.Time { return tNow }})
	require.NoError(t, err)
	t.Cleanup(func() { _ = r.Close() })
	requireDeny(t, eval(t, r, req("SWE", []*node{dsc}, nil)), CodeUnknownCountry)

	// add an anchor -> picked up by the watcher
	writeAnchors(t, root, map[string][]*node{"SWE": {csca}})
	require.Eventually(t, func() bool {
		return eval(t, r, req("SWE", []*node{dsc}, nil)).Decision
	}, 5*time.Second, 20*time.Millisecond)

	// add a brand new country directory -> watches are re-armed, then picked up
	deu := newCSCA(t, kindP256, "CSCA DE", "DE")
	writeAnchors(t, root, map[string][]*node{"DEU": {deu}})
	require.Eventually(t, func() bool { return len(r.Countries()) == 2 }, 5*time.Second, 20*time.Millisecond)
	// ... and files added to it afterwards are seen too
	deu2 := newCSCA(t, kindP256, "CSCA DE 2", "DE")
	time.Sleep(100 * time.Millisecond)
	writeAnchors(t, root, map[string][]*node{"DEU": {deu2}})
	require.Eventually(t, func() bool { return len(r.Info().TrustAnchors) == 3 }, 5*time.Second, 20*time.Millisecond)

	// removing the anchor revokes trust
	require.NoError(t, os.Remove(filepath.Join(root, "SWE", fingerprint(csca.cert)+".pem")))
	require.Eventually(t, func() bool {
		return !eval(t, r, req("SWE", []*node{dsc}, nil)).Decision
	}, 5*time.Second, 20*time.Millisecond)

	// anchors dir disappearing keeps previous data on explicit refresh
	require.NoError(t, os.RemoveAll(root))
	assert.Error(t, r.Refresh(context.Background()))
	assert.True(t, r.Healthy())
	assert.Len(t, r.Countries(), 1) // DEU still served from the last good snapshot
}

// TestWatch_SustainedEventsCannotStarveReload: events arriving faster than the
// debounce period must not postpone a reload forever, or a removed CSCA would
// stay trusted for the whole stream.
func TestWatch_SustainedEventsCannotStarveReload(t *testing.T) {
	csca := newCSCA(t, kindP256, "CSCA", "SE")
	dsc := newDSC(t, kindP256, csca, "SE")
	noise := newCSCA(t, kindP256, "Noise", "SE")
	root := t.TempDir()
	writeAnchors(t, root, map[string][]*node{"SWE": {csca}})

	const debounce = 50 * time.Millisecond
	r, err := New(Config{AnchorsDir: root, Watch: true, ReloadDebounce: debounce, Logger: quietLogger(), Now: func() time.Time { return tNow }})
	require.NoError(t, err)
	t.Cleanup(func() { _ = r.Close() })
	require.True(t, eval(t, r, req("SWE", []*node{dsc}, nil)).Decision)

	stop := make(chan struct{})
	done := make(chan struct{})
	go func() { // a steady stream of relevant events, well inside the debounce period
		defer close(done)
		noisePath := filepath.Join(root, "SWE", "noise.pem")
		for {
			select {
			case <-stop:
				return
			case <-time.After(debounce / 5):
				_ = os.WriteFile(noisePath, noise.pem(), 0o644)
			}
		}
	}()
	defer func() { close(stop); <-done }()

	require.NoError(t, os.Remove(filepath.Join(root, "SWE", fingerprint(csca.cert)+".pem")))
	require.Eventually(t, func() bool {
		return !eval(t, r, req("SWE", []*node{dsc}, nil)).Decision
	}, maxReloadDelayFactor*debounce*4, 20*time.Millisecond,
		"the reload must run within a bounded delay even while events keep arriving")
}

// TestCountryDirectorySymlinkRejected: a symlinked country directory must not
// be silently skipped, least of all under crls_dir where it would drop
// revocation data while loading still succeeded.
func TestCountryDirectorySymlinkRejected(t *testing.T) {
	csca := newCSCA(t, kindP256, "CSCA", "SE")
	build := func(t *testing.T) (anchors, crls, real string) {
		root := t.TempDir()
		anchors, crls, real = filepath.Join(root, "anchors"), filepath.Join(root, "crls"), filepath.Join(root, "real-swe")
		writeAnchors(t, anchors, map[string][]*node{"SWE": {csca}})
		require.NoError(t, os.MkdirAll(real, 0o755))
		require.NoError(t, os.MkdirAll(crls, 0o755))
		return
	}
	t.Run("crls country symlink", func(t *testing.T) {
		anchors, crls, real := build(t)
		require.NoError(t, os.Symlink(real, filepath.Join(crls, "SWE")))
		_, err := New(Config{AnchorsDir: anchors, CRLsDir: crls, Logger: quietLogger()})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "symlink")
	})
	t.Run("anchors country symlink", func(t *testing.T) {
		anchors, _, real := build(t)
		require.NoError(t, os.Symlink(real, filepath.Join(anchors, "DEU")))
		_, err := New(Config{AnchorsDir: anchors, Logger: quietLogger()})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "symlink")
	})
	t.Run("dangling crls country symlink", func(t *testing.T) {
		anchors, crls, _ := build(t)
		require.NoError(t, os.Symlink(filepath.Join(crls, "nowhere"), filepath.Join(crls, "SWE")))
		_, err := New(Config{AnchorsDir: anchors, CRLsDir: crls, Logger: quietLogger()})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "symlink")
	})
	t.Run("symlinked root stays supported", func(t *testing.T) {
		anchors, _, _ := build(t)
		link := filepath.Join(filepath.Dir(anchors), "current")
		require.NoError(t, os.Symlink(anchors, link))
		r, err := New(Config{AnchorsDir: link, Logger: quietLogger()})
		require.NoError(t, err)
		t.Cleanup(func() { _ = r.Close() })
		assert.Len(t, r.Countries(), 1)
	})
	// A link to a file elsewhere: replacing its target fires no event in the
	// watched tree, so the watcher could never notice. Refused up front.
	t.Run("anchor file symlink", func(t *testing.T) {
		anchors, _, _ := build(t)
		outside := filepath.Join(t.TempDir(), "x.pem")
		require.NoError(t, os.WriteFile(outside, csca.pem(), 0o644))
		require.NoError(t, os.Symlink(outside, filepath.Join(anchors, "SWE", "alias.pem")))
		_, err := New(Config{AnchorsDir: anchors, Logger: quietLogger()})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "symlink")
	})
	t.Run("crl file symlink", func(t *testing.T) {
		anchors, crls, _ := build(t)
		require.NoError(t, os.MkdirAll(filepath.Join(crls, "SWE"), 0o755))
		outside := filepath.Join(t.TempDir(), "x.crl")
		require.NoError(t, os.WriteFile(outside, []byte("irrelevant"), 0o644))
		require.NoError(t, os.Symlink(outside, filepath.Join(crls, "SWE", "a.crl")))
		_, err := New(Config{AnchorsDir: anchors, CRLsDir: crls, Logger: quietLogger()})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "symlink")
	})
	t.Run("country-named symlink to a file", func(t *testing.T) {
		anchors, crls, _ := build(t)
		target := filepath.Join(t.TempDir(), "f")
		require.NoError(t, os.WriteFile(target, []byte("x"), 0o644))
		require.NoError(t, os.Symlink(target, filepath.Join(crls, "SWE")))
		_, err := New(Config{AnchorsDir: anchors, CRLsDir: crls, Logger: quietLogger()})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "symlink")
	})
	t.Run("country-named regular file", func(t *testing.T) {
		anchors, crls, _ := build(t)
		require.NoError(t, os.WriteFile(filepath.Join(crls, "SWE"), []byte("not a directory"), 0o644))
		_, err := New(Config{AnchorsDir: anchors, CRLsDir: crls, Logger: quietLogger()})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "not a directory")
	})
	t.Run("unrelated stray file is ignored", func(t *testing.T) {
		anchors, _, _ := build(t)
		require.NoError(t, os.WriteFile(filepath.Join(anchors, "README"), []byte("x"), 0o644))
		r, err := New(Config{AnchorsDir: anchors, Logger: quietLogger()})
		require.NoError(t, err)
		t.Cleanup(func() { _ = r.Close() })
	})
	t.Run("a stray file symlink that is not a directory is ignored", func(t *testing.T) {
		anchors, _, _ := build(t)
		require.NoError(t, os.Symlink("/nonexistent", filepath.Join(anchors, "dangling")))
		r, err := New(Config{AnchorsDir: anchors, Logger: quietLogger()})
		require.NoError(t, err)
		t.Cleanup(func() { _ = r.Close() })
	})
}

func TestWatchSetupFailure(t *testing.T) {
	root := t.TempDir()
	crls := filepath.Join(root, "crls") // does not exist: load fails before watching
	_, err := New(Config{AnchorsDir: root, CRLsDir: crls, Watch: true, Logger: quietLogger()})
	require.Error(t, err)
}

func TestCountryTable(t *testing.T) {
	assert.Len(t, alpha3ToAlpha2, 250) // 249 ISO 3166-1 + XKX
	assert.Len(t, alpha2ToAlpha3, len(alpha3ToAlpha2))
	for a3, a2 := range alpha3ToAlpha2 {
		assert.Len(t, a3, 3)
		assert.Len(t, a2, 2)
		assert.Equal(t, a3, alpha2ToAlpha3[a2])
	}
	for a2, a3 := range map[string]string{"SE": "SWE", "DE": "DEU", "NL": "NLD", "GB": "GBR", "CH": "CHE", "XK": "XKX", "US": "USA"} {
		assert.True(t, countryMatches(a3, a2))
		assert.True(t, countryMatches(a3, lower(a2)))
	}
	assert.False(t, countryMatches("SWE", "DE"))
	assert.False(t, countryMatches("ZZZ", "ZZ"))
	assert.False(t, countryMatches("SWE", ""))
}

func lower(s string) string {
	b := []byte(s)
	for i := range b {
		if b[i] >= 'A' && b[i] <= 'Z' {
			b[i] += 32
		}
	}
	return string(b)
}

// TestThroughManagerWithPolicy exercises the registry behind the
// RegistryManager with the documented policy: signing_time must survive
// request-context sanitization, and key-type/key-binding constraints apply.
func TestThroughManagerWithPolicy(t *testing.T) {
	csca := newCSCA(t, kindP256, "CSCA", "SE")
	s := dscSpec("DSC old", "SE")
	s.notBefore, s.notAfter = t2010, t2012
	oldDSC := issue(t, s, newKey(t, kindP256), csca)
	r := newReg(t, map[string][]*node{"SWE": {csca}})

	mgr := registry.NewRegistryManager(registry.FirstMatch, 5*time.Second)
	mgr.Register(r)
	pm := registry.NewPolicyManager()
	pm.RegisterPolicy(&registry.Policy{
		Name:        ActionName,
		Registries:  []string{r.Info().Name},
		Constraints: registry.PolicyConstraints{RequireKeyBinding: true, AllowedKeyTypes: []string{"x5c"}},
	})
	mgr.SetPolicyManager(pm)

	resp, err := mgr.Evaluate(context.Background(), req("SWE", []*node{oldDSC}, map[string]interface{}{"signing_time": "2011-06-01T00:00:00Z"}))
	require.NoError(t, err)
	require.True(t, resp.Decision, "%v", resp.Context)

	resp, err = mgr.Evaluate(context.Background(), req("SWE", []*node{oldDSC}, nil))
	require.NoError(t, err)
	require.False(t, resp.Decision)

	jwk := req("SWE", []*node{oldDSC}, nil)
	jwk.Resource.Type = "jwk"
	resp, err = mgr.Evaluate(context.Background(), jwk)
	require.NoError(t, err)
	require.False(t, resp.Decision)
}

func TestEvaluate_WeakSignatureAlgorithms(t *testing.T) {
	csca := newCSCA(t, kindP256, "CSCA", "SE")
	t.Run("SHA-1 signed DSC is refused", func(t *testing.T) {
		s := dscSpec("DSC", "SE")
		s.sha1 = true
		dsc := issue(t, s, newKey(t, kindP256), csca)
		r := newReg(t, map[string][]*node{"SWE": {csca}})
		requireDeny(t, eval(t, r, req("SWE", []*node{dsc}, nil)), CodeChainInvalid)
	})
	t.Run("SHA-1 signed link certificate is refused", func(t *testing.T) {
		kp := newKey(t, kindP256)
		newRoot := issue(t, cscaSpec("CSCA new", "SE"), kp, nil)
		s := cscaSpec("CSCA new", "SE")
		s.sha1 = true
		link := issue(t, s, kp, csca)
		dsc := newDSC(t, kindP256, newRoot, "SE")
		r := newReg(t, map[string][]*node{"SWE": {csca}})
		requireDeny(t, eval(t, r, req("SWE", []*node{dsc, link}, nil)), CodeChainInvalid)
	})
}

func TestEvaluate_SearchBoundsAndCancellation(t *testing.T) {
	realCSCA := newCSCA(t, kindP256, "CSCA SE", "SE")
	r := newReg(t, map[string][]*node{"SWE": {realCSCA}})

	// Many distinct certificates sharing one name and key: every one signs
	// every other, so the walk is combinatorial and never reaches an anchor.
	kp := newKey(t, kindP256)
	var extras []*node
	for i := 0; i < maxRequestCerts-1; i++ {
		s := cscaSpec("Loop CA", "SE")
		s.serial = int64(1000 + i)
		extras = append(extras, issue(t, s, kp, nil))
	}
	dsc := issue(t, dscSpec("DSC", "SE"), newKey(t, kindP256), extras[0])
	chain := append([]*node{dsc}, extras...)

	t.Run("work limit is an explicit denial", func(t *testing.T) {
		resp := eval(t, r, req("SWE", chain, nil))
		requireDeny(t, resp, CodeChainInvalid)
		assert.Contains(t, resp.Context.Reason["error"], "work limit")
	})
	t.Run("canceled context stops the search", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		resp, err := r.Evaluate(ctx, req("SWE", chain, nil))
		require.NoError(t, err)
		requireDeny(t, resp, CodeChainInvalid)
		assert.Contains(t, resp.Context.Reason["error"], "canceled")
	})
}

func TestNamesEqual(t *testing.T) {
	assert.True(t, namesEqual([]byte{1}, []byte{1}, "a", "b"))
	assert.True(t, namesEqual([]byte{1}, []byte{2}, "CN=Foo", "cn=foo"))
	assert.False(t, namesEqual([]byte{1}, []byte{2}, "CN=Foo", "CN=Bar"))
}

func TestCRLLoading_SkipsNonCRLFiles(t *testing.T) {
	csca := newCSCA(t, kindP256, "CSCA", "SE")
	dsc := newDSC(t, kindP256, csca, "SE")
	anchors, crls := t.TempDir(), t.TempDir()
	writeAnchors(t, anchors, map[string][]*node{"SWE": {csca}})
	require.NoError(t, os.MkdirAll(filepath.Join(crls, "SWE"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(crls, "SWE", "README.txt"), []byte("note"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(crls, "SWE", "upload.crl.tmp"), []byte("partial"), 0o644))
	r, err := New(Config{AnchorsDir: anchors, CRLsDir: crls, Logger: quietLogger(), Now: func() time.Time { return tNow }})
	require.NoError(t, err)
	t.Cleanup(func() { _ = r.Close() })
	require.True(t, eval(t, r, req("SWE", []*node{dsc}, nil)).Decision)
}

func TestEvaluate_DSCMustNotBeCA(t *testing.T) {
	csca := newCSCA(t, kindP256, "CSCA", "SE")
	r := newReg(t, map[string][]*node{"SWE": {csca}})
	s := cscaSpec("CA DSC", "SE")
	s.usage = usageDigitalSignature | usageCertSignCRLSign
	ca := issue(t, s, newKey(t, kindP256), csca)
	requireDeny(t, eval(t, r, req("SWE", []*node{ca}, nil)), CodeBadKeyUsage)
}

func TestEvaluate_OversizedCertificateRefused(t *testing.T) {
	csca := newCSCA(t, kindP256, "CSCA", "SE")
	r := newReg(t, map[string][]*node{"SWE": {csca}})
	rq := req("SWE", nil, nil)
	rq.Resource.Key = []interface{}{strings.Repeat("A", maxCertB64Len+1)}
	requireDeny(t, eval(t, r, rq), CodeMalformedRequest)
}

func TestEvaluate_LinkWithoutKeyUsageRefused(t *testing.T) {
	oldCSCA := newCSCA(t, kindP256, "CSCA old", "SE")
	kp := newKey(t, kindP256)
	rolled := issue(t, cscaSpec("CSCA new", "SE"), kp, nil)
	ls := cscaSpec("CSCA new", "SE")
	ls.usage = 0 // no keyUsage extension
	link := issue(t, ls, kp, oldCSCA)
	dsc := newDSC(t, kindP256, rolled, "SE")
	r := newReg(t, map[string][]*node{"SWE": {oldCSCA}})
	requireDeny(t, eval(t, r, req("SWE", []*node{dsc, link}, nil)), CodeChainInvalid)
}

func TestWatch_RecoversFromRootReplacement(t *testing.T) {
	csca := newCSCA(t, kindP256, "CSCA", "SE")
	dsc := newDSC(t, kindP256, csca, "SE")
	root := t.TempDir()
	writeAnchors(t, root, map[string][]*node{"SWE": {csca}})
	r, err := New(Config{AnchorsDir: root, Watch: true, ReloadDebounce: 20 * time.Millisecond, Logger: quietLogger(), Now: func() time.Time { return tNow }})
	require.NoError(t, err)
	t.Cleanup(func() { _ = r.Close() })
	require.True(t, eval(t, r, req("SWE", []*node{dsc}, nil)).Decision)

	// Replace the whole tree; the root stays absent past the first debounce.
	require.NoError(t, os.RemoveAll(root))
	time.Sleep(100 * time.Millisecond)
	require.NoError(t, os.MkdirAll(filepath.Join(root, "SWE"), 0o755))

	// The retry picks up the replacement and revokes the removed anchor.
	require.Eventually(t, func() bool {
		return !eval(t, r, req("SWE", []*node{dsc}, nil)).Decision
	}, 5*time.Second, 20*time.Millisecond)

	// ... and the re-armed watch sees later additions in the new tree.
	time.Sleep(100 * time.Millisecond)
	writeAnchors(t, root, map[string][]*node{"SWE": {csca}})
	require.Eventually(t, func() bool {
		return eval(t, r, req("SWE", []*node{dsc}, nil)).Decision
	}, 5*time.Second, 20*time.Millisecond)
}

func TestWatch_SymlinkSwap(t *testing.T) {
	csca := newCSCA(t, kindP256, "CSCA", "SE")
	dsc := newDSC(t, kindP256, csca, "SE")
	base := t.TempDir()
	v1, v2 := filepath.Join(base, "v1"), filepath.Join(base, "v2")
	writeAnchors(t, v1, map[string][]*node{"SWE": {csca}})
	require.NoError(t, os.MkdirAll(filepath.Join(v2, "SWE"), 0o755))
	link := filepath.Join(base, "current")
	require.NoError(t, os.Symlink(v1, link))

	cfg := Config{AnchorsDir: link, Watch: true, ReloadDebounce: 20 * time.Millisecond, Logger: quietLogger(), Now: func() time.Time { return tNow }}
	// On Linux the parent directory's inotify watch reports the rename, so the
	// swap is picked up from that event; the default 30s root check is far
	// outside the deadline below, so it cannot be what passes the test there.
	// kqueue (macOS, BSD) raises no event for a rename over an existing
	// directory entry, so on those platforms the root check is the mechanism
	// that notices the swap: shorten it to exercise that path instead.
	if runtime.GOOS != "linux" {
		cfg.RootCheckInterval = 30 * time.Millisecond
	}
	r, err := New(cfg)
	require.NoError(t, err)
	t.Cleanup(func() { _ = r.Close() })
	require.True(t, eval(t, r, req("SWE", []*node{dsc}, nil)).Decision)

	// Atomic symlink swap; the old target stays intact.
	tmp := filepath.Join(base, "current.tmp")
	require.NoError(t, os.Symlink(v2, tmp))
	require.NoError(t, os.Rename(tmp, link))
	require.Eventually(t, func() bool {
		return !eval(t, r, req("SWE", []*node{dsc}, nil)).Decision
	}, 5*time.Second, 20*time.Millisecond)
}

func TestRelevantEvent(t *testing.T) {
	r := &Registry{cfg: Config{AnchorsDir: "/a/anchors", CRLsDir: "/a/crls"}}
	for _, n := range []string{"/a", "/a/anchors", "/a/anchors/SWE", "/a/anchors/SWE/x.pem", "/a/crls/SWE/y.crl"} {
		assert.True(t, r.relevantEvent(n), n)
	}
	for _, n := range []string{"/", "/a/other", "/a/other/file", "/a/anchors/SWE/deeper/file"} {
		assert.False(t, r.relevantEvent(n), n)
	}
}

func TestEvaluate_EmptyKeyUsageExtensionRefused(t *testing.T) {
	csca := newCSCA(t, kindP256, "CSCA", "SE")
	r := newReg(t, map[string][]*node{"SWE": {csca}})
	s := dscSpec("DSC", "SE")
	s.usage = 0
	s.emptyUsage = true
	dsc := issue(t, s, newKey(t, kindP256), csca)
	requireDeny(t, eval(t, r, req("SWE", []*node{dsc}, nil)), CodeBadKeyUsage)
}

func TestEvaluate_SubjectTypeMustBeKey(t *testing.T) {
	csca := newCSCA(t, kindP256, "CSCA", "SE")
	dsc := newDSC(t, kindP256, csca, "SE")
	r := newReg(t, map[string][]*node{"SWE": {csca}})
	rq := req("SWE", []*node{dsc}, nil)
	rq.Subject.Type = "url"
	requireDeny(t, eval(t, r, rq), CodeMalformedRequest)
}

func TestEvaluate_SameNameSuppliedLinkWithWrongKeyIsChainInvalid(t *testing.T) {
	csca := newCSCA(t, kindP256, "CSCA", "SE")
	other := issue(t, cscaSpec("Other CA", "SE"), newKey(t, kindP256), nil)
	impostor := issue(t, cscaSpec("Other CA", "SE"), newKey(t, kindP256), nil) // same name, different key
	dsc := newDSC(t, kindP256, other, "SE")
	r := newReg(t, map[string][]*node{"SWE": {csca}})
	requireDeny(t, eval(t, r, req("SWE", []*node{dsc, impostor}, nil)), CodeChainInvalid)
}

func TestEvaluate_TooManyCertificatesRejectedUpFront(t *testing.T) {
	csca := newCSCA(t, kindP256, "CSCA", "SE")
	r := newReg(t, map[string][]*node{"SWE": {csca}})
	rq := req("SWE", nil, nil)
	keys := make([]interface{}, maxRequestCerts+1)
	for i := range keys {
		keys[i] = 7 // never inspected: the count is checked first
	}
	rq.Resource.Key = keys
	resp := eval(t, r, rq)
	requireDeny(t, resp, CodeMalformedRequest)
	assert.Contains(t, resp.Context.Reason["error"], "maximum")
}

func TestNew_ReloadsAfterWatchesArmed(t *testing.T) {
	csca := newCSCA(t, kindP256, "CSCA", "SE")
	dsc := newDSC(t, kindP256, csca, "SE")
	root := t.TempDir()
	writeAnchors(t, root, map[string][]*node{"SWE": {csca}})
	// The anchor is removed after the initial load but before New returns;
	// the reconciling reload must pick that up.
	r, err := New(Config{
		AnchorsDir: root, Watch: true, Logger: quietLogger(), Now: func() time.Time { return tNow },
		afterArm: func() { _ = os.Remove(filepath.Join(root, "SWE", fingerprint(csca.cert)+".pem")) },
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = r.Close() })
	requireDeny(t, eval(t, r, req("SWE", []*node{dsc}, nil)), CodeUnknownCountry)
}

func TestExplicitECParameters(t *testing.T) {
	t.Run("explicit-parameter P-256 CSCA loads as anchor and a DSC chains to it", func(t *testing.T) {
		csca := issue(t, cscaSpec("CSCA explicit", "SE"), newKey(t, kindP256Explicit), nil)
		require.NotNil(t, csca.cert.PublicKey)
		require.NotEmpty(t, csca.cert.RawTBSCertificate)
		// stdlib alone rejects the anchor, so the plugin must be doing the work
		_, stdErr := x509.ParseCertificate(csca.cert.Raw)
		require.Error(t, stdErr)

		dsc := newDSC(t, kindP256, csca, "SE")
		r := newReg(t, map[string][]*node{"SWE": {csca}})
		require.Len(t, r.Info().TrustAnchors, 1)
		resp := eval(t, r, req("SWE", []*node{dsc}, nil))
		require.True(t, resp.Decision, "%v", resp.Context.Reason)
	})

	t.Run("explicit-parameter parameters that match no known curve stay rejected and are logged", func(t *testing.T) {
		bad := issue2(t, cscaSpec("CSCA bad params", "SE"), newKey(t, kindP256ExplicitBadCofactor))
		root := t.TempDir()
		require.NoError(t, os.MkdirAll(filepath.Join(root, "SWE"), 0o755))
		require.NoError(t, os.WriteFile(filepath.Join(root, "SWE", "bad.pem"), pemBytes("CERTIFICATE", bad), 0o644))

		var logs bytes.Buffer
		lg := slog.New(slog.NewTextHandler(&logs, nil))
		r, err := New(Config{AnchorsDir: root, Logger: lg, Now: func() time.Time { return tNow }})
		require.NoError(t, err)
		t.Cleanup(func() { _ = r.Close() })
		assert.Empty(t, r.Countries())
		assert.Contains(t, logs.String(), "skipping")
		assert.Contains(t, logs.String(), "bad.pem")
	})

	t.Run("real national CSCAs with explicit parameters (HUN P-521, DEU brainpoolP384r1)", func(t *testing.T) {
		root := t.TempDir()
		for _, c := range []struct{ dir, file string }{
			{"HUN", "csca_hun_explicit_params.pem"},
			{"DEU", "csca_deu_explicit_params.pem"},
		} {
			data, err := os.ReadFile(filepath.Join("testdata", c.file))
			require.NoError(t, err)
			require.NoError(t, os.MkdirAll(filepath.Join(root, c.dir), 0o755))
			require.NoError(t, os.WriteFile(filepath.Join(root, c.dir, c.file), data, 0o644))
		}
		r, err := New(Config{AnchorsDir: root, Logger: quietLogger(), Now: func() time.Time { return tNow }})
		require.NoError(t, err)
		t.Cleanup(func() { _ = r.Close() })
		assert.ElementsMatch(t, []string{"DEU", "HUN"}, r.Countries())
		assert.Len(t, r.Info().TrustAnchors, 2)
	})
}

func TestSigningTimePrecisionPreserved(t *testing.T) {
	csca := newCSCA(t, kindP256, "CSCA", "SE")
	s := dscSpec("DSC", "SE")
	s.notBefore, s.notAfter = t2010, t2012
	dsc := issue(t, s, newKey(t, kindP256), csca)
	r := newReg(t, map[string][]*node{"SWE": {csca}})

	// Allowed response echoes the instant that was used, fractional part included.
	resp := eval(t, r, req("SWE", []*node{dsc}, map[string]interface{}{"signing_time": "2011-06-01T00:00:00.123456789Z"}))
	require.True(t, resp.Decision, "%v", resp.Context.Reason)
	admin := resp.Context.Reason["admin"].(map[string]interface{})
	assert.Equal(t, "2011-06-01T00:00:00.123456789Z", admin["signing_time"])

	// Denial detail at the notAfter boundary shows the sub-second instant, so it
	// cannot read as equal to the limit it was denied against.
	resp = eval(t, r, req("SWE", []*node{dsc}, map[string]interface{}{"signing_time": "2012-01-01T00:00:00.5Z"}))
	requireDeny(t, resp, CodeExpired)
	assert.Contains(t, resp.Context.Reason["error"], "2012-01-01T00:00:00.5Z")
}

func TestCRLDataIndexesSerials(t *testing.T) {
	c := newCRLData(&x509.RevocationList{RevokedCertificateEntries: []x509.RevocationListEntry{
		{SerialNumber: big.NewInt(7)}, {SerialNumber: big.NewInt(-3)}, {SerialNumber: new(big.Int).Lsh(big.NewInt(1), 100)},
	}})
	assert.True(t, c.isRevoked(big.NewInt(7)))
	assert.True(t, c.isRevoked(big.NewInt(-3)))
	assert.True(t, c.isRevoked(new(big.Int).Lsh(big.NewInt(1), 100)))
	assert.False(t, c.isRevoked(big.NewInt(8)))
	assert.False(t, newCRLData(&x509.RevocationList{}).isRevoked(big.NewInt(1)))
}

func TestCountryDirsInspectFailureFailsLoad(t *testing.T) {
	_, err := countryDirs(filepath.Join(t.TempDir(), "missing"))
	require.Error(t, err)
}

// Verifying the same CRL against the same issuer for many candidate paths
// must happen once per evaluation.
func TestCRLSignatureVerdictsMemoized(t *testing.T) {
	csca := newCSCA(t, kindP256, "CSCA", "SE")
	dsc := newDSC(t, kindP256, csca, "SE")
	other := newCSCA(t, kindP256, "CSCA", "SE") // same DN, different key
	der, err := x509.CreateRevocationList(testRand{}, &x509.RevocationList{
		Number: big.NewInt(1), ThisUpdate: t2020, NextUpdate: t2040,
		RevokedCertificateEntries: []x509.RevocationListEntry{{SerialNumber: dsc.cert.SerialNumber, RevocationTime: t2020}},
	}, csca.cert, csca.key.ec)
	require.NoError(t, err)
	parsed, err := x509.ParseRevocationList(der)
	require.NoError(t, err)
	crl := newCRLData(parsed)

	r := newReg(t, map[string][]*node{"SWE": {csca}})
	vc := crlVerdicts{}
	for i := 0; i < 5; i++ {
		assert.True(t, r.crlSignatureOK(vc, crl, csca.cert))
		assert.False(t, r.crlSignatureOK(vc, crl, other.cert))
	}
	assert.Len(t, vc, 2, "one verdict per (CRL, issuer) pair, however many paths ask")

	// and through checkPath: repeated calls with a shared cache still deny, adding no entries
	for i := 0; i < 3; i++ {
		d := r.checkPath([]*x509.Certificate{dsc.cert, csca.cert}, tNow, []*crlData{crl}, nil, pathLenPolicy{}, vc)
		require.NotNil(t, d)
		assert.False(t, d.Decision)
	}
	assert.Len(t, vc, 2)
}

func TestInfoTrustAnchorsAreACopy(t *testing.T) {
	csca := newCSCA(t, kindP256, "CSCA", "SE")
	r := newReg(t, map[string][]*node{"SWE": {csca}})
	first := r.Info().TrustAnchors
	require.Len(t, first, 1)
	want := first[0]
	first[0] = "tampered"
	assert.Equal(t, want, r.Info().TrustAnchors[0], "mutating a returned Info must not change the registry's metadata")
}

// anchors_dir is a literal path: metacharacters must not turn it into a
// pattern that reads a sibling directory's certificates as anchors.
func TestAnchorsDirMetacharactersAreLiteral(t *testing.T) {
	csca := newCSCA(t, kindP256, "CSCA", "SE")
	dsc := newDSC(t, kindP256, csca, "SE")
	base := t.TempDir()
	reviewed := filepath.Join(base, "anchors[1]") // the configured tree: empty SWE directory
	sibling := filepath.Join(base, "anchors1")    // what Glob's [1] would match
	require.NoError(t, os.MkdirAll(filepath.Join(reviewed, "SWE"), 0o755))
	writeAnchors(t, sibling, map[string][]*node{"SWE": {csca}})

	r, err := New(Config{AnchorsDir: reviewed, Logger: quietLogger(), Now: func() time.Time { return tNow }})
	require.NoError(t, err)
	t.Cleanup(func() { _ = r.Close() })
	assert.Empty(t, r.Info().TrustAnchors, "the sibling directory must not be read")
	resp := eval(t, r, req("SWE", []*node{dsc}, nil))
	require.False(t, resp.Decision, "a certificate from anchors1 must not be trusted via anchors[1]")
}

// A symlink in an ANCESTOR of the roots (anchors_dir=/base/current/anchors,
// current -> v1) swapped atomically with the old tree left intact raises no
// event on any watched directory; the resolved-location poll catches it.
func TestWatch_AncestorSymlinkSwap(t *testing.T) {
	csca := newCSCA(t, kindP256, "CSCA", "SE")
	dsc := newDSC(t, kindP256, csca, "SE")
	revoking := func() []byte {
		der, err := x509.CreateRevocationList(testRand{}, &x509.RevocationList{
			Number: big.NewInt(1), ThisUpdate: t2020, NextUpdate: t2040,
			RevokedCertificateEntries: []x509.RevocationListEntry{{SerialNumber: dsc.cert.SerialNumber, RevocationTime: t2020}},
		}, csca.cert, csca.key.ec)
		require.NoError(t, err)
		return der
	}

	for _, tc := range []struct {
		name    string
		v2Trees func(t *testing.T, v2 string) // what the replacement tree holds
		want    string                        // denial code after the swap
	}{
		{"anchors replaced by an empty tree", func(t *testing.T, v2 string) {
			require.NoError(t, os.MkdirAll(filepath.Join(v2, "anchors", "SWE"), 0o755))
			require.NoError(t, os.MkdirAll(filepath.Join(v2, "crls", "SWE"), 0o755))
		}, CodeUnknownCountry},
		{"new CRL appears in the replacement tree", func(t *testing.T, v2 string) {
			writeAnchors(t, filepath.Join(v2, "anchors"), map[string][]*node{"SWE": {csca}})
			require.NoError(t, os.MkdirAll(filepath.Join(v2, "crls", "SWE"), 0o755))
			require.NoError(t, os.WriteFile(filepath.Join(v2, "crls", "SWE", "a.crl"), revoking(), 0o644))
		}, CodeRevoked},
	} {
		t.Run(tc.name, func(t *testing.T) {
			base := t.TempDir()
			v1, v2 := filepath.Join(base, "v1"), filepath.Join(base, "v2")
			writeAnchors(t, filepath.Join(v1, "anchors"), map[string][]*node{"SWE": {csca}})
			require.NoError(t, os.MkdirAll(filepath.Join(v1, "crls", "SWE"), 0o755))
			tc.v2Trees(t, v2)
			link := filepath.Join(base, "current")
			require.NoError(t, os.Symlink(v1, link))

			r, err := New(Config{
				AnchorsDir: filepath.Join(link, "anchors"), CRLsDir: filepath.Join(link, "crls"),
				Watch: true, ReloadDebounce: 20 * time.Millisecond, RootCheckInterval: 30 * time.Millisecond,
				Logger: quietLogger(), Now: func() time.Time { return tNow },
			})
			require.NoError(t, err)
			t.Cleanup(func() { _ = r.Close() })
			require.True(t, eval(t, r, req("SWE", []*node{dsc}, nil)).Decision)

			tmp := filepath.Join(base, "current.tmp")
			require.NoError(t, os.Symlink(v2, tmp))
			require.NoError(t, os.Rename(tmp, link)) // v1 stays intact
			require.Eventually(t, func() bool {
				resp := eval(t, r, req("SWE", []*node{dsc}, nil))
				return !resp.Decision && code(resp) == tc.want
			}, 5*time.Second, 20*time.Millisecond)
		})
	}
}

func TestIsIndirectCRL_DuplicateExtension(t *testing.T) {
	ext := func(v []byte) pkix.Extension { return pkix.Extension{Id: oidIssuingDistPoint, Value: v} }
	direct, indirect := []byte{0x30, 0x03, 0x84, 0x01, 0x00}, []byte{0x30, 0x03, 0x84, 0x01, 0xff}
	_, err := isIndirectCRL(&x509.RevocationList{Extensions: []pkix.Extension{ext(direct), ext(indirect)}})
	require.Error(t, err)
	_, err = isIndirectCRL(&x509.RevocationList{Extensions: []pkix.Extension{ext(indirect), ext(direct)}})
	require.Error(t, err)
	got, err := isIndirectCRL(&x509.RevocationList{})
	require.NoError(t, err)
	assert.False(t, got)
}

func TestEvaluate_ResourceIDMustMatchSubjectID(t *testing.T) {
	csca := newCSCA(t, kindP256, "CSCA", "SE")
	dsc := newDSC(t, kindP256, csca, "SE")
	r := newReg(t, map[string][]*node{"SWE": {csca}})
	for name, id := range map[string]string{"mismatched": "DEU", "missing": "", "case differs": "swe"} {
		t.Run(name, func(t *testing.T) {
			q := req("SWE", []*node{dsc}, nil)
			q.Resource.ID = id
			requireDeny(t, eval(t, r, q), CodeMalformedRequest)
		})
	}
	require.True(t, eval(t, r, req("SWE", []*node{dsc}, nil)).Decision)
}

// Replacing a real ancestor directory IN PLACE (old tree kept, no symlink) must
// be noticed too. Two shapes: the root's parent itself (the event path:
// MOVE_SELF on its watch) and a higher ancestor (no event at all on any watched
// inode, so only the root identity poll can see it).
func TestWatch_InPlaceAncestorReplacement(t *testing.T) {
	csca := newCSCA(t, kindP256, "CSCA", "SE")
	dsc := newDSC(t, kindP256, csca, "SE")

	for _, tc := range []struct {
		name     string
		depth    string // path from the swapped directory down to anchors/
		interval time.Duration
	}{
		{"root's parent replaced (event path)", "anchors", time.Hour},
		{"higher ancestor replaced (identity poll)", filepath.Join("b", "anchors"), 30 * time.Millisecond},
	} {
		t.Run(tc.name, func(t *testing.T) {
			base := t.TempDir()
			cur, old, next := filepath.Join(base, "cur"), filepath.Join(base, "old"), filepath.Join(base, "next")
			anchors := filepath.Join(cur, tc.depth)
			writeAnchors(t, anchors, map[string][]*node{"SWE": {csca}})
			// the replacement has the same layout but no anchors
			require.NoError(t, os.MkdirAll(filepath.Join(next, tc.depth, "SWE"), 0o755))

			r, err := New(Config{
				AnchorsDir: anchors, Watch: true, ReloadDebounce: 20 * time.Millisecond, RootCheckInterval: tc.interval,
				Logger: quietLogger(), Now: func() time.Time { return tNow },
			})
			require.NoError(t, err)
			t.Cleanup(func() { _ = r.Close() })
			require.True(t, eval(t, r, req("SWE", []*node{dsc}, nil)).Decision)

			require.NoError(t, os.Rename(cur, old))  // old tree stays intact
			require.NoError(t, os.Rename(next, cur)) // a new real directory takes its path
			require.Eventually(t, func() bool {
				return !eval(t, r, req("SWE", []*node{dsc}, nil)).Decision
			}, 5*time.Second, 20*time.Millisecond)
		})
	}
}

// ---- CRL authority across a CSCA key rollover ----

type rolloverEnv struct {
	cscaOld, cscaNew *node
}

func mkSignedCRL(t *testing.T, signer *node, issuerName *node, revoked ...*node) []byte {
	t.Helper()
	var entries []x509.RevocationListEntry
	for _, n := range revoked {
		entries = append(entries, x509.RevocationListEntry{SerialNumber: n.cert.SerialNumber, RevocationTime: t2020})
	}
	// x509.CreateRevocationList takes the issuer name from the issuer cert.
	der, err := x509.CreateRevocationList(testRand{}, &x509.RevocationList{
		Number: big.NewInt(1), ThisUpdate: t2020, NextUpdate: t2020.Add(24 * time.Hour),
		RevokedCertificateEntries: entries,
	}, issuerName.cert, signer.key.ec)
	require.NoError(t, err)
	return der
}

func regWithCRL(t *testing.T, anchors map[string][]*node, crlCountry string, crl []byte) *Registry {
	t.Helper()
	ad, cd := t.TempDir(), t.TempDir()
	writeAnchors(t, ad, anchors)
	require.NoError(t, os.MkdirAll(filepath.Join(cd, crlCountry), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(cd, crlCountry, "current.crl"), crl, 0o644))
	r, err := New(Config{AnchorsDir: ad, CRLsDir: cd, Logger: quietLogger(), Now: func() time.Time { return tNow }})
	require.NoError(t, err)
	t.Cleanup(func() { _ = r.Close() })
	return r
}

func TestCRLAfterKeyRollover(t *testing.T) {
	cscaOld := newCSCA(t, kindP256, "CSCA", "SE")
	cscaNew := issue(t, cscaSpec("CSCA", "SE"), newKey(t, kindP256), nil) // same name, new key
	dsc := newDSC(t, kindP256, cscaOld, "SE")

	crlDER, err := x509.CreateRevocationList(testRand{}, &x509.RevocationList{
		Number: big.NewInt(1), ThisUpdate: t2020, NextUpdate: t2020.Add(24 * time.Hour),
		RevokedCertificateEntries: []x509.RevocationListEntry{{SerialNumber: dsc.cert.SerialNumber, RevocationTime: t2020}},
	}, cscaNew.cert, cscaNew.key.ec) // signed with the NEW key
	require.NoError(t, err)

	anchors, crls := t.TempDir(), t.TempDir()
	writeAnchors(t, anchors, map[string][]*node{"SWE": {cscaOld, cscaNew}})
	require.NoError(t, os.MkdirAll(filepath.Join(crls, "SWE"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(crls, "SWE", "current.crl"), crlDER, 0o644))
	r, err := New(Config{AnchorsDir: anchors, CRLsDir: crls, Logger: quietLogger(), Now: func() time.Time { return tNow }})
	require.NoError(t, err)
	t.Cleanup(func() { _ = r.Close() })

	requireDeny(t, eval(t, r, req("SWE", []*node{dsc}, nil)), CodeRevoked)
}

func TestCRLAuthority(t *testing.T) {
	cscaOld := newCSCA(t, kindP256, "CSCA", "SE")
	cscaNew := issue(t, cscaSpec("CSCA", "SE"), newKey(t, kindP256), nil)
	dscOld := newDSC(t, kindP256, cscaOld, "SE")
	dscNew := newDSC(t, kindP256, cscaNew, "SE")
	stranger := issue(t, cscaSpec("CSCA", "SE"), newKey(t, kindP256), nil) // same name, never reviewed
	otherName := issue(t, cscaSpec("Other CA", "SE"), newKey(t, kindP256), nil)
	deu := issue(t, cscaSpec("CSCA", "DE"), newKey(t, kindP256), nil) // same DN apart from C
	both := map[string][]*node{"SWE": {cscaOld, cscaNew}}

	t.Run("old-key and new-key DSCs are both revoked by the new-key CRL", func(t *testing.T) {
		r := regWithCRL(t, both, "SWE", mkSignedCRL(t, cscaNew, cscaNew, dscOld, dscNew))
		requireDeny(t, eval(t, r, req("SWE", []*node{dscOld}, nil)), CodeRevoked)
		requireDeny(t, eval(t, r, req("SWE", []*node{dscNew}, nil)), CodeRevoked)
	})
	t.Run("old-key CRL still revokes (unchanged)", func(t *testing.T) {
		r := regWithCRL(t, both, "SWE", mkSignedCRL(t, cscaOld, cscaOld, dscOld))
		requireDeny(t, eval(t, r, req("SWE", []*node{dscOld}, nil)), CodeRevoked)
	})
	t.Run("unlisted DSC is still allowed", func(t *testing.T) {
		good := newDSC(t, kindP256, cscaOld, "SE")
		r := regWithCRL(t, both, "SWE", mkSignedCRL(t, cscaNew, cscaNew, dscOld))
		require.True(t, eval(t, r, req("SWE", []*node{good}, nil)).Decision)
	})
	t.Run("CRL signed by an unreviewed same-name key is ignored", func(t *testing.T) {
		r := regWithCRL(t, both, "SWE", mkSignedCRL(t, stranger, cscaNew, dscOld))
		require.True(t, eval(t, r, req("SWE", []*node{dscOld}, nil)).Decision)
	})
	t.Run("CRL signed by an unrelated key under another name is ignored", func(t *testing.T) {
		r := regWithCRL(t, map[string][]*node{"SWE": {cscaOld, otherName}}, "SWE", mkSignedCRL(t, otherName, otherName, dscOld))
		require.True(t, eval(t, r, req("SWE", []*node{dscOld}, nil)).Decision, "issuer name differs from the DSC's issuer")
	})
	t.Run("another state's anchor is not an authority", func(t *testing.T) {
		// CRL says issuer 'CSCA' (C=SE) but is signed by the DEU anchor's key; only
		// DEU holds that key, so it cannot be verified against any SWE anchor.
		crl := mkSignedCRL(t, deu, cscaNew, dscOld)
		r := regWithCRL(t, map[string][]*node{"SWE": {cscaOld, cscaNew}, "DEU": {deu}}, "SWE", crl)
		require.True(t, eval(t, r, req("SWE", []*node{dscOld}, nil)).Decision)
	})
	t.Run("same-name anchor of another country is not used", func(t *testing.T) {
		// New key exists ONLY as a DEU anchor with the same CN; the SWE side
		// has just the old key. A CRL under the SWE name signed by it is ignored.
		newKeyDE := &node{key: cscaNew.key, cert: cscaNew.cert, spec: cscaNew.spec}
		r := regWithCRL(t, map[string][]*node{"SWE": {cscaOld}, "DEU": {deu, newKeyDE}}, "SWE", mkSignedCRL(t, cscaNew, cscaNew, dscOld))
		_ = deu
		require.True(t, eval(t, r, req("SWE", []*node{dscOld}, nil)).Decision)
	})
	t.Run("issuer-name mismatch: CRL for another issuer name does not apply", func(t *testing.T) {
		r := regWithCRL(t, map[string][]*node{"SWE": {cscaOld, cscaNew, otherName}}, "SWE", mkSignedCRL(t, otherName, otherName, dscOld))
		require.True(t, eval(t, r, req("SWE", []*node{dscOld}, nil)).Decision)
	})
	t.Run("stale CRL still counts for a positive hit (unchanged)", func(t *testing.T) {
		// NextUpdate is 2020-01-02, long before tNow
		r := regWithCRL(t, both, "SWE", mkSignedCRL(t, cscaNew, cscaNew, dscOld))
		requireDeny(t, eval(t, r, req("SWE", []*node{dscOld}, nil)), CodeRevoked)
	})
}

// A DSC reached through a link certificate: DSC -> link(new key, same name,
// signed by the old anchor). Only the OLD anchor is reviewed; the new key is
// known only from the request-supplied link, which sits on the validated path.
func TestCRLAuthorityViaLinkCertificate(t *testing.T) {
	cscaOld := newCSCA(t, kindP256, "CSCA", "SE")
	newKP := newKey(t, kindP256)
	link := issue(t, cscaSpec("CSCA", "SE"), newKP, cscaOld) // new key, same name, signed by old
	newRoot := issue(t, cscaSpec("CSCA", "SE"), newKP, nil)  // the same new key as a self-signed root
	dsc := newDSC(t, kindP256, newRoot, "SE")                // issued under the new key
	signedByNew := mkSignedCRL(t, newRoot, newRoot, dsc)

	t.Run("CRL signed by the new key, link on the path", func(t *testing.T) {
		r := regWithCRL(t, map[string][]*node{"SWE": {cscaOld}}, "SWE", signedByNew)
		requireDeny(t, eval(t, r, req("SWE", []*node{dsc, link}, nil)), CodeRevoked)
	})
	t.Run("new root also an anchor", func(t *testing.T) {
		r := regWithCRL(t, map[string][]*node{"SWE": {cscaOld, newRoot}}, "SWE", signedByNew)
		requireDeny(t, eval(t, r, req("SWE", []*node{dsc, link}, nil)), CodeRevoked)
	})
	t.Run("CRL revoking the link certificate itself, signed by the old key", func(t *testing.T) {
		r := regWithCRL(t, map[string][]*node{"SWE": {cscaOld}}, "SWE", mkSignedCRL(t, cscaOld, cscaOld, link))
		requireDeny(t, eval(t, r, req("SWE", []*node{dsc, link}, nil)), CodeRevoked)
	})
	t.Run("a link that is not on the validated path is no authority", func(t *testing.T) {
		// DSC chains to no reviewed anchor via this link (link signed by a stranger)
		stranger := newCSCA(t, kindP256, "CSCA", "SE")
		fakeLink := issue(t, cscaSpec("CSCA", "SE"), newKP, stranger)
		r := regWithCRL(t, map[string][]*node{"SWE": {cscaOld}}, "SWE", signedByNew)
		resp := eval(t, r, req("SWE", []*node{dsc, fakeLink}, nil))
		require.False(t, resp.Decision) // no chain at all
	})
}
