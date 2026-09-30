package emrtd

import (
	"context"
	"crypto/x509"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
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
		r := build(t, map[string][]byte{"a.crl": mkCRL(t, csca, dsc)})
		requireDeny(t, eval(t, r, req("SWE", []*node{dsc}, map[string]interface{}{"signing_time": "2020-06-01T00:00:00Z"})), CodeRevoked)
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
