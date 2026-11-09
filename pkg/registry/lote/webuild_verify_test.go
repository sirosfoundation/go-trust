package lote_test

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/sirosfoundation/go-trust/pkg/authzen"
	"github.com/sirosfoundation/go-trust/pkg/registry/lote"
)

// Signature verification of the WE BUILD WP4 lists, offline: the JSON LoTL and
// the Raidiam LoTE carry an embedded {protected, signature} object, the XML
// LoTEs and classic TSLs an enveloped XMLDSig. Every list is self-signed by its
// publisher, so the signer certificates are the trust anchors.

func webuildAnchors(t *testing.T, names ...string) lote.LoTETrustAnchorProvider {
	t.Helper()
	pool := x509.NewCertPool()
	for _, n := range names {
		data, err := os.ReadFile(filepath.Join(webuildDir, "anchors", n+".pem"))
		require.NoError(t, err)
		block, _ := pem.Decode(data)
		require.NotNil(t, block, n)
		cert, err := x509.ParseCertificate(block.Bytes)
		require.NoError(t, err)
		pool.AddCert(cert)
	}
	return lote.NewStaticTrustAnchorProvider(pool)
}

var allWebuildAnchors = []string{
	"lotl-signer", "wrpac-providers-raidiam-signer",
	"eaa-provider-credimi", "eaa-provider-idunion", "eaa-provider-nxd-foundation",
	"qeaa-provider-credimi", "qeaa-provider-idunion", "qeaa-provider-nxd-foundation",
	"pid-provider-idunion", "pub-eaa-provider-idunion", "ebwoid-provider-idunion",
	"wallet-provider-idunion", "wrpac-provider-idunion", "wrprc-provider-idunion",
}

func writeVariant(t *testing.T, name string, mutate func(string) string) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(webuildDir, name))
	require.NoError(t, err)
	out := mutate(string(raw))
	require.NotEqual(t, string(raw), out, "mutation did not change %s", name)
	p := filepath.Join(t.TempDir(), name)
	require.NoError(t, os.WriteFile(p, []byte(out), 0o600))
	return p
}

// snapshotTransport makes every published list URL resolve to its local
// snapshot, so a verified LoTL can be resolved offline with its content (and
// so its signature) untouched. It replaces http.DefaultTransport for the test:
// do not use with t.Parallel.
func snapshotTransport(t *testing.T) {
	t.Helper()
	srcs, err := os.ReadFile(filepath.Join(webuildDir, "sources.json"))
	require.NoError(t, err)
	var byFile map[string]string
	require.NoError(t, json.Unmarshal(srcs, &byFile))
	byURL := map[string]string{}
	for f, u := range byFile {
		byURL[u] = filepath.Join(webuildDir, f)
	}
	prev := http.DefaultTransport
	http.DefaultTransport = roundTripFunc(func(req *http.Request) (*http.Response, error) {
		f, ok := byURL[req.URL.String()]
		if !ok {
			return &http.Response{StatusCode: http.StatusNotFound, Body: http.NoBody, Request: req}, nil
		}
		data, err := os.ReadFile(f)
		if err != nil {
			return nil, err
		}
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(bytes.NewReader(data)), Request: req}, nil
	})
	t.Cleanup(func() { http.DefaultTransport = prev })
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// #238: the JSON LoTL's embedded signature object verifies, and the whole
// LoTL then resolves with every pointer target verified too (XML LoTEs by
// XMLDSig, the Raidiam LoTE by its embedded JWS, classic TSLs by XMLDSig).
func TestWebuildWP4_VerifiedLoTLResolves(t *testing.T) {
	snapshotTransport(t)
	path := filepath.Join(webuildDir, "lotl.json")
	var logs bytes.Buffer
	reg, err := lote.New(lote.Config{
		Now: webuildNow, Name: "verified", LoTLSources: []string{path}, VerifyJWS: true,
		TrustAnchorProvider: webuildAnchors(t, allWebuildAnchors...),
		Logger:              slog.New(slog.NewTextHandler(&logs, nil)),
	})
	require.NoError(t, err)
	require.True(t, reg.Healthy())
	// Every pointer (7 LoTEs and 6 classic TSLs) verified; none was skipped.
	assert.NotContains(t, logs.String(), "source skipped", logs.String())
	assert.Equal(t, 13, strings.Count(logs.String(), "signature verified")+strings.Count(logs.String(), "XMLDSig verified")-1, logs.String())

	for _, tc := range webuildLoTEs {
		l := loadWebuildLoTE(t, tc.file)
		id := l.TrustedEntitiesList[0].TrustedEntityInformation.TEInformationURI[0].URIValue
		resp, err := reg.Evaluate(context.Background(), &authzen.EvaluationRequest{
			Subject:  authzen.Subject{Type: "key", ID: id},
			Resource: authzen.Resource{Type: "x5c", ID: id},
		})
		require.NoError(t, err)
		assert.Truef(t, resp.Decision, "%s: %s not resolvable through the verified LoTL", tc.file, id)
	}
}

// Verification is anchored: the LoTL signer alone does not vouch for the
// lists it points to, so with only that anchor every pointer target is
// skipped and nothing is trusted.
func TestWebuildWP4_VerifiedLoTLPointerNeedsOwnAnchor(t *testing.T) {
	snapshotTransport(t)
	path := filepath.Join(webuildDir, "lotl.json")
	reg, err := lote.New(lote.Config{
		Now: webuildNow, Name: "lotl-anchor-only", LoTLSources: []string{path}, VerifyJWS: true,
		TrustAnchorProvider: webuildAnchors(t, "lotl-signer"),
	})
	require.NoError(t, err)
	l := loadWebuildLoTE(t, "pid-providers.xml")
	id := l.TrustedEntitiesList[0].TrustedEntityInformation.TEInformationURI[0].URIValue
	resp, err := reg.Evaluate(context.Background(), &authzen.EvaluationRequest{
		Subject:  authzen.Subject{Type: "key", ID: id},
		Resource: authzen.Resource{Type: "x5c", ID: id},
	})
	require.NoError(t, err)
	assert.False(t, resp.Decision)
}

func TestWebuildWP4_LoTLEmbeddedSignatureRejected(t *testing.T) {
	cases := map[string]struct {
		mutate  func(string) string
		anchors []string
	}{
		"content changed": {func(s string) string {
			return strings.Replace(s, "WE BUILD WP4 Trust Group", "WE BUILD WP4 Trust Grouq", 1)
		}, []string{"lotl-signer"}},
		"wrong anchor": {func(s string) string { return s + " " }, []string{"eaa-provider-credimi"}},
		"signature removed": {func(s string) string {
			i := strings.Index(s, `"signature"`)
			return s[:i] + `"x"` + s[i+len(`"signature"`):]
		}, []string{"lotl-signer"}},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			p := writeVariant(t, "lotl.json", tc.mutate)
			_, err := lote.New(lote.Config{
				Now: webuildNow, LoTLSources: []string{p}, VerifyJWS: true,
				TrustAnchorProvider: webuildAnchors(t, tc.anchors...),
			})
			require.Error(t, err)
		})
	}
}

// The signed bytes are a canonical re-serialisation, so formatting and member
// order in the published file do not matter: a re-indented, re-ordered copy of
// the LoTL verifies as well.
func TestWebuildWP4_LoTLVerifiesAfterReformatting(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(webuildDir, "lotl.json"))
	require.NoError(t, err)
	var doc map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(raw, &doc))
	// Signature first, compact: both differ from the published layout.
	reformatted := `{"signature":` + string(doc["signature"]) + `,"LoTE":` + string(doc["LoTE"]) + `}`
	var compact bytes.Buffer
	require.NoError(t, json.Compact(&compact, []byte(reformatted)))
	p := filepath.Join(t.TempDir(), "lotl.json")
	require.NoError(t, os.WriteFile(p, compact.Bytes(), 0o600))


	snapshotTransport(t) // pointers resolve offline to the snapshots
	_, err = lote.New(lote.Config{
		Now: webuildNow, LoTLSources: []string{p}, VerifyJWS: true,
		TrustAnchorProvider: webuildAnchors(t, "lotl-signer"),
	})
	require.NoError(t, err)
}

// The Raidiam LoTE is a JSON LoTE with the same embedded signature form.
func TestWebuildWP4_RaidiamLoTEVerifies(t *testing.T) {
	src := filepath.Join(webuildDir, "wrpac-providers-raidiam.json")
	_, err := lote.New(lote.Config{Now: webuildNow, Sources: []string{src}, VerifyJWS: true,
		TrustAnchorProvider: webuildAnchors(t, "wrpac-providers-raidiam-signer")})
	require.NoError(t, err)

	_, err = lote.New(lote.Config{Now: webuildNow, Sources: []string{src}, VerifyJWS: true,
		TrustAnchorProvider: webuildAnchors(t, "lotl-signer")})
	require.Error(t, err)

	tampered := writeVariant(t, "wrpac-providers-raidiam.json", func(s string) string {
		return strings.Replace(s, `"lang": "en"`, `"lang": "sv"`, 1)
	})
	_, err = lote.New(lote.Config{Now: webuildNow, Sources: []string{tampered}, VerifyJWS: true,
		TrustAnchorProvider: webuildAnchors(t, "wrpac-providers-raidiam-signer")})
	require.Error(t, err)
}

// #239: XML LoTEs are verified by their enveloped XMLDSig, never handed to the
// JWS parser.
func TestWebuildWP4_XMLLoTEsVerify(t *testing.T) {
	for _, tc := range webuildLoTEs {
		if !strings.HasSuffix(tc.file, ".xml") {
			continue
		}
		t.Run(tc.file, func(t *testing.T) {
			reg, err := lote.New(lote.Config{
				Now: webuildNow, Name: tc.file, Sources: []string{filepath.Join(webuildDir, tc.file)},
				VerifyJWS: true, TrustAnchorProvider: webuildAnchors(t, allWebuildAnchors...),
			})
			require.NoError(t, err)
			l := loadWebuildLoTE(t, tc.file)
			id := l.TrustedEntitiesList[0].TrustedEntityInformation.TEInformationURI[0].URIValue
			resp, err := reg.Evaluate(context.Background(), &authzen.EvaluationRequest{
				Subject:  authzen.Subject{Type: "key", ID: id},
				Resource: authzen.Resource{Type: "x5c", ID: id},
			})
			require.NoError(t, err)
			assert.True(t, resp.Decision)
		})
	}
}

func TestWebuildWP4_XMLLoTERejected(t *testing.T) {
	const file = "pub-eaa-providers.xml"
	cfg := func(src string, anchors ...string) lote.Config {
		return lote.Config{Now: webuildNow, Sources: []string{src}, VerifyJWS: true, TrustAnchorProvider: webuildAnchors(t, anchors...)}
	}
	orig := filepath.Join(webuildDir, file)

	t.Run("wrong anchor", func(t *testing.T) {
		_, err := lote.New(cfg(orig, "pid-provider-idunion", "lotl-signer")) // the list is signed by pub-eaa-provider-idunion
		// pid-provider-idunion is a different certificate even though the subject matches.
		require.Error(t, err)
		assert.NotContains(t, err.Error(), "cannot parse as compact JWT")
	})
	t.Run("tampered content", func(t *testing.T) {
		p := writeVariant(t, file, func(s string) string {
			return strings.Replace(s, "<LoTESequenceNumber>1<", "<LoTESequenceNumber>2<", 1)
		})
		_, err := lote.New(cfg(p, "pub-eaa-provider-idunion"))
		require.Error(t, err)
	})
	t.Run("signature stripped", func(t *testing.T) {
		p := writeVariant(t, file, func(s string) string {
			i := strings.Index(s, "<ds:Signature")
			j := strings.Index(s, "</ds:Signature>")
			if i < 0 || j < 0 {
				i = strings.Index(s, "<Signature")
				j = strings.Index(s, "</Signature>")
				return s[:i] + s[j+len("</Signature>"):]
			}
			return s[:i] + s[j+len("</ds:Signature>"):]
		})
		_, err := lote.New(cfg(p, "pub-eaa-provider-idunion"))
		require.Error(t, err)
	})
}
