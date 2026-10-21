package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"io"
	"math/big"
	"net/http"
	"os"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/sirosfoundation/g119612/pkg/logging"
	"github.com/sirosfoundation/go-trust/pkg/authzen"
	"github.com/sirosfoundation/go-trust/pkg/config"
	"github.com/sirosfoundation/go-trust/pkg/registry"
	"github.com/sirosfoundation/go-trust/pkg/registry/static"
)

// jwksRoundTripper serves a fixed JWKS for any host, so the whitelist loads its
// keys through the real Refresh path without the network.
type jwksRoundTripper struct{ jwks []byte }

func (j jwksRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.URL.Path == "/.well-known/jwks.json" {
		return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": {"application/json"}},
			Body: io.NopCloser(bytes.NewReader(j.jwks)), Request: r}, nil
	}
	return &http.Response{StatusCode: 404, Body: io.NopCloser(strings.NewReader("")), Request: r}, nil
}

type gdcFixture struct {
	leafB64 string
	otherB6 string
	mgr     func(t *testing.T, strategy registry.ResolutionStrategy, withPolicies bool) *registry.RegistryManager
}

func newGDCFixture(t *testing.T) gdcFixture {
	t.Helper()
	mk := func(dns string) (*x509.Certificate, *ecdsa.PrivateKey) {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		tmpl := &x509.Certificate{
			SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: dns}, DNSNames: []string{dns},
			NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature,
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
		if err != nil {
			t.Fatal(err)
		}
		c, _ := x509.ParseCertificate(der)
		return c, key
	}
	leaf, key := mk("verifier.example.com")
	other, _ := mk("verifier.example.com") // same name, different key: not pinned

	ecdhKey, err := key.PublicKey.ECDH()
	if err != nil {
		t.Fatal(err)
	}
	raw := ecdhKey.Bytes()
	jwks, _ := json.Marshal(map[string]interface{}{"keys": []interface{}{map[string]interface{}{
		"kty": "EC", "crv": "P-256", "use": "sig", "kid": "k1",
		"x": base64.RawURLEncoding.EncodeToString(raw[1:33]),
		"y": base64.RawURLEncoding.EncodeToString(raw[33:]),
	}}})

	yamlBytes, err := os.ReadFile("../../docs/examples/gdc-verifier-ids-policies.yaml")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	path := dir + "/config.yaml"
	if err := os.WriteFile(path, yamlBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}

	return gdcFixture{
		leafB64: base64.StdEncoding.EncodeToString(leaf.Raw),
		otherB6: base64.StdEncoding.EncodeToString(other.Raw),
		mgr: func(t *testing.T, strategy registry.ResolutionStrategy, withPolicies bool) *registry.RegistryManager {
			t.Helper()
			wl := static.NewWhitelistRegistry(
				static.WithWhitelistName("sirosid-gdc Fly whitelist"),
				static.WithHTTPClient(&http.Client{Transport: jwksRoundTripper{jwks}}),
				static.WithWhitelistConfig(static.WhitelistConfig{
					Lists: map[string][]string{
						"verifiers":   {"https://verifier.example.com"},
						"pid-issuers": {"https://issuer.example.com"},
						// Catch-all list: lets the verifier through for actions without
						// a list of their own, so unknown/other actions are exercised
						// on a positive path too, not just on denies.
						"trusted_subjects": {"https://verifier.example.com"},
					},
					Actions: map[string]string{
						"credential-verifier": "verifiers", "verifier": "verifiers",
						"credential-issuer": "pid-issuers", "mdoc-issuer": "pid-issuers", "mdoc-issuer-auth": "pid-issuers",
					},
				}))
			if err := wl.Refresh(context.Background()); err != nil {
				t.Fatal(err)
			}
			mgr := registry.NewRegistryManager(strategy, 10*time.Second)
			mgr.Register(wl)
			mgr.Register(static.NewNeverTrustedRegistry("stand-in for mdociaca/mdocrical/didweb"))
			if withPolicies {
				configurePoliciesFromConfig(cfg, mgr, logging.SilentLogger())
			}
			return mgr
		},
	}
}

func gdcReq(action, clientID, b64 string) *authzen.EvaluationRequest {
	req := &authzen.EvaluationRequest{
		Subject:  authzen.Subject{Type: "key", ID: clientID},
		Resource: authzen.Resource{Type: "x5c", ID: clientID, Key: []interface{}{b64}},
	}
	if action != "" {
		req.Action = &authzen.Action{Name: action}
	}
	return req
}

// normalise strips what legitimately differs between two evaluations: timings and
// the policy name that the policy path adds to a positive reason.
func normalise(t *testing.T, resp *authzen.EvaluationResponse) string {
	t.Helper()
	b, _ := json.Marshal(resp)
	var m map[string]interface{}
	_ = json.Unmarshal(b, &m)
	var scrub func(v interface{})
	scrub = func(v interface{}) {
		switch x := v.(type) {
		case map[string]interface{}:
			delete(x, "resolution_ms")
			delete(x, "duration_ms")
			delete(x, "policy")
			delete(x, "verifier_ids")
			for _, c := range x {
				scrub(c)
			}
			// Parallel strategies list registries in completion order.
			for _, key := range []string{"all_results", "registry_results"} {
				if rs, ok := x[key].([]interface{}); ok {
					sort.Slice(rs, func(i, j int) bool {
						a, _ := json.Marshal(rs[i])
						b, _ := json.Marshal(rs[j])
						return string(a) < string(b)
					})
				}
			}
		case []interface{}:
			for _, c := range x {
				scrub(c)
			}
		}
	}
	scrub(m)
	out, _ := json.Marshal(m)
	return string(out)
}

// The shipped gdc policies snippet adds verifier_ids for the verifier actions and
// changes nothing else for any other action, whichever strategy the PDP uses.
func TestGDCPoliciesSnippet_OnlyAddsVerifierIDs(t *testing.T) {
	fx := newGDCFixture(t)
	const rp = "x509_san_dns:verifier.example.com"

	type tc struct {
		action, clientID, cert string
		wantIDs                bool
	}
	cases := []tc{
		{"credential-verifier", rp, fx.leafB64, true},
		{"verifier", rp, fx.leafB64, true},
		{"credential-verifier", rp, fx.otherB6, false}, // key not pinned: deny
		{"credential-issuer", "https://issuer.example.com", fx.leafB64, false},
		{"mdoc-issuer", "https://issuer.example.com", fx.leafB64, false},
		{"mdoc-issuer-auth", "https://issuer.example.com", fx.leafB64, false},
		{"credential-issuer", rp, fx.leafB64, false},  // verifier subject asking an issuer action
		{"some-future-action", rp, fx.leafB64, false}, // unknown action
		{"", rp, fx.leafB64, false},                   // no action at all
		{"mdoc-issuer", "https://stranger.example", fx.leafB64, false},
	}
	for _, strategy := range []registry.ResolutionStrategy{registry.FirstMatch, registry.Sequential, registry.AllRegistries, registry.BestMatch} {
		for _, c := range cases {
			name := string(strategy) + "/" + c.action + "/" + c.clientID
			t.Run(name, func(t *testing.T) {
				before, err := fx.mgr(t, strategy, false).Evaluate(context.Background(), gdcReq(c.action, c.clientID, c.cert))
				if err != nil {
					t.Fatal(err)
				}
				after, err := fx.mgr(t, strategy, true).Evaluate(context.Background(), gdcReq(c.action, c.clientID, c.cert))
				if err != nil {
					t.Fatal(err)
				}
				if before.Decision != after.Decision {
					t.Fatalf("decision changed %v -> %v", before.Decision, after.Decision)
				}
				if b, a := normalise(t, before), normalise(t, after); b != a {
					t.Fatalf("response changed beyond verifier_ids/policy name:\nbefore %s\nafter  %s", b, a)
				}
				if len(before.Context.VerifierIDs) != 0 {
					t.Fatal("verifier_ids present without a policies section")
				}
				got := after.Context.VerifierIDs
				if c.wantIDs {
					if !after.Decision || len(got) != 1 || got[0].Type != "x509_san_dns" ||
						got[0].ID != "verifier.example.com" || got[0].Basis != "client-id-binding" {
						t.Fatalf("verifier_ids = %+v, want one x509_san_dns verifier.example.com", got)
					}
				} else if len(got) != 0 {
					t.Fatalf("unexpected verifier_ids %+v", got)
				}
			})
		}
	}
}

// Documents the routing rules a policies section introduces, which the sirosid-dev
// rollout relies on (see docs/examples/gdc-verifier-ids-policies.yaml).
func TestPoliciesRouting_UnknownActionRules(t *testing.T) {
	fx := newGDCFixture(t)
	const rp = "x509_san_dns:verifier.example.com"

	// fail_closed_on_unknown_action turns every unlisted action into a deny: this
	// is why the gdc snippet must not set it.
	mgr := fx.mgr(t, registry.FirstMatch, true)
	mgr.GetPolicyManager().SetFailClosedOnUnknownAction(true)
	resp, _ := mgr.Evaluate(context.Background(), gdcReq("mdoc-issuer", "https://issuer.example.com", fx.leafB64))
	if resp.Decision {
		t.Fatal("fail-closed must deny an action with no policy")
	}
	resp, _ = mgr.Evaluate(context.Background(), gdcReq("credential-verifier", rp, fx.leafB64))
	if !resp.Decision || len(resp.Context.VerifierIDs) != 1 {
		t.Fatalf("a listed action must still work under fail-closed: %+v", resp)
	}

	// default_policy applies to unlisted actions (and to requests with no action).
	mgr = fx.mgr(t, registry.FirstMatch, true)
	pm := mgr.GetPolicyManager()
	if err := pm.SetDefaultPolicy(pm.GetPolicy("verifier")); err != nil {
		t.Fatal(err)
	}
	resp, _ = mgr.Evaluate(context.Background(), gdcReq("some-future-action", rp, fx.leafB64))
	if !resp.Decision || len(resp.Context.VerifierIDs) != 1 {
		t.Fatalf("default_policy should have applied to an unlisted action: %+v", resp)
	}
}
