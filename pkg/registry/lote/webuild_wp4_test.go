package lote_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"github.com/sirosfoundation/go-trust/pkg/authzenclient"
	"github.com/sirosfoundation/go-trust/pkg/testserver"
	"math/big"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/sirosfoundation/g119612/pkg/etsi119602"
	"github.com/sirosfoundation/go-trust/pkg/authzen"
	"github.com/sirosfoundation/go-trust/pkg/registry/lote"
)

// Snapshots of the WE BUILD WP4 trust infrastructure, taken from the LoTL
// published by github.com/webuild-consortium/wp4-trust-group
// (https://webuild-consortium.github.io/wp4-trust-group/) and the lists it
// points to. See testdata/webuild-wp4/sources.json for the origin of each file.
const webuildDir = "../../../testdata/webuild-wp4"

// webuildNow pins the clock to when the snapshots were taken, so the tests do
// not start failing as the lists pass their NextUpdate.
func webuildNow() time.Time { return time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC) }

type webuildList struct {
	file     string
	loteType string
	entities int // entries in the snapshot
}

var webuildLoTEs = []webuildList{
	{"wallet-providers.xml", "http://uri.etsi.org/19602/LoTEType/EUWalletProvidersList", 24},
	{"registrars.xml", "http://uri.etsi.org/19602/LoTEType/EURegistrarsAndRegistersList", 8},
	{"wrprc-providers.xml", "http://uri.etsi.org/19602/LoTEType/EUWRPRCProvidersList", 3},
	{"pid-providers.xml", "http://uri.etsi.org/19602/LoTEType/EUPIDProvidersList", 11},
	{"pub-eaa-providers.xml", "http://uri.etsi.org/19602/LoTEType/EUPubEAAProvidersList", 11},
	{"wrpac-providers.xml", "http://uri.etsi.org/19602/LoTEType/EUWRPACProvidersList", 9},
	{"wrpac-providers-raidiam.json", "http://uri.etsi.org/19602/LoTEType/EUWRPACProvidersList", 1},
}

func loadWebuildLoTE(t *testing.T, file string) *etsi119602.ListOfTrustedEntities {
	t.Helper()
	l, err := etsi119602.FetchLoTE(filepath.Join(webuildDir, file), nil)
	require.NoError(t, err)
	return l
}

func TestWebuildWP4_LoTEsParse(t *testing.T) {
	for _, tc := range webuildLoTEs {
		t.Run(tc.file, func(t *testing.T) {
			l := loadWebuildLoTE(t, tc.file)
			assert.Equal(t, tc.loteType, l.ListAndSchemeInformation.LoTEType)
			assert.Len(t, l.TrustedEntitiesList, tc.entities)

			reg, err := lote.New(lote.Config{Now: webuildNow, Name: tc.file, Sources: []string{filepath.Join(webuildDir, tc.file)}})
			require.NoError(t, err)
			assert.True(t, reg.Healthy())
		})
	}
}

// Every certificate a WP4 list publishes must be accepted as the x5c of its
// own entity, addressed by the identifier the list gives that entity.
func TestWebuildWP4_EveryListedCertificateIsTrusted(t *testing.T) {
	for _, tc := range webuildLoTEs {
		t.Run(tc.file, func(t *testing.T) {
			reg, err := lote.New(lote.Config{Now: webuildNow, Name: tc.file, Sources: []string{filepath.Join(webuildDir, tc.file)}})
			require.NoError(t, err)
			l := loadWebuildLoTE(t, tc.file)

			checked := 0
			for _, ent := range l.TrustedEntitiesList {
				info := ent.TrustedEntityInformation
				id := info.TEInformationURI[0].URIValue
				for _, svc := range ent.TrustedEntityServices {
					for _, c := range svc.ServiceInformation.ServiceDigitalIdentity.X509Certificates {
						resp, err := reg.Evaluate(context.Background(), &authzen.EvaluationRequest{
							Subject:  authzen.Subject{Type: "key", ID: id},
							Resource: authzen.Resource{Type: "x5c", ID: id, Key: []interface{}{c.Val}},
						})
						require.NoError(t, err)
						assert.Truef(t, resp.Decision, "%s (%s): listed certificate not trusted: %v",
							info.TEName[0].Value, id, resp.Context)
						checked++
					}
				}
			}
			assert.NotZero(t, checked)
		})
	}
}

// A certificate listed for one entity must not be accepted for another list's
// registry: PID providers are not wallet providers.
func TestWebuildWP4_CertificateNotTrustedInOtherList(t *testing.T) {
	pid, err := lote.New(lote.Config{Now: webuildNow, Sources: []string{filepath.Join(webuildDir, "pid-providers.xml")}})
	require.NoError(t, err)
	wallets := loadWebuildLoTE(t, "wallet-providers.xml")
	ent := wallets.TrustedEntitiesList[0]
	id := ent.TrustedEntityInformation.TEInformationURI[0].URIValue
	cert := ent.TrustedEntityServices[0].ServiceInformation.ServiceDigitalIdentity.X509Certificates[0].Val
	_, derr := base64.StdEncoding.DecodeString(cert)
	require.NoError(t, derr)

	resp, err := pid.Evaluate(context.Background(), &authzen.EvaluationRequest{
		Subject:  authzen.Subject{Type: "key", ID: id},
		Resource: authzen.Resource{Type: "x5c", ID: id, Key: []interface{}{cert}},
	})
	require.NoError(t, err)
	assert.False(t, resp.Decision)
}

// localLoTL copies the published LoTL into a temp dir with every pointer
// rewritten to the local snapshot of the list it points to, so LoTL
// resolution runs offline against the real document structure.
func localLoTL(t *testing.T, name string) (path string, pointers int) {
	t.Helper()
	srcs, err := os.ReadFile(filepath.Join(webuildDir, "sources.json"))
	require.NoError(t, err)
	var byFile map[string]string
	require.NoError(t, json.Unmarshal(srcs, &byFile))
	byURL := map[string]string{}
	for f, u := range byFile {
		byURL[u] = f
	}

	data, err := os.ReadFile(filepath.Join(webuildDir, name))
	require.NoError(t, err)
	out := string(data)
	for u, f := range byURL {
		abs, err := filepath.Abs(filepath.Join(webuildDir, f))
		require.NoError(t, err)
		if strings.Contains(out, u) {
			pointers++
		}
		out = strings.ReplaceAll(out, u, abs)
	}
	path = filepath.Join(t.TempDir(), name)
	require.NoError(t, os.WriteFile(path, []byte(out), 0o600))
	return path, pointers
}

// The LoTL is published as both JSON and XML; both must resolve to the same
// set of lists and make the entities of the LoTE-typed pointers available.
func TestWebuildWP4_LoTLResolves(t *testing.T) {
	for _, name := range []string{"lotl.json", "lotl.xml"} {
		t.Run(name, func(t *testing.T) {
			if name == "lotl.xml" {
				// The XML LoTL is a TS 119 612 TrustServiceStatusList
				// (TSLType EUlistofthelists), not a TS 119 602 document. It must
				// be refused outright rather than load as an empty, healthy list.
				_, err := lote.New(lote.Config{Now: webuildNow, Name: name, LoTLSources: []string{filepath.Join(webuildDir, name)}})
				require.Error(t, err)
				return
			}
			path, pointers := localLoTL(t, name)
			assert.Equal(t, 13, pointers, "every pointer in the LoTL must map to a snapshot")

			reg, err := lote.New(lote.Config{Now: webuildNow, Name: name, LoTLSources: []string{path}})
			require.NoError(t, err)
			require.True(t, reg.Healthy())

			// One listed entity per LoTE-typed pointer, addressed by its identifier.
			for _, tc := range webuildLoTEs {
				l := loadWebuildLoTE(t, tc.file)
				ent := l.TrustedEntitiesList[0]
				id := ent.TrustedEntityInformation.TEInformationURI[0].URIValue
				resp, err := reg.Evaluate(context.Background(), &authzen.EvaluationRequest{
					Subject:  authzen.Subject{Type: "key", ID: id},
					Resource: authzen.Resource{Type: "x5c", ID: id},
				})
				require.NoError(t, err)
				assert.Truef(t, resp.Decision, "%s: %s not resolvable through the LoTL: %v", tc.file, id, resp.Context)
			}
		})
	}
}

// Full round-trip through the AuthZEN HTTP API, with the LoTL resolved to all
// WP4 LoTEs and a certificate listed in one of them.
func TestWebuildWP4_AuthZENRoundTrip(t *testing.T) {
	path, _ := localLoTL(t, "lotl.json")
	reg, err := lote.New(lote.Config{Now: webuildNow, Name: "webuild-wp4", LoTLSources: []string{path}})
	require.NoError(t, err)
	srv := testserver.New(testserver.WithRegistry(reg))
	defer srv.Close()
	client := authzenclient.New(srv.URL())

	l := loadWebuildLoTE(t, "pid-providers.xml")
	ent := l.TrustedEntitiesList[0]
	id := ent.TrustedEntityInformation.TEInformationURI[0].URIValue
	cert := ent.TrustedEntityServices[0].ServiceInformation.ServiceDigitalIdentity.X509Certificates[0].Val

	resp, err := client.Evaluate(context.Background(), &authzen.EvaluationRequest{
		Subject:  authzen.Subject{Type: "key", ID: id},
		Resource: authzen.Resource{Type: "x5c", ID: id, Key: []interface{}{cert}},
	})
	require.NoError(t, err)
	assert.True(t, resp.Decision)

	// A certificate that no WP4 list publishes is refused.
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	der, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "rogue"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true,
	}, &x509.Certificate{}, &key.PublicKey, key)
	require.NoError(t, err)
	rogue, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	resp, err = client.Evaluate(context.Background(), &authzen.EvaluationRequest{
		Subject:  authzen.Subject{Type: "key", ID: id},
		Resource: authzen.Resource{Type: "x5c", ID: id, Key: []interface{}{base64.StdEncoding.EncodeToString(rogue.Raw)}},
	})
	require.NoError(t, err)
	assert.False(t, resp.Decision)
}

const webuildLoTLURL = "https://webuild-consortium.github.io/wp4-trust-group/list_of_trusted_lists.json"

// Live check of the published WP4 LoTL (JSON). The lists it points to are
// published by several operators and change, so this only asserts that the
// LoTL resolves to at least one list per LoTE type that was published when
// the snapshots were taken, and that none of them has lapsed.
func TestWebuildWP4_PublishedLoTL(t *testing.T) {
	if os.Getenv("GT_INTEGRATION") == "" {
		t.Skip("set GT_INTEGRATION to a non-empty value to run live integration tests")
	}
	lotl, err := etsi119602.FetchLoTL(webuildLoTLURL, &etsi119602.FetchOptions{Timeout: 20 * time.Second})
	require.NoError(t, err)

	lapsed := 0
	for _, ptr := range lotl.ListAndSchemeInformation.PointersToOtherLoTE {
		if len(ptr.LoTEQualifiers) == 0 || strings.Contains(ptr.LoTEQualifiers[0].LoTEType, "TSLType") {
			continue // TS 119 612 TSLs are covered by the etsi registry tests
		}
		l, err := etsi119602.FetchLoTE(ptr.LoTELocation, &etsi119602.FetchOptions{Timeout: 20 * time.Second})
		if !assert.NoErrorf(t, err, "%s", ptr.LoTELocation) {
			continue
		}
		assert.Equal(t, ptr.LoTEQualifiers[0].LoTEType, l.ListAndSchemeInformation.LoTEType, ptr.LoTELocation)
		if next, perr := time.Parse(time.RFC3339, l.ListAndSchemeInformation.NextUpdate); perr == nil && next.Before(time.Now()) {
			lapsed++
			t.Logf("list past NextUpdate (%s): %s", next.Format(time.DateOnly), ptr.LoTELocation)
		}
	}
	assert.Zero(t, lapsed, "lists past their NextUpdate are still published by the LoTL")

	reg, err := lote.New(lote.Config{Now: webuildNow, LoTLSources: []string{webuildLoTLURL}, FetchTimeout: 20 * time.Second})
	require.NoError(t, err)
	assert.True(t, reg.Healthy())
}

// The Raidiam WRPAC list lapses on 2026-11-06; the others run to 2027-04.
func TestWebuildWP4_StaleLists(t *testing.T) {
	later := func() time.Time { return time.Date(2026, 11, 7, 0, 0, 0, 0, time.UTC) }
	raidiam := filepath.Join(webuildDir, "wrpac-providers-raidiam.json")

	t.Run("direct source is refused", func(t *testing.T) {
		_, err := lote.New(lote.Config{Now: later, Sources: []string{raidiam}})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "stale")
	})

	t.Run("AllowStale accepts it", func(t *testing.T) {
		_, err := lote.New(lote.Config{Now: later, AllowStale: true, Sources: []string{raidiam}})
		require.NoError(t, err)
	})

	t.Run("LoTL pointer is skipped, fresh lists still resolve", func(t *testing.T) {
		path, _ := localLoTL(t, "lotl.json")
		reg, err := lote.New(lote.Config{Now: later, LoTLSources: []string{path}})
		require.NoError(t, err)

		ask := func(l *etsi119602.ListOfTrustedEntities) bool {
			id := l.TrustedEntitiesList[0].TrustedEntityInformation.TEInformationURI[0].URIValue
			resp, err := reg.Evaluate(context.Background(), &authzen.EvaluationRequest{
				Subject:  authzen.Subject{Type: "key", ID: id},
				Resource: authzen.Resource{Type: "x5c", ID: id},
			})
			require.NoError(t, err)
			return resp.Decision
		}
		assert.True(t, ask(loadWebuildLoTE(t, "pid-providers.xml")))
		// The Raidiam entity's identifier is not shared with the fresh WRPAC list.
		assert.False(t, ask(loadWebuildLoTE(t, "wrpac-providers-raidiam.json")))
	})

	t.Run("LoTL itself stale is refused", func(t *testing.T) {
		path, _ := localLoTL(t, "lotl.json")
		_, err := lote.New(lote.Config{LoTLSources: []string{path},
			Now: func() time.Time { return time.Date(2027, 4, 1, 0, 0, 0, 0, time.UTC) }})
		require.Error(t, err)
	})
}

// The WP4 LoTL points at six TS 119 612 TSLs next to its LoTEs; their service
// certificates must resolve through the LoTL like any other list's.
func TestWebuildWP4_LoTLResolvesClassicTSLPointers(t *testing.T) {
	path, _ := localLoTL(t, "lotl.json")
	reg, err := lote.New(lote.Config{Now: webuildNow, LoTLSources: []string{path}})
	require.NoError(t, err)

	for _, f := range []string{"idunion-eaa.xml", "credimi-eaa.xml", "nxd-eaa.xml", "idunion-qeaa.xml", "credimi-qeaa.xml", "nxd-qeaa.xml"} {
		raw, err := os.ReadFile(filepath.Join(webuildDir, f))
		require.NoError(t, err)
		block := regexp.MustCompile(`(?s)<TSPService>.*?</TSPService>`).FindString(string(raw))
		cert := regexp.MustCompile(`<X509Certificate>\s*([^<\s]+)\s*</X509Certificate>`).FindStringSubmatch(block)[1]

		resp, err := reg.Evaluate(context.Background(), &authzen.EvaluationRequest{
			Subject:  authzen.Subject{Type: "key", ID: "https://rp.example"},
			Resource: authzen.Resource{Type: "x5c", ID: "https://rp.example", Key: []interface{}{cert}},
		})
		require.NoError(t, err)
		assert.Truef(t, resp.Decision, "%s: service certificate not trusted through the LoTL: %v", f, resp.Context)
	}
}
