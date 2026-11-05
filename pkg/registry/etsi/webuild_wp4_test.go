package etsi_test

import (
	"context"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/sirosfoundation/go-trust/pkg/authzen"
	"github.com/sirosfoundation/go-trust/pkg/registry/etsi"
)

// Snapshots of the TS 119 612 trusted lists referenced by the WE BUILD WP4
// LoTL (github.com/webuild-consortium/wp4-trust-group), each paired with the
// signer trust anchor its tl_entries/ file in that repository publishes.
// See testdata/webuild-wp4/sources.json for the origin of each file.
const webuildDir = "../../../testdata/webuild-wp4"

// webuildNow pins the clock to when the snapshots were taken, so the tests do
// not start failing as the lists pass their NextUpdate.
func webuildNow() time.Time { return time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC) }

var webuildTSLs = []struct {
	file   string
	anchor string
	certs  int // service certificates in the snapshot
}{
	{"idunion-eaa.xml", "eaa-provider-idunion", 5},
	{"credimi-eaa.xml", "eaa-provider-credimi", 1},
	{"nxd-eaa.xml", "eaa-provider-nxd-foundation", 33},
	{"idunion-qeaa.xml", "qeaa-provider-idunion", 9},
	{"credimi-qeaa.xml", "qeaa-provider-credimi", 1},
	{"nxd-qeaa.xml", "qeaa-provider-nxd-foundation", 2},
}

func webuildPath(f string) string { return filepath.Join(webuildDir, f) }
func anchorPath(a string) string  { return filepath.Join(webuildDir, "anchors", a+".pem") }

func TestWebuildWP4_TSLSignaturesVerifyAgainstPublishedAnchors(t *testing.T) {
	for _, tc := range webuildTSLs {
		t.Run(tc.file, func(t *testing.T) {
			reg, err := etsi.NewTSLRegistry(etsi.TSLConfig{Now: webuildNow,
				Name:             tc.file,
				TSLFiles:         []string{webuildPath(tc.file)},
				LOTLSignerBundle: anchorPath(tc.anchor),
				RequireSignature: true,
			})
			require.NoError(t, err)
			assert.Equal(t, tc.certs, reg.CertificateCount())
		})
	}
}

// Verification must be anchored to the list's own signer, not to any anchor.
func TestWebuildWP4_TSLRejectsWrongAnchor(t *testing.T) {
	_, err := etsi.NewTSLRegistry(etsi.TSLConfig{Now: webuildNow,
		TSLFiles:         []string{webuildPath("idunion-eaa.xml")},
		LOTLSignerBundle: anchorPath("eaa-provider-credimi"),
		RequireSignature: true,
	})
	assert.Error(t, err)
}

func TestWebuildWP4_TSLRejectsTamperedList(t *testing.T) {
	raw, err := os.ReadFile(webuildPath("idunion-eaa.xml"))
	require.NoError(t, err)
	tampered := strings.Replace(string(raw), "<TSLSequenceNumber>1<", "<TSLSequenceNumber>2<", 1)
	require.NotEqual(t, string(raw), tampered, "fixture no longer contains the sequence number to tamper with")
	path := filepath.Join(t.TempDir(), "tampered.xml")
	require.NoError(t, os.WriteFile(path, []byte(tampered), 0o600))

	_, err = etsi.NewTSLRegistry(etsi.TSLConfig{Now: webuildNow,
		TSLFiles:         []string{path},
		LOTLSignerBundle: anchorPath("eaa-provider-idunion"),
		RequireSignature: true,
	})
	assert.Error(t, err)
}

// Scheme-operator identities (outside <TSPService>) are not service certificates.
var sdiCert = regexp.MustCompile(`(?s)<TSPService>.*?</TSPService>`)
var x509Val = regexp.MustCompile(`<X509Certificate>\s*([^<\s]+)\s*</X509Certificate>`)

// Every service certificate a list publishes must be accepted as an x5c.
func TestWebuildWP4_EveryListedServiceCertificateIsTrusted(t *testing.T) {
	for _, tc := range webuildTSLs {
		t.Run(tc.file, func(t *testing.T) {
			reg, err := etsi.NewTSLRegistry(etsi.TSLConfig{Now: webuildNow, Name: tc.file, TSLFiles: []string{webuildPath(tc.file)}})
			require.NoError(t, err)
			raw, err := os.ReadFile(webuildPath(tc.file))
			require.NoError(t, err)

			n := 0
			for _, block := range sdiCert.FindAllString(string(raw), -1) {
				for _, m := range x509Val.FindAllStringSubmatch(block, -1) {
					resp, err := reg.Evaluate(context.Background(), &authzen.EvaluationRequest{
						Subject:  authzen.Subject{Type: "key", ID: "x"},
						Resource: authzen.Resource{Type: "x5c", ID: "x", Key: []interface{}{m[1]}},
					})
					require.NoError(t, err)
					assert.Truef(t, resp.Decision, "listed certificate %.40s... not trusted: %v", m[1], resp.Context)
					n++
				}
			}
			assert.Equal(t, tc.certs, n)
		})
	}
}

// A certificate from one list is not trusted by a registry loaded with another.
func TestWebuildWP4_ServiceCertificateNotTrustedByOtherList(t *testing.T) {
	raw, err := os.ReadFile(webuildPath("credimi-eaa.xml"))
	require.NoError(t, err)
	block := sdiCert.FindString(string(raw))
	cert := x509Val.FindStringSubmatch(block)[1]

	reg, err := etsi.NewTSLRegistry(etsi.TSLConfig{Now: webuildNow, TSLFiles: []string{webuildPath("idunion-eaa.xml")}})
	require.NoError(t, err)
	resp, err := reg.Evaluate(context.Background(), &authzen.EvaluationRequest{
		Subject:  authzen.Subject{Type: "key", ID: "x"},
		Resource: authzen.Resource{Type: "x5c", ID: "x", Key: []interface{}{cert}},
	})
	require.NoError(t, err)
	assert.False(t, resp.Decision)
}

func TestWebuildWP4_StaleTSL(t *testing.T) {
	far := func() time.Time { return time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC) }
	path := webuildPath("idunion-eaa.xml")

	_, err := etsi.NewTSLRegistry(etsi.TSLConfig{Now: far, TSLFiles: []string{path}})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "stale")

	reg, err := etsi.NewTSLRegistry(etsi.TSLConfig{Now: far, AllowStale: true, TSLFiles: []string{path}})
	require.NoError(t, err)
	assert.Equal(t, 5, reg.CertificateCount())
}
