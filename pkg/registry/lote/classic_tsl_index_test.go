package lote

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"log/slog"
	"math/big"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/beevik/etree"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/sirosfoundation/g119612/pkg/dsig"
	"github.com/sirosfoundation/g119612/pkg/etsi119602"
)

func TestClassicTSL_TargetMustDeclareClassicType(t *testing.T) {
	// The index picks the status rules from the document's own TSLType, so a
	// classic pointer must not reach a target that declares anything else.
	f := newJWSFixture(t)
	svcCA, svcKey := newCA(t, "CA")
	for name, declared := range map[string]string{
		"empty":     "",
		"lote type": etsi119602.LoTETypePIDProviders,
	} {
		t.Run(name, func(t *testing.T) {
			xml := bytes.Replace(classicTSLXML(false, "", classicSvc{svcCA, "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/accreditationrevoked"}),
				[]byte(tslTypeEUGeneric), []byte(declared), 1)
			base := strings.ReplaceAll(name, " ", "_")
			tsl := f.writeFile(base+".xml", xml)
			lotl := f.plainLoTL(base+".json", classicPointer(tsl))
			var buf bytes.Buffer

			reg, err := New(Config{LoTLSources: []string{lotl}, Logger: slog.New(slog.NewTextHandler(&buf, nil))})
			require.NoError(t, err)
			assert.Empty(t, reg.lotes)
			assert.False(t, listsCert(t, reg, svcCA, svcKey))
			assert.Contains(t, buf.String(), "which is not a TS 119 612 TSL type")
		})
	}
}

func TestClassicTSL_UntrustedEntityNotReachableByID(t *testing.T) {
	f := newJWSFixture(t)
	revokedCA, _ := newCA(t, "Revoked")
	grantedCA, _ := newCA(t, "Granted")
	revoked := f.writeFile("revoked.xml", classicTSLXML(false, "", classicSvc{revokedCA, "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/accreditationrevoked"}))
	granted := f.writeFile("granted.xml", classicTSLXML(false, "", classicSvc{grantedCA, svcStatusGranted}))
	lotl := f.plainLoTL("lotl.json", classicPointer(revoked), classicPointer(granted))

	reg, err := New(Config{LoTLSources: []string{lotl}})
	require.NoError(t, err)
	// Resolution-only lookup by the qualified entity id.
	assert.False(t, evaluates(t, reg, revoked+"#tsp0-svc0"), "entity whose only service is revoked must not be resolvable")
	assert.True(t, evaluates(t, reg, granted+"#tsp0-svc0"))
}

func TestClassicTSL_Verified_SignerNotFirstInKeyInfo(t *testing.T) {
	// X509Data is an unordered set: a KeyInfo that lists the intermediate
	// before the signing leaf must still verify, with only the root pinned.
	f := newJWSFixture(t)
	inter, interKey := f.intermediate()
	svcCA, svcKey := newCA(t, "CA")
	leaf, key := signerLeaf(t, inter, interKey, time.Now().Add(time.Hour))
	signed, err := dsig.SignXMLWithXAdES(classicTSLXML(false, "", classicSvc{svcCA, svcStatusGranted}), key, leaf)
	require.NoError(t, err)
	doc := etree.NewDocument()
	require.NoError(t, doc.ReadFromBytes(signed))
	x509Data := doc.Root().FindElement("./Signature/KeyInfo/X509Data")
	require.NotNil(t, x509Data)
	existing := x509Data.SelectElement("X509Certificate")
	require.NotNil(t, existing)
	extra := etree.NewElement("X509Certificate")
	extra.Space = existing.Space
	extra.SetText(base64.StdEncoding.EncodeToString(inter.Raw))
	x509Data.InsertChildAt(existing.Index(), extra)
	out, err := doc.WriteToBytes()
	require.NoError(t, err)

	tsl := f.writeFile("tsl.xml", out)
	lotl := f.lotl("lotl.jws", classicPointer(tsl))
	reg, err := New(f.verifiedConfig(lotl))
	require.NoError(t, err)
	assert.True(t, listsCert(t, reg, svcCA, svcKey))
}

// intermediate issues an intermediate CA from the fixture root.
func (f *jwsFixture) intermediate() (*x509.Certificate, *ecdsa.PrivateKey) {
	f.t.Helper()
	key := newECKey(f.t)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: "Intermediate"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(12 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, f.ca, &key.PublicKey, f.caKey)
	require.NoError(f.t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(f.t, err)
	return cert, key
}

func TestClassicTSL_SkippedCountIsPerRefresh(t *testing.T) {
	f := newJWSFixture(t)
	lotl := f.plainLoTL("lotl.json", classicPointer(filepath.Join(f.dir, "missing.xml")))
	var buf bytes.Buffer
	reg, err := New(Config{LoTLSources: []string{lotl}, Logger: slog.New(slog.NewTextHandler(&buf, nil))})
	require.NoError(t, err)
	buf.Reset()
	require.NoError(t, reg.Refresh(context.Background()))
	assert.Contains(t, buf.String(), "lotl_pointers_skipped=1")
}
