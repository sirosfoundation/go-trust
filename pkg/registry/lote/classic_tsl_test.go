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
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/beevik/etree"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/sirosfoundation/g119612/pkg/dsig"
	"github.com/sirosfoundation/g119612/pkg/etsi119602"
	"github.com/sirosfoundation/go-trust/pkg/authzen"
)

const (
	tslTypeEUGeneric = "http://uri.etsi.org/TrstSvc/TrustedList/TSLType/EUgeneric"
	svcStatusGranted = "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted"
)

// classicSvc is one service in a generated classic TSL.
type classicSvc struct {
	cert   *x509.Certificate
	status string
}

// classicTSLXML builds a minimal, unsigned TS 119 612 TSL. ext, when
// non-empty, is added as an (initially empty) element before the TSP list so a
// test can sign a document that already contains that container.
func classicTSLXML(withContainer bool, pointerTo string, svcs ...classicSvc) []byte {
	var b strings.Builder
	b.WriteString(`<?xml version="1.0" encoding="UTF-8"?>`)
	b.WriteString(`<TrustServiceStatusList xmlns="http://uri.etsi.org/02231/v2#" TSLTag="http://uri.etsi.org/19612/TSLTag">`)
	b.WriteString(`<SchemeInformation><TSLVersionIdentifier>5</TSLVersionIdentifier><TSLSequenceNumber>1</TSLSequenceNumber>`)
	b.WriteString(`<TSLType>` + tslTypeEUGeneric + `</TSLType><SchemeTerritory>SE</SchemeTerritory>`)
	if pointerTo != "" {
		b.WriteString(`<PointersToOtherTSL><OtherTSLPointer><TSLLocation>` + pointerTo + `</TSLLocation></OtherTSLPointer></PointersToOtherTSL>`)
	}
	b.WriteString(`</SchemeInformation>`)
	if withContainer {
		b.WriteString(`<Container></Container>`)
	}
	b.WriteString(`<TrustServiceProviderList><TrustServiceProvider><TSPInformation><TSPName><Name xml:lang="en">Test TSP</Name></TSPName></TSPInformation><TSPServices>`)
	for _, s := range svcs {
		b.WriteString(`<TSPService><ServiceInformation>`)
		b.WriteString(`<ServiceTypeIdentifier>http://uri.etsi.org/TrstSvc/Svctype/CA/PKC</ServiceTypeIdentifier>`)
		b.WriteString(`<ServiceName><Name xml:lang="en">Svc ` + s.cert.Subject.CommonName + `</Name></ServiceName>`)
		b.WriteString(`<ServiceDigitalIdentity><DigitalId><X509Certificate>` + base64.StdEncoding.EncodeToString(s.cert.Raw) + `</X509Certificate></DigitalId></ServiceDigitalIdentity>`)
		b.WriteString(`<ServiceStatus>` + s.status + `</ServiceStatus><StatusStartingTime>2025-01-01T00:00:00Z</StatusStartingTime>`)
		b.WriteString(`</ServiceInformation></TSPService>`)
	}
	b.WriteString(`</TSPServices></TrustServiceProvider></TrustServiceProviderList></TrustServiceStatusList>`)
	return []byte(b.String())
}

// newCA creates an independent CA (a service CA listed in a TSL, or an
// untrusted signing CA).
func newCA(t *testing.T, cn string) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key := newECKey(t)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return cert, key
}

// signerLeaf issues a TSL-signing leaf from ca.
func signerLeaf(t *testing.T, ca *x509.Certificate, caKey *ecdsa.PrivateKey, notAfter time.Time) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key := newECKey(t)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: "TSL Signer"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &key.PublicKey, caKey)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return cert, key
}

// signTSL signs xml (enveloped XAdES) with a leaf issued by the fixture CA.
func (f *jwsFixture) signTSL(xml []byte) []byte {
	f.t.Helper()
	return signTSLWith(f.t, xml, f.ca, f.caKey)
}

func signTSLWith(t *testing.T, xml []byte, ca *x509.Certificate, caKey *ecdsa.PrivateKey) []byte {
	t.Helper()
	leaf, key := signerLeaf(t, ca, caKey, time.Now().Add(24*time.Hour))
	out, err := dsig.SignXMLWithXAdES(xml, key, leaf)
	require.NoError(t, err)
	return out
}

func (f *jwsFixture) writeFile(name string, data []byte) string {
	f.t.Helper()
	p := filepath.Join(f.dir, name)
	require.NoError(f.t, os.WriteFile(p, data, 0o600))
	return p
}

func classicPointer(location string) etsi119602.OtherLoTEPointer {
	return lotlPointer(location, tslTypeEUGeneric, "SE")
}

// plainLoTL writes an unsigned JSON LoTL (for verification-off tests).
func (f *jwsFixture) plainLoTL(name string, ptrs ...etsi119602.OtherLoTEPointer) string {
	f.t.Helper()
	l := &etsi119602.ListOfTrustedLists{ListAndSchemeInformation: etsi119602.ListAndSchemeInformation{
		LoTEVersionIdentifier: 1, SchemeTerritory: "EU", LoTEType: etsi119602.LoTLTypeEU,
		SchemeOperatorName:  etsi119602.NameSet{{Lang: "en", Value: "EU"}},
		ListIssueDateTime:   "2026-01-01T00:00:00Z",
		NextUpdate:          "2027-01-01T00:00:00Z",
		PointersToOtherLoTE: ptrs,
	}}
	data, err := l.MarshalLoTL()
	require.NoError(f.t, err)
	return f.writeFile(name, data)
}

// listsCert reports whether an x5c chain [leaf, ca] issued by ca is trusted by reg.
func listsCert(t *testing.T, reg *Registry, ca *x509.Certificate, caKey *ecdsa.PrivateKey) bool {
	t.Helper()
	leaf, _ := signerLeaf(t, ca, caKey, time.Now().Add(time.Hour))
	resp, err := reg.Evaluate(context.Background(), &authzen.EvaluationRequest{
		Subject: authzen.Subject{Type: "key", ID: "https://rp.example"},
		Resource: authzen.Resource{Type: "x5c", ID: "https://rp.example", Key: []interface{}{
			base64.StdEncoding.EncodeToString(leaf.Raw),
			base64.StdEncoding.EncodeToString(ca.Raw),
		}},
	})
	require.NoError(t, err)
	return resp.Decision
}

func (f *jwsFixture) verifiedConfig(src string, extra ...func(*Config)) Config {
	cfg := Config{LoTLSources: []string{src}, VerifyJWS: true, TrustAnchorProvider: f.provider()}
	for _, fn := range extra {
		fn(&cfg)
	}
	return cfg
}

func TestClassicTSL_Unverified_Loaded(t *testing.T) {
	f := newJWSFixture(t)
	svcCA, svcKey := newCA(t, "EAA Provider CA")
	tsl := f.writeFile("tsl.xml", classicTSLXML(false, "", classicSvc{svcCA, svcStatusGranted}))
	lotl := f.plainLoTL("lotl.json", classicPointer(tsl))

	reg, err := New(Config{LoTLSources: []string{lotl}})
	require.NoError(t, err)
	assert.True(t, listsCert(t, reg, svcCA, svcKey), "certificate only present in the classic TSL must be trusted")
	assert.Len(t, reg.lotes, 1)
}

func TestClassicTSL_Unverified_FetchFailureSkipped(t *testing.T) {
	f := newJWSFixture(t)
	lotl := f.plainLoTL("lotl.json", classicPointer(filepath.Join(f.dir, "missing.xml")))
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))

	reg, err := New(Config{LoTLSources: []string{lotl}, Logger: logger})
	require.NoError(t, err)
	assert.Empty(t, reg.lotes)
	assert.Contains(t, buf.String(), "level=ERROR")
	assert.Contains(t, buf.String(), "failed to load classic TSL from LoTL pointer; source skipped")
	assert.Contains(t, buf.String(), "lotl_pointers_skipped=1")
}

func TestClassicTSL_Unverified_NestedPointersWarned(t *testing.T) {
	f := newJWSFixture(t)
	svcCA, _ := newCA(t, "CA")
	tsl := f.writeFile("tsl.xml", classicTSLXML(false, "https://example.invalid/other.xml", classicSvc{svcCA, svcStatusGranted}))
	lotl := f.plainLoTL("lotl.json", classicPointer(tsl))
	var buf bytes.Buffer

	_, err := New(Config{LoTLSources: []string{lotl}, Logger: slog.New(slog.NewTextHandler(&buf, nil))})
	require.NoError(t, err)
	assert.Contains(t, buf.String(), "pointers to other TSLs; they are not followed")
}

func TestClassicTSL_Verified_Valid(t *testing.T) {
	f := newJWSFixture(t)
	svcCA, svcKey := newCA(t, "EAA Provider CA")
	tsl := f.writeFile("tsl.xml", f.signTSL(classicTSLXML(false, "", classicSvc{svcCA, svcStatusGranted})))
	lotl := f.lotl("lotl.jws", classicPointer(tsl))

	reg, err := New(f.verifiedConfig(lotl))
	require.NoError(t, err)
	assert.True(t, listsCert(t, reg, svcCA, svcKey))
}

func TestClassicTSL_Verified_MixedWithNativeLoTE(t *testing.T) {
	f := newJWSFixture(t)
	svcCA, svcKey := newCA(t, "EAA Provider CA")
	tsl := f.writeFile("tsl.xml", f.signTSL(classicTSLXML(false, "", classicSvc{svcCA, svcStatusGranted})))
	lote := f.lote("native.jws", "https://native.example")
	lotl := f.lotl("lotl.jws", lotlPointer(lote, etsi119602.LoTETypePIDProviders, "SE"), classicPointer(tsl))

	reg, err := New(f.verifiedConfig(lotl))
	require.NoError(t, err)
	assert.True(t, evaluates(t, reg, "https://native.example"))
	assert.True(t, listsCert(t, reg, svcCA, svcKey))
	assert.Len(t, reg.lotes, 2)
}

func TestClassicTSL_Verified_Rejected(t *testing.T) {
	f := newJWSFixture(t)
	svcCA, svcKey := newCA(t, "EAA Provider CA")
	plain := classicTSLXML(true, "", classicSvc{svcCA, svcStatusGranted})
	otherCA, otherKey := newCA(t, "Untrusted Signing CA")

	cases := map[string][]byte{
		"unsigned":         plain,
		"untrusted signer": signTSLWith(t, plain, otherCA, otherKey),
		"tampered after signing": bytes.Replace(f.signTSL(plain),
			[]byte("Test TSP"), []byte("Evil TSP"), 1),
		"signature nested outside root": nestSignature(t, f.signTSL(plain)),
		"second signature":              duplicateSignature(t, f.signTSL(plain)),
	}
	for name, doc := range cases {
		t.Run(name, func(t *testing.T) {
			tsl := f.writeFile(strings.ReplaceAll(name, " ", "_")+".xml", doc)
			lotl := f.lotl(strings.ReplaceAll(name, " ", "_")+".jws", classicPointer(tsl))
			var buf bytes.Buffer

			reg, err := New(f.verifiedConfig(lotl, func(c *Config) { c.Logger = slog.New(slog.NewTextHandler(&buf, nil)) }))
			require.NoError(t, err)
			assert.False(t, listsCert(t, reg, svcCA, svcKey), "unverifiable classic TSL must never contribute entities")
			assert.Empty(t, reg.lotes)
			assert.Contains(t, buf.String(), "level=ERROR")
			assert.Contains(t, buf.String(), "classic TSL signature verification failed")
		})
	}
}

// nestSignature moves the (valid) Signature into a container that was part of
// the signed content. The signed digest still matches the root minus the
// signature, so the library alone accepts it; go-trust requires the signature
// to be a direct child of the root.
func nestSignature(t *testing.T, signed []byte) []byte {
	t.Helper()
	doc := etree.NewDocument()
	require.NoError(t, doc.ReadFromBytes(signed))
	root := doc.Root()
	sig := root.FindElement("./Signature")
	require.NotNil(t, sig)
	container := root.FindElement("./Container")
	require.NotNil(t, container)
	root.RemoveChild(sig)
	container.AddChild(sig)
	out, err := doc.WriteToBytes()
	require.NoError(t, err)
	return out
}

func duplicateSignature(t *testing.T, signed []byte) []byte {
	t.Helper()
	doc := etree.NewDocument()
	require.NoError(t, doc.ReadFromBytes(signed))
	root := doc.Root()
	root.AddChild(root.FindElement("./Signature").Copy())
	out, err := doc.WriteToBytes()
	require.NoError(t, err)
	return out
}

func TestClassicTSL_Verified_UntrustedStatusNotIndexed(t *testing.T) {
	// A verified, correctly signed TSL still only confers trust for services
	// in a trusted status.
	f := newJWSFixture(t)
	for name, status := range map[string]string{
		"withdrawn":                 "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/withdrawn",
		"supervisionincessation":    "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/supervisionincessation",
		"deprecatedatnationallevel": "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/deprecatedatnationallevel",
		"accreditationrevoked":      "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/accreditationrevoked",
		"empty":                     "",
	} {
		t.Run(name, func(t *testing.T) {
			svcCA, svcKey := newCA(t, "CA "+name)
			tsl := f.writeFile(name+".xml", f.signTSL(classicTSLXML(false, "", classicSvc{svcCA, status})))
			lotl := f.lotl(name+".jws", classicPointer(tsl))
			reg, err := New(f.verifiedConfig(lotl))
			require.NoError(t, err)
			assert.False(t, listsCert(t, reg, svcCA, svcKey))
		})
	}
}

func TestClassicTSL_TrustedStatusVariants(t *testing.T) {
	for _, s := range []string{
		"http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted",
		"https://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted/",
		"http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/recognisedatnationallevel",
		"http://uri.etsi.org/TrstSvc/Svcstatus/undersupervision",
	} {
		assert.True(t, classicStatusTrusted(s), s)
	}
	assert.False(t, classicStatusTrusted("http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/withdrawn"))
}

func TestClassicTSL_EntityIDsDoNotCollideAcrossLists(t *testing.T) {
	// FromTSL derives ids from service type and position only, so two lists
	// would overwrite each other in the byID index without qualification.
	f := newJWSFixture(t)
	caA, keyA := newCA(t, "CA A")
	caB, keyB := newCA(t, "CA B")
	a := f.writeFile("a.xml", classicTSLXML(false, "", classicSvc{caA, svcStatusGranted}))
	b := f.writeFile("b.xml", classicTSLXML(false, "", classicSvc{caB, svcStatusGranted}))
	lotl := f.plainLoTL("lotl.json", classicPointer(a), classicPointer(b))

	reg, err := New(Config{LoTLSources: []string{lotl}})
	require.NoError(t, err)
	assert.Len(t, reg.index.byID, 2)
	assert.True(t, listsCert(t, reg, caA, keyA))
	assert.True(t, listsCert(t, reg, caB, keyB))
}

func TestClassicTSL_NativeStatusRuleUnchanged(t *testing.T) {
	assert.True(t, serviceStatusIndexed(false, false, "http://example/supervisionincessation"), "non-classic keeps skip-withdrawn rule")
	assert.False(t, serviceStatusIndexed(false, false, "http://example/withdrawn"))
	assert.False(t, serviceStatusIndexed(true, false, "x"))
}

func TestIsClassicTSLSchemeType(t *testing.T) {
	assert.True(t, IsClassicTSLSchemeType(tslTypeEUGeneric))
	assert.True(t, IsClassicTSLSchemeType("https://uri.etsi.org/TrstSvc/TrustedList/TSLType/EUgeneric/"))
	assert.False(t, IsClassicTSLSchemeType(etsi119602.LoTETypePIDProviders))
	assert.False(t, IsClassicTSLSchemeType(etsi119602.LoTLTypeEU))
	assert.False(t, IsClassicTSLSchemeType(""))
}

func TestVerifyTSLSignature_Direct(t *testing.T) {
	f := newJWSFixture(t)
	svcCA, _ := newCA(t, "CA")
	signed := f.signTSL(classicTSLXML(false, "", classicSvc{svcCA, svcStatusGranted}))
	ctx := context.Background()

	t.Run("valid returns verified payload", func(t *testing.T) {
		signer, payload, err := verifyTSLSignature(ctx, signed, f.roots, time.Now())
		require.NoError(t, err)
		assert.Equal(t, "TSL Signer", signer.Subject.CommonName)
		assert.Contains(t, string(payload), "Test TSP")
		assert.NotContains(t, string(payload), "Signature")
	})
	t.Run("nil roots refused", func(t *testing.T) {
		_, _, err := verifyTSLSignature(ctx, signed, nil, time.Now())
		require.Error(t, err)
	})
	t.Run("signer expired at verification time", func(t *testing.T) {
		_, _, err := verifyTSLSignature(ctx, signed, f.roots, time.Now().Add(72*time.Hour))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "chain validation failed")
	})
	t.Run("not xml", func(t *testing.T) {
		_, _, err := verifyTSLSignature(ctx, []byte("{not xml"), f.roots, time.Now())
		require.Error(t, err)
	})
	t.Run("sha1 refused", func(t *testing.T) {
		weak := bytes.Replace(signed, []byte("ecdsa-sha256"), []byte("ecdsa-sha1"), 1)
		_, _, err := verifyTSLSignature(ctx, weak, f.roots, time.Now())
		require.Error(t, err)
		assert.Contains(t, err.Error(), "SHA-1")
	})
	t.Run("exactly one signature required", func(t *testing.T) {
		_, _, err := verifyTSLSignature(ctx, duplicateSignature(t, signed), f.roots, time.Now())
		require.Error(t, err)
		assert.Contains(t, err.Error(), "exactly one")
	})
	t.Run("signature must be a root child", func(t *testing.T) {
		_, _, err := verifyTSLSignature(ctx, nestSignature(t, f.signTSL(classicTSLXML(true, "", classicSvc{svcCA, svcStatusGranted}))), f.roots, time.Now())
		require.Error(t, err)
		assert.Contains(t, err.Error(), "direct child")
	})
	t.Run("no certificate in KeyInfo", func(t *testing.T) {
		doc := etree.NewDocument()
		require.NoError(t, doc.ReadFromBytes(signed))
		ki := doc.Root().FindElement("./Signature/KeyInfo")
		require.NotNil(t, ki)
		ki.Parent().RemoveChild(ki)
		out, err := doc.WriteToBytes()
		require.NoError(t, err)
		_, _, err = verifyTSLSignature(ctx, out, f.roots, time.Now())
		require.Error(t, err)
		assert.Contains(t, err.Error(), "KeyInfo")
	})
	t.Run("garbage certificate in KeyInfo", func(t *testing.T) {
		doc := etree.NewDocument()
		require.NoError(t, doc.ReadFromBytes(signed))
		c := doc.Root().FindElement("./Signature/KeyInfo/X509Data/X509Certificate")
		require.NotNil(t, c)
		c.SetText("AAAA")
		out, err := doc.WriteToBytes()
		require.NoError(t, err)
		_, _, err = verifyTSLSignature(ctx, out, f.roots, time.Now())
		require.Error(t, err)
		assert.Contains(t, err.Error(), "signer chain")
	})
	t.Run("signed content altered", func(t *testing.T) {
		bad := bytes.Replace(signed, []byte("Test TSP"), []byte("Evil TSP"), 1)
		_, _, err := verifyTSLSignature(ctx, bad, f.roots, time.Now())
		require.Error(t, err)
	})
}

func TestClassicTSL_FailClosedWithoutAnchorsStillRefuses(t *testing.T) {
	f := newJWSFixture(t)
	lotl := f.plainLoTL("lotl.json")
	_, err := New(Config{LoTLSources: []string{lotl}, VerifyJWS: true})
	require.ErrorIs(t, err, ErrVerifyJWSNoAnchors)
}
