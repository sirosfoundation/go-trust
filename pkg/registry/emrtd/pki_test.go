package emrtd

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	gematik "github.com/gematik/zero-lab/go/brainpool"
	"github.com/stretchr/testify/require"
)

// This file builds test PKIs by hand-assembling DER. crypto/x509 cannot
// create certificates for brainpool keys, which ICAO DSCs/CSCAs commonly use.

type keyKind int

const (
	kindP256 keyKind = iota
	kindBrainpool256
	kindRSAPSS
)

type testKey struct {
	kind keyKind
	ec   *ecdsa.PrivateKey
	rsa  *rsa.PrivateKey
}

func newKey(t *testing.T, k keyKind) *testKey {
	t.Helper()
	tk := &testKey{kind: k}
	var err error
	switch k {
	case kindP256:
		tk.ec, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case kindBrainpool256:
		tk.ec, err = ecdsa.GenerateKey(gematik.P256r1(), rand.Reader)
	case kindRSAPSS:
		tk.rsa, err = rsa.GenerateKey(rand.Reader, 2048)
	}
	require.NoError(t, err)
	return tk
}

func (k *testKey) spki(t *testing.T) []byte {
	t.Helper()
	switch k.kind {
	case kindP256:
		b, err := x509.MarshalPKIXPublicKey(&k.ec.PublicKey)
		require.NoError(t, err)
		return b
	case kindBrainpool256:
		b, err := gematik.MarshalPKIXPublicKey(&k.ec.PublicKey)
		require.NoError(t, err)
		return b
	default:
		b, err := x509.MarshalPKIXPublicKey(&k.rsa.PublicKey)
		require.NoError(t, err)
		return b
	}
}

var (
	oidECDSASHA256 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}
	oidRSAPSS      = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 10}
)

// pssSHA256Params is the DER of RSASSA-PSS-params for SHA-256/MGF1-SHA-256/salt 32.
var pssSHA256Params, _ = hex.DecodeString("3034a00f300d06096086480165030402010500a11c301a06092a864886f70d010108300d06096086480165030402010500a203020120")

func (k *testKey) sigAlg() pkix.AlgorithmIdentifier {
	if k.kind == kindRSAPSS {
		return pkix.AlgorithmIdentifier{Algorithm: oidRSAPSS, Parameters: asn1.RawValue{FullBytes: pssSHA256Params}}
	}
	return pkix.AlgorithmIdentifier{Algorithm: oidECDSASHA256}
}

func (k *testKey) sign(t *testing.T, tbs []byte) []byte {
	t.Helper()
	d := sha256.Sum256(tbs)
	if k.kind == kindRSAPSS {
		sig, err := rsa.SignPSS(rand.Reader, k.rsa, crypto.SHA256, d[:], &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash})
		require.NoError(t, err)
		return sig
	}
	sig, err := ecdsa.SignASN1(rand.Reader, k.ec, d[:])
	require.NoError(t, err)
	return sig
}

type validity struct{ NotBefore, NotAfter time.Time }

type tbsCert struct {
	Version      int `asn1:"optional,explicit,default:0,tag:0"`
	SerialNumber *big.Int
	SigAlg       pkix.AlgorithmIdentifier
	Issuer       asn1.RawValue
	Validity     validity
	Subject      asn1.RawValue
	SPKI         asn1.RawValue
	Extensions   []pkix.Extension `asn1:"omitempty,optional,explicit,tag:3"`
}

type certDER struct {
	TBS    asn1.RawValue
	SigAlg pkix.AlgorithmIdentifier
	Sig    asn1.BitString
}

// spec describes one certificate to build.
type spec struct {
	cn        string
	country   string // alpha-2; "" omits C
	notBefore time.Time
	notAfter  time.Time
	ca        bool
	noBC      bool // omit basicConstraints entirely
	usage     byte // first keyUsage byte; 0 omits the extension
	serial    int64
}

const (
	usageDigitalSignature byte = 0x80
	usageCertSignCRLSign  byte = 0x06
)

// node is a generated certificate plus its key.
type node struct {
	key  *testKey
	cert *x509.Certificate
	spec spec
}

func name(t *testing.T, s spec) []byte {
	t.Helper()
	n := pkix.Name{CommonName: s.cn, Organization: []string{"Test"}}
	if s.country != "" {
		n.Country = []string{s.country}
	}
	b, err := asn1.Marshal(n.ToRDNSequence())
	require.NoError(t, err)
	return b
}

// issue builds a certificate for subject key `sk`, signed by `issuer` (nil = self-signed).
func issue(t *testing.T, s spec, sk *testKey, issuer *node) *node {
	t.Helper()
	signer := sk
	issuerName := name(t, s)
	if issuer != nil {
		signer = issuer.key
		issuerName = name(t, issuer.spec)
	}
	if s.serial == 0 {
		n, err := rand.Int(rand.Reader, big.NewInt(1<<40))
		require.NoError(t, err)
		s.serial = n.Int64() + 1
	}
	var exts []pkix.Extension
	if !s.noBC {
		bc, err := asn1.Marshal(struct {
			CA bool `asn1:"optional"`
		}{s.ca})
		require.NoError(t, err)
		exts = append(exts, pkix.Extension{Id: asn1.ObjectIdentifier{2, 5, 29, 19}, Critical: true, Value: bc})
	}
	ski := sha256.Sum256(sk.spki(t))
	skiVal, err := asn1.Marshal(ski[:20])
	require.NoError(t, err)
	exts = append(exts, pkix.Extension{Id: asn1.ObjectIdentifier{2, 5, 29, 14}, Value: skiVal})
	if s.usage != 0 {
		ku, err := asn1.Marshal(asn1.BitString{Bytes: []byte{s.usage}, BitLength: 7})
		require.NoError(t, err)
		exts = append(exts, pkix.Extension{Id: asn1.ObjectIdentifier{2, 5, 29, 15}, Critical: true, Value: ku})
	}
	tbs, err := asn1.Marshal(tbsCert{
		Version:      2,
		SerialNumber: big.NewInt(s.serial),
		SigAlg:       signer.sigAlg(),
		Issuer:       asn1.RawValue{FullBytes: issuerName},
		Validity:     validity{s.notBefore.UTC(), s.notAfter.UTC()},
		Subject:      asn1.RawValue{FullBytes: name(t, s)},
		SPKI:         asn1.RawValue{FullBytes: sk.spki(t)},
		Extensions:   exts,
	})
	require.NoError(t, err)
	sig := signer.sign(t, tbs)
	der, err := asn1.Marshal(certDER{
		TBS:    asn1.RawValue{FullBytes: tbs},
		SigAlg: signer.sigAlg(),
		Sig:    asn1.BitString{Bytes: sig, BitLength: len(sig) * 8},
	})
	require.NoError(t, err)

	ext := testExt()
	cert, err := ext.ParseCertificate(der)
	require.NoError(t, err)
	require.NotNil(t, cert.PublicKey)
	return &node{key: sk, cert: cert, spec: s}
}

func (n *node) b64() string { return base64.StdEncoding.EncodeToString(n.cert.Raw) }

func (n *node) pem() []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: n.cert.Raw})
}

var (
	t2005 = time.Date(2005, 1, 1, 0, 0, 0, 0, time.UTC)
	t2010 = time.Date(2010, 1, 1, 0, 0, 0, 0, time.UTC)
	t2012 = time.Date(2012, 1, 1, 0, 0, 0, 0, time.UTC)
	t2020 = time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	t2040 = time.Date(2040, 1, 1, 0, 0, 0, 0, time.UTC)
	tNow  = time.Date(2026, 9, 30, 10, 0, 0, 0, time.UTC)
)

func cscaSpec(cn, c string) spec {
	return spec{cn: cn, country: c, notBefore: t2005, notAfter: t2040, ca: true, usage: usageCertSignCRLSign}
}

func dscSpec(cn, c string) spec {
	return spec{cn: cn, country: c, notBefore: t2020, notAfter: t2040, usage: usageDigitalSignature}
}

func newCSCA(t *testing.T, k keyKind, cn, c string) *node {
	t.Helper()
	return issue(t, cscaSpec(cn, c), newKey(t, k), nil)
}

func newDSC(t *testing.T, k keyKind, csca *node, c string) *node {
	t.Helper()
	return issue(t, dscSpec("DSC", c), newKey(t, k), csca)
}

// writeAnchors lays out root/<ALPHA3>/<fp>.pem.
func writeAnchors(t *testing.T, root string, anchors map[string][]*node) {
	t.Helper()
	for country, list := range anchors {
		dir := filepath.Join(root, country)
		require.NoError(t, os.MkdirAll(dir, 0o755))
		for _, n := range list {
			require.NoError(t, os.WriteFile(filepath.Join(dir, fingerprint(n.cert)+".pem"), n.pem(), 0o644))
		}
	}
}
