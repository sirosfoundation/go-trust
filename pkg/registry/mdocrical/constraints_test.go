package mdocrical

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"

	"github.com/sirosfoundation/go-trust/pkg/authzen"
)

const (
	oidPolicyA = "1.2.3.4.5"
	oidPolicyB = "1.2.3.4.6"
	oidEKUA    = "1.3.6.1.4.1.99999.1"
	oidEKUB    = "1.3.6.1.4.1.99999.2"
)

func mustOID(t *testing.T, s string) x509.OID {
	t.Helper()
	o, err := x509.ParseOID(s)
	if err != nil {
		t.Fatal(err)
	}
	return o
}

// leafWith issues a reader certificate carrying the given policies and EKUs
// (as dotted OIDs), under issuer.
func leafWith(t *testing.T, issuer *x509.Certificate, issuerKey *ecdsa.PrivateKey, serial int64, policies []string, ekus []string) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject:      pkix.Name{CommonName: "Reader"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	for _, p := range policies {
		tmpl.Policies = append(tmpl.Policies, mustOID(t, p))
	}
	for _, e := range ekus {
		oid, err := parseASN1OID(e)
		if err != nil {
			t.Fatal(err)
		}
		tmpl.UnknownExtKeyUsage = append(tmpl.UnknownExtKeyUsage, oid)
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, issuer, &key.PublicKey, issuerKey)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

func TestConstraintSatisfied(t *testing.T) {
	ca, caKey := generateCA(t, "CA")
	plain := leafWith(t, ca, caKey, 10, nil, nil)
	both := leafWith(t, ca, caKey, 11, []string{oidPolicyA, oidPolicyB}, []string{oidEKUA})
	twoEKU := leafWith(t, ca, caKey, 12, []string{oidPolicyA}, []string{oidEKUA, oidEKUB})
	three := uint64(3)
	zero := uint64(0)
	ext := map[string]cbor.RawMessage{"x": {0xf5}}

	cases := []struct {
		name          string
		c             TrustConstraint
		leaf          *x509.Certificate
		intermediates int
		want          bool
	}{
		{"empty constraint holds", TrustConstraint{}, plain, 0, true},
		{"policy present", TrustConstraint{Policies: []string{oidPolicyA}}, both, 0, true},
		{"all policies required", TrustConstraint{Policies: []string{oidPolicyA, oidPolicyB}}, both, 0, true},
		{"policy missing", TrustConstraint{Policies: []string{oidPolicyA, "1.9.9"}}, both, 0, false},
		{"no policies on leaf", TrustConstraint{Policies: []string{oidPolicyA}}, plain, 0, false},
		{"eku allowed", TrustConstraint{EKU: []string{oidEKUA}}, both, 0, true},
		{"eku not allowed", TrustConstraint{EKU: []string{oidEKUB}}, both, 0, false},
		{"every leaf eku must be allowed", TrustConstraint{EKU: []string{oidEKUA}}, twoEKU, 0, false},
		{"both ekus allowed", TrustConstraint{EKU: []string{oidEKUA, oidEKUB}}, twoEKU, 0, true},
		{"eku required but leaf has none", TrustConstraint{EKU: []string{oidEKUA}}, plain, 0, false},
		{"pathLen within", TrustConstraint{PathLen: &three}, plain, 3, true},
		{"pathLen exceeded", TrustConstraint{PathLen: &three}, plain, 4, false},
		{"pathLen zero, direct", TrustConstraint{PathLen: &zero}, plain, 0, true},
		{"pathLen zero, one intermediate", TrustConstraint{PathLen: &zero}, plain, 1, false},
		{"certificateProfiles cannot be established", TrustConstraint{CertificateProfiles: []string{"urn:x"}}, plain, 0, false},
		{"unknown extension", TrustConstraint{Extensions: ext}, plain, 0, false},
		{"all members must hold", TrustConstraint{Policies: []string{oidPolicyA}, EKU: []string{oidEKUB}}, both, 0, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := constraintSatisfied(tc.c, tc.leaf, tc.intermediates); got != tc.want {
				t.Errorf("got %v, want %v", got, tc.want)
			}
		})
	}

	// At least one fully satisfied constraint is enough; constraints are not combined.
	if !trustConstraintsSatisfied([]TrustConstraint{{Policies: []string{"1.9.9"}}, {Policies: []string{oidPolicyA}}}, both, 0) {
		t.Error("second constraint satisfied, expected trusted")
	}
	if trustConstraintsSatisfied([]TrustConstraint{{Policies: []string{"1.9.9"}}, {EKU: []string{oidEKUB}}}, both, 0) {
		t.Error("no single constraint satisfied, expected untrusted")
	}
}

func TestIntermediatesBelow(t *testing.T) {
	for k, want := range map[int]int{0: 0, 1: 0, 2: 1, 3: 2} {
		if got := intermediatesBelow(k); got != want {
			t.Errorf("intermediatesBelow(%d) = %d, want %d", k, got, want)
		}
	}
}

// End to end: constraints on the governing CertificateInfo decide the verdict,
// the misspelt CDDL key is honoured, and the override restores the old behaviour.
func TestEvaluate_EnforcesTrustConstraints(t *testing.T) {
	ricalRoot, ricalRootKey := generateCA(t, "Test RICAL Root")
	signerCert, signerKey := generateLeaf(t, ricalRoot, ricalRootKey, "Test RICAL Signer", 2)
	readerCA, readerCAKey := generateCA(t, "Test Reader CA")
	good := leafWith(t, readerCA, readerCAKey, 20, []string{oidPolicyA}, nil)
	bad := leafWith(t, readerCA, readerCAKey, 21, nil, nil)

	run := func(t *testing.T, info RICALCertificateInfo, ignore bool, leaf *x509.Certificate) bool {
		t.Helper()
		info.Certificate, info.SerialNumber, info.SKI = readerCA.Raw, readerCA.SerialNumber, readerCA.SubjectKeyId
		rical := &RICAL{
			Version: "1.0", Provider: "p", Date: time.Now().UTC().Format(time.RFC3339),
			Type:             "org.iso.18013.5.1.reader_authentication",
			CertificateInfos: []RICALCertificateInfo{info},
		}
		mock := newMockRicalServer(t, buildSignedRical(t, rical, signerCert, signerKey))
		defer mock.Close()
		reg, err := New(&Config{
			RicalProviderURL: mock.URL(), RicalRootCertificatePEM: certPEM(ricalRoot),
			AllowHTTP: true, AllowPrivateIPs: true, IgnoreTrustConstraints: ignore,
		})
		if err != nil {
			t.Fatal(err)
		}
		resp, err := reg.Evaluate(context.Background(), &authzen.EvaluationRequest{
			Resource: authzen.Resource{Type: "x5c", Key: []interface{}{certBase64(leaf), certBase64(readerCA)}},
		})
		if err != nil {
			t.Fatal(err)
		}
		return resp.Decision
	}

	withPolicy := RICALCertificateInfo{TrustConstraints: []TrustConstraint{{Policies: []string{oidPolicyA}}}}
	if !run(t, withPolicy, false, good) {
		t.Error("leaf with the required policy should be trusted")
	}
	if run(t, withPolicy, false, bad) {
		t.Error("leaf without the required policy must be denied")
	}
	if !run(t, withPolicy, true, bad) {
		t.Error("ignore_trust_constraints restores the permissive behaviour")
	}
	if run(t, RICALCertificateInfo{TrustConstraints: []TrustConstraint{{Extensions: map[string]cbor.RawMessage{"x": {0xf5}}}}}, false, good) {
		t.Error("a constraint with unknown extensions is not satisfied")
	}
	misspelt := RICALCertificateInfo{MisspeltTrustConstraints: []TrustConstraint{{Policies: []string{oidPolicyA}}}}
	if run(t, misspelt, false, bad) {
		t.Error("constraints under the CDDL spelling must be enforced")
	}
	if !run(t, RICALCertificateInfo{}, false, bad) {
		t.Error("no constraints: unchanged")
	}
}

func parseASN1OID(s string) (asn1.ObjectIdentifier, error) {
	var out asn1.ObjectIdentifier
	for _, part := range strings.Split(s, ".") {
		n, err := strconv.Atoi(part)
		if err != nil {
			return nil, err
		}
		out = append(out, n)
	}
	return out, nil
}
