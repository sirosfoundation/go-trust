package mdocrical

import (
	"context"
	"encoding/base64"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"

	"github.com/sirosfoundation/go-trust/pkg/authzen"
)

func ricalRegistry(t *testing.T, infos func(readerCA []byte) []RICALCertificateInfo) (*Registry, *RICAL) {
	t.Helper()
	ricalRoot, ricalRootKey := generateCA(t, "Test RICAL Root")
	signerCert, signerKey := generateLeaf(t, ricalRoot, ricalRootKey, "Test RICAL Signer", 2)
	readerCA, _ := generateCA(t, "Test Reader CA")
	rical := &RICAL{
		Version: "1.0", Provider: "p", Date: time.Now().UTC().Format(time.RFC3339),
		Type:             "org.iso.18013.5.1.reader_authentication",
		CertificateInfos: infos(readerCA.Raw),
	}
	mock := newMockRicalServer(t, buildSignedRical(t, rical, signerCert, signerKey))
	t.Cleanup(mock.Close)
	reg, err := New(&Config{Name: "geneva-rical", RicalProviderURL: mock.URL(), RicalRootCertificatePEM: certPEM(ricalRoot), AllowHTTP: true, AllowPrivateIPs: true})
	if err != nil {
		t.Fatal(err)
	}
	return reg, rical
}

func preloadReq(types ...string) *authzen.EvaluationRequest {
	return &authzen.EvaluationRequest{
		Subject: authzen.Subject{Type: "key", ID: "geneva-rical"},
		Context: map[string]interface{}{authzen.TrustAnchorsPolicyContextKey: types},
	}
}

// The export mirrors the RICAL entry, flags what the PDP cannot evaluate, and
// carries the fields needed to find the governing entry bottom-up (F.3.2.6).
func TestTrustAnchors_RICALMirrorsEntries(t *testing.T) {
	three := uint64(3)
	var caDER []byte
	reg, _ := ricalRegistry(t, func(ca []byte) []RICALCertificateInfo {
		caDER = ca
		return []RICALCertificateInfo{{
			Certificate: ca, SKI: []byte{1, 2, 3}, AKI: []byte{9}, IsTrustAnchor: true,
			Type: "reader", Name: "Reader CA", IssuingCountry: "CH",
			TrustConstraints: []TrustConstraint{
				{Policies: []string{oidPolicyA}, EKU: []string{oidEKUA}, PathLen: &three},
				{Extensions: map[string]cbor.RawMessage{"x": {0xf5}}},
			},
		}, {Certificate: []byte("garbage")}}
	})
	resp, err := reg.Evaluate(context.Background(), preloadReq("rical"))
	if err != nil || !resp.Decision || len(resp.Context.TrustAnchors) != 1 {
		t.Fatalf("preload failed: %v %+v", err, resp)
	}
	set := resp.Context.TrustAnchors[0]
	if set.Type != "rical" || set.Registry != "geneva-rical" || len(set.Anchors) != 1 {
		t.Fatalf("unexpected set: %+v", set)
	}
	a := set.Anchors[0]
	if a.X5C != base64.StdEncoding.EncodeToString(caDER) || a.SKI != "AQID" || a.AKI != "CQ==" ||
		a.IsTrustAnchor == nil || !*a.IsTrustAnchor || a.Type != "reader" || a.Name != "Reader CA" || a.IssuingCountry != "CH" {
		t.Errorf("anchor does not mirror the entry: %+v", a)
	}
	if len(a.TrustConstraints) != 2 {
		t.Fatalf("constraints: %+v", a.TrustConstraints)
	}
	c0, c1 := a.TrustConstraints[0], a.TrustConstraints[1]
	if c0.UnsupportedExtensions || c0.Policies[0] != oidPolicyA || c0.EKU[0] != oidEKUA || *c0.PathLen != 3 {
		t.Errorf("first constraint: %+v", c0)
	}
	if !c1.UnsupportedExtensions {
		t.Error("a constraint with extensions must be flagged")
	}
}

// A present-but-empty eku (decoded from a wire list; the test encoder would drop
// it) must not be exported as no restriction.
func TestTrustAnchors_RICALEmptyMemberNotExportedAsUnrestricted(t *testing.T) {
	reg, _ := ricalRegistry(t, func(ca []byte) []RICALCertificateInfo { return []RICALCertificateInfo{{Certificate: ca}} })
	ca, _ := generateCA(t, "X")
	set, ok := reg.trustAnchorSet(&RICAL{Date: time.Now().UTC().Format(time.RFC3339), CertificateInfos: []RICALCertificateInfo{{
		Certificate:      ca.Raw,
		TrustConstraints: []TrustConstraint{{EKU: []string{}}, {CertificateProfiles: []string{}}},
	}}})
	if !ok {
		t.Fatal("set not built")
	}
	for i, c := range set.Anchors[0].TrustConstraints {
		if !c.UnsupportedExtensions {
			t.Errorf("constraint %d: present-but-empty member exported as unrestricted", i)
		}
	}
}

func TestTrustAnchors_RICALAbsentIsTrustAnchorOmitted(t *testing.T) {
	reg, _ := ricalRegistry(t, func(ca []byte) []RICALCertificateInfo {
		return []RICALCertificateInfo{{Certificate: ca}}
	})
	resp, _ := reg.Evaluate(context.Background(), preloadReq("rical"))
	if a := resp.Context.TrustAnchors[0].Anchors[0]; a.IsTrustAnchor != nil {
		t.Errorf("is_trust_anchor must be omitted when the source does not say true: %+v", a)
	}
}

func TestTrustAnchors_RICALPreloadGating(t *testing.T) {
	reg, _ := ricalRegistry(t, func(ca []byte) []RICALCertificateInfo {
		return []RICALCertificateInfo{{Certificate: ca}}
	})
	if reg.SupportsResolutionOnly() || !reg.SupportsResolutionOnlyFor(preloadReq("rical")) || reg.SupportsResolutionOnlyFor(preloadReq("vical")) {
		t.Error("resolution-only support exists only for an enabled preload")
	}
	resp, _ := reg.Evaluate(context.Background(), preloadReq("vical"))
	if resp.Decision || len(resp.Context.TrustAnchors) != 0 {
		t.Errorf("type not enabled: denial without anchors, got %+v", resp)
	}
}

func TestTrustAnchors_RICALOnPositiveEvaluation(t *testing.T) {
	ricalRoot, ricalRootKey := generateCA(t, "Test RICAL Root")
	signerCert, signerKey := generateLeaf(t, ricalRoot, ricalRootKey, "Test RICAL Signer", 2)
	readerCA, readerCAKey := generateCA(t, "Test Reader CA")
	leaf := leafWith(t, readerCA, readerCAKey, 40, nil, nil)
	rical := &RICAL{
		Version: "1.0", Provider: "p", Date: time.Now().UTC().Format(time.RFC3339),
		Type:             "org.iso.18013.5.1.reader_authentication",
		CertificateInfos: []RICALCertificateInfo{{Certificate: readerCA.Raw, SKI: readerCA.SubjectKeyId}},
	}
	mock := newMockRicalServer(t, buildSignedRical(t, rical, signerCert, signerKey))
	defer mock.Close()
	reg, err := New(&Config{RicalProviderURL: mock.URL(), RicalRootCertificatePEM: certPEM(ricalRoot), AllowHTTP: true, AllowPrivateIPs: true})
	if err != nil {
		t.Fatal(err)
	}
	eval := func(ctx map[string]interface{}) *authzen.EvaluationResponse {
		resp, err := reg.Evaluate(context.Background(), &authzen.EvaluationRequest{
			Resource: authzen.Resource{Type: "x5c", Key: []interface{}{certBase64(leaf), certBase64(readerCA)}}, Context: ctx})
		if err != nil || !resp.Decision {
			t.Fatalf("expected trusted: %v %+v", err, resp)
		}
		return resp
	}
	if len(eval(nil).Context.TrustAnchors) != 0 {
		t.Error("anchors must not appear unless the policy enables them")
	}
	if got := eval(map[string]interface{}{authzen.TrustAnchorsPolicyContextKey: []string{"rical"}}).Context.TrustAnchors; len(got) != 1 {
		t.Errorf("want one set, got %+v", got)
	}
}

func TestTrustAnchors_RICALExpiredOffersNothing(t *testing.T) {
	ricalRoot, ricalRootKey := generateCA(t, "Test RICAL Root")
	signerCert, signerKey := generateLeaf(t, ricalRoot, ricalRootKey, "Test RICAL Signer", 2)
	readerCA, _ := generateCA(t, "Test Reader CA")
	rical := &RICAL{
		Version: "1.0", Provider: "p", Date: time.Now().UTC().Format(time.RFC3339),
		NotAfter:         time.Now().Add(-time.Minute).UTC().Format(time.RFC3339),
		CertificateInfos: []RICALCertificateInfo{{Certificate: readerCA.Raw}},
	}
	mock := newMockRicalServer(t, buildSignedRical(t, rical, signerCert, signerKey))
	defer mock.Close()
	reg, err := New(&Config{Name: "geneva-rical", RicalProviderURL: mock.URL(), RicalRootCertificatePEM: certPEM(ricalRoot), AllowHTTP: true, AllowPrivateIPs: true})
	if err != nil {
		t.Fatal(err)
	}
	resp, _ := reg.Evaluate(context.Background(), preloadReq("rical"))
	if resp.Decision || len(resp.Context.TrustAnchors) != 0 {
		t.Errorf("an expired list must not be offered: %+v", resp)
	}
}
