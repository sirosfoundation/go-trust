package registry

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/json"
	"math/big"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/sirosfoundation/go-trust/pkg/authzen"
	"github.com/sirosfoundation/go-trust/pkg/registry/rpcert"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// vidCertOpts describes a leaf for the verifier_ids tests.
type vidCertOpts struct {
	orgID    string // organizationIdentifier (2.5.4.97)
	serial   string // Subject serialNumber
	policy   string // WRPAC policy OID, "" for none
	dns      []string
	uris     []string
	noEmails bool // omit the contact SAN so WRPAC profile validation fails
}

// makeVIDCert builds a parsed leaf, so organizationIdentifier is visible in
// Subject.Names exactly as it is on a certificate off the wire.
func makeVIDCert(t *testing.T, o vidCertOpts) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	subject := pkix.Name{Country: []string{"SE"}, Organization: []string{"Test AB"}, CommonName: "rp", SerialNumber: o.serial}
	if o.orgID != "" {
		subject.ExtraNames = []pkix.AttributeTypeAndValue{{Type: asn1.ObjectIdentifier{2, 5, 4, 97}, Value: o.orgID}}
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      subject,
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		DNSNames:     o.dns,
	}
	tmpl.KeyUsage = x509.KeyUsageDigitalSignature
	if !o.noEmails {
		tmpl.EmailAddresses = []string{"admin@rp.example"}
	}
	for _, u := range o.uris {
		parsed, err := url.Parse(u)
		require.NoError(t, err)
		tmpl.URIs = append(tmpl.URIs, parsed)
	}
	if o.policy != "" {
		oid, err := x509.ParseOID(o.policy)
		require.NoError(t, err)
		tmpl.Policies = []x509.OID{oid}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return cert
}

// vidReq builds a request whose context carries what applyPolicyToRequest
// would write for a policy enabling the given types.
func vidReq(subjectID string, types []string, extra map[string]interface{}) *authzen.EvaluationRequest {
	ctx := map[string]interface{}{}
	if types != nil {
		ctx[authzen.VerifierIDsPolicyContextKey] = types
	}
	for k, v := range extra {
		ctx[k] = v
	}
	return &authzen.EvaluationRequest{
		Subject:  authzen.Subject{Type: "key", ID: subjectID},
		Resource: authzen.Resource{Type: "x5c"},
		Context:  ctx,
	}
}

func idsOf(ids []authzen.VerifierID) map[string]authzen.VerifierID {
	m := map[string]authzen.VerifierID{}
	for _, v := range ids {
		m[v.Type] = v
	}
	return m
}

func TestVerifierIDTypesEnabled(t *testing.T) {
	assert.Nil(t, VerifierIDTypesEnabled(nil))
	assert.Nil(t, VerifierIDTypesEnabled(&authzen.EvaluationRequest{}))
	assert.Nil(t, VerifierIDTypesEnabled(vidReq("x", nil, nil)), "policy off")

	assert.Equal(t, []string{"semantic", "x509_san_dns"}, VerifierIDTypesEnabled(vidReq("x", []string{"semantic", "x509_san_dns"}, nil)))
	// From JSON the policy list is []interface{}.
	req := vidReq("x", nil, map[string]interface{}{authzen.VerifierIDsPolicyContextKey: []interface{}{"x509_san_uri"}})
	assert.Equal(t, []string{"x509_san_uri"}, VerifierIDTypesEnabled(req))

	hint := func(h string) map[string]interface{} {
		return map[string]interface{}{authzen.VerifierIDHintContextKey: h}
	}
	assert.Equal(t, []string{"x509_san_dns"}, VerifierIDTypesEnabled(vidReq("x", []string{"semantic", "x509_san_dns"}, hint("x509_san_dns"))))
	// The hint only narrows: it cannot enable a type the policy did not.
	assert.Empty(t, VerifierIDTypesEnabled(vidReq("x", []string{"semantic"}, hint("x509_san_dns"))))
	assert.NotNil(t, VerifierIDTypesEnabled(vidReq("x", []string{"semantic"}, hint("x509_san_dns"))))
	// ...and with the policy off, a hint enables nothing.
	assert.Nil(t, VerifierIDTypesEnabled(vidReq("x", nil, hint("x509_san_dns"))))
	// Empty / non-string hint is ignored.
	assert.Equal(t, []string{"x509_san_dns"}, VerifierIDTypesEnabled(vidReq("x", []string{"x509_san_dns"}, hint(""))))
}

func TestAddVerifierID_FailsClosed(t *testing.T) {
	req := vidReq("x", []string{"x509_san_dns"}, nil)

	allow := &authzen.EvaluationResponse{Decision: true}
	AddVerifierID(allow, req, "x509_san_dns", "rp.example", "client-id-binding")
	require.NotNil(t, allow.Context)
	assert.Equal(t, []authzen.VerifierID{{Type: "x509_san_dns", ID: "rp.example", Basis: "client-id-binding"}}, allow.Context.VerifierIDs)

	AddVerifierID(allow, req, "x509_san_dns", "rp.example", "client-id-binding")
	assert.Len(t, allow.Context.VerifierIDs, 1, "duplicates are not added twice")

	deny := &authzen.EvaluationResponse{Decision: false}
	AddVerifierID(deny, req, "x509_san_dns", "rp.example", "client-id-binding")
	assert.Nil(t, deny.Context, "nothing on a deny")

	notEnabled := &authzen.EvaluationResponse{Decision: true}
	AddVerifierID(notEnabled, req, "x509_san_uri", "https://rp.example", "client-id-binding")
	assert.Nil(t, notEnabled.Context, "type the policy did not enable")

	empty := &authzen.EvaluationResponse{Decision: true}
	AddVerifierID(empty, req, "x509_san_dns", "", "client-id-binding")
	assert.Nil(t, empty.Context)

	AddVerifierID(nil, req, "x509_san_dns", "x", "b") // must not panic
}

func TestAddDIDVerifierID_RequiresSameDID(t *testing.T) {
	req := vidReq("did:web:rp.example#key-1", []string{"decentralized_identifier"}, nil)
	ok := &authzen.EvaluationResponse{Decision: true}
	AddDIDVerifierID(ok, req, "did:web:rp.example")
	require.NotNil(t, ok.Context)
	assert.Equal(t, []authzen.VerifierID{{Type: "decentralized_identifier", ID: "did:web:rp.example", Basis: "did-resolution"}}, ok.Context.VerifierIDs,
		"the fragment is dropped: the identifier is the DID, not a verification method")

	other := &authzen.EvaluationResponse{Decision: true}
	AddDIDVerifierID(other, req, "did:web:other.example")
	assert.Nil(t, other.Context, "a document with a different id is never emitted")

	AddDIDVerifierID(&authzen.EvaluationResponse{Decision: true}, nil, "did:web:rp.example") // must not panic
}

func TestCanonicalForms(t *testing.T) {
	got, ok := CanonicalDNSName("RP.Example.COM.")
	assert.True(t, ok)
	assert.Equal(t, "rp.example.com", got)
	got, ok = CanonicalDNSName("rp.example.com")
	assert.True(t, ok)
	assert.Equal(t, "rp.example.com", got)
	assert.Equal(t, "did:web:Example.com:Path", CanonicalDID("did:web:Example.com:Path#key-1"), "no case folding in a DID")
	assert.Equal(t, "did:web:example.com", CanonicalDID("did:web:example.com"))
}

// ---------------------------------------------------------------------------
// Enrichment: x5c-derived identifiers
// ---------------------------------------------------------------------------

func TestEnrichVerifierIDs_PolicyOffEmitsNothing(t *testing.T) {
	cert := makeVIDCert(t, vidCertOpts{orgID: "VATSE-556000000101", policy: rpcert.OIDNCPLegalPerson, dns: []string{"rp.example.com"}})
	res := EnrichX5CResponseWithProfiles(vidReq("x509_san_dns:rp.example.com", nil, nil), cert, rpcert.DefaultProfileRegistry())
	assert.Empty(t, res.VerifierIDs)

	resp := &authzen.EvaluationResponse{Decision: true}
	ApplyEnrichmentToResponse(resp, res)
	assert.Empty(t, resp.Context.VerifierIDs)
}

func TestEnrichVerifierIDs_Semantic_LegalPerson(t *testing.T) {
	cert := makeVIDCert(t, vidCertOpts{orgID: "VATSE-556000000101", policy: rpcert.OIDNCPLegalPerson})
	req := vidReq("https://rp.example.com", []string{"semantic"}, nil)
	res := EnrichX5CResponseWithProfiles(req, cert, rpcert.DefaultProfileRegistry())

	require.True(t, res.Decision)
	assert.Equal(t, []authzen.VerifierID{{
		Type: "semantic", ID: "semantic_id:VATSE-556000000101", Basis: "x5c-chain",
	}}, res.VerifierIDs)

	resp := &authzen.EvaluationResponse{Decision: true}
	ApplyEnrichmentToResponse(resp, res)
	assert.Equal(t, res.VerifierIDs, resp.Context.VerifierIDs)
}

// ETSI TS 119 475 5.1.5: natural-person semantic identifiers live in serialNumber.
func TestEnrichVerifierIDs_Semantic_NaturalPerson(t *testing.T) {
	cert := makeVIDCert(t, vidCertOpts{serial: "PNOSE-196001010101", policy: rpcert.OIDNCPNaturalPerson})
	res := EnrichX5CResponseWithProfiles(vidReq("https://rp.example.com", []string{"semantic"}, nil), cert, rpcert.DefaultProfileRegistry())
	require.True(t, res.Decision)
	assert.Equal(t, []authzen.VerifierID{{
		Type: "semantic", ID: "semantic_id:PNOSE-196001010101", Basis: "x5c-chain",
	}}, res.VerifierIDs)
}

// A serialNumber that is not a semantic identifier must not be emitted as
// `semantic`, for a legal or a natural person, with or without a profile.
func TestEnrichVerifierIDs_Semantic_NonSemanticSerialNumberNotEmitted(t *testing.T) {
	for _, policy := range []string{rpcert.OIDNCPLegalPerson, rpcert.OIDNCPNaturalPerson, ""} {
		cert := makeVIDCert(t, vidCertOpts{serial: "123456", policy: policy})
		res := EnrichX5CResponseWithProfiles(vidReq("https://rp.example.com", []string{"semantic"}, nil), cert, rpcert.DefaultProfileRegistry())
		assert.True(t, res.Decision)
		assert.Empty(t, res.VerifierIDs, "policy %q", policy)
	}
	// And with no profile registry at all.
	cert := makeVIDCert(t, vidCertOpts{serial: "123456"})
	assert.Empty(t, EnrichX5CResponse(vidReq("https://rp.example.com", []string{"semantic"}, nil), cert).VerifierIDs)
}

func TestEnrichVerifierIDs_Semantic_WithoutProfileRegistry(t *testing.T) {
	cert := makeVIDCert(t, vidCertOpts{orgID: "VATSE-556000000101", policy: rpcert.OIDNCPLegalPerson})
	res := EnrichX5CResponse(vidReq("https://rp.example.com", []string{"semantic"}, nil), cert)
	require.Len(t, res.VerifierIDs, 1)
	assert.Equal(t, "semantic_id:VATSE-556000000101", res.VerifierIDs[0].ID)
}

// Without a natural/legal-person policy OID the organizationIdentifier could be a
// natural person's affiliation rather than the verifier, so nothing is emitted.
func TestEnrichVerifierIDs_Semantic_UnclassifiedCertificateEmitsNothing(t *testing.T) {
	cert := makeVIDCert(t, vidCertOpts{orgID: "VATSE-556000000101"})
	assert.Empty(t, EnrichX5CResponse(vidReq("https://rp.example.com", []string{"semantic"}, nil), cert).VerifierIDs)
}

func TestEnrichVerifierIDs_DNS_CanonicalFormAndBasis(t *testing.T) {
	cert := makeVIDCert(t, vidCertOpts{dns: []string{"rp.example.com"}})
	// Mixed case and a trailing dot are one name: it must be one identifier.
	// VerifyLeafBinding is an exact match, so the cert carries the spelling used.
	certMixed := makeVIDCert(t, vidCertOpts{dns: []string{"RP.Example.com."}})

	res := EnrichX5CResponse(vidReq("x509_san_dns:rp.example.com", []string{"x509_san_dns"}, nil), cert)
	assert.Equal(t, []authzen.VerifierID{{Type: "x509_san_dns", ID: "rp.example.com", Basis: "client-id-binding"}}, res.VerifierIDs)

	res = EnrichX5CResponse(vidReq("x509_san_dns:RP.Example.com.", []string{"x509_san_dns"}, nil), certMixed)
	assert.Equal(t, []authzen.VerifierID{{Type: "x509_san_dns", ID: "rp.example.com", Basis: "client-id-binding"}}, res.VerifierIDs)
}

func TestEnrichVerifierIDs_URI_ByteForByte(t *testing.T) {
	cert := makeVIDCert(t, vidCertOpts{uris: []string{"https://rp.example.com/Path/"}})
	res := EnrichX5CResponse(vidReq("x509_san_uri:https://rp.example.com/Path/", []string{"x509_san_uri"}, nil), cert)
	assert.Equal(t, []authzen.VerifierID{{Type: "x509_san_uri", ID: "https://rp.example.com/Path/", Basis: "client-id-binding"}}, res.VerifierIDs,
		"case and trailing slash are kept: not re-serialised")

	// A "//" in the value (the credential-offer regression) survives.
	cert = makeVIDCert(t, vidCertOpts{uris: []string{"https://rp.example.com//a"}})
	res = EnrichX5CResponse(vidReq("x509_san_uri:https://rp.example.com//a", []string{"x509_san_uri"}, nil), cert)
	require.Len(t, res.VerifierIDs, 1)
	assert.Equal(t, "https://rp.example.com//a", res.VerifierIDs[0].ID)
}

func TestEnrichVerifierIDs_UnverifiedClientIDNeverEchoed(t *testing.T) {
	cert := makeVIDCert(t, vidCertOpts{dns: []string{"rp.example.com"}, uris: []string{"https://rp.example.com"}, orgID: "VATSE-1"})
	types := []string{"x509_san_dns", "x509_san_uri"}

	// client_id names a host that is not a SAN of the leaf.
	res := EnrichX5CResponse(vidReq("x509_san_dns:evil.example.net", types, nil), cert)
	assert.Empty(t, res.VerifierIDs)
	res = EnrichX5CResponse(vidReq("x509_san_uri:https://evil.example.net", types, nil), cert)
	assert.Empty(t, res.VerifierIDs)

	// A scheme with no SAN binding (x509_hash) and a plain URL carry nothing.
	res = EnrichX5CResponse(vidReq("x509_hash:abcd", types, nil), cert)
	assert.Empty(t, res.VerifierIDs)
	res = EnrichX5CResponse(vidReq("https://rp.example.com", types, nil), cert)
	assert.Empty(t, res.VerifierIDs)

	// Wildcard client_id is not an identifier of one RP, even if the SAN is literally the same.
	wild := makeVIDCert(t, vidCertOpts{dns: []string{"*.example.com"}})
	res = EnrichX5CResponse(vidReq("x509_san_dns:*.example.com", []string{"x509_san_dns"}, nil), wild)
	assert.Empty(t, res.VerifierIDs)

	// A dns binding does not satisfy the uri type and vice versa.
	res = EnrichX5CResponse(vidReq("x509_san_dns:rp.example.com", []string{"x509_san_uri"}, nil), cert)
	assert.Empty(t, res.VerifierIDs)
}

// Nothing is emitted when profile validation failed, even though that is only a
// warning for the decision.
func TestEnrichVerifierIDs_ProfileValidationFailureEmitsNothing(t *testing.T) {
	cert := makeVIDCert(t, vidCertOpts{orgID: "VATSE-556000000101", policy: rpcert.OIDNCPLegalPerson, dns: []string{"rp.example.com"}, noEmails: true})
	req := vidReq("x509_san_dns:rp.example.com", []string{"semantic", "x509_san_dns"}, nil)
	res := EnrichX5CResponseWithProfiles(req, cert, rpcert.DefaultProfileRegistry())

	require.True(t, res.Decision, "profile failure is a warning, not a deny")
	require.NotEmpty(t, res.ProfileValidationError)
	assert.Empty(t, res.VerifierIDs)

	// Apply must not smuggle identifiers in either, even if a caller set them.
	res.VerifierIDs = []authzen.VerifierID{{Type: "semantic", ID: "semantic_id:VATSE-1"}}
	resp := &authzen.EvaluationResponse{Decision: true}
	ApplyEnrichmentToResponse(resp, res)
	assert.Empty(t, resp.Context.VerifierIDs)
}

func TestEnrichVerifierIDs_DenyEmitsNothing(t *testing.T) {
	cert := makeVIDCert(t, vidCertOpts{orgID: "VATSE-556000000101", policy: rpcert.OIDNCPLegalPerson})

	// Enrichment denies (required policy OID missing): nothing is derived.
	req := vidReq("https://rp.example.com", []string{"semantic"}, map[string]interface{}{
		"required_cert_policy_oids": []string{"1.2.3.4"},
	})
	res := EnrichX5CResponseWithProfiles(req, cert, rpcert.DefaultProfileRegistry())
	assert.False(t, res.Decision)
	assert.Empty(t, res.VerifierIDs)

	// A deny response never gets identifiers, whatever the enrichment says.
	good := EnrichX5CResponseWithProfiles(vidReq("https://rp.example.com", []string{"semantic"}, nil), cert, rpcert.DefaultProfileRegistry())
	require.NotEmpty(t, good.VerifierIDs)
	deny := &authzen.EvaluationResponse{Decision: false}
	ApplyEnrichmentToResponse(deny, good)
	assert.Empty(t, deny.Context.VerifierIDs)

	// An enrichment that itself denied (e.g. one a caller built by hand).
	good.Decision = false
	allow := &authzen.EvaluationResponse{Decision: true}
	ApplyEnrichmentToResponse(allow, good)
	assert.Empty(t, allow.Context.VerifierIDs)
}

// Intermediary request: the identifier is the end RP's. The leaf is the end
// RP's certificate (semantic is established); the client_id of a brokered
// request is not shown to name the end RP, so dns/uri are omitted; the
// intermediary's own (unvalidated) chain is never a source.
func TestEnrichVerifierIDs_Intermediary(t *testing.T) {
	cert := makeVIDCert(t, vidCertOpts{orgID: "VATSE-556000000101", policy: rpcert.OIDNCPLegalPerson, dns: []string{"rp.example.com"}})
	extra := map[string]interface{}{
		"allow_intermediaries": true,
		"intermediary_x5c":     []string{"MIIBintermediary"},
	}
	res := EnrichX5CResponseWithProfiles(
		vidReq("x509_san_dns:rp.example.com", []string{"semantic", "x509_san_dns"}, extra), cert, rpcert.DefaultProfileRegistry())

	require.True(t, res.Decision)
	require.True(t, res.IsIntermediaryRequest)
	got := idsOf(res.VerifierIDs)
	require.Contains(t, got, "semantic")
	assert.Equal(t, "semantic_id:VATSE-556000000101", got["semantic"].ID)
	assert.NotContains(t, got, "x509_san_dns", "dns cannot be established as the end RP's for an intermediary")

	// Same request without the intermediary: dns is there, so the omission is
	// the intermediary's doing.
	res = EnrichX5CResponseWithProfiles(
		vidReq("x509_san_dns:rp.example.com", []string{"semantic", "x509_san_dns"}, nil), cert, rpcert.DefaultProfileRegistry())
	assert.Contains(t, idsOf(res.VerifierIDs), "x509_san_dns")

	// Intermediary with a leaf that has no semantic id: nothing at all.
	bare := makeVIDCert(t, vidCertOpts{serial: "123456", dns: []string{"rp.example.com"}})
	res = EnrichX5CResponseWithProfiles(
		vidReq("x509_san_dns:rp.example.com", []string{"semantic", "x509_san_dns"}, extra), bare, rpcert.DefaultProfileRegistry())
	assert.Empty(t, res.VerifierIDs)
}

func TestEnrichVerifierIDs_HintNarrowsToOneEntry(t *testing.T) {
	cert := makeVIDCert(t, vidCertOpts{orgID: "VATSE-556000000101", policy: rpcert.OIDNCPLegalPerson, dns: []string{"rp.example.com"}})
	types := []string{"semantic", "x509_san_dns"}
	profiles := rpcert.DefaultProfileRegistry()

	all := EnrichX5CResponseWithProfiles(vidReq("x509_san_dns:rp.example.com", types, nil), cert, profiles)
	assert.Len(t, all.VerifierIDs, 2, "everything the policy enables")

	hinted := map[string]interface{}{authzen.VerifierIDHintContextKey: "x509_san_dns"}
	one := EnrichX5CResponseWithProfiles(vidReq("x509_san_dns:rp.example.com", types, hinted), cert, profiles)
	require.Len(t, one.VerifierIDs, 1)
	assert.Equal(t, "x509_san_dns", one.VerifierIDs[0].Type)

	// A hint for a type the policy does not enable returns nothing.
	hinted = map[string]interface{}{authzen.VerifierIDHintContextKey: "x509_san_uri"}
	none := EnrichX5CResponseWithProfiles(vidReq("x509_san_dns:rp.example.com", types, hinted), cert, profiles)
	assert.Empty(t, none.VerifierIDs)
}

func TestApplyEnrichmentToResponse_VerifierIDsJSONShape(t *testing.T) {
	cert := makeVIDCert(t, vidCertOpts{orgID: "VATSE-556000000101", policy: rpcert.OIDNCPLegalPerson, dns: []string{"rp.example.com"}})
	res := EnrichX5CResponseWithProfiles(vidReq("x509_san_dns:rp.example.com", []string{"semantic", "x509_san_dns"}, nil), cert, rpcert.DefaultProfileRegistry())
	resp := &authzen.EvaluationResponse{Decision: true}
	ApplyEnrichmentToResponse(resp, res)

	b, err := json.Marshal(resp)
	require.NoError(t, err)
	assert.JSONEq(t, `{"decision":true,"context":{"reason":{"matched_profile":"wrpac"},"trust_metadata":{"rp_profile":"wrpac"},"verifier_ids":[
		{"verifier_id_type":"semantic","verifier_id":"semantic_id:VATSE-556000000101","basis":"x5c-chain"},
		{"verifier_id_type":"x509_san_dns","verifier_id":"rp.example.com","basis":"client-id-binding"}]}}`, string(b))
}

// The vectors are shared with the SDKs, which hash the value byte for byte and
// must produce the same strings.
func TestEnrichVerifierIDs_DNS_SharedVectors(t *testing.T) {
	raw, err := os.ReadFile("testdata/x509_san_dns_verifier_id_vectors.json")
	require.NoError(t, err)
	var file struct {
		Vectors []struct {
			Name       string  `json:"name"`
			SAN        string  `json:"san"`
			ClientID   string  `json:"client_id"`
			VerifierID *string `json:"verifier_id"`
		} `json:"vectors"`
	}
	require.NoError(t, json.Unmarshal(raw, &file))
	require.NotEmpty(t, file.Vectors)

	for _, v := range file.Vectors {
		t.Run(v.Name, func(t *testing.T) {
			// A SAN that Go's x509 builder refuses to encode can only be exercised
			// through the canonicaliser, which is where non-ASCII is refused.
			cert := makeVIDCert(t, vidCertOpts{dns: []string{v.SAN}})
			res := EnrichX5CResponse(vidReq(v.ClientID, []string{"x509_san_dns"}, nil), cert)
			if v.VerifierID == nil {
				assert.Empty(t, res.VerifierIDs)
				return
			}
			require.Len(t, res.VerifierIDs, 1)
			assert.Equal(t, authzen.VerifierID{Type: "x509_san_dns", ID: *v.VerifierID, Basis: "client-id-binding"}, res.VerifierIDs[0])
		})
	}
}

// Non-ASCII is refused by the canonicaliser itself, not left to the SAN binding
// (a non-ASCII dNSName does not survive certificate parsing, but the rule must
// not depend on that).
func TestCanonicalDNSName_RefusesWhatIsNotAnIdentifier(t *testing.T) {
	for _, name := range []string{"", ".", "bücher.example", "a..b", ".a", "a.b..", " a.b", "a.b ", "*.example.com", "a\tb.example", strings.Repeat("a", 64) + ".example"} {
		got, ok := CanonicalDNSName(name)
		assert.False(t, ok, "%q", name)
		assert.Empty(t, got, "%q", name)
	}
}
