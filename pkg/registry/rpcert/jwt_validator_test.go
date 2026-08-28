package rpcert

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// buildWRPRCJWT creates a minimal WRPRC JWT (unsigned — the header includes a
// real x5c chain but the signature is a dummy byte, which is fine for payload
// extraction tests; signature verification tests use the real leaf key).
func buildWRPRCJWT(t *testing.T, payload wrprcPayload, signerCert *x509.Certificate, signerKey *ecdsa.PrivateKey) string {
	t.Helper()

	x5cDER := base64.StdEncoding.EncodeToString(signerCert.Raw)
	hdr := map[string]interface{}{
		"typ": WRPRCTyp,
		"alg": "ES256",
		"x5c": []string{x5cDER},
	}
	hdrJSON, _ := json.Marshal(hdr)
	hdrB64 := base64.RawURLEncoding.EncodeToString(hdrJSON)

	payJSON, _ := json.Marshal(payload)
	payB64 := base64.RawURLEncoding.EncodeToString(payJSON)

	// Sign the header.payload with the signer key
	msg := hdrB64 + "." + payB64
	sig, err := signerKey.Sign(rand.Reader, []byte(msg), nil)
	if err != nil {
		sig = []byte("dummy")
	}
	sigB64 := base64.RawURLEncoding.EncodeToString(sig)

	return msg + "." + sigB64
}

// generateWRPRCProviderCert generates a self-signed WRPRC provider CA cert.
func generateWRPRCProviderCert(t *testing.T) (*x509.Certificate, *ecdsa.PrivateKey, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber:          big.NewInt(42),
		Subject:               pkix.Name{Organization: []string{"WRPRC Provider TSP"}, CommonName: "wrprc-ca.example.com"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)

	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return cert, key, pool
}

// annex C example payload (with the spec's typo corrected: "leagal_name" → "legal_name").
// Uses relative timestamps to stay valid at any test run time.
func annexCPayload() wrprcPayload {
	iat := time.Now().Add(-time.Hour).Unix()
	exp := time.Now().Add(11 * 30 * 24 * time.Hour).Unix() // ~11 months — within GEN-5.2.4-08 limit
	return wrprcPayload{
		Name: "Example GmbH",
		Sub: wrprcSub{
			LegalName: "Example GmbH",
			ID:        "LEIXG-529900T8BM49AURSDO55",
		},
		Entitlements:  []string{EntitlementNonQEAAProvider},
		Country:       "DE",
		PrivacyPolicy: "https://example-company.com/en/privacy-policy",
		PolicyIDs:     []string{OIDWRPRCPolicy},
		Iat:           iat,
		Exp:           exp,
		Purpose: []MultiLangString{
			{Lang: "en-US", Value: "Required for checking the minimum age"},
			{Lang: "de-DE", Value: "Benötigt für die Überprüfung des Mindestalters"},
		},
		Credentials: []wrprcCredential{
			{
				Format: "dc+sd-jwt",
				Meta:   map[string]interface{}{"vct_values": []interface{}{"https://credentials.example.com/identity_credential"}},
				Claims: []wrprcClaim{
					{Path: []string{"given_name"}},
					{Path: []string{"family_name"}},
					{Path: []string{"address", "street_address"}},
				},
			},
		},
		PublicBody: false,
		Status: &wrprcStatus{
			StatusList: struct {
				Idx int    `json:"idx"`
				URI string `json:"uri"`
			}{Idx: 0, URI: "https://example.com/statuslists/1"},
		},
		Act: &wrprcAct{Sub: "DE:EX-987654381"},
	}
}

// ---------------------------------------------------------------------------
// JWTRegistrationCertValidator
// ---------------------------------------------------------------------------

func TestJWTValidator_Format(t *testing.T) {
	v := NewJWTRegistrationCertValidator(nil)
	assert.Equal(t, "jwt", v.Format())
}

func TestJWTValidator_NilRoots(t *testing.T) {
	v := NewJWTRegistrationCertValidator(nil)
	_, err := v.Validate(context.Background(), []byte("a.b.c"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no trust anchors configured")
}

func TestJWTValidator_NotThreeParts(t *testing.T) {
	cert, key, pool := generateWRPRCProviderCert(t)
	_ = cert
	_ = key
	v := NewJWTRegistrationCertValidator(pool)
	_, err := v.Validate(context.Background(), []byte("onlyone"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "expected 3 parts")
}

func TestJWTValidator_WrongTyp(t *testing.T) {
	cert, key, pool := generateWRPRCProviderCert(t)

	x5cDER := base64.StdEncoding.EncodeToString(cert.Raw)
	hdr := map[string]interface{}{"typ": "JWT", "alg": "ES256", "x5c": []string{x5cDER}}
	hdrJSON, _ := json.Marshal(hdr)
	hdrB64 := base64.RawURLEncoding.EncodeToString(hdrJSON)

	payload := annexCPayload()
	payJSON, _ := json.Marshal(payload)
	payB64 := base64.RawURLEncoding.EncodeToString(payJSON)

	sig, _ := key.Sign(rand.Reader, []byte(hdrB64+"."+payB64), nil)
	token := hdrB64 + "." + payB64 + "." + base64.RawURLEncoding.EncodeToString(sig)

	v := NewJWTRegistrationCertValidator(pool)
	_, err := v.Validate(context.Background(), []byte(token))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unexpected JWT typ")
}

func TestJWTValidator_MissingX5C(t *testing.T) {
	_, _, pool := generateWRPRCProviderCert(t)

	hdr := map[string]interface{}{"typ": WRPRCTyp, "alg": "ES256"}
	hdrJSON, _ := json.Marshal(hdr)
	hdrB64 := base64.RawURLEncoding.EncodeToString(hdrJSON)
	payB64 := base64.RawURLEncoding.EncodeToString([]byte("{}"))

	v := NewJWTRegistrationCertValidator(pool)
	_, err := v.Validate(context.Background(), []byte(hdrB64+"."+payB64+".sig"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "missing x5c")
}

func TestJWTValidator_UntrustedChain(t *testing.T) {
	cert, key, _ := generateWRPRCProviderCert(t)
	emptyPool := x509.NewCertPool() // different pool — cert not trusted

	payload := annexCPayload()
	token := buildWRPRCJWT(t, payload, cert, key)

	v := NewJWTRegistrationCertValidator(emptyPool)
	_, err := v.Validate(context.Background(), []byte(token))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "chain validation failed")
}

func TestJWTValidator_MissingEntitlements(t *testing.T) {
	cert, key, pool := generateWRPRCProviderCert(t)

	payload := annexCPayload()
	payload.Entitlements = nil // violates GEN-5.2.4-03

	token := buildWRPRCJWT(t, payload, cert, key)
	v := NewJWTRegistrationCertValidator(pool)
	_, err := v.Validate(context.Background(), []byte(token))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "GEN-5.2.4-03")
}

func TestJWTValidator_MissingSub(t *testing.T) {
	cert, key, pool := generateWRPRCProviderCert(t)

	payload := annexCPayload()
	payload.Sub = wrprcSub{} // empty sub

	token := buildWRPRCJWT(t, payload, cert, key)
	v := NewJWTRegistrationCertValidator(pool)
	_, err := v.Validate(context.Background(), []byte(token))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no usable sub claim")
}

func TestJWTValidator_ExpExceeds12Months(t *testing.T) {
	cert, key, pool := generateWRPRCProviderCert(t)

	payload := annexCPayload()
	payload.Iat = time.Now().Unix()
	payload.Exp = time.Now().Add(13 * 30 * 24 * time.Hour).Unix() // ~13 months

	token := buildWRPRCJWT(t, payload, cert, key)
	v := NewJWTRegistrationCertValidator(pool)
	_, err := v.Validate(context.Background(), []byte(token))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "GEN-5.2.4-08")
}

func TestJWTValidator_AnnexCExample(t *testing.T) {
	cert, key, pool := generateWRPRCProviderCert(t)

	payload := annexCPayload()
	token := buildWRPRCJWT(t, payload, cert, key)

	v := NewJWTRegistrationCertValidator(pool)
	ent, err := v.Validate(context.Background(), []byte(token))
	require.NoError(t, err)
	require.NotNil(t, ent)

	// Subject (Table 7)
	assert.Equal(t, "LEIXG-529900T8BM49AURSDO55", ent.Subject.ID)
	assert.Equal(t, "Example GmbH", ent.Subject.LegalName)
	assert.Equal(t, "LEIXG-529900T8BM49AURSDO55", ent.RPIdentifier)

	// Trade name
	assert.Equal(t, "Example GmbH", ent.TradeName)

	// Country
	assert.Equal(t, "DE", ent.Country)

	// Entitlement role URI (Annex A.2.3)
	assert.Equal(t, []string{EntitlementNonQEAAProvider}, ent.EntitlementURIs)
	assert.True(t, ent.IsEAAProvider())
	assert.False(t, ent.HasEntitlement(EntitlementPIDProvider))

	// Policy OID (OVR-6.1.3-01)
	assert.Contains(t, ent.PolicyIDs, OIDWRPRCPolicy)

	// DCQL allowed attributes extracted from credentials[].claims[].path[0]
	assert.ElementsMatch(t, []string{"given_name", "family_name", "address"}, ent.AllowedAttributes)

	// Purpose multilang
	require.Len(t, ent.Purpose, 2)
	assert.Equal(t, "en-US", ent.Purpose[0].Lang)

	// Status list
	assert.Equal(t, "https://example.com/statuslists/1", ent.StatusListURI)
	assert.Equal(t, 0, ent.StatusListIndex)

	// Intermediary delegation (act.sub → ActingIntermediary)
	assert.Equal(t, "DE:EX-987654381", ent.ActingIntermediary)

	// Public body flag
	assert.False(t, ent.IsPublicBody)

	// Privacy policy
	assert.Equal(t, "https://example-company.com/en/privacy-policy", ent.PrivacyPolicyURI)

	// Registration state. Validate never verifies the JWT signature - it
	// only evaluates the x5c chain - so the entitlements come back
	// StatusUnknown and IsValid reports false. This assertion previously
	// required the opposite, which is what made the missing signature check
	// look intentional: a payload swapped under an authentic header would
	// have been reported as a valid registration.
	assert.Equal(t, StatusUnknown, ent.RegistrationStatus)
	assert.False(t, ent.IsValid())
}

func TestJWTValidator_OverRequestDetection(t *testing.T) {
	cert, key, pool := generateWRPRCProviderCert(t)
	payload := annexCPayload()
	token := buildWRPRCJWT(t, payload, cert, key)

	v := NewJWTRegistrationCertValidator(pool)
	ent, err := v.Validate(context.Background(), []byte(token))
	require.NoError(t, err)

	// RP entitled to given_name, family_name, address
	result := DetectOverRequest(ent, []string{"given_name", "family_name"})
	assert.False(t, result.IsOverRequest)

	// Request includes birth_date which is not in credentials
	result = DetectOverRequest(ent, []string{"given_name", "birth_date"})
	assert.True(t, result.IsOverRequest)
	assert.Equal(t, []string{"birth_date"}, result.OverRequested)
}

// ---------------------------------------------------------------------------
// Entitlement constants and helpers
// ---------------------------------------------------------------------------

func TestEntitlementConstants_AllDefined(t *testing.T) {
	assert.Len(t, AllEntitlementURIs, 10, "Annex A.2 defines exactly 10 entitlements")
}

func TestEntitlementConstants_URIPrefix(t *testing.T) {
	for _, uri := range AllEntitlementURIs {
		assert.True(t, strings.HasPrefix(uri, "https://uri.etsi.org/19475/Entitlement/"),
			"entitlement URI should start with ETSI namespace: %s", uri)
	}
}

func TestSubEntitlementConstants_URIPrefix(t *testing.T) {
	for _, uri := range []string{
		SubEntitlementPSPAS, SubEntitlementPSPPI, SubEntitlementPSPAI,
		SubEntitlementPSPIC, SubEntitlementPSPUnspecified,
	} {
		assert.True(t, strings.HasPrefix(uri, "https://uri.etsi.org/19475/SubEntitlement/"),
			"sub-entitlement URI should start with ETSI SubEntitlement namespace: %s", uri)
	}
}

func TestHasEntitlement(t *testing.T) {
	ent := &RPEntitlements{
		EntitlementURIs: []string{EntitlementNonQEAAProvider, EntitlementServiceProvider},
	}
	assert.True(t, ent.HasEntitlement(EntitlementNonQEAAProvider))
	assert.True(t, ent.HasEntitlement(EntitlementServiceProvider))
	assert.False(t, ent.HasEntitlement(EntitlementPIDProvider))
}

func TestIsEAAProvider(t *testing.T) {
	for _, uri := range []string{
		EntitlementQEAAProvider,
		EntitlementNonQEAAProvider,
		EntitlementPUBEAAProvider,
	} {
		ent := &RPEntitlements{EntitlementURIs: []string{uri}}
		assert.True(t, ent.IsEAAProvider(), "expected IsEAAProvider for %s", uri)
	}
	ent := &RPEntitlements{EntitlementURIs: []string{EntitlementServiceProvider}}
	assert.False(t, ent.IsEAAProvider())
}

func TestOIDWRPRCPolicy(t *testing.T) {
	assert.Equal(t, "0.4.0.19475.3.1", OIDWRPRCPolicy)
}

// ---------------------------------------------------------------------------
// WRPRCSubject
// ---------------------------------------------------------------------------

func TestWRPRCSubject_LegalPerson(t *testing.T) {
	sub := WRPRCSubject{
		LegalName: "Example GmbH",
		ID:        "LEIXG-529900T8BM49AURSDO55",
	}
	assert.NotEmpty(t, sub.LegalName)
	assert.NotEmpty(t, sub.ID)
	assert.Empty(t, sub.GivenName)
}

func TestWRPRCSubject_NaturalPerson(t *testing.T) {
	sub := WRPRCSubject{
		GivenName:  "Hans",
		FamilyName: "Müller",
		ID:         "VATDE-DE123456789",
	}
	assert.Empty(t, sub.LegalName)
	assert.NotEmpty(t, sub.GivenName)
	assert.NotEmpty(t, sub.FamilyName)
}

// ---------------------------------------------------------------------------
// topLevelClaimNames
// ---------------------------------------------------------------------------

func TestTopLevelClaimNames(t *testing.T) {
	creds := []wrprcCredential{
		{
			Claims: []wrprcClaim{
				{Path: []string{"given_name"}},
				{Path: []string{"family_name"}},
				{Path: []string{"address", "street_address"}},
			},
		},
		{
			Claims: []wrprcClaim{
				{Path: []string{"given_name"}}, // duplicate — should be deduplicated
				{Path: []string{"age_over_18"}},
			},
		},
	}
	attrs := topLevelClaimNames(creds)
	assert.ElementsMatch(t, []string{"given_name", "family_name", "address", "age_over_18"}, attrs)
}

func TestTopLevelClaimNames_Empty(t *testing.T) {
	assert.Nil(t, topLevelClaimNames(nil))
	assert.Nil(t, topLevelClaimNames([]wrprcCredential{}))
}

// ---------------------------------------------------------------------------
// parseX5CChain
// ---------------------------------------------------------------------------

func TestParseX5CChain_EmptySlice(t *testing.T) {
	_, _, err := parseX5CChain([]string{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "empty")
}

func TestParseX5CChain_InvalidBase64(t *testing.T) {
	_, _, err := parseX5CChain([]string{"not-valid-base64!!!"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "x5c[0]")
}

func TestParseX5CChain_ValidSingleCert(t *testing.T) {
	cert, _, _ := generateWRPRCProviderCert(t)
	b64 := base64.StdEncoding.EncodeToString(cert.Raw)
	leaf, ints, err := parseX5CChain([]string{b64})
	require.NoError(t, err)
	assert.Equal(t, cert.SerialNumber, leaf.SerialNumber)
	_ = ints
}

// ---------------------------------------------------------------------------
// ValidatorRegistry with JWT format
// ---------------------------------------------------------------------------

func TestValidatorRegistry_JWTFormat(t *testing.T) {
	reg := NewValidatorRegistry()
	_, _, pool := generateWRPRCProviderCert(t)
	v := NewJWTRegistrationCertValidator(pool)
	reg.Register("jwt", v)

	got, err := reg.Get("jwt")
	require.NoError(t, err)
	assert.Equal(t, "jwt", got.Format())

	formats := reg.Formats()
	assert.Contains(t, formats, "jwt")
}

// Ensure the Annex C typo note is documented: the spec has "leagal_name" but
// we map it to "legal_name". This test verifies the canonical field name.
func TestWRPRCPayload_LegalNameFieldIsCanonical(t *testing.T) {
	raw := `{"legal_name":"Acme Corp","id":"NTRDEX-HRB123456B"}`
	var sub wrprcSub
	require.NoError(t, json.Unmarshal([]byte(raw), &sub))
	assert.Equal(t, "Acme Corp", sub.LegalName)

	// Spec Annex C has a typo "leagal_name" — we do NOT support the typo
	rawTypo := `{"leagal_name":"Acme Corp","id":"NTRDEX-HRB123456B"}`
	var subTypo wrprcSub
	require.NoError(t, json.Unmarshal([]byte(rawTypo), &subTypo))
	assert.Empty(t, subTypo.LegalName, "spec typo 'leagal_name' is not parsed — use canonical 'legal_name'")
	_ = fmt.Sprintf("TODO: file a corrigendum to TS 119 475 v1.1.1 Annex C: 'leagal_name' should be 'legal_name'")
}

// TestJWTValidator_TypIsComparedExactly pins the strict reading. A JWT typ
// is nominally a media type and so case-insensitive, which makes this the
// kind of check that gets softened back by a well-meaning edit.
func TestJWTValidator_TypIsComparedExactly(t *testing.T) {
	cert, key, pool := generateWRPRCProviderCert(t)
	token := buildWRPRCJWT(t, annexCPayload(), cert, key)

	// Re-encode the header with a case variant of the media type.
	parts := strings.Split(token, ".")
	require.Len(t, parts, 3)
	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	require.NoError(t, err)
	var header map[string]any
	require.NoError(t, json.Unmarshal(headerBytes, &header))
	header["typ"] = strings.ToUpper(WRPRCTyp)
	reencoded, err := json.Marshal(header)
	require.NoError(t, err)
	parts[0] = base64.RawURLEncoding.EncodeToString(reencoded)

	v := NewJWTRegistrationCertValidator(pool)
	_, err = v.Validate(context.Background(), []byte(strings.Join(parts, ".")))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unexpected JWT typ")
}
