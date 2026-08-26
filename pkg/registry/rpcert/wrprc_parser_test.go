package rpcert

import (
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// Real Registrar output
// ---------------------------------------------------------------------------

// TestParseWRPRCClaims_GermanSandbox parses a certificate actually issued by
// the German EUDI sandbox Registrar. It differs from a strict reading of the
// v1.1.1 tables in four ways at once, each of which broke a parser that
// assumed the tables literally.
func TestParseWRPRCClaims_GermanSandbox(t *testing.T) {
	token, err := os.ReadFile("testdata/german-sandbox-wrprc.jwt")
	require.NoError(t, err)

	payload, err := ParseWRPRCJWTPayload(string(token))
	require.NoError(t, err)

	ent, err := ParseWRPRCClaims(payload)
	require.NoError(t, err)

	// sub is a bare identifier string, not the structured object.
	assert.Equal(t, "NTRDE-BD7070256AF93987", ent.Subject.ID)
	assert.Equal(t, "NTRDE-BD7070256AF93987", ent.RPIdentifier)

	// The legal name is a sibling claim, not nested under sub.
	assert.Equal(t, "Siros Foundation", ent.Subject.LegalName)
	assert.Equal(t, "Siros Foundation", ent.TradeName)

	// The DCQL claim list is named "claim", not "claims". Reading only
	// "claims" yields an empty set here, which downstream means "may
	// request nothing" rather than failing.
	assert.ElementsMatch(t,
		[]string{"birth_date", "family_name", "given_name"},
		ent.AllowedAttributes)

	// srv_description arrives as a list of lists, not a flat list.
	require.Len(t, ent.ServiceDescriptions, 1)
	assert.Equal(t, "en", ent.ServiceDescriptions[0].Lang)
	assert.Equal(t, "Web Relying Party", ent.ServiceDescriptions[0].Value)

	assert.Equal(t, "DE", ent.Country)
	assert.Equal(t, []string{EntitlementServiceProvider}, ent.EntitlementURIs)
	require.Len(t, ent.Purpose, 1)
	assert.Equal(t, "Demo", ent.Purpose[0].Value)
	assert.Equal(t, "https://siros.org/contact", ent.SupportURI)

	// The revocation reference a status-list checker needs.
	assert.Equal(t, "https://sandbox.eudi-wallet.org/api/status-management/status-list", ent.StatusListURI)
	assert.Equal(t, 9940, ent.StatusListIndex)

	// Parsing alone establishes nothing.
	assert.Equal(t, StatusUnknown, ent.RegistrationStatus)
	assert.False(t, ent.IsValid())
}

// ---------------------------------------------------------------------------
// Version tolerance
// ---------------------------------------------------------------------------

// TestParseWRPRCClaims_VersionEquivalence is the conformance test for the
// whole point of this parser: the same registration expressed in v1.1.1 and
// v1.2.1 spellings must reduce to the same entitlements.
func TestParseWRPRCClaims_VersionEquivalence(t *testing.T) {
	v111 := []byte(`{
		"name": "Example GmbH",
		"sub": {"id": "LEIXG-1234", "legal_name": "Example GmbH"},
		"country": "DE",
		"entitlements": ["` + EntitlementPIDProvider + `"],
		"service": [{"lang": "en", "value": "Identity"}],
		"credentials": [
			{"format": "dc+sd-jwt", "claims": [{"path": ["given_name"]}, {"path": ["family_name"]}]}
		],
		"provided_attestations": [
			{"format": "mso_mdoc", "meta": {"doctype_value": "org.iso.18013.5.1.mDL"}}
		]
	}`)

	v121 := []byte(`{
		"name": "Example GmbH",
		"sub": "LEIXG-1234",
		"sub_ln": "Example GmbH",
		"country": "DE",
		"entitlements": ["` + EntitlementPIDProvider + `"],
		"srv_description": [[{"lang": "en", "value": "Identity"}]],
		"credentials": [
			{"format": "dc+sd-jwt", "claim": [{"path": ["given_name"]}, {"path": ["family_name"]}]}
		],
		"provides_attestations": [
			{"format": "mso_mdoc", "meta": {"doctype_value": "org.iso.18013.5.1.mDL"}}
		]
	}`)

	oldEnt, err := ParseWRPRCClaims(v111)
	require.NoError(t, err)
	newEnt, err := ParseWRPRCClaims(v121)
	require.NoError(t, err)

	assert.Equal(t, oldEnt, newEnt, "v1.1.1 and v1.2.1 spellings must parse identically")

	// Spot-check that "identical" is not "identically empty".
	assert.Equal(t, "LEIXG-1234", newEnt.Subject.ID)
	assert.Equal(t, "Example GmbH", newEnt.Subject.LegalName)
	assert.ElementsMatch(t, []string{"given_name", "family_name"}, newEnt.AllowedAttributes)
	require.Len(t, newEnt.ProvidedAttestations, 1)
	require.Len(t, newEnt.ServiceDescriptions, 1)
}

func TestParseWRPRCClaims_SubShapes(t *testing.T) {
	tests := []struct {
		name       string
		sub        string
		extra      string
		wantID     string
		wantLegal  string
		wantRPID   string
		wantGiven  string
		wantFamily string
	}{
		{
			name:      "bare identifier string",
			sub:       `"NTRDE-1"`,
			wantID:    "NTRDE-1",
			wantRPID:  "NTRDE-1",
			wantLegal: "",
		},
		{
			name:      "structured object",
			sub:       `{"id": "NTRDE-2", "legal_name": "Legal Two"}`,
			wantID:    "NTRDE-2",
			wantLegal: "Legal Two",
			wantRPID:  "NTRDE-2",
		},
		{
			name:      "flat sibling wins over nested",
			sub:       `{"id": "NTRDE-3", "legal_name": "Nested"}`,
			extra:     `"sub_ln": "Flat",`,
			wantID:    "NTRDE-3",
			wantLegal: "Flat",
			wantRPID:  "NTRDE-3",
		},
		{
			name:       "natural person without an identifier",
			sub:        `{}`,
			extra:      `"sub_gn": "Ada", "sub_fn": "Lovelace",`,
			wantGiven:  "Ada",
			wantFamily: "Lovelace",
			wantRPID:   "Ada Lovelace",
		},
		{
			name:      "legal name only falls back for the identifier",
			sub:       `{"legal_name": "Nameless GmbH"}`,
			wantLegal: "Nameless GmbH",
			wantRPID:  "Nameless GmbH",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			doc := []byte(`{"sub": ` + tt.sub + `,` + tt.extra +
				`"entitlements": ["` + EntitlementServiceProvider + `"]}`)
			ent, err := ParseWRPRCClaims(doc)
			require.NoError(t, err)
			assert.Equal(t, tt.wantID, ent.Subject.ID)
			assert.Equal(t, tt.wantLegal, ent.Subject.LegalName)
			assert.Equal(t, tt.wantGiven, ent.Subject.GivenName)
			assert.Equal(t, tt.wantFamily, ent.Subject.FamilyName)
			assert.Equal(t, tt.wantRPID, ent.RPIdentifier)
		})
	}
}

func TestParseWRPRCClaims_Rejects(t *testing.T) {
	tests := []struct {
		name    string
		doc     string
		wantErr string
	}{
		{
			name:    "not JSON",
			doc:     `not json at all`,
			wantErr: "parsing payload",
		},
		{
			name:    "no sub claim",
			doc:     `{"entitlements": ["` + EntitlementServiceProvider + `"]}`,
			wantErr: "no usable sub claim",
		},
		{
			name:    "no entitlements (GEN-5.2.4-03)",
			doc:     `{"sub": "NTRDE-1"}`,
			wantErr: "no entitlements claim",
		},
		{
			name:    "empty entitlements list is the same as absent",
			doc:     `{"sub": "NTRDE-1", "entitlements": []}`,
			wantErr: "no entitlements claim",
		},
		{
			name:    "sub is neither string nor object",
			doc:     `{"sub": 42, "entitlements": ["x"]}`,
			wantErr: "neither an identifier string nor an object",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseWRPRCClaims([]byte(tt.doc))
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.wantErr)
		})
	}
}

// TestParseWRPRCClaims_ClaimListPreferenceIsNotAMerge pins that a document
// carrying both spellings takes one list rather than concatenating them.
func TestParseWRPRCClaims_ClaimListPreferenceIsNotAMerge(t *testing.T) {
	doc := []byte(`{
		"sub": "NTRDE-1",
		"entitlements": ["` + EntitlementServiceProvider + `"],
		"credentials": [{"format": "dc+sd-jwt",
			"claim":  [{"path": ["given_name"]}],
			"claims": [{"path": ["family_name"]}]}]
	}`)
	ent, err := ParseWRPRCClaims(doc)
	require.NoError(t, err)
	assert.Equal(t, []string{"given_name"}, ent.AllowedAttributes)
}

func TestParseWRPRCClaims_NestedClaimPathTakesTopLevel(t *testing.T) {
	doc := []byte(`{
		"sub": "NTRDE-1",
		"entitlements": ["` + EntitlementServiceProvider + `"],
		"credentials": [{"claim": [
			{"path": ["address", "locality"]},
			{"path": ["address", "postal_code"]},
			{"path": []},
			{"path": [""]}
		]}]
	}`)
	ent, err := ParseWRPRCClaims(doc)
	require.NoError(t, err)
	assert.Equal(t, []string{"address"}, ent.AllowedAttributes)
}

func TestParseWRPRCClaims_OptionalClaims(t *testing.T) {
	doc := []byte(`{
		"sub": "NTRDE-1",
		"entitlements": ["` + EntitlementServiceProvider + `"],
		"act": {"sub": "INTERMEDIARY-9"},
		"public_body": true,
		"policy_id": ["` + OIDWRPRCPolicy + `"],
		"iat": 1700000000,
		"exp": 1710000000
	}`)
	ent, err := ParseWRPRCClaims(doc)
	require.NoError(t, err)

	assert.Equal(t, "INTERMEDIARY-9", ent.ActingIntermediary)
	assert.True(t, ent.IsPublicBody)
	assert.Equal(t, []string{OIDWRPRCPolicy}, ent.PolicyIDs)
	require.NotNil(t, ent.ValidFrom)
	require.NotNil(t, ent.ValidUntil)
	assert.Equal(t, int64(1700000000), ent.ValidFrom.Unix())
	assert.Equal(t, int64(1710000000), ent.ValidUntil.Unix())
}

func TestParseWRPRCJWTPayload(t *testing.T) {
	t.Run("extracts the middle segment", func(t *testing.T) {
		// {"sub":"x"} base64url-encoded, with dummy header and signature.
		payload, err := ParseWRPRCJWTPayload("aGVhZGVy.eyJzdWIiOiJ4In0.c2ln")
		require.NoError(t, err)
		assert.JSONEq(t, `{"sub":"x"}`, string(payload))
	})

	t.Run("surrounding whitespace is tolerated", func(t *testing.T) {
		_, err := ParseWRPRCJWTPayload("  aGVhZGVy.eyJzdWIiOiJ4In0.c2ln\n")
		require.NoError(t, err)
	})

	t.Run("wrong segment count", func(t *testing.T) {
		_, err := ParseWRPRCJWTPayload("only.two")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "expected 3 segments, got 2")
	})

	t.Run("payload is not base64url", func(t *testing.T) {
		_, err := ParseWRPRCJWTPayload("aGVhZGVy.not!base64.c2ln")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "decoding JWT payload segment")
	})
}

// ---------------------------------------------------------------------------
// Entitlement predicates
// ---------------------------------------------------------------------------

func TestIsAttestationProvider(t *testing.T) {
	tests := []struct {
		name string
		uris []string
		want bool
	}{
		{"PID provider", []string{EntitlementPIDProvider}, true},
		{"QEAA provider", []string{EntitlementQEAAProvider}, true},
		{"non-qualified EAA provider", []string{EntitlementNonQEAAProvider}, true},
		{"public EAA provider", []string{EntitlementPUBEAAProvider}, true},
		{"plain service provider", []string{EntitlementServiceProvider}, false},
		{"signature creation only", []string{EntitlementESigESealCreationProvider}, false},
		{"none", nil, false},
		{"mixed", []string{EntitlementServiceProvider, EntitlementPIDProvider}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ent := &RPEntitlements{EntitlementURIs: tt.uris}
			assert.Equal(t, tt.want, ent.IsAttestationProvider())
		})
	}
}

// TestIsAttestationProviderIncludesPIDUnlikeIsEAAProvider pins the one
// distinction between the two predicates, since PID is not an EAA and the
// difference is easy to erase by accident.
func TestIsAttestationProviderIncludesPIDUnlikeIsEAAProvider(t *testing.T) {
	ent := &RPEntitlements{EntitlementURIs: []string{EntitlementPIDProvider}}
	assert.False(t, ent.IsEAAProvider())
	assert.True(t, ent.IsAttestationProvider())
}

func TestProvidesAttestation(t *testing.T) {
	ent := &RPEntitlements{
		ProvidedAttestations: []CredentialQuery{
			{Format: "mso_mdoc", Meta: map[string]any{"doctype_value": "org.iso.18013.5.1.mDL"}},
			{Format: "dc+sd-jwt", Meta: map[string]any{"vct_values": []any{"eu.europa.ec.eudi.pid.1", "urn:example:other"}}},
			{Format: "jwt_vc_json"}, // no meta: the format is not narrowed
		},
	}

	tests := []struct {
		name      string
		format    string
		typeValue string
		want      bool
	}{
		{"mdoc doctype matches", "mso_mdoc", "org.iso.18013.5.1.mDL", true},
		{"mdoc doctype does not match", "mso_mdoc", "org.iso.18013.5.1.other", false},
		{"sd-jwt vct in the list", "dc+sd-jwt", "eu.europa.ec.eudi.pid.1", true},
		{"sd-jwt second vct in the list", "dc+sd-jwt", "urn:example:other", true},
		{"sd-jwt vct absent", "dc+sd-jwt", "urn:example:missing", false},
		{"unregistered format", "vc+sd-jwt", "eu.europa.ec.eudi.pid.1", false},
		{"empty type asks about the format alone", "mso_mdoc", "", true},
		{"empty type on an unregistered format", "ldp_vc", "", false},
		{"unconstrained format covers any type", "jwt_vc_json", "anything-at-all", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, ent.ProvidesAttestation(tt.format, tt.typeValue))
		})
	}
}

// TestProvidesAttestation_MetaValueShapes covers the shapes a decoded meta
// value can take: encoding/json yields []any, while a caller constructing
// entitlements in Go is likely to use []string.
func TestProvidesAttestation_MetaValueShapes(t *testing.T) {
	fromGo := &RPEntitlements{ProvidedAttestations: []CredentialQuery{
		{Format: "dc+sd-jwt", Meta: map[string]any{"vct_values": []string{"vct-a"}}},
	}}
	assert.True(t, fromGo.ProvidesAttestation("dc+sd-jwt", "vct-a"))
	assert.False(t, fromGo.ProvidesAttestation("dc+sd-jwt", "vct-b"))

	nonString := &RPEntitlements{ProvidedAttestations: []CredentialQuery{
		{Format: "dc+sd-jwt", Meta: map[string]any{"vct_values": []any{42}}},
	}}
	assert.False(t, nonString.ProvidesAttestation("dc+sd-jwt", "42"))
}

func TestProvidesAttestation_NoRegisteredAttestations(t *testing.T) {
	ent := &RPEntitlements{}
	assert.False(t, ent.ProvidesAttestation("mso_mdoc", "org.iso.18013.5.1.mDL"))
	assert.False(t, ent.ProvidesAttestation("mso_mdoc", ""))
}

// ---------------------------------------------------------------------------
// GEN-5.2.4-08
// ---------------------------------------------------------------------------

func TestCheckWRPRCValidityPeriod(t *testing.T) {
	iat := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	at := func(d time.Time) *time.Time { return &d }

	tests := []struct {
		name    string
		from    *time.Time
		until   *time.Time
		wantErr bool
	}{
		{"exactly twelve months", at(iat), at(iat.AddDate(0, 12, 0)), false},
		{"well within", at(iat), at(iat.AddDate(0, 3, 0)), false},
		{"a second over", at(iat), at(iat.AddDate(0, 12, 0).Add(time.Second)), true},
		{"two years", at(iat), at(iat.AddDate(2, 0, 0)), true},
		{"no issuance time", nil, at(iat.AddDate(5, 0, 0)), false},
		{"no expiry", at(iat), nil, false},
		{"neither", nil, nil, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := CheckWRPRCValidityPeriod(&RPEntitlements{ValidFrom: tt.from, ValidUntil: tt.until})
			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), "GEN-5.2.4-08")
				return
			}
			assert.NoError(t, err)
		})
	}
}

func TestCheckWRPRCValidityPeriod_Nil(t *testing.T) {
	assert.NoError(t, CheckWRPRCValidityPeriod(nil))
}

// TestParseWRPRCClaims_ServiceIdentifier covers the claim that
// CheckWRPACWRPRCServiceBinding compares against. Nothing populated it from
// a JWT before this parser, so that binding check could never fire on a
// parsed registration certificate.
func TestParseWRPRCClaims_ServiceIdentifier(t *testing.T) {
	doc := []byte(`{
		"sub": "NTRDE-1",
		"entitlements": ["` + EntitlementServiceProvider + `"],
		"service_identifier": "https://rp.example/service/a"
	}`)
	ent, err := ParseWRPRCClaims(doc)
	require.NoError(t, err)
	assert.Equal(t, "https://rp.example/service/a", ent.ServiceIdentifier)

	// And the binding it exists to serve now has something to compare.
	assert.NoError(t, CheckWRPACWRPRCServiceBinding("https://rp.example/service/a", ent))
	assert.Error(t, CheckWRPACWRPRCServiceBinding("https://rp.example/service/b", ent))
}
