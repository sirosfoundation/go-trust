package registry

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"net/url"
	"testing"
	"time"

	"github.com/sirosfoundation/go-trust/pkg/authzen"
	"github.com/sirosfoundation/go-trust/pkg/registry/rpcert"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// ExtractRequiredCertPolicyOIDs
// ---------------------------------------------------------------------------

func TestExtractRequiredCertPolicyOIDs(t *testing.T) {
	tests := []struct {
		name string
		req  *authzen.EvaluationRequest
		want []string
	}{
		{
			name: "nil context",
			req:  &authzen.EvaluationRequest{},
			want: nil,
		},
		{
			name: "no key",
			req:  &authzen.EvaluationRequest{Context: map[string]interface{}{"other": "val"}},
			want: nil,
		},
		{
			name: "string slice",
			req: &authzen.EvaluationRequest{
				Context: map[string]interface{}{"required_cert_policy_oids": []string{"1.2.3.4", "1.2.3.5"}},
			},
			want: []string{"1.2.3.4", "1.2.3.5"},
		},
		{
			name: "interface slice (from JSON)",
			req: &authzen.EvaluationRequest{
				Context: map[string]interface{}{"required_cert_policy_oids": []interface{}{"1.2.3.4"}},
			},
			want: []string{"1.2.3.4"},
		},
		{
			name: "wrong type",
			req: &authzen.EvaluationRequest{
				Context: map[string]interface{}{"required_cert_policy_oids": "not-a-slice"},
			},
			want: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ExtractRequiredCertPolicyOIDs(tt.req)
			assert.Equal(t, tt.want, got)
		})
	}
}

// ---------------------------------------------------------------------------
// ValidateCertPolicyOIDs
// ---------------------------------------------------------------------------

func TestValidateCertPolicyOIDs(t *testing.T) {
	cert := &x509.Certificate{
		PolicyIdentifiers: []asn1.ObjectIdentifier{
			{1, 2, 3, 4},    // "1.2.3.4"
			{2, 16, 840, 1}, // "2.16.840.1"
		},
	}

	t.Run("match found", func(t *testing.T) {
		matched, oids := ValidateCertPolicyOIDs(cert, []string{"1.2.3.4"})
		assert.True(t, matched)
		assert.Equal(t, []string{"1.2.3.4"}, oids)
	})

	t.Run("multiple matches", func(t *testing.T) {
		matched, oids := ValidateCertPolicyOIDs(cert, []string{"1.2.3.4", "2.16.840.1"})
		assert.True(t, matched)
		assert.Len(t, oids, 2)
	})

	t.Run("no match", func(t *testing.T) {
		matched, oids := ValidateCertPolicyOIDs(cert, []string{"9.9.9.9"})
		assert.False(t, matched)
		assert.Empty(t, oids)
	})

	t.Run("empty cert policies", func(t *testing.T) {
		emptyCert := &x509.Certificate{}
		matched, oids := ValidateCertPolicyOIDs(emptyCert, []string{"1.2.3.4"})
		assert.False(t, matched)
		assert.Empty(t, oids)
	})
}

// ---------------------------------------------------------------------------
// ShouldExtractRPIdentity
// ---------------------------------------------------------------------------

func TestShouldExtractRPIdentity(t *testing.T) {
	tests := []struct {
		name string
		req  *authzen.EvaluationRequest
		want bool
	}{
		{
			name: "nil context",
			req:  &authzen.EvaluationRequest{},
			want: false,
		},
		{
			name: "not set",
			req:  &authzen.EvaluationRequest{Context: map[string]interface{}{}},
			want: false,
		},
		{
			name: "true",
			req:  &authzen.EvaluationRequest{Context: map[string]interface{}{"extract_rp_identity": true}},
			want: true,
		},
		{
			name: "false",
			req:  &authzen.EvaluationRequest{Context: map[string]interface{}{"extract_rp_identity": false}},
			want: false,
		},
		{
			name: "wrong type",
			req:  &authzen.EvaluationRequest{Context: map[string]interface{}{"extract_rp_identity": "yes"}},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, ShouldExtractRPIdentity(tt.req))
		})
	}
}

// ---------------------------------------------------------------------------
// ExtractRPIdentity
// ---------------------------------------------------------------------------

func TestExtractRPIdentity(t *testing.T) {
	uri1, _ := url.Parse("https://rp.example.com")
	cert := &x509.Certificate{
		Subject: pkix.Name{
			Organization: []string{"Test Corp", "Subsidiary"},
			CommonName:   "rp.example.com",
			Country:      []string{"SE"},
			SerialNumber: "RP-12345",
		},
		DNSNames:       []string{"rp.example.com", "rp2.example.com"},
		URIs:           []*url.URL{uri1},
		EmailAddresses: []string{"admin@rp.example.com"},
		PolicyIdentifiers: []asn1.ObjectIdentifier{
			{1, 2, 3, 4},
		},
		NotBefore: time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:  time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
	}

	identity := ExtractRPIdentity(cert)

	require.NotNil(t, identity)
	assert.Equal(t, []string{"Test Corp", "Subsidiary"}, identity["organization"])
	assert.Equal(t, "rp.example.com", identity["common_name"])
	assert.Equal(t, []string{"SE"}, identity["country"])
	assert.Equal(t, "RP-12345", identity["serial_number"])
	assert.Equal(t, []string{"rp.example.com", "rp2.example.com"}, identity["dns_sans"])
	assert.Equal(t, []string{"https://rp.example.com"}, identity["uri_sans"])
	assert.Equal(t, []string{"admin@rp.example.com"}, identity["email_sans"])
	assert.Equal(t, []string{"1.2.3.4"}, identity["policy_oids"])
	assert.Equal(t, "2024-01-01T00:00:00Z", identity["not_before"])
	assert.Equal(t, "2025-01-01T00:00:00Z", identity["not_after"])
}

func TestExtractRPIdentity_MinimalCert(t *testing.T) {
	cert := &x509.Certificate{
		Subject: pkix.Name{
			CommonName: "minimal.example.com",
		},
		NotBefore: time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:  time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
	}

	identity := ExtractRPIdentity(cert)

	assert.Equal(t, "minimal.example.com", identity["common_name"])
	assert.Nil(t, identity["organization"])
	assert.Nil(t, identity["dns_sans"])
	assert.Nil(t, identity["uri_sans"])
	assert.Nil(t, identity["email_sans"])
	assert.Nil(t, identity["policy_oids"])
}

// ---------------------------------------------------------------------------
// EnrichX5CResponse
// ---------------------------------------------------------------------------

func TestEnrichX5CResponse_NoEnrichment(t *testing.T) {
	req := &authzen.EvaluationRequest{}
	cert := &x509.Certificate{}

	result := EnrichX5CResponse(req, cert)
	assert.True(t, result.Decision)
	assert.Nil(t, result.MatchedPolicyOIDs)
	assert.Nil(t, result.RPIdentity)
}

func TestEnrichX5CResponse_PolicyOIDMatch(t *testing.T) {
	req := &authzen.EvaluationRequest{
		Context: map[string]interface{}{
			"required_cert_policy_oids": []string{"1.2.3.4"},
		},
	}
	cert := &x509.Certificate{
		PolicyIdentifiers: []asn1.ObjectIdentifier{{1, 2, 3, 4}},
	}

	result := EnrichX5CResponse(req, cert)
	assert.True(t, result.Decision)
	assert.Equal(t, []string{"1.2.3.4"}, result.MatchedPolicyOIDs)
}

func TestEnrichX5CResponse_PolicyOIDMismatch(t *testing.T) {
	req := &authzen.EvaluationRequest{
		Context: map[string]interface{}{
			"required_cert_policy_oids": []string{"9.9.9.9"},
		},
	}
	cert := &x509.Certificate{
		PolicyIdentifiers: []asn1.ObjectIdentifier{{1, 2, 3, 4}},
	}

	result := EnrichX5CResponse(req, cert)
	assert.False(t, result.Decision)
	assert.NotNil(t, result.FailureReason)
	assert.Equal(t, "certificate does not contain required policy OIDs", result.FailureReason["error"])
}

func TestEnrichX5CResponse_RPIdentity(t *testing.T) {
	req := &authzen.EvaluationRequest{
		Context: map[string]interface{}{
			"extract_rp_identity": true,
		},
	}
	cert := &x509.Certificate{
		Subject: pkix.Name{
			Organization: []string{"Test Corp"},
			CommonName:   "test.example.com",
		},
		NotBefore: time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:  time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
	}

	result := EnrichX5CResponse(req, cert)
	assert.True(t, result.Decision)
	require.NotNil(t, result.RPIdentity)
	assert.Equal(t, "test.example.com", result.RPIdentity["common_name"])
}

func TestEnrichX5CResponse_BothFeatures(t *testing.T) {
	req := &authzen.EvaluationRequest{
		Context: map[string]interface{}{
			"required_cert_policy_oids": []string{"1.2.3.4"},
			"extract_rp_identity":       true,
		},
	}
	cert := &x509.Certificate{
		Subject: pkix.Name{
			Organization: []string{"Test Corp"},
		},
		PolicyIdentifiers: []asn1.ObjectIdentifier{{1, 2, 3, 4}},
		NotBefore:         time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:          time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
	}

	result := EnrichX5CResponse(req, cert)
	assert.True(t, result.Decision)
	assert.Equal(t, []string{"1.2.3.4"}, result.MatchedPolicyOIDs)
	require.NotNil(t, result.RPIdentity)
	assert.Equal(t, []string{"Test Corp"}, result.RPIdentity["organization"])
}

// ---------------------------------------------------------------------------
// ApplyEnrichmentToResponse
// ---------------------------------------------------------------------------

func TestApplyEnrichmentToResponse(t *testing.T) {
	resp := &authzen.EvaluationResponse{
		Decision: true,
		Context: &authzen.EvaluationResponseContext{
			Reason: map[string]interface{}{"admin": "trusted"},
		},
	}

	enrichment := &X5CEnrichmentResult{
		Decision:          true,
		MatchedPolicyOIDs: []string{"1.2.3.4"},
		RPIdentity:        map[string]interface{}{"common_name": "test.example.com"},
	}

	ApplyEnrichmentToResponse(resp, enrichment)

	// Check reason
	assert.Equal(t, []string{"1.2.3.4"}, resp.Context.Reason["matched_policy_oids"])

	// Check trust metadata
	tm, ok := resp.Context.TrustMetadata.(map[string]interface{})
	require.True(t, ok)
	assert.Equal(t, []string{"1.2.3.4"}, tm["matched_policy_oids"])
	assert.NotNil(t, tm["rp_identity"])
}

func TestApplyEnrichmentToResponse_NilEnrichment(t *testing.T) {
	resp := &authzen.EvaluationResponse{
		Decision: true,
		Context: &authzen.EvaluationResponseContext{
			Reason: map[string]interface{}{"admin": "trusted"},
		},
	}

	ApplyEnrichmentToResponse(resp, nil)
	assert.Nil(t, resp.Context.TrustMetadata)
}

func TestApplyEnrichmentToResponse_NoOIDsNoIdentity(t *testing.T) {
	resp := &authzen.EvaluationResponse{
		Decision: true,
		Context: &authzen.EvaluationResponseContext{
			Reason: map[string]interface{}{"admin": "trusted"},
		},
	}

	enrichment := &X5CEnrichmentResult{Decision: true}
	ApplyEnrichmentToResponse(resp, enrichment)

	assert.Nil(t, resp.Context.Reason["matched_policy_oids"])
	assert.Nil(t, resp.Context.TrustMetadata)
}

// ---------------------------------------------------------------------------
// Over-request detection via EnrichX5CResponse
// ---------------------------------------------------------------------------

func TestEnrichX5CResponse_OverRequestWarnOnly(t *testing.T) {
	cert := &x509.Certificate{
		Subject: pkix.Name{CommonName: "Test RP"},
	}
	req := &authzen.EvaluationRequest{
		Context: map[string]interface{}{
			"requested_attributes": []string{"family_name", "age_over_18", "birthdate"},
			"allowed_attributes":   []string{"family_name", "birthdate"},
		},
	}

	result := EnrichX5CResponse(req, cert)

	assert.True(t, result.Decision, "warn-only mode should not deny")
	require.NotNil(t, result.OverRequest)
	assert.True(t, result.OverRequest.IsOverRequest)
	assert.Equal(t, []string{"age_over_18"}, result.OverRequest.OverRequested)
}

func TestEnrichX5CResponse_OverRequestStrict(t *testing.T) {
	cert := &x509.Certificate{
		Subject: pkix.Name{CommonName: "Test RP"},
	}
	req := &authzen.EvaluationRequest{
		Context: map[string]interface{}{
			"requested_attributes":     []string{"family_name", "age_over_18"},
			"allowed_attributes":       []string{"family_name"},
			"strict_entitlement_check": true,
		},
	}

	result := EnrichX5CResponse(req, cert)

	assert.False(t, result.Decision, "strict mode should deny over-request")
	assert.Contains(t, result.FailureReason["error"], "beyond their entitlements")
	assert.Equal(t, []string{"age_over_18"}, result.FailureReason["over_requested"])
}

func TestEnrichX5CResponse_NoOverRequest(t *testing.T) {
	cert := &x509.Certificate{
		Subject: pkix.Name{CommonName: "Test RP"},
	}
	req := &authzen.EvaluationRequest{
		Context: map[string]interface{}{
			"requested_attributes": []string{"family_name"},
			"allowed_attributes":   []string{"family_name", "birthdate"},
		},
	}

	result := EnrichX5CResponse(req, cert)

	assert.True(t, result.Decision)
	require.NotNil(t, result.OverRequest)
	assert.False(t, result.OverRequest.IsOverRequest)
	assert.Empty(t, result.OverRequest.OverRequested)
}

func TestEnrichX5CResponse_OverRequestFromDCQL(t *testing.T) {
	cert := &x509.Certificate{
		Subject: pkix.Name{CommonName: "Test RP"},
	}
	req := &authzen.EvaluationRequest{
		Action: &authzen.Action{
			Name: "authenticate",
			Parameters: map[string]interface{}{
				"query": map[string]interface{}{
					"credentials": []interface{}{
						map[string]interface{}{
							"id":     "pid",
							"format": "vc+sd-jwt",
							"claims": []interface{}{
								map[string]interface{}{"path": []interface{}{"family_name"}},
								map[string]interface{}{"path": []interface{}{"age_over_18"}},
							},
						},
					},
				},
			},
		},
		Context: map[string]interface{}{
			"allowed_attributes": []string{"family_name"},
		},
	}

	result := EnrichX5CResponse(req, cert)

	assert.True(t, result.Decision, "warn-only mode")
	require.NotNil(t, result.OverRequest)
	assert.True(t, result.OverRequest.IsOverRequest)
	assert.Equal(t, []string{"age_over_18"}, result.OverRequest.OverRequested)
}

func TestApplyEnrichmentToResponse_OverRequestWarnings(t *testing.T) {
	resp := &authzen.EvaluationResponse{
		Decision: true,
		Context: &authzen.EvaluationResponseContext{
			Reason: map[string]interface{}{"status": "ok"},
		},
	}
	enrichment := &X5CEnrichmentResult{
		Decision: true,
		OverRequest: &rpcert.OverRequestResult{
			Allowed:       []string{"family_name"},
			Requested:     []string{"family_name", "age_over_18"},
			OverRequested: []string{"age_over_18"},
			IsOverRequest: true,
		},
	}

	ApplyEnrichmentToResponse(resp, enrichment)

	warnings, ok := resp.Context.Reason["over_request_warnings"].(map[string]interface{})
	require.True(t, ok, "over_request_warnings should be present")
	assert.Equal(t, []string{"age_over_18"}, warnings["over_requested"])
}

// ---------------------------------------------------------------------------
// Intermediary verification via EnrichX5CResponse
// ---------------------------------------------------------------------------

func TestEnrichX5CResponse_IntermediaryAllowed(t *testing.T) {
	cert := &x509.Certificate{
		Subject: pkix.Name{CommonName: "Target RP"},
	}
	req := &authzen.EvaluationRequest{
		Context: map[string]interface{}{
			"intermediary_x5c":     []string{"base64-cert-data"},
			"allow_intermediaries": true,
		},
	}

	result := EnrichX5CResponse(req, cert)

	assert.True(t, result.Decision)
	assert.True(t, result.IsIntermediaryRequest)
	require.NotNil(t, result.IntermediaryIdentity)
	assert.Equal(t, "Target RP", result.IntermediaryIdentity["rp_subject"])
	assert.Equal(t, false, result.IntermediaryIdentity["verified"])
}

func TestEnrichX5CResponse_IntermediaryDenied(t *testing.T) {
	cert := &x509.Certificate{
		Subject: pkix.Name{CommonName: "Target RP"},
	}
	req := &authzen.EvaluationRequest{
		Context: map[string]interface{}{
			"intermediary_x5c": []string{"base64-cert-data"},
		},
	}

	result := EnrichX5CResponse(req, cert)

	assert.False(t, result.Decision)
	assert.True(t, result.IsIntermediaryRequest)
	assert.Contains(t, result.FailureReason["error"], "not allowed by policy")
}

func TestEnrichX5CResponse_NoIntermediary(t *testing.T) {
	cert := &x509.Certificate{
		Subject: pkix.Name{CommonName: "Direct RP"},
	}
	req := &authzen.EvaluationRequest{
		Context: map[string]interface{}{},
	}

	result := EnrichX5CResponse(req, cert)

	assert.True(t, result.Decision)
	assert.False(t, result.IsIntermediaryRequest)
	assert.Nil(t, result.IntermediaryIdentity)
}

func TestApplyEnrichmentToResponse_IntermediaryMetadata(t *testing.T) {
	resp := &authzen.EvaluationResponse{
		Decision: true,
		Context: &authzen.EvaluationResponseContext{
			Reason: map[string]interface{}{"status": "ok"},
		},
	}
	enrichment := &X5CEnrichmentResult{
		Decision:              true,
		IsIntermediaryRequest: true,
		IntermediaryIdentity: map[string]interface{}{
			"intermediary_x5c_leaf": "Broker Corp",
			"rp_subject":            "Target RP",
		},
	}

	ApplyEnrichmentToResponse(resp, enrichment)

	tm, ok := resp.Context.TrustMetadata.(map[string]interface{})
	require.True(t, ok)
	assert.Equal(t, true, tm["is_intermediary_request"])
	intermediary, ok := tm["intermediary"].(map[string]interface{})
	require.True(t, ok)
	assert.Equal(t, "Broker Corp", intermediary["intermediary_x5c_leaf"])
}

// ---------------------------------------------------------------------------
// EnrichX5CResponseWithProfiles — profile matching integration tests
// ---------------------------------------------------------------------------

// wrpacPolicyOID is a WRPAC policy OID for test certs.
var wrpacPolicyOID = asn1.ObjectIdentifier{0, 4, 0, 194118, 1, 2} // NCP-l-eudiwrp

func TestEnrichWithProfiles_MatchesWRPAC(t *testing.T) {
	profiles := rpcert.DefaultProfileRegistry()
	uri1, _ := url.Parse("https://rp.example.com")
	cert := &x509.Certificate{
		Subject: pkix.Name{
			Organization: []string{"Test Corp"},
			CommonName:   "rp.example.com",
			Country:      []string{"SE"},
			SerialNumber: "VATSE-123456",
		},
		KeyUsage:          x509.KeyUsageContentCommitment,
		PolicyIdentifiers: []asn1.ObjectIdentifier{wrpacPolicyOID},
		URIs:              []*url.URL{uri1},
		EmailAddresses:    []string{"admin@rp.example.com"},
		NotBefore:         time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:          time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
	}

	req := &authzen.EvaluationRequest{
		Context: map[string]interface{}{
			"extract_rp_identity": true,
		},
	}

	result := EnrichX5CResponseWithProfiles(req, cert, profiles)

	assert.True(t, result.Decision)
	assert.Equal(t, "wrpac", result.MatchedProfile)
	assert.Empty(t, result.ProfileValidationError)

	// Profile-specific identity should have subject_type and organization_identifier
	require.NotNil(t, result.RPIdentity)
	assert.Equal(t, "legal_person", result.RPIdentity["subject_type"])
	assert.Equal(t, "VATSE-123456", result.RPIdentity["organization_identifier"])
	assert.Equal(t, "normalised", result.RPIdentity["policy_level"])
	assert.Equal(t, "NCP-l-eudiwrp", result.RPIdentity["policy_id"])

	// Contact info should be structured under "contact"
	contacts, ok := result.RPIdentity["contact"].(map[string]interface{})
	require.True(t, ok, "expected structured contact info from WRPAC profile")
	assert.NotNil(t, contacts["emails"])
	assert.NotNil(t, contacts["uris"])
}

func TestEnrichWithProfiles_NoProfileMatch(t *testing.T) {
	profiles := rpcert.DefaultProfileRegistry()
	cert := &x509.Certificate{
		Subject: pkix.Name{
			CommonName: "generic.example.com",
		},
		PolicyIdentifiers: []asn1.ObjectIdentifier{{2, 5, 29, 32, 0}}, // anyPolicy
		NotBefore:         time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:          time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
	}

	req := &authzen.EvaluationRequest{
		Context: map[string]interface{}{
			"extract_rp_identity": true,
		},
	}

	result := EnrichX5CResponseWithProfiles(req, cert, profiles)

	assert.True(t, result.Decision)
	assert.Empty(t, result.MatchedProfile)

	// Should fall back to generic identity (serial_number key, flat SANs)
	require.NotNil(t, result.RPIdentity)
	assert.Equal(t, "generic.example.com", result.RPIdentity["common_name"])
	// Generic extractor uses "serial_number", not "organization_identifier"
	assert.Nil(t, result.RPIdentity["organization_identifier"])
	assert.Nil(t, result.RPIdentity["subject_type"])
}

func TestEnrichWithProfiles_ProfileValidationWarning(t *testing.T) {
	profiles := rpcert.DefaultProfileRegistry()
	// WRPAC cert missing required keyUsage — validation should warn
	cert := &x509.Certificate{
		Subject: pkix.Name{
			Organization: []string{"Test Corp"},
			CommonName:   "test.example.com",
			SerialNumber: "VATDE-999",
		},
		KeyUsage:          x509.KeyUsageDigitalSignature, // missing nonRepudiation
		PolicyIdentifiers: []asn1.ObjectIdentifier{wrpacPolicyOID},
		EmailAddresses:    []string{"admin@test.example.com"},
		NotBefore:         time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:          time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
	}

	req := &authzen.EvaluationRequest{
		Context: map[string]interface{}{
			"extract_rp_identity": true,
		},
	}

	result := EnrichX5CResponseWithProfiles(req, cert, profiles)

	assert.True(t, result.Decision, "profile validation warnings should not deny")
	assert.Equal(t, "wrpac", result.MatchedProfile)
	assert.Contains(t, result.ProfileValidationError, "nonRepudiation")
}

func TestEnrichWithProfiles_NilRegistry(t *testing.T) {
	cert := &x509.Certificate{
		Subject:           pkix.Name{CommonName: "test"},
		PolicyIdentifiers: []asn1.ObjectIdentifier{wrpacPolicyOID},
		NotBefore:         time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:          time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
	}
	req := &authzen.EvaluationRequest{
		Context: map[string]interface{}{
			"extract_rp_identity": true,
		},
	}

	result := EnrichX5CResponseWithProfiles(req, cert, nil)

	assert.True(t, result.Decision)
	assert.Empty(t, result.MatchedProfile, "nil registry should skip profile matching")
	require.NotNil(t, result.RPIdentity)
}

func TestApplyEnrichmentToResponse_ProfileMetadata(t *testing.T) {
	resp := &authzen.EvaluationResponse{
		Decision: true,
		Context: &authzen.EvaluationResponseContext{
			Reason: map[string]interface{}{"status": "ok"},
		},
	}
	enrichment := &X5CEnrichmentResult{
		Decision:       true,
		MatchedProfile: "wrpac",
		RPIdentity: map[string]interface{}{
			"subject_type": "legal_person",
		},
	}

	ApplyEnrichmentToResponse(resp, enrichment)

	assert.Equal(t, "wrpac", resp.Context.Reason["matched_profile"])
	tm, ok := resp.Context.TrustMetadata.(map[string]interface{})
	require.True(t, ok)
	assert.Equal(t, "wrpac", tm["rp_profile"])
	assert.NotNil(t, tm["rp_identity"])
}

func TestApplyEnrichmentToResponse_ProfileValidationWarning(t *testing.T) {
	resp := &authzen.EvaluationResponse{
		Decision: true,
		Context: &authzen.EvaluationResponseContext{
			Reason: map[string]interface{}{"status": "ok"},
		},
	}
	enrichment := &X5CEnrichmentResult{
		Decision:               true,
		MatchedProfile:         "wrpac",
		ProfileValidationError: "wrpac: certificate keyUsage does not include nonRepudiation",
	}

	ApplyEnrichmentToResponse(resp, enrichment)

	assert.Equal(t, "wrpac: certificate keyUsage does not include nonRepudiation",
		resp.Context.Reason["profile_validation_warning"])
}

// ---------------------------------------------------------------------------
// WRPACOrgID population (Thread 8 — explicit regression guard)
// ---------------------------------------------------------------------------

func TestEnrichX5CResponseWithProfiles_WRPACOrgID_Populated(t *testing.T) {
	// Build a WRPAC certificate with a Subject.SerialNumber (organization_identifier).
	cert := buildWRPACCert(t, "LEIXG-529900T8BM49AURSDO55")
	req := &authzen.EvaluationRequest{
		Context: map[string]interface{}{"extract_rp_identity": true},
	}

	result := EnrichX5CResponseWithProfiles(req, cert, rpcert.DefaultProfileRegistry())

	assert.Equal(t, "wrpac", result.MatchedProfile)
	assert.Equal(t, "LEIXG-529900T8BM49AURSDO55", result.WRPACOrgID,
		"WRPACOrgID must be populated from WRPAC organization_identifier for binding checks")
}

func TestEnrichX5CResponseWithProfiles_WRPACOrgID_PopulatedWithoutFullIdentity(t *testing.T) {
	// Verify WRPACOrgID is populated even when extract_rp_identity is NOT set —
	// the binding check must work independently of full identity extraction.
	cert := buildWRPACCert(t, "LEIXG-529900T8BM49AURSDO55")
	req := &authzen.EvaluationRequest{} // no extract_rp_identity

	result := EnrichX5CResponseWithProfiles(req, cert, rpcert.DefaultProfileRegistry())

	assert.Equal(t, "wrpac", result.MatchedProfile)
	assert.Equal(t, "LEIXG-529900T8BM49AURSDO55", result.WRPACOrgID,
		"WRPACOrgID must be populated regardless of extract_rp_identity flag")
	assert.Nil(t, result.RPIdentity, "RPIdentity must be nil when not requested")
}

func TestEnrichX5CResponseWithProfiles_WRPACOrgID_EmptyWhenNoProfile(t *testing.T) {
	// A non-WRPAC cert should leave WRPACOrgID empty.
	cert := &x509.Certificate{
		Subject: pkix.Name{SerialNumber: "SN-12345"},
	}
	req := &authzen.EvaluationRequest{}

	result := EnrichX5CResponseWithProfiles(req, cert, nil)

	assert.Empty(t, result.WRPACOrgID)
}

// buildWRPACCert creates a WRPAC certificate struct with the given org identifier
// in Subject.SerialNumber, carrying the NCP-l-eudiwrp policy OID.
// Uses a bare struct (like other enrichment tests) to avoid Go 1.22+ Policies
// vs PolicyIdentifiers migration issues in x509.CreateCertificate.
func buildWRPACCert(t *testing.T, orgID string) *x509.Certificate {
	t.Helper()
	return &x509.Certificate{
		Subject: pkix.Name{
			SerialNumber: orgID,
			Organization: []string{"Test Corp"},
			Country:      []string{"SE"},
		},
		KeyUsage:          x509.KeyUsageContentCommitment,
		PolicyIdentifiers: []asn1.ObjectIdentifier{{0, 4, 0, 194118, 1, 2}}, // NCP-l-eudiwrp
		NotBefore:         time.Now().Add(-time.Minute),
		NotAfter:          time.Now().Add(time.Hour),
	}
}
