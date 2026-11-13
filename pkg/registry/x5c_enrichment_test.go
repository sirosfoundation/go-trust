package registry

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/url"
	"strings"
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

	result := EnrichX5CResponseWithProfiles(req, cert, profiles, nil)

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

	result := EnrichX5CResponseWithProfiles(req, cert, profiles, nil)

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
	// WRPAC cert without any contact method in subjectAltName — validation should warn
	cert := &x509.Certificate{
		Subject: pkix.Name{
			Organization: []string{"Test Corp"},
			CommonName:   "test.example.com",
			SerialNumber: "VATDE-999",
		},
		KeyUsage:          x509.KeyUsageDigitalSignature,
		PolicyIdentifiers: []asn1.ObjectIdentifier{wrpacPolicyOID},
		NotBefore:         time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:          time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
	}

	req := &authzen.EvaluationRequest{
		Context: map[string]interface{}{
			"extract_rp_identity": true,
		},
	}

	result := EnrichX5CResponseWithProfiles(req, cert, profiles, nil)

	assert.True(t, result.Decision, "profile validation warnings should not deny")
	assert.Equal(t, "wrpac", result.MatchedProfile)
	assert.Contains(t, result.ProfileValidationError, "subjectAltName")
}

// A conformant access (authentication) certificate: keyUsage digitalSignature,
// EKU clientAuth, policy NCP-l-eudiwrp. Issue #91: must produce no warning.
func TestEnrichWithProfiles_DigitalSignatureOnlyNoWarning(t *testing.T) {
	profiles := rpcert.DefaultProfileRegistry()
	cert := &x509.Certificate{
		Subject: pkix.Name{
			Organization: []string{"Test Corp"},
			CommonName:   "test.example.com",
			SerialNumber: "VATDE-999",
		},
		KeyUsage:          x509.KeyUsageDigitalSignature,
		ExtKeyUsage:       []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
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

	result := EnrichX5CResponseWithProfiles(req, cert, profiles, nil)

	assert.True(t, result.Decision)
	assert.Equal(t, "wrpac", result.MatchedProfile)
	assert.Empty(t, result.ProfileValidationError)
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

	result := EnrichX5CResponseWithProfiles(req, cert, nil, nil)

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
		ProfileValidationError: "wrpac: subjectAltName missing required contact information (URI or email)",
	}

	ApplyEnrichmentToResponse(resp, enrichment)

	assert.Equal(t, "wrpac: subjectAltName missing required contact information (URI or email)",
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

	result := EnrichX5CResponseWithProfiles(req, cert, rpcert.DefaultProfileRegistry(), nil)

	assert.Equal(t, "wrpac", result.MatchedProfile)
	assert.Equal(t, "LEIXG-529900T8BM49AURSDO55", result.WRPACOrgID,
		"WRPACOrgID must be populated from WRPAC organization_identifier for binding checks")
}

func TestEnrichX5CResponseWithProfiles_WRPACOrgID_PopulatedWithoutFullIdentity(t *testing.T) {
	// Verify WRPACOrgID is populated even when extract_rp_identity is NOT set —
	// the binding check must work independently of full identity extraction.
	cert := buildWRPACCert(t, "LEIXG-529900T8BM49AURSDO55")
	req := &authzen.EvaluationRequest{} // no extract_rp_identity

	result := EnrichX5CResponseWithProfiles(req, cert, rpcert.DefaultProfileRegistry(), nil)

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

	result := EnrichX5CResponseWithProfiles(req, cert, nil, nil)

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

// ---------------------------------------------------------------------------
// The WRPRC evaluation path (the EAAP presentation model)
// ---------------------------------------------------------------------------

// mintWRPRC mints a registrar-shaped WRPRC JWT (typ rc-wrp+jwt, ES256, the
// registrar CA in x5c) and returns the token plus a validator anchored to
// that CA.
func mintWRPRC(t *testing.T, claims map[string]interface{}) (string, WRPRCVerifier) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(42),
		Subject:               pkix.Name{Organization: []string{"Registrar CA"}, CommonName: "registrar.example"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)
	caCert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	pool := x509.NewCertPool()
	pool.AddCert(caCert)

	header := map[string]interface{}{
		"typ": rpcert.WRPRCTyp,
		"alg": "ES256",
		"x5c": []string{base64.StdEncoding.EncodeToString(caCert.Raw)},
	}
	hdrJSON, err := json.Marshal(header)
	require.NoError(t, err)
	hdrB64 := base64.RawURLEncoding.EncodeToString(hdrJSON)
	payJSON, err := json.Marshal(claims)
	require.NoError(t, err)
	payB64 := base64.RawURLEncoding.EncodeToString(payJSON)
	signingInput := hdrB64 + "." + payB64
	sig, err := mintWRPRCSignature(key, "ES256", []byte(signingInput))
	require.NoError(t, err)
	token := signingInput + "." + base64.RawURLEncoding.EncodeToString(sig)
	return token, NewAnchoredWRPRCVerifier(pool)
}

// wrprcClaims is the minimal registrar payload the parser accepts: a usable
// sub, non-empty entitlements, and a validity window. An empty act mints the
// DIRECT shape; a non-empty one names the acting intermediary (Table 10).
func wrprcClaims(act string) map[string]interface{} {
	now := time.Now()
	claims := map[string]interface{}{
		"name":           "Fronted RP GmbH",
		"sub":            "LEIXG-FRONTED",
		"sub_ln":         "Fronted RP GmbH",
		"country":        "DE",
		"entitlements":   []string{"urn:example:entitlement:non-qeaa-provider"},
		"privacy_policy": "https://fronted.example/privacy",
		"iat":            now.Add(-time.Hour).Unix(),
		"exp":            now.Add(30 * 24 * time.Hour).Unix(),
		"credentials": []map[string]interface{}{
			{
				"format": "dc+sd-jwt",
				"claims": []map[string]interface{}{{"path": []string{"given_name"}}},
			},
		},
	}
	if act != "" {
		claims["act"] = map[string]interface{}{"sub": act}
	}
	return claims
}

// wrpacLeaf mints a WRPAC-shaped leaf (the NCP-l-eudiwrp policy OID so the
// wrpac profile matches it, the organizationIdentifier DN attribute) whose
// profile extraction yields orgID.
func wrpacLeaf(t *testing.T, orgID string) *x509.Certificate {
	t.Helper()
	return makeVIDCert(t, vidCertOpts{orgID: orgID, policy: rpcert.OIDNCPLegalPerson})
}

func TestEnrichX5CResponse_WRPRCNoValidatorFailsClosed(t *testing.T) {
	token, _ := mintWRPRC(t, wrprcClaims(""))
	req := &authzen.EvaluationRequest{Context: map[string]interface{}{"wrprc": token}}
	result := EnrichX5CResponseWithProfiles(req, &x509.Certificate{}, nil, nil)
	assert.False(t, result.Decision)
	require.NotNil(t, result.FailureReason)
	assert.Contains(t, result.FailureReason["error"], "no registrar trust anchors")
}

func TestEnrichX5CResponse_WRPRCUnanchoredChainDenies(t *testing.T) {
	// A validator anchored to a DIFFERENT registrar CA: the WRPRC's chain
	// does not validate, so the presentation fails closed.
	token, _ := mintWRPRC(t, wrprcClaims(""))
	_, other := mintWRPRC(t, wrprcClaims("LEIXG-X"))
	req := &authzen.EvaluationRequest{Context: map[string]interface{}{"wrprc": token}}
	result := EnrichX5CResponseWithProfiles(req, &x509.Certificate{}, nil, other)
	assert.False(t, result.Decision)
	require.NotNil(t, result.FailureReason)
	assert.Contains(t, result.FailureReason["error"], "failed validation")
}

func TestEnrichX5CResponse_WRPRCDirectSurfaces(t *testing.T) {
	token, validator := mintWRPRC(t, wrprcClaims(""))
	req := &authzen.EvaluationRequest{Context: map[string]interface{}{"wrprc": token}}
	result := EnrichX5CResponseWithProfiles(req, wrpacLeaf(t, "LEIXG-FRONTED"), rpcert.DefaultProfileRegistry(), validator)
	assert.True(t, result.Decision)
	require.NotNil(t, result.WRPRCEntitlements)
	assert.Equal(t, "LEIXG-FRONTED", result.WRPRCEntitlements.Subject.ID)
	assert.False(t, result.IsIntermediaryRequest)
	assert.Nil(t, result.IntermediaryIdentity)

	// ApplyEnrichmentToResponse surfaces the WRPRC into the trust metadata.
	resp := &authzen.EvaluationResponse{Decision: true, Context: &authzen.EvaluationResponseContext{}}
	ApplyEnrichmentToResponse(resp, result)
	md, ok := resp.Context.TrustMetadata.(map[string]interface{})
	require.True(t, ok)
	wrprc, ok := md["wrprc"].(map[string]interface{})
	require.True(t, ok)
	assert.Equal(t, "LEIXG-FRONTED", wrprc["fronted_rp_id"])
	assert.Equal(t, "Fronted RP GmbH", wrprc["fronted_rp_legal_name"])
	assert.Equal(t, "", wrprc["acting_intermediary"])
}

func TestEnrichX5CResponse_WRPRCIntermediaryNotAllowed(t *testing.T) {
	// The WRPRC names an acting intermediary, but the policy does not admit
	// intermediaries: deny, regardless of anything else.
	token, validator := mintWRPRC(t, wrprcClaims("LEIXG-INTERMEDIARY"))
	req := &authzen.EvaluationRequest{Context: map[string]interface{}{"wrprc": token}}
	result := EnrichX5CResponseWithProfiles(req, &x509.Certificate{}, nil, validator)
	assert.False(t, result.Decision)
	require.NotNil(t, result.FailureReason)
	assert.Contains(t, result.FailureReason["error"], "not allowed by policy")
}

func TestEnrichX5CResponse_WRPRCIntermediaryAllowedVerified(t *testing.T) {
	token, validator := mintWRPRC(t, wrprcClaims("LEIXG-INTERMEDIARY"))
	req := &authzen.EvaluationRequest{Context: map[string]interface{}{
		"wrprc":                token,
		"allow_intermediaries": true,
	}}
	result := EnrichX5CResponseWithProfiles(req, wrpacLeaf(t, "LEIXG-INTERMEDIARY"), rpcert.DefaultProfileRegistry(), validator)
	assert.True(t, result.Decision)
	assert.True(t, result.IsIntermediaryRequest)
	require.NotNil(t, result.IntermediaryIdentity)
	assert.Equal(t, true, result.IntermediaryIdentity["verified"])
	assert.Equal(t, "LEIXG-INTERMEDIARY", result.IntermediaryIdentity["acting_intermediary"])
	assert.Equal(t, "LEIXG-FRONTED", result.IntermediaryIdentity["fronted_rp_id"])
}

func TestEnrichX5CResponse_WRPRCOverRequestAuthoritative(t *testing.T) {
	// The WRPRC's credential queries allow given_name only. The request asks
	// for given_name AND family_name: strict mode denies on the registrar's
	// authoritative set — policy-configured allowed_attributes play no role
	// when the WRPRC is present.
	token, validator := mintWRPRC(t, wrprcClaims(""))
	req := &authzen.EvaluationRequest{Context: map[string]interface{}{
		"wrprc":                    token,
		"requested_attributes":     []string{"given_name", "family_name"},
		"strict_entitlement_check": true,
		"allowed_attributes":       []string{"given_name", "family_name", "anything"},
	}}
	result := EnrichX5CResponseWithProfiles(req, wrpacLeaf(t, "LEIXG-FRONTED"), rpcert.DefaultProfileRegistry(), validator)
	assert.False(t, result.Decision)
	require.NotNil(t, result.OverRequest)
	assert.True(t, result.OverRequest.IsOverRequest)
	assert.Equal(t, []string{"family_name"}, result.OverRequest.OverRequested)

	// Without strict mode the over-request surfaces as a warning.
	req.Context["strict_entitlement_check"] = false
	result = EnrichX5CResponseWithProfiles(req, wrpacLeaf(t, "LEIXG-FRONTED"), rpcert.DefaultProfileRegistry(), validator)
	assert.True(t, result.Decision)
	require.NotNil(t, result.OverRequest)
	assert.True(t, result.OverRequest.IsOverRequest)
}

func TestEnrichX5CResponse_WRPRCSwappedPayloadDenies(t *testing.T) {
	// The exact hole the deprecated JWTRegistrationCertValidator leaves: an
	// authentic registrar header (real x5c chain, anchored) with the payload
	// swapped underneath it. The chain anchors, the typ is right — only the
	// signature check catches it, and here it must.
	token, validator := mintWRPRC(t, wrprcClaims(""))
	parts := strings.Split(token, ".")
	// Re-encode a DIFFERENT payload under the authentic header+signature.
	forged := wrprcClaims("")
	forged["sub"] = "LEIXG-ATTACKER"
	forgedJSON, err := json.Marshal(forged)
	require.NoError(t, err)
	tampered := parts[0] + "." + base64.RawURLEncoding.EncodeToString(forgedJSON) + "." + parts[2]
	req := &authzen.EvaluationRequest{Context: map[string]interface{}{"wrprc": tampered}}
	result := EnrichX5CResponseWithProfiles(req, &x509.Certificate{}, nil, validator)
	assert.False(t, result.Decision)
	require.NotNil(t, result.FailureReason)
	assert.Contains(t, result.FailureReason["error"], "failed validation")
	assert.Nil(t, result.WRPRCEntitlements)
}

func TestEnrichX5CResponse_WRPRCUnboundIdentityFailsClosed(t *testing.T) {
	// A chain-valid WRPAC-shaped certificate with no usable binding identifier
	// (a legal-person certificate without organizationIdentifier) must not adopt
	// the WRPRC's identity: the binding is required on this path, not optional-skip.
	token, validator := mintWRPRC(t, wrprcClaims(""))
	leaf := makeVIDCert(t, vidCertOpts{policy: rpcert.OIDNCPLegalPerson})
	req := &authzen.EvaluationRequest{Context: map[string]interface{}{"wrprc": token}}
	result := EnrichX5CResponseWithProfiles(req, leaf, rpcert.DefaultProfileRegistry(), validator)
	assert.False(t, result.Decision)
	require.NotNil(t, result.FailureReason)
	assert.Contains(t, result.FailureReason["error"], "no usable binding identifier")
}

func TestEnrichX5CResponse_WRPRCExpiredDenies(t *testing.T) {
	claims := wrprcClaims("")
	claims["exp"] = time.Now().Add(-time.Hour).Unix()
	token, validator := mintWRPRC(t, claims)
	req := &authzen.EvaluationRequest{Context: map[string]interface{}{"wrprc": token}}
	result := EnrichX5CResponseWithProfiles(req, wrpacLeaf(t, "LEIXG-FRONTED"), rpcert.DefaultProfileRegistry(), validator)
	assert.False(t, result.Decision)
	assert.Contains(t, result.FailureReason["wrprc"], "expired")
}

func TestEnrichX5CResponse_WRPRCNotYetValidDenies(t *testing.T) {
	// iat beyond the 60-second skew: not yet valid, denied.
	claims := wrprcClaims("")
	claims["iat"] = time.Now().Add(10 * time.Minute).Unix()
	claims["exp"] = time.Now().Add(30 * 24 * time.Hour).Unix()
	token, validator := mintWRPRC(t, claims)
	req := &authzen.EvaluationRequest{Context: map[string]interface{}{"wrprc": token}}
	result := EnrichX5CResponseWithProfiles(req, wrpacLeaf(t, "LEIXG-FRONTED"), rpcert.DefaultProfileRegistry(), validator)
	assert.False(t, result.Decision)
	assert.Contains(t, result.FailureReason["wrprc"], "not yet valid")
}

func TestEnrichX5CResponse_WRPRCNoWindowDenies(t *testing.T) {
	// No iat/exp at all: no validity window to evaluate, denied.
	claims := wrprcClaims("")
	delete(claims, "iat")
	delete(claims, "exp")
	token, validator := mintWRPRC(t, claims)
	req := &authzen.EvaluationRequest{Context: map[string]interface{}{"wrprc": token}}
	result := EnrichX5CResponseWithProfiles(req, wrpacLeaf(t, "LEIXG-FRONTED"), rpcert.DefaultProfileRegistry(), validator)
	assert.False(t, result.Decision)
	assert.Contains(t, result.FailureReason["wrprc"], "no validity window")
}

func TestEnrichX5CResponse_WRPRCEmptyGrantIsAuthoritative(t *testing.T) {
	// A WRPRC granting NO credential queries is an authoritative empty
	// grant: every requested attribute is an over-request — even with
	// policy-configured allowed_attributes present, which this path
	// bypasses.
	claims := wrprcClaims("")
	delete(claims, "credentials")
	token, validator := mintWRPRC(t, claims)
	req := &authzen.EvaluationRequest{Context: map[string]interface{}{
		"wrprc":                    token,
		"requested_attributes":     []string{"given_name"},
		"strict_entitlement_check": true,
		"allowed_attributes":       []string{"given_name"},
	}}
	result := EnrichX5CResponseWithProfiles(req, wrpacLeaf(t, "LEIXG-FRONTED"), rpcert.DefaultProfileRegistry(), validator)
	assert.False(t, result.Decision)
	require.NotNil(t, result.OverRequest)
	assert.True(t, result.OverRequest.IsOverRequest)
	assert.Equal(t, []string{"given_name"}, result.OverRequest.OverRequested)
}

func TestWRPRCAlgorithmCurvePairingEnforced(t *testing.T) {
	// RFC 7518 §3.4 fixes the curve by the algorithm: an ES256 token signed
	// by a P-384 key must not pass with a 96-byte signature.
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(42),
		Subject:               pkix.Name{Organization: []string{"Registrar CA"}, CommonName: "registrar.example"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)
	caCert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	pool := x509.NewCertPool()
	pool.AddCert(caCert)

	header := map[string]interface{}{
		"typ": "rc-wrp+jwt",
		"alg": "ES256",
		"x5c": []string{base64.StdEncoding.EncodeToString(caCert.Raw)},
	}
	hdrJSON, err := json.Marshal(header)
	require.NoError(t, err)
	hdrB64 := base64.RawURLEncoding.EncodeToString(hdrJSON)
	payJSON, err := json.Marshal(wrprcClaims(""))
	require.NoError(t, err)
	payB64 := base64.RawURLEncoding.EncodeToString(payJSON)
	signingInput := hdrB64 + "." + payB64
	digest := sha256.Sum256([]byte(signingInput))
	r, s, err := ecdsa.Sign(rand.Reader, key, digest[:])
	require.NoError(t, err)
	// r || s at the P-384 width — 96 bytes for an ES256-declared token.
	sig := make([]byte, 96)
	r.FillBytes(sig[:48])
	s.FillBytes(sig[48:])
	token := signingInput + "." + base64.RawURLEncoding.EncodeToString(sig)

	verifier := NewAnchoredWRPRCVerifier(pool)
	_, err = verifier.VerifyWRPRC(context.Background(), []byte(token))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "requires curve P-256")
}

func TestEnrichX5CResponse_WRPRCNaturalPersonBindsByPersonalIdentifier(t *testing.T) {
	// A natural-person WRPAC carries the personal identifier in serialNumber
	// (ETSI TS 119 475 §5.1.5), not the organizationIdentifier: the binding
	// must use the PERSON's identifier, and the matching personal WRPRC
	// binds.
	claims := wrprcClaims("")
	claims["sub"] = "PNOSE-1234567890"
	token, validator := mintWRPRC(t, claims)
	leaf := makeVIDCert(t, vidCertOpts{serial: "PNOSE-1234567890", policy: rpcert.OIDNCPNaturalPerson})
	req := &authzen.EvaluationRequest{Context: map[string]interface{}{"wrprc": token}}
	result := EnrichX5CResponseWithProfiles(req, leaf, rpcert.DefaultProfileRegistry(), validator)
	assert.True(t, result.Decision)
	require.NotNil(t, result.WRPRCEntitlements)

	// The same person's certificate must NOT bind an ORGANIZATION's WRPRC:
	// the person is not the organization, whatever DN attributes they share.
	orgClaims := wrprcClaims("")
	orgClaims["sub"] = "LEIXG-SOME-ORG"
	orgToken, orgValidator := mintWRPRC(t, orgClaims)
	req = &authzen.EvaluationRequest{Context: map[string]interface{}{"wrprc": orgToken}}
	result = EnrichX5CResponseWithProfiles(req, leaf, rpcert.DefaultProfileRegistry(), orgValidator)
	assert.False(t, result.Decision)
	require.NotNil(t, result.FailureReason)
	assert.Contains(t, result.FailureReason["error"], "does not bind to the WRPRC")
}

func TestEnrichX5CResponse_WRPRCServiceIdentifierBinds(t *testing.T) {
	// The service-identifier binding (OIDWRPACServiceIdentifier): within
	// one organization, a certificate for service A must not receive a
	// WRPRC issued for service B.
	claims := wrprcClaims("")
	claims["service_identifier"] = "https://services.example/a"
	token, validator := mintWRPRC(t, claims)
	leafForB := makeVIDCert(t, vidCertOpts{
		orgID:     "LEIXG-FRONTED",
		policy:    rpcert.OIDNCPLegalPerson,
		serviceID: "https://services.example/b",
	})
	req := &authzen.EvaluationRequest{Context: map[string]interface{}{"wrprc": token}}
	result := EnrichX5CResponseWithProfiles(req, leafForB, rpcert.DefaultProfileRegistry(), validator)
	assert.False(t, result.Decision)
	require.NotNil(t, result.FailureReason)
	assert.Contains(t, result.FailureReason["error"], "service identifier does not bind")

	// The matching service on both sides binds.
	leafForA := makeVIDCert(t, vidCertOpts{
		orgID:     "LEIXG-FRONTED",
		policy:    rpcert.OIDNCPLegalPerson,
		serviceID: "https://services.example/a",
	})
	result = EnrichX5CResponseWithProfiles(req, leafForA, rpcert.DefaultProfileRegistry(), validator)
	assert.True(t, result.Decision)
}

func TestEnrichX5CResponse_WRPRCIntermediatedDistinctServiceIDsAllow(t *testing.T) {
	// The service-identifier binding distinguishes services of ONE
	// organization: an intermediated presentation legitimately carries
	// the INTERMEDIARY's service identifier beside the FRONTED RP's, and
	// distinct URIs must not deny a correctly bound act presentation.
	claims := wrprcClaims("LEIXG-INTERMEDIARY")
	claims["service_identifier"] = "https://fronted.example/services/rp"
	token, validator := mintWRPRC(t, claims)
	leaf := makeVIDCert(t, vidCertOpts{
		orgID:     "LEIXG-INTERMEDIARY",
		policy:    rpcert.OIDNCPLegalPerson,
		serviceID: "https://intermediary.example/services/presentation",
	})
	req := &authzen.EvaluationRequest{Context: map[string]interface{}{
		"wrprc":                token,
		"allow_intermediaries": true,
	}}
	result := EnrichX5CResponseWithProfiles(req, leaf, rpcert.DefaultProfileRegistry(), validator)
	assert.True(t, result.Decision)
}

func TestEnrichX5CResponse_WRPRCWholeCredentialRequestStrictDenies(t *testing.T) {
	// A DCQL credential query WITHOUT claims requests the whole credential —
	// a scope the WRPRC's attribute-level grants cannot represent. Strict
	// mode denies; otherwise the unrepresentable scope is a warning.
	token, validator := mintWRPRC(t, wrprcClaims(""))
	leaf := wrpacLeaf(t, "LEIXG-FRONTED")
	query := map[string]interface{}{
		"credentials": []interface{}{
			map[string]interface{}{"id": "pid", "format": "dc+sd-jwt"},
		},
	}
	req := &authzen.EvaluationRequest{Context: map[string]interface{}{
		"wrprc":                    token,
		"query":                    query,
		"strict_entitlement_check": true,
	}}
	result := EnrichX5CResponseWithProfiles(req, leaf, rpcert.DefaultProfileRegistry(), validator)
	assert.False(t, result.Decision)
	require.NotNil(t, result.FailureReason)
	assert.Contains(t, result.FailureReason["error"], "whole credential")

	// Without strict mode: allow, with the unrepresentable scope surfaced.
	req.Context["strict_entitlement_check"] = false
	result = EnrichX5CResponseWithProfiles(req, leaf, rpcert.DefaultProfileRegistry(), validator)
	assert.True(t, result.Decision)
	require.NotNil(t, result.OverRequest)
	assert.True(t, result.OverRequest.IsOverRequest)
}

func TestEnrichX5CResponse_WRPRCContextQueryOverRequest(t *testing.T) {
	// The DCQL query rides request.Context["query"] (the manager's allowlist
	// admits it there too), not only action.Parameters: the over-request
	// check must read it.
	token, validator := mintWRPRC(t, wrprcClaims(""))
	leaf := wrpacLeaf(t, "LEIXG-FRONTED")
	query := map[string]interface{}{
		"credentials": []interface{}{
			map[string]interface{}{
				"id":     "pid",
				"format": "dc+sd-jwt",
				"claims": []interface{}{
					map[string]interface{}{"path": []interface{}{"given_name"}},
					map[string]interface{}{"path": []interface{}{"family_name"}},
				},
			},
		},
	}
	req := &authzen.EvaluationRequest{Context: map[string]interface{}{
		"wrprc":                    token,
		"query":                    query,
		"strict_entitlement_check": true,
	}}
	result := EnrichX5CResponseWithProfiles(req, leaf, rpcert.DefaultProfileRegistry(), validator)
	assert.False(t, result.Decision)
	require.NotNil(t, result.OverRequest)
	assert.Equal(t, []string{"family_name"}, result.OverRequest.OverRequested)
}

func TestEnrichX5CResponse_WRPRCIntermediatedOmitsVerifierIDs(t *testing.T) {
	// The leaf on an intermediated presentation is the INTERMEDIARY's
	// certificate: emitting its semantic identifier as the end RP's verifier
	// ID would attribute the fronted RP's presentations to the intermediary.
	claims := wrprcClaims("LEIXG-INTERMEDIARY")
	token, validator := mintWRPRC(t, claims)
	leaf := makeVIDCert(t, vidCertOpts{
		orgID:  "LEIXG-INTERMEDIARY",
		policy: rpcert.OIDNCPLegalPerson,
		uris:   []string{"https://intermediary.example"},
	})
	req := &authzen.EvaluationRequest{Context: map[string]interface{}{
		"wrprc":                token,
		"allow_intermediaries": true,
		"return_verifier_ids":  []string{"semantic"},
	}}
	result := EnrichX5CResponseWithProfiles(req, leaf, rpcert.DefaultProfileRegistry(), validator)
	assert.True(t, result.Decision)
	assert.Empty(t, result.VerifierIDs, "an intermediated WRPRC must not derive verifier IDs from the intermediary's certificate")

	// A DIRECT presentation still derives them.
	directToken, directValidator := mintWRPRC(t, wrprcClaims(""))
	req = &authzen.EvaluationRequest{Context: map[string]interface{}{
		"wrprc":               directToken,
		"return_verifier_ids": []string{"semantic"},
	}}
	result = EnrichX5CResponseWithProfiles(req, wrpacLeaf(t, "LEIXG-FRONTED"), rpcert.DefaultProfileRegistry(), directValidator)
	assert.True(t, result.Decision)
	assert.NotEmpty(t, result.VerifierIDs)
}

func TestVerifyWRPRC_CritHeaderRefused(t *testing.T) {
	// RFC 7515 §4.1.11: a correctly signed token declaring a critical header
	// parameter this verifier does not implement is refused.
	tok, v := mintTestWRPRCTokenWithTyp(t, "rc-wrp+jwt", nil)
	parts := split3(t, tok)
	var header map[string]interface{}
	err := json.Unmarshal(b64Decode(t, parts[0]), &header)
	require.NoError(t, err)
	header["crit"] = []string{"custom-ext"}
	hdrJSON, err := json.Marshal(header)
	require.NoError(t, err)
	// The header change invalidates the signature, which is fine: the crit
	// check fires before signature verification either way.
	withCrit := base64.RawURLEncoding.EncodeToString(hdrJSON) + "." + parts[1] + "." + parts[2]
	_, err = v.VerifyWRPRC(context.Background(), []byte(withCrit))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "critical header")
}

func TestEnrichX5CResponse_WRPRCMixedQueryWholeCredentialStrictDenies(t *testing.T) {
	// A MIXED query — one claims-less credential (the whole credential)
	// beside one with an ALLOWED claim — must not slip the whole-credential
	// scope past strict mode through the allowed claim's attribute check.
	token, validator := mintWRPRC(t, wrprcClaims(""))
	leaf := wrpacLeaf(t, "LEIXG-FRONTED")
	query := map[string]interface{}{
		"credentials": []interface{}{
			map[string]interface{}{"id": "whole", "format": "dc+sd-jwt"},
			map[string]interface{}{
				"id":     "scoped",
				"format": "dc+sd-jwt",
				"claims": []interface{}{
					map[string]interface{}{"path": []interface{}{"given_name"}},
				},
			},
		},
	}
	req := &authzen.EvaluationRequest{Context: map[string]interface{}{
		"wrprc":                    token,
		"query":                    query,
		"strict_entitlement_check": true,
	}}
	result := EnrichX5CResponseWithProfiles(req, leaf, rpcert.DefaultProfileRegistry(), validator)
	assert.False(t, result.Decision)
	require.NotNil(t, result.FailureReason)
	assert.Contains(t, result.FailureReason["error"], "whole credential")

	// Non-strict: allow, with the whole-credential warning preserved even
	// though the explicit claim (given_name) is within the grant.
	req.Context["strict_entitlement_check"] = false
	result = EnrichX5CResponseWithProfiles(req, leaf, rpcert.DefaultProfileRegistry(), validator)
	assert.True(t, result.Decision)
	require.NotNil(t, result.OverRequest)
	assert.True(t, result.OverRequest.IsOverRequest)
	assert.Equal(t, []string{"<the entire credential>"}, result.OverRequest.OverRequested)
}
