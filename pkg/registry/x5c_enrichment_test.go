package registry

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"net/url"
	"testing"
	"time"

	"github.com/sirosfoundation/go-trust/pkg/authzen"
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
