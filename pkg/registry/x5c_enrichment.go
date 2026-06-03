package registry

import (
	"crypto/x509"
	"time"

	"github.com/sirosfoundation/go-trust/pkg/authzen"
)

// X5CEnrichmentResult holds the results of post-chain-validation enrichment
// (cert policy OID validation and RP identity extraction).
type X5CEnrichmentResult struct {
	// Decision is false if required policy OIDs were not found.
	Decision bool

	// MatchedPolicyOIDs lists the policy OIDs that matched the requirements.
	MatchedPolicyOIDs []string

	// RPIdentity is the extracted RP identity map (nil if not requested).
	RPIdentity map[string]interface{}

	// FailureReason is set when Decision is false, describing why.
	FailureReason map[string]interface{}
}

// EnrichX5CResponse performs post-chain-validation enrichment on a successful
// x5c evaluation: validates certificate policy OIDs (if required) and extracts
// RP identity (if requested). Both features are controlled via request context
// fields injected by policy configuration.
//
// Call this after successful chain validation. If the result has Decision=false,
// the caller should return a deny response with result.FailureReason merged
// into the reason map.
func EnrichX5CResponse(req *authzen.EvaluationRequest, leaf *x509.Certificate) *X5CEnrichmentResult {
	result := &X5CEnrichmentResult{Decision: true}

	// Validate certificate policy OIDs if required
	requiredOIDs := ExtractRequiredCertPolicyOIDs(req)
	if len(requiredOIDs) > 0 {
		matched, matchedOIDs := ValidateCertPolicyOIDs(leaf, requiredOIDs)
		if !matched {
			leafOIDs := make([]string, 0, len(leaf.PolicyIdentifiers))
			for _, oid := range leaf.PolicyIdentifiers {
				leafOIDs = append(leafOIDs, oid.String())
			}
			result.Decision = false
			result.FailureReason = map[string]interface{}{
				"error":                   "certificate does not contain required policy OIDs",
				"required_policy_oids":    requiredOIDs,
				"certificate_policy_oids": leafOIDs,
			}
			return result
		}
		result.MatchedPolicyOIDs = matchedOIDs
	}

	// Extract RP identity if requested
	if ShouldExtractRPIdentity(req) {
		result.RPIdentity = ExtractRPIdentity(leaf)
	}

	return result
}

// ApplyEnrichmentToResponse merges X5CEnrichmentResult into an existing
// successful EvaluationResponse, adding matched_policy_oids to the reason
// and trust metadata (rp_identity, matched_policy_oids) if present.
func ApplyEnrichmentToResponse(resp *authzen.EvaluationResponse, enrichment *X5CEnrichmentResult) {
	if enrichment == nil {
		return
	}
	if resp.Context == nil {
		resp.Context = &authzen.EvaluationResponseContext{}
	}
	if resp.Context.Reason == nil {
		resp.Context.Reason = make(map[string]interface{})
	}

	if len(enrichment.MatchedPolicyOIDs) > 0 {
		resp.Context.Reason["matched_policy_oids"] = enrichment.MatchedPolicyOIDs
	}

	// Build trust metadata if we have identity or matched OIDs
	var trustMetadata map[string]interface{}
	if enrichment.RPIdentity != nil {
		trustMetadata = map[string]interface{}{
			"rp_identity": enrichment.RPIdentity,
		}
	}
	if len(enrichment.MatchedPolicyOIDs) > 0 {
		if trustMetadata == nil {
			trustMetadata = make(map[string]interface{})
		}
		trustMetadata["matched_policy_oids"] = enrichment.MatchedPolicyOIDs
	}

	if trustMetadata != nil {
		// Merge into existing TrustMetadata if it's already a map
		if existing, ok := resp.Context.TrustMetadata.(map[string]interface{}); ok {
			for k, v := range trustMetadata {
				existing[k] = v
			}
		} else if resp.Context.TrustMetadata == nil {
			resp.Context.TrustMetadata = trustMetadata
		}
	}
}

// ExtractRequiredCertPolicyOIDs extracts required certificate policy OIDs from
// the request context. These can be set via policy config or passed dynamically.
func ExtractRequiredCertPolicyOIDs(req *authzen.EvaluationRequest) []string {
	if req.Context == nil {
		return nil
	}
	v, ok := req.Context["required_cert_policy_oids"]
	if !ok {
		return nil
	}
	switch oids := v.(type) {
	case []string:
		return oids
	case []interface{}:
		result := make([]string, 0, len(oids))
		for _, s := range oids {
			if str, ok := s.(string); ok {
				result = append(result, str)
			}
		}
		return result
	}
	return nil
}

// ValidateCertPolicyOIDs checks whether the certificate contains at least one
// of the required policy OIDs. Returns true and the matched OIDs if found.
func ValidateCertPolicyOIDs(cert *x509.Certificate, requiredOIDs []string) (bool, []string) {
	required := make(map[string]bool, len(requiredOIDs))
	for _, oid := range requiredOIDs {
		required[oid] = true
	}

	var matched []string
	for _, policyOID := range cert.PolicyIdentifiers {
		oidStr := policyOID.String()
		if required[oidStr] {
			matched = append(matched, oidStr)
		}
	}
	return len(matched) > 0, matched
}

// ShouldExtractRPIdentity checks whether RP identity extraction is requested
// via the request context field "extract_rp_identity".
func ShouldExtractRPIdentity(req *authzen.EvaluationRequest) bool {
	if req.Context == nil {
		return false
	}
	v, ok := req.Context["extract_rp_identity"]
	if !ok {
		return false
	}
	b, ok := v.(bool)
	return ok && b
}

// ExtractRPIdentity extracts RP identity information from a leaf certificate.
// Returns a map with organization, common name, country, serial number, and SANs.
func ExtractRPIdentity(cert *x509.Certificate) map[string]interface{} {
	identity := map[string]interface{}{}

	if len(cert.Subject.Organization) > 0 {
		identity["organization"] = cert.Subject.Organization
	}
	if cert.Subject.CommonName != "" {
		identity["common_name"] = cert.Subject.CommonName
	}
	if len(cert.Subject.Country) > 0 {
		identity["country"] = cert.Subject.Country
	}
	if cert.Subject.SerialNumber != "" {
		identity["serial_number"] = cert.Subject.SerialNumber
	}
	if cert.SerialNumber != nil {
		identity["certificate_serial_number"] = cert.SerialNumber.String()
	}
	if len(cert.DNSNames) > 0 {
		identity["dns_sans"] = cert.DNSNames
	}
	if len(cert.URIs) > 0 {
		uriSANs := make([]string, 0, len(cert.URIs))
		for _, uri := range cert.URIs {
			if uri != nil {
				uriSANs = append(uriSANs, uri.String())
			}
		}
		if len(uriSANs) > 0 {
			identity["uri_sans"] = uriSANs
		}
	}
	if len(cert.EmailAddresses) > 0 {
		identity["email_sans"] = cert.EmailAddresses
	}

	// Include certificate policy OIDs for downstream consumers
	if len(cert.PolicyIdentifiers) > 0 {
		policyOIDs := make([]string, len(cert.PolicyIdentifiers))
		for i, oid := range cert.PolicyIdentifiers {
			policyOIDs[i] = oid.String()
		}
		identity["policy_oids"] = policyOIDs
	}

	// Include validity period
	identity["not_before"] = cert.NotBefore.Format(time.RFC3339)
	identity["not_after"] = cert.NotAfter.Format(time.RFC3339)

	return identity
}
