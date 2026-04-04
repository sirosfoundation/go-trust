package authzen

import (
	"encoding/json"
	"testing"
)

// TestEvaluationRequestValidation tests the Validate() method
func TestEvaluationRequestValidation(t *testing.T) {
	tests := []struct {
		name      string
		request   EvaluationRequest
		wantError bool
		errorMsg  string
	}{
		{
			name: "valid x5c request",
			request: EvaluationRequest{
				Subject:  Subject{Type: "key", ID: "did:example:123"},
				Resource: Resource{Type: "x5c", ID: "did:example:123", Key: []interface{}{"certbase64"}},
			},
			wantError: false,
		},
		{
			name: "invalid subject type",
			request: EvaluationRequest{
				Subject:  Subject{Type: "user", ID: "alice"},
				Resource: Resource{Type: "x5c", ID: "alice", Key: []interface{}{"cert"}},
			},
			wantError: true,
			errorMsg:  "subject.type must be 'key'",
		},
		{
			name: "resource.id does not match subject.id",
			request: EvaluationRequest{
				Subject:  Subject{Type: "key", ID: "alice"},
				Resource: Resource{Type: "x5c", ID: "bob", Key: []interface{}{"cert"}},
			},
			wantError: true,
			errorMsg:  "resource.id (bob) must match subject.id (alice)",
		},
		// Resolution-only request tests
		{
			name: "valid resolution-only request - no type or key",
			request: EvaluationRequest{
				Subject:  Subject{Type: "key", ID: "did:web:example.com"},
				Resource: Resource{ID: "did:web:example.com"},
			},
			wantError: false,
		},
		{
			name: "valid resolution-only request - type but no key",
			request: EvaluationRequest{
				Subject:  Subject{Type: "key", ID: "did:web:example.com"},
				Resource: Resource{Type: "jwk", ID: "did:web:example.com"},
			},
			wantError: false,
		},
		{
			name: "valid resolution-only request - empty key slice",
			request: EvaluationRequest{
				Subject:  Subject{Type: "key", ID: "did:web:example.com"},
				Resource: Resource{Type: "jwk", ID: "did:web:example.com", Key: []interface{}{}},
			},
			wantError: false,
		},
		{
			name: "resolution-only request with mismatched ids",
			request: EvaluationRequest{
				Subject:  Subject{Type: "key", ID: "did:web:alice.com"},
				Resource: Resource{ID: "did:web:bob.com"},
			},
			wantError: true,
			errorMsg:  "resource.id (did:web:bob.com) must match subject.id (did:web:alice.com)",
		},
		{
			name: "resolution-only request with subject.id only",
			request: EvaluationRequest{
				Subject:  Subject{Type: "key", ID: "did:web:example.com"},
				Resource: Resource{},
			},
			wantError: false,
		},
		{
			name: "full request missing resource.id",
			request: EvaluationRequest{
				Subject:  Subject{Type: "key", ID: "did:example:123"},
				Resource: Resource{Type: "jwk", Key: []interface{}{"keydata"}},
			},
			wantError: true,
			errorMsg:  "resource.id must be present",
		},
		{
			name: "full request with invalid resource.type",
			request: EvaluationRequest{
				Subject:  Subject{Type: "key", ID: "did:example:123"},
				Resource: Resource{Type: "pem", ID: "did:example:123", Key: []interface{}{"pemdata"}},
			},
			wantError: true,
			errorMsg:  "resource.type must be 'jwk' or 'x5c'",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.request.Validate()
			if tt.wantError && err == nil {
				t.Errorf("Expected error, got nil")
			}
			if !tt.wantError && err != nil {
				t.Errorf("Unexpected error: %v", err)
			}
		})
	}
}

// TestIsResolutionOnlyRequest tests the IsResolutionOnlyRequest method
func TestIsResolutionOnlyRequest(t *testing.T) {
	tests := []struct {
		name     string
		request  EvaluationRequest
		expected bool
	}{
		{
			name: "full request with type and key",
			request: EvaluationRequest{
				Subject:  Subject{Type: "key", ID: "did:example:123"},
				Resource: Resource{Type: "jwk", ID: "did:example:123", Key: []interface{}{"keydata"}},
			},
			expected: false,
		},
		{
			name: "resolution-only - no type",
			request: EvaluationRequest{
				Subject:  Subject{Type: "key", ID: "did:web:example.com"},
				Resource: Resource{ID: "did:web:example.com", Key: []interface{}{"keydata"}},
			},
			expected: true,
		},
		{
			name: "resolution-only - no key",
			request: EvaluationRequest{
				Subject:  Subject{Type: "key", ID: "did:web:example.com"},
				Resource: Resource{Type: "jwk", ID: "did:web:example.com"},
			},
			expected: true,
		},
		{
			name: "resolution-only - empty key slice",
			request: EvaluationRequest{
				Subject:  Subject{Type: "key", ID: "did:web:example.com"},
				Resource: Resource{Type: "jwk", ID: "did:web:example.com", Key: []interface{}{}},
			},
			expected: true,
		},
		{
			name: "resolution-only - no type or key",
			request: EvaluationRequest{
				Subject:  Subject{Type: "key", ID: "did:web:example.com"},
				Resource: Resource{ID: "did:web:example.com"},
			},
			expected: true,
		},
		{
			name: "resolution-only - empty resource",
			request: EvaluationRequest{
				Subject:  Subject{Type: "key", ID: "did:web:example.com"},
				Resource: Resource{},
			},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.request.IsResolutionOnlyRequest()
			if result != tt.expected {
				t.Errorf("IsResolutionOnlyRequest() = %v, expected %v", result, tt.expected)
			}
		})
	}
}

// TestEvaluationRequestSerialization tests JSON marshaling
func TestEvaluationRequestSerialization(t *testing.T) {
	request := EvaluationRequest{
		Subject:  Subject{Type: "key", ID: "did:example:test"},
		Resource: Resource{Type: "x5c", ID: "did:example:test", Key: []interface{}{"certdata"}},
	}

	jsonData, err := json.Marshal(request)
	if err != nil {
		t.Fatalf("Failed to marshal: %v", err)
	}

	var decoded EvaluationRequest
	err = json.Unmarshal(jsonData, &decoded)
	if err != nil {
		t.Fatalf("Failed to unmarshal: %v", err)
	}
}

// TestEvaluationResponseWithTrustMetadata tests TrustMetadata serialization
func TestEvaluationResponseWithTrustMetadata(t *testing.T) {
	// Test with DID Document style trust_metadata
	didDocument := map[string]interface{}{
		"@context": []string{"https://www.w3.org/ns/did/v1"},
		"id":       "did:web:example.com",
		"verificationMethod": []map[string]interface{}{
			{
				"id":           "did:web:example.com#key-1",
				"type":         "JsonWebKey2020",
				"controller":   "did:web:example.com",
				"publicKeyJwk": map[string]string{"kty": "EC", "crv": "P-256"},
			},
		},
	}

	response := EvaluationResponse{
		Decision: true,
		Context: &EvaluationResponseContext{
			ID:            "decision-123",
			TrustMetadata: didDocument,
		},
	}

	jsonData, err := json.Marshal(response)
	if err != nil {
		t.Fatalf("Failed to marshal response with trust_metadata: %v", err)
	}

	// Verify trust_metadata is present in JSON
	var decoded map[string]interface{}
	err = json.Unmarshal(jsonData, &decoded)
	if err != nil {
		t.Fatalf("Failed to unmarshal: %v", err)
	}

	ctx, ok := decoded["context"].(map[string]interface{})
	if !ok {
		t.Fatal("Expected context in response")
	}

	trustMeta, ok := ctx["trust_metadata"].(map[string]interface{})
	if !ok {
		t.Fatal("Expected trust_metadata in context")
	}

	if trustMeta["id"] != "did:web:example.com" {
		t.Errorf("Expected trust_metadata.id = 'did:web:example.com', got %v", trustMeta["id"])
	}
}

// TestResolutionOnlyResponseSerialization tests the full resolution-only flow
func TestResolutionOnlyResponseSerialization(t *testing.T) {
	// Test that resolution-only requests produce valid responses with trust_metadata
	request := EvaluationRequest{
		Subject:  Subject{Type: "key", ID: "did:web:example.com"},
		Resource: Resource{ID: "did:web:example.com"}, // No type or key = resolution-only
	}

	if !request.IsResolutionOnlyRequest() {
		t.Error("Expected request to be identified as resolution-only")
	}

	if err := request.Validate(); err != nil {
		t.Errorf("Resolution-only request should be valid: %v", err)
	}

	// Create a typical resolution-only response
	response := EvaluationResponse{
		Decision: true,
		Context: &EvaluationResponseContext{
			TrustMetadata: map[string]interface{}{
				"@context": []string{"https://www.w3.org/ns/did/v1"},
				"id":       "did:web:example.com",
			},
		},
	}

	jsonData, err := json.Marshal(response)
	if err != nil {
		t.Fatalf("Failed to marshal resolution response: %v", err)
	}

	// Verify structure
	var decoded EvaluationResponse
	err = json.Unmarshal(jsonData, &decoded)
	if err != nil {
		t.Fatalf("Failed to unmarshal response: %v", err)
	}

	if decoded.Context == nil || decoded.Context.TrustMetadata == nil {
		t.Error("Expected trust_metadata in decoded response")
	}
}

// TestTrustMetadataOmitEmpty tests that trust_metadata is omitted when nil
func TestTrustMetadataOmitEmpty(t *testing.T) {
	response := EvaluationResponse{
		Decision: true,
		Context: &EvaluationResponseContext{
			ID:            "test-id",
			TrustMetadata: nil, // Should be omitted
		},
	}

	jsonData, err := json.Marshal(response)
	if err != nil {
		t.Fatalf("Failed to marshal: %v", err)
	}

	var decoded map[string]interface{}
	err = json.Unmarshal(jsonData, &decoded)
	if err != nil {
		t.Fatalf("Failed to unmarshal: %v", err)
	}

	ctx := decoded["context"].(map[string]interface{})
	if _, exists := ctx["trust_metadata"]; exists {
		t.Error("trust_metadata should be omitted when nil")
	}
}
// TestActionParametersSerialization tests that action.parameters serializes correctly
func TestActionParametersSerialization(t *testing.T) {
	request := EvaluationRequest{
		Subject:  Subject{Type: "key", ID: "https://issuer.example.gov"},
		Resource: Resource{Type: "x5c", ID: "https://issuer.example.gov", Key: []interface{}{"certdata"}},
		Action: &Action{
			Name: "urn:eudi:credential-issuer",
			Parameters: map[string]interface{}{
				"credential_types": []string{"eu.europa.ec.eudi.pid.1", "eu.europa.ec.eudi.msisdn.1"},
			},
		},
	}

	jsonData, err := json.Marshal(request)
	if err != nil {
		t.Fatalf("Failed to marshal: %v", err)
	}

	// Verify JSON structure
	var decoded map[string]interface{}
	err = json.Unmarshal(jsonData, &decoded)
	if err != nil {
		t.Fatalf("Failed to unmarshal: %v", err)
	}

	action, ok := decoded["action"].(map[string]interface{})
	if !ok {
		t.Fatal("Expected action in request")
	}

	if action["name"] != "urn:eudi:credential-issuer" {
		t.Errorf("Expected action.name = 'urn:eudi:credential-issuer', got %v", action["name"])
	}

	params, ok := action["parameters"].(map[string]interface{})
	if !ok {
		t.Fatal("Expected parameters in action")
	}

	credTypes, ok := params["credential_types"].([]interface{})
	if !ok {
		t.Fatal("Expected credential_types in parameters")
	}

	if len(credTypes) != 2 {
		t.Errorf("Expected 2 credential types, got %d", len(credTypes))
	}

	// Verify round-trip
	var decodedRequest EvaluationRequest
	err = json.Unmarshal(jsonData, &decodedRequest)
	if err != nil {
		t.Fatalf("Failed to unmarshal to EvaluationRequest: %v", err)
	}

	if decodedRequest.Action == nil {
		t.Fatal("Expected action after unmarshal")
	}

	if decodedRequest.Action.Parameters == nil {
		t.Fatal("Expected action.parameters after unmarshal")
	}
}

// TestActionParametersOmitEmpty tests that action.parameters is omitted when nil
func TestActionParametersOmitEmpty(t *testing.T) {
	request := EvaluationRequest{
		Subject:  Subject{Type: "key", ID: "did:example:123"},
		Resource: Resource{Type: "x5c", ID: "did:example:123", Key: []interface{}{"certdata"}},
		Action: &Action{
			Name:       "http://ec.europa.eu/NS/wallet-provider",
			Parameters: nil, // Should be omitted
		},
	}

	jsonData, err := json.Marshal(request)
	if err != nil {
		t.Fatalf("Failed to marshal: %v", err)
	}

	var decoded map[string]interface{}
	err = json.Unmarshal(jsonData, &decoded)
	if err != nil {
		t.Fatalf("Failed to unmarshal: %v", err)
	}

	action := decoded["action"].(map[string]interface{})
	if _, exists := action["parameters"]; exists {
		t.Error("parameters should be omitted when nil")
	}
}
