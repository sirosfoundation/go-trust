package authzen

import (
	"encoding/json"
	"testing"
)

// FuzzEvaluationRequestValidate fuzzes the Validate method with arbitrary JSON.
// This catches panics, infinite loops, or unexpected crashes in the validation
// and JSON unmarshaling pipeline.
func FuzzEvaluationRequestValidate(f *testing.F) {
	// Seed with representative valid and invalid shapes
	seeds := []string{
		// Valid x5c request
		`{"subject":{"type":"key","id":"did:web:x"},"resource":{"type":"x5c","id":"did:web:x","key":["cert"]}}`,
		// Valid jwk request
		`{"subject":{"type":"key","id":"did:web:x"},"resource":{"type":"jwk","id":"did:web:x","key":[{"kty":"EC"}]}}`,
		// Resolution-only
		`{"subject":{"type":"key","id":"did:web:x"},"resource":{"id":"did:web:x"}}`,
		// With action
		`{"subject":{"type":"key","id":"x"},"resource":{"type":"x5c","id":"x","key":["c"]},"action":{"name":"issuer"}}`,
		// With action parameters
		`{"subject":{"type":"key","id":"x"},"resource":{"type":"x5c","id":"x","key":["c"]},"action":{"name":"issuer","parameters":{"credential_types":["pid"]}}}`,
		// With context
		`{"subject":{"type":"key","id":"x"},"resource":{"type":"x5c","id":"x","key":["c"]},"context":{"flow":"issuance"}}`,
		// Empty
		`{}`,
		// Invalid subject type
		`{"subject":{"type":"user","id":"alice"},"resource":{"type":"x5c","id":"alice","key":["c"]}}`,
		// Mismatched IDs
		`{"subject":{"type":"key","id":"a"},"resource":{"type":"x5c","id":"b","key":["c"]}}`,
		// Null fields
		`{"subject":{"type":"key","id":"x"},"resource":{"type":"x5c","id":"x","key":null}}`,
		// URL subject
		`{"subject":{"type":"url","id":"https://example.com"},"resource":{"id":"https://example.com"}}`,
	}

	for _, s := range seeds {
		f.Add([]byte(s))
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		var req EvaluationRequest
		if err := json.Unmarshal(data, &req); err != nil {
			return // Invalid JSON is fine to skip
		}

		// Validate must not panic
		_ = req.Validate()

		// IsResolutionOnlyRequest must not panic
		_ = req.IsResolutionOnlyRequest()

		// Re-marshal must not panic
		_, _ = json.Marshal(req)
	})
}

// FuzzEvaluationResponseRoundTrip fuzzes response marshaling round-trips.
func FuzzEvaluationResponseRoundTrip(f *testing.F) {
	seeds := []string{
		`{"decision":true}`,
		`{"decision":false,"context":{"reason":{"error":"not found"}}}`,
		`{"decision":true,"context":{"trust_metadata":{"id":"did:web:x"}}}`,
		`{"decision":false}`,
		`{}`,
	}

	for _, s := range seeds {
		f.Add([]byte(s))
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		var resp EvaluationResponse
		if err := json.Unmarshal(data, &resp); err != nil {
			return
		}

		// Re-marshal must not panic
		out, err := json.Marshal(resp)
		if err != nil {
			t.Fatalf("marshal failed for valid response: %v", err)
		}

		// Round-trip: unmarshal must succeed
		var resp2 EvaluationResponse
		if err := json.Unmarshal(out, &resp2); err != nil {
			t.Fatalf("round-trip unmarshal failed: %v", err)
		}
	})
}

// FuzzPDPMetadataRoundTrip fuzzes PDPMetadata marshaling.
func FuzzPDPMetadataRoundTrip(f *testing.F) {
	seeds := []string{
		`{"policy_decision_point":"https://pdp.example.com","access_evaluation_endpoint":"https://pdp.example.com/evaluation"}`,
		`{}`,
	}

	for _, s := range seeds {
		f.Add([]byte(s))
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		var meta PDPMetadata
		if err := json.Unmarshal(data, &meta); err != nil {
			return
		}
		_, _ = json.Marshal(meta)
	})
}
