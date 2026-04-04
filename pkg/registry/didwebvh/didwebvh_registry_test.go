package didwebvh

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/sirosfoundation/go-trust/pkg/authzen"
	reg "github.com/sirosfoundation/go-trust/pkg/registry"
)

func TestDidToHTTPURL(t *testing.T) {
	r, err := NewDIDWebVHRegistry(Config{})
	if err != nil {
		t.Fatalf("Failed to create registry: %v", err)
	}

	tests := []struct {
		name        string
		did         string
		wantSCID    string
		wantURL     string
		wantErr     bool
		errContains string
	}{
		{
			name:     "simple domain",
			did:      "did:webvh:QmWtQnHnZnZnZnZnZnZnZnZnZnZnZnZnZnZnZnZnZnZnZnZ:example.com",
			wantSCID: "QmWtQnHnZnZnZnZnZnZnZnZnZnZnZnZnZnZnZnZnZnZnZnZ",
			wantURL:  "https://example.com/.well-known/did.jsonl",
			wantErr:  false,
		},
		{
			name:     "domain with path",
			did:      "did:webvh:QmWtQnHnZnZnZnZnZnZnZnZnZnZnZnZnZnZnZnZnZnZnZnZ:example.com:dids:issuer",
			wantSCID: "QmWtQnHnZnZnZnZnZnZnZnZnZnZnZnZnZnZnZnZnZnZnZnZ",
			wantURL:  "https://example.com/dids/issuer/did.jsonl",
			wantErr:  false,
		},
		{
			name:     "domain with port (percent encoded)",
			did:      "did:webvh:QmWtQnHnZnZnZnZnZnZnZnZnZnZnZnZnZnZnZnZnZnZnZnZ:localhost%3A8080",
			wantSCID: "QmWtQnHnZnZnZnZnZnZnZnZnZnZnZnZnZnZnZnZnZnZnZnZ",
			wantURL:  "https://localhost:8080/.well-known/did.jsonl",
			wantErr:  false,
		},
		{
			name:        "invalid prefix",
			did:         "did:web:example.com",
			wantErr:     true,
			errContains: "not a did:webvh identifier",
		},
		{
			name:        "missing domain",
			did:         "did:webvh:QmWtQnHnZnZnZnZnZnZnZnZnZnZnZnZnZnZnZnZnZnZnZnZ",
			wantErr:     true,
			errContains: "missing domain",
		},
		{
			name:        "invalid SCID (too short)",
			did:         "did:webvh:abc123:example.com",
			wantErr:     true,
			errContains: "invalid SCID format",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotSCID, gotURL, err := r.didToHTTPURL(tt.did)
			if tt.wantErr {
				if err == nil {
					t.Errorf("didToHTTPURL() expected error, got nil")
					return
				}
				if tt.errContains != "" && !strings.Contains(err.Error(), tt.errContains) {
					t.Errorf("didToHTTPURL() error = %v, want error containing %s", err, tt.errContains)
				}
				return
			}
			if err != nil {
				t.Errorf("didToHTTPURL() unexpected error: %v", err)
				return
			}
			if gotSCID != tt.wantSCID {
				t.Errorf("didToHTTPURL() SCID = %v, want %v", gotSCID, tt.wantSCID)
			}
			if gotURL != tt.wantURL {
				t.Errorf("didToHTTPURL() URL = %v, want %v", gotURL, tt.wantURL)
			}
		})
	}
}

func TestIsValidSCID(t *testing.T) {
	tests := []struct {
		name  string
		scid  string
		valid bool
	}{
		{
			name:  "valid base58btc SCID (46 chars)",
			scid:  "QmWtQnHnZnZnZnZnZnZnZnZnZnZnZnZnZnZnZnZnZnZnZnZ",
			valid: true,
		},
		{
			name:  "valid shorter SCID",
			scid:  "QmWtQnHnZnZnZnZnZnZnZnZnZnZnZnZn",
			valid: true,
		},
		{
			name:  "too short",
			scid:  "QmWtQnHn",
			valid: false,
		},
		{
			name:  "invalid characters (contains 0)",
			scid:  "0mWtQnHnZnZnZnZnZnZnZnZnZnZnZnZnZnZnZnZnZnZnZnZ",
			valid: false,
		},
		{
			name:  "invalid characters (contains O)",
			scid:  "OmWtQnHnZnZnZnZnZnZnZnZnZnZnZnZnZnZnZnZnZnZnZnZ",
			valid: false,
		},
		{
			name:  "invalid characters (contains l)",
			scid:  "lmWtQnHnZnZnZnZnZnZnZnZnZnZnZnZnZnZnZnZnZnZnZnZ",
			valid: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isValidSCID(tt.scid)
			if got != tt.valid {
				t.Errorf("isValidSCID(%s) = %v, want %v", tt.scid, got, tt.valid)
			}
		})
	}
}

func TestBase58btcEncode(t *testing.T) {
	tests := []struct {
		name   string
		input  []byte
		output string
	}{
		{
			name:   "empty",
			input:  []byte{},
			output: "",
		},
		{
			name:   "single zero",
			input:  []byte{0},
			output: "1",
		},
		{
			name:   "leading zeros",
			input:  []byte{0, 0, 1},
			output: "112",
		},
		{
			name:   "hello",
			input:  []byte("hello"),
			output: "Cn8eVZg",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := base58btcEncode(tt.input)
			if got != tt.output {
				t.Errorf("base58btcEncode(%v) = %v, want %v", tt.input, got, tt.output)
			}
		})
	}
}

func TestJWKsMatch(t *testing.T) {
	tests := []struct {
		name  string
		jwk1  map[string]interface{}
		jwk2  map[string]interface{}
		match bool
	}{
		{
			name: "matching Ed25519 keys",
			jwk1: map[string]interface{}{
				"kty": "OKP",
				"crv": "Ed25519",
				"x":   "abc123",
			},
			jwk2: map[string]interface{}{
				"kty": "OKP",
				"crv": "Ed25519",
				"x":   "abc123",
			},
			match: true,
		},
		{
			name: "different x values",
			jwk1: map[string]interface{}{
				"kty": "OKP",
				"crv": "Ed25519",
				"x":   "abc123",
			},
			jwk2: map[string]interface{}{
				"kty": "OKP",
				"crv": "Ed25519",
				"x":   "xyz789",
			},
			match: false,
		},
		{
			name: "different key types",
			jwk1: map[string]interface{}{
				"kty": "OKP",
				"crv": "Ed25519",
				"x":   "abc123",
			},
			jwk2: map[string]interface{}{
				"kty": "EC",
				"crv": "P-256",
				"x":   "abc123",
				"y":   "def456",
			},
			match: false,
		},
		{
			name: "matching EC keys",
			jwk1: map[string]interface{}{
				"kty": "EC",
				"crv": "P-256",
				"x":   "abc123",
				"y":   "def456",
			},
			jwk2: map[string]interface{}{
				"kty": "EC",
				"crv": "P-256",
				"x":   "abc123",
				"y":   "def456",
			},
			match: true,
		},
		{
			name: "EC keys with different y",
			jwk1: map[string]interface{}{
				"kty": "EC",
				"crv": "P-256",
				"x":   "abc123",
				"y":   "def456",
			},
			jwk2: map[string]interface{}{
				"kty": "EC",
				"crv": "P-256",
				"x":   "abc123",
				"y":   "different",
			},
			match: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := reg.JWKsMatch(tt.jwk1, tt.jwk2)
			if got != tt.match {
				t.Errorf("JWKsMatch() = %v, want %v", got, tt.match)
			}
		})
	}
}

func TestValidateVersionTime(t *testing.T) {
	r, _ := NewDIDWebVHRegistry(Config{})

	now := time.Now()
	past := now.Add(-time.Hour)
	future := now.Add(time.Hour)

	tests := []struct {
		name        string
		entryTime   string
		prevEntries []DIDLogEntry
		wantErr     bool
	}{
		{
			name:        "valid first entry",
			entryTime:   past.Format(time.RFC3339),
			prevEntries: nil,
			wantErr:     false,
		},
		{
			name:      "valid subsequent entry",
			entryTime: now.Format(time.RFC3339),
			prevEntries: []DIDLogEntry{
				{VersionTime: past.Format(time.RFC3339)},
			},
			wantErr: false,
		},
		{
			name:        "time in future",
			entryTime:   future.Format(time.RFC3339),
			prevEntries: nil,
			wantErr:     true,
		},
		{
			name:      "time before previous entry",
			entryTime: past.Format(time.RFC3339),
			prevEntries: []DIDLogEntry{
				{VersionTime: now.Format(time.RFC3339)},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			entry := &DIDLogEntry{VersionTime: tt.entryTime}
			err := r.validateVersionTime(entry, tt.prevEntries)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateVersionTime() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestRegistryInterface(t *testing.T) {
	r, err := NewDIDWebVHRegistry(Config{
		Description: "Test Registry",
		Timeout:     10 * time.Second,
	})
	if err != nil {
		t.Fatalf("Failed to create registry: %v", err)
	}

	// Test Info()
	info := r.Info()
	if info.Name != "didwebvh-registry" {
		t.Errorf("Info().Name = %v, want didwebvh-registry", info.Name)
	}
	if info.Type != "did:webvh" {
		t.Errorf("Info().Type = %v, want did:webvh", info.Type)
	}
	if info.Description != "Test Registry" {
		t.Errorf("Info().Description = %v, want Test Registry", info.Description)
	}

	// Test Healthy()
	if !r.Healthy() {
		t.Error("Healthy() should return true")
	}

	// Test SupportsResolutionOnly()
	if !r.SupportsResolutionOnly() {
		t.Error("SupportsResolutionOnly() should return true")
	}

	// Test SupportedResourceTypes()
	types := r.SupportedResourceTypes()
	if len(types) != 1 || types[0] != "jwk" {
		t.Errorf("SupportedResourceTypes() = %v, want [jwk]", types)
	}

	// Test Refresh()
	err = r.Refresh(context.Background())
	if err != nil {
		t.Errorf("Refresh() should return nil, got %v", err)
	}
}

func TestEvaluateInvalidDID(t *testing.T) {
	r, _ := NewDIDWebVHRegistry(Config{})

	// Test with non-did:webvh identifier
	req := &authzen.EvaluationRequest{
		Subject: authzen.Subject{
			ID: "did:web:example.com",
		},
	}

	resp, err := r.Evaluate(context.Background(), req)
	if err != nil {
		t.Fatalf("Evaluate() returned error: %v", err)
	}

	if resp.Decision {
		t.Error("Evaluate() should return Decision=false for non-did:webvh DID")
	}

	if resp.Context == nil || resp.Context.Reason == nil {
		t.Fatal("Evaluate() should return reason in context")
	}

	reason := resp.Context.Reason
	errMsg, ok := reason["error"].(string)
	if !ok || !strings.Contains(errMsg, "must be a did:webvh identifier") {
		t.Errorf("Evaluate() error message = %v, want 'must be a did:webvh identifier'", reason["error"])
	}
}

func TestMockDIDResolution(t *testing.T) {
	// Create a mock DID Log
	scid := "QmWtQnHnZnZnZnZnZnZnZnZnZnZnZnZnZnZnZnZnZnZnZnZ"
	now := time.Now().UTC()

	didLogEntry := DIDLogEntry{
		VersionID:   "1-" + scid,
		VersionTime: now.Format(time.RFC3339),
		Parameters: DIDParameters{
			Method:     "did:webvh:1.0",
			SCID:       scid,
			UpdateKeys: []string{"z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"},
		},
		State: DIDDocument{
			Context: []string{"https://www.w3.org/ns/did/v1"},
			ID:      "did:webvh:" + scid + ":example.com",
			VerificationMethod: []VerificationMethod{
				{
					ID:         "did:webvh:" + scid + ":example.com#key-1",
					Type:       "Ed25519VerificationKey2020",
					Controller: "did:webvh:" + scid + ":example.com",
					PublicKeyJwk: map[string]interface{}{
						"kty": "OKP",
						"crv": "Ed25519",
						"x":   "abc123xyz",
					},
				},
			},
		},
		Proof: []map[string]interface{}{
			{
				"type":               "DataIntegrityProof",
				"cryptosuite":        "eddsa-jcs-2022",
				"verificationMethod": "did:webvh:" + scid + ":example.com#key-1",
				"proofPurpose":       "assertionMethod",
				"proofValue":         "z4K6mLqH9FfVJM",
			},
		},
	}

	logJSON, _ := json.Marshal(didLogEntry)

	// Create mock HTTP server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/did.jsonl" {
			w.Header().Set("Content-Type", "text/jsonl")
			w.Write(logJSON)
			w.Write([]byte("\n"))
		} else {
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	// Extract host from server URL
	serverHost := strings.TrimPrefix(server.URL, "http://")

	// Create registry with custom HTTP client and allow HTTP
	r, _ := NewDIDWebVHRegistry(Config{
		AllowHTTP: true,
	})
	r.SetHTTPClient(server.Client())

	// Build did:webvh identifier for our test server
	// Note: The SCID verification will fail because we can't compute a valid SCID
	// without proper JCS canonicalization, but this tests the basic flow
	did := "did:webvh:" + scid + ":" + strings.ReplaceAll(serverHost, ":", "%3A")

	// Test resolution (will fail SCID verification but tests the flow)
	ctx := context.Background()
	req := &authzen.EvaluationRequest{
		Subject: authzen.Subject{
			ID: did,
		},
	}

	resp, err := r.Evaluate(ctx, req)
	if err != nil {
		t.Fatalf("Evaluate() returned error: %v", err)
	}

	// The resolution should fail at SCID verification since we can't compute a valid SCID
	// This tests the basic resolution flow
	t.Logf("Evaluate response: Decision=%v, Reason=%v", resp.Decision, resp.Context.Reason)
}

func TestMergeParameters(t *testing.T) {
	tests := []struct {
		name     string
		current  DIDParameters
		new      DIDParameters
		expected DIDParameters
	}{
		{
			name:    "merge SCID",
			current: DIDParameters{},
			new: DIDParameters{
				SCID:   "abc123",
				Method: "did:webvh:1.0",
			},
			expected: DIDParameters{
				SCID:   "abc123",
				Method: "did:webvh:1.0",
			},
		},
		{
			name: "update keys override",
			current: DIDParameters{
				UpdateKeys: []string{"key1"},
			},
			new: DIDParameters{
				UpdateKeys: []string{"key2", "key3"},
			},
			expected: DIDParameters{
				UpdateKeys: []string{"key2", "key3"},
			},
		},
		{
			name: "deactivated persists",
			current: DIDParameters{
				Deactivated: true,
			},
			new: DIDParameters{},
			expected: DIDParameters{
				Deactivated: true,
			},
		},
		{
			name: "TTL updates",
			current: DIDParameters{
				TTL: 3600,
			},
			new: DIDParameters{
				TTL: 7200,
			},
			expected: DIDParameters{
				TTL: 7200,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mergeParameters(&tt.current, &tt.new)

			if tt.current.SCID != tt.expected.SCID {
				t.Errorf("SCID = %v, want %v", tt.current.SCID, tt.expected.SCID)
			}
			if tt.current.Method != tt.expected.Method {
				t.Errorf("Method = %v, want %v", tt.current.Method, tt.expected.Method)
			}
			if tt.current.Deactivated != tt.expected.Deactivated {
				t.Errorf("Deactivated = %v, want %v", tt.current.Deactivated, tt.expected.Deactivated)
			}
			if tt.current.TTL != tt.expected.TTL {
				t.Errorf("TTL = %v, want %v", tt.current.TTL, tt.expected.TTL)
			}
		})
	}
}

// =============================================================================
// Live Integration Tests
// =============================================================================

// TestPublicMediatorResolution tests resolution of the public mediator DID.
// This test requires network access and is skipped if the mediator is unavailable.
func TestPublicMediatorResolution(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping network-dependent test in short mode")
	}
	if os.Getenv("SKIP_NETWORK_TESTS") != "" {
		t.Skip("Skipping network test (SKIP_NETWORK_TESTS set)")
	}

	// Public mediator DID
	mediatorDID := "did:webvh:QmetnhxzJXTJ9pyXR1BbZ2h6DomY6SB1ZbzFPrjYyaEq9V:fpp.storm.ws:public-mediator"

	t.Logf("Testing resolution of public mediator: %s", mediatorDID)

	// Create registry with reasonable timeout
	registry, err := NewDIDWebVHRegistry(Config{
		Timeout:     60 * time.Second,
		Description: "Public mediator integration test",
	})
	if err != nil {
		t.Fatalf("Failed to create registry: %v", err)
	}

	// First, test URL construction
	scid, httpURL, err := registry.didToHTTPURL(mediatorDID)
	if err != nil {
		t.Fatalf("didToHTTPURL failed: %v", err)
	}

	t.Logf("  SCID: %s", scid)
	t.Logf("  URL: %s", httpURL)

	expectedURL := "https://fpp.storm.ws/public-mediator/did.jsonl"
	if httpURL != expectedURL {
		t.Errorf("URL mismatch: got %s, want %s", httpURL, expectedURL)
	}

	// Now test actual resolution
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// Create a resolution-only request
	req := &authzen.EvaluationRequest{
		Subject:  authzen.Subject{Type: "did", ID: mediatorDID},
		Resource: authzen.Resource{Type: "resolution", ID: mediatorDID},
	}

	t.Log("Resolving DID document...")
	resp, err := registry.Evaluate(ctx, req)
	if err != nil {
		t.Fatalf("Evaluate failed: %v", err)
	}

	// Log the full response for debugging
	if resp.Context != nil && resp.Context.Reason != nil {
		t.Logf("Response reason: %v", resp.Context.Reason)
	}

	if !resp.Decision {
		// Check if it's a network error - skip in that case
		if resp.Context != nil && resp.Context.Reason != nil {
			reason := resp.Context.Reason
			if errMsg, ok := reason["error"].(string); ok {
				if strings.Contains(errMsg, "context deadline exceeded") ||
					strings.Contains(errMsg, "connection refused") ||
					strings.Contains(errMsg, "no such host") ||
					strings.Contains(errMsg, "i/o timeout") {
					t.Skipf("Mediator not accessible: %s", errMsg)
				}
			}
		}
		t.Fatalf("DID resolution failed: decision=%v", resp.Decision)
	}

	t.Log("✓ DID resolution successful!")

	// Verify trust metadata contains expected fields
	if resp.Context != nil && resp.Context.TrustMetadata != nil {
		meta, ok := resp.Context.TrustMetadata.(map[string]interface{})
		if !ok {
			t.Logf("TrustMetadata is not map[string]interface{}: %T", resp.Context.TrustMetadata)
		} else {
			// Check DID ID matches
			if id, ok := meta["id"].(string); ok {
				if id != mediatorDID {
					t.Errorf("DID mismatch: got %s, want %s", id, mediatorDID)
				}
				t.Logf("  DID ID: %s", id)
			}

			// Check for verification methods
			if vms, ok := meta["verificationMethod"].([]map[string]interface{}); ok {
				t.Logf("  Verification methods: %d", len(vms))
				for _, vm := range vms {
					t.Logf("    - %v (%v)", vm["id"], vm["type"])
				}
			} else if vmsI, ok := meta["verificationMethod"].([]interface{}); ok {
				t.Logf("  Verification methods: %d", len(vmsI))
				for _, vm := range vmsI {
					if vmMap, ok := vm.(map[string]interface{}); ok {
						t.Logf("    - %v (%v)", vmMap["id"], vmMap["type"])
					}
				}
			}

			// Check for services (mediator should have DIDCommMessaging service)
			if services, ok := meta["service"].([]interface{}); ok {
				t.Logf("  Services: %d", len(services))
				for _, svc := range services {
					if svcMap, ok := svc.(map[string]interface{}); ok {
						t.Logf("    - %v (%v)", svcMap["id"], svcMap["type"])
					}
				}
			}
		}
	}
}

// TestPublicMediatorURLConstruction tests URL construction for the public mediator DID.
func TestPublicMediatorURLConstruction(t *testing.T) {
	registry, err := NewDIDWebVHRegistry(Config{})
	if err != nil {
		t.Fatalf("Failed to create registry: %v", err)
	}

	tests := []struct {
		name     string
		did      string
		wantSCID string
		wantURL  string
	}{
		{
			name:     "public mediator",
			did:      "did:webvh:QmetnhxzJXTJ9pyXR1BbZ2h6DomY6SB1ZbzFPrjYyaEq9V:fpp.storm.ws:public-mediator",
			wantSCID: "QmetnhxzJXTJ9pyXR1BbZ2h6DomY6SB1ZbzFPrjYyaEq9V",
			wantURL:  "https://fpp.storm.ws/public-mediator/did.jsonl",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			scid, url, err := registry.didToHTTPURL(tt.did)
			if err != nil {
				t.Fatalf("didToHTTPURL failed: %v", err)
			}
			if scid != tt.wantSCID {
				t.Errorf("SCID = %s, want %s", scid, tt.wantSCID)
			}
			if url != tt.wantURL {
				t.Errorf("URL = %s, want %s", url, tt.wantURL)
			}
		})
	}
}
