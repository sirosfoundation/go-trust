// Package didwebvh implements a TrustRegistry using the did:webvh method specification.
//
// The did:webvh method extends did:web with verifiable history, providing:
// - Self-certifying identifiers (SCIDs) derived from the initial DID log entry
// - A verifiable chain of DID document versions stored in a JSON Lines log file
// - Cryptographic verification of each log entry via Data Integrity proofs
//
// The specification is available at: https://identity.foundation/didwebvh/v1.0/
package didwebvh

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/SUNET/vc/pkg/vc20/crypto/jcs"

	"github.com/multiformats/go-multibase"
	"github.com/sirosfoundation/go-trust/pkg/authzen"
	"github.com/sirosfoundation/go-trust/pkg/registry"
)

// DIDWebVHRegistry implements a trust registry using the did:webvh method.
// It resolves DID documents via HTTPS and validates the verifiable history.
type DIDWebVHRegistry struct {
	httpClient  registry.HTTPClientInterface
	timeout     time.Duration
	description string
	allowHTTP   bool // For testing only
}

// Config holds configuration for creating a DIDWebVHRegistry.
type Config struct {
	// Timeout for HTTP requests (default: 30 seconds)
	Timeout time.Duration `json:"timeout,omitempty"`

	// Description of this registry instance
	Description string `json:"description,omitempty"`

	// InsecureSkipVerify disables TLS certificate verification (NOT RECOMMENDED for production)
	InsecureSkipVerify bool `json:"insecure_skip_verify,omitempty"`

	// AllowHTTP allows using HTTP instead of HTTPS for DID resolution.
	// WARNING: This should only be used for testing. The did:webvh spec requires HTTPS.
	AllowHTTP bool `json:"allow_http,omitempty"`

	// AllowPrivateIPs permits requests to private/internal networks (RFC 1918).
	// WARNING: This should only be used for testing or internal deployments.
	AllowPrivateIPs bool `json:"allow_private_ips,omitempty"`
}

// DIDDocument represents a W3C DID Document.
// See https://www.w3.org/TR/did-core/
type DIDDocument struct {
	Context            interface{}          `json:"@context,omitempty"`
	ID                 string               `json:"id"`
	Controller         interface{}          `json:"controller,omitempty"`
	AlsoKnownAs        []string             `json:"alsoKnownAs,omitempty"`
	VerificationMethod []VerificationMethod `json:"verificationMethod,omitempty"`
	Authentication     interface{}          `json:"authentication,omitempty"`
	AssertionMethod    interface{}          `json:"assertionMethod,omitempty"`
	KeyAgreement       interface{}          `json:"keyAgreement,omitempty"`
	Service            interface{}          `json:"service,omitempty"`
}

// VerificationMethod represents a verification method in a DID document.
type VerificationMethod struct {
	ID                 string                 `json:"id"`
	Type               string                 `json:"type"`
	Controller         string                 `json:"controller"`
	PublicKeyJwk       map[string]interface{} `json:"publicKeyJwk,omitempty"`
	PublicKeyMultibase string                 `json:"publicKeyMultibase,omitempty"`
}

// DIDLogEntry represents a single entry in the did:webvh DID Log.
type DIDLogEntry struct {
	VersionID   string                   `json:"versionId"`
	VersionTime string                   `json:"versionTime"`
	Parameters  DIDParameters            `json:"parameters"`
	State       DIDDocument              `json:"state"`
	Proof       []map[string]interface{} `json:"proof,omitempty"`
}

// DIDParameters holds the parameters for DID processing.
type DIDParameters struct {
	// Method specifies the did:webvh specification version (e.g., "did:webvh:1.0")
	Method string `json:"method,omitempty"`

	// SCID is the self-certifying identifier (required in first entry only)
	SCID string `json:"scid,omitempty"`

	// UpdateKeys are multikey-formatted public keys authorized to sign updates
	UpdateKeys []string `json:"updateKeys,omitempty"`

	// NextKeyHashes are hashes of pre-rotation keys for the next entry
	NextKeyHashes []string `json:"nextKeyHashes,omitempty"`

	// Witness defines the witness configuration
	Witness *WitnessConfig `json:"witness,omitempty"`

	// Watchers is a list of watcher URLs
	Watchers []string `json:"watchers,omitempty"`

	// Portable indicates if the DID can be moved to a different location
	Portable bool `json:"portable,omitempty"`

	// Deactivated indicates if the DID has been deactivated
	Deactivated bool `json:"deactivated,omitempty"`

	// TTL is the time-to-live in seconds for caching
	TTL int `json:"ttl,omitempty"`
}

// WitnessConfig defines the witness configuration for a DID.
type WitnessConfig struct {
	Threshold int            `json:"threshold,omitempty"`
	Witnesses []WitnessEntry `json:"witnesses,omitempty"`
}

// WitnessEntry represents a single witness.
type WitnessEntry struct {
	ID string `json:"id"`
}

// DIDMetadata represents the resolution metadata for a did:webvh DID.
type DIDMetadata struct {
	VersionID   string         `json:"versionId"`
	VersionTime string         `json:"versionTime"`
	Created     string         `json:"created"`
	Updated     string         `json:"updated"`
	SCID        string         `json:"scid"`
	Portable    bool           `json:"portable"`
	Deactivated bool           `json:"deactivated"`
	TTL         string         `json:"ttl,omitempty"`
	Witness     *WitnessConfig `json:"witness,omitempty"`
	Watchers    []string       `json:"watchers,omitempty"`
}

// NewDIDWebVHRegistry creates a new did:webvh trust registry.
//
// The registry uses SafeHTTPClient with SSRF protection that blocks requests
// to private/internal IP addresses by default. This can be overridden with
// AllowPrivateIPs for testing or internal deployments.
func NewDIDWebVHRegistry(config Config) (*DIDWebVHRegistry, error) {
	timeout := config.Timeout
	if timeout == 0 {
		timeout = 30 * time.Second
	}

	description := config.Description
	if description == "" {
		description = "DID WebVH Method (did:webvh) Registry - Verifiable History"
	}

	// Use SafeHTTPClient with SSRF protection
	// See ADR 0012: SSRF Mitigation Strategy
	httpClient := registry.NewSafeHTTPClient(registry.SafeClientConfig{
		Timeout:            timeout,
		AllowHTTP:          config.AllowHTTP,
		AllowPrivateIPs:    config.AllowPrivateIPs,
		InsecureSkipVerify: config.InsecureSkipVerify,
	})

	return &DIDWebVHRegistry{
		httpClient:  httpClient,
		timeout:     timeout,
		description: description,
		allowHTTP:   config.AllowHTTP,
	}, nil
}

// Evaluate implements TrustRegistry.Evaluate by resolving did:webvh DIDs and validating key bindings.
func (r *DIDWebVHRegistry) Evaluate(ctx context.Context, req *authzen.EvaluationRequest) (*authzen.EvaluationResponse, error) {
	startTime := time.Now()

	// Validate that subject.id is a did:webvh identifier
	if !strings.HasPrefix(req.Subject.ID, "did:webvh:") {
		return &authzen.EvaluationResponse{
			Decision: false,
			Context: &authzen.EvaluationResponseContext{
				Reason: map[string]interface{}{
					"error": fmt.Sprintf("subject.id must be a did:webvh identifier, got: %s", req.Subject.ID),
				},
			},
		}, nil
	}

	// Extract the base DID without fragment
	baseDID := req.Subject.ID
	if idx := strings.Index(baseDID, "#"); idx != -1 {
		baseDID = baseDID[:idx]
	}

	// Resolve the DID document by processing the DID Log
	didDoc, metadata, err := r.resolveDID(ctx, baseDID)
	if err != nil {
		return &authzen.EvaluationResponse{
			Decision: false,
			Context: &authzen.EvaluationResponseContext{
				Reason: map[string]interface{}{
					"error":         fmt.Sprintf("failed to resolve DID: %v", err),
					"resolution_ms": time.Since(startTime).Milliseconds(),
				},
			},
		}, nil
	}

	// Check if DID is deactivated
	if metadata.Deactivated {
		return &authzen.EvaluationResponse{
			Decision: false,
			Context: &authzen.EvaluationResponseContext{
				Reason: map[string]interface{}{
					"error":       "DID has been deactivated",
					"deactivated": true,
					"scid":        metadata.SCID,
				},
			},
		}, nil
	}

	// Check policy constraints from request context (set by policy mapper)
	if denial := r.checkPolicyConstraints(req, didDoc, baseDID, startTime); denial != nil {
		return denial, nil
	}

	// Check if this is a resolution-only request
	if req.IsResolutionOnlyRequest() {
		return r.buildResolutionOnlyResponse(didDoc, metadata, startTime), nil
	}

	// For full trust evaluation, validate the key binding
	matched, matchedMethod, err := r.verifyKeyBinding(req, didDoc)
	if err != nil {
		return &authzen.EvaluationResponse{
			Decision: false,
			Context: &authzen.EvaluationResponseContext{
				Reason: map[string]interface{}{
					"error":         err.Error(),
					"resolution_ms": time.Since(startTime).Milliseconds(),
				},
			},
		}, nil
	}

	if !matched {
		return &authzen.EvaluationResponse{
			Decision: false,
			Context: &authzen.EvaluationResponseContext{
				Reason: map[string]interface{}{
					"error":                "no matching verification method found in DID document",
					"verification_methods": len(didDoc.VerificationMethod),
					"resolution_ms":        time.Since(startTime).Milliseconds(),
				},
			},
		}, nil
	}

	// Success - key binding is valid
	return &authzen.EvaluationResponse{
		Decision: true,
		Context: &authzen.EvaluationResponseContext{
			Reason: map[string]interface{}{
				"did":                  didDoc.ID,
				"verification_method":  matchedMethod.ID,
				"key_type":             matchedMethod.Type,
				"resolution_ms":        time.Since(startTime).Milliseconds(),
				"verification_methods": len(didDoc.VerificationMethod),
				"scid":                 metadata.SCID,
				"verifiable_history":   true,
			},
			TrustMetadata: r.didDocumentToTrustMetadata(didDoc, metadata),
		},
	}, nil
}

// buildResolutionOnlyResponse creates an EvaluationResponse for resolution-only requests.
func (r *DIDWebVHRegistry) buildResolutionOnlyResponse(didDoc *DIDDocument, metadata *DIDMetadata, startTime time.Time) *authzen.EvaluationResponse {
	return &authzen.EvaluationResponse{
		Decision: true,
		Context: &authzen.EvaluationResponseContext{
			Reason: map[string]interface{}{
				"did":                  didDoc.ID,
				"resolution_only":      true,
				"resolution_ms":        time.Since(startTime).Milliseconds(),
				"verification_methods": len(didDoc.VerificationMethod),
				"scid":                 metadata.SCID,
				"verifiable_history":   true,
				"version_id":           metadata.VersionID,
			},
			TrustMetadata: r.didDocumentToTrustMetadata(didDoc, metadata),
		},
	}
}

// didDocumentToTrustMetadata converts a DIDDocument and metadata to trust_metadata format.
func (r *DIDWebVHRegistry) didDocumentToTrustMetadata(didDoc *DIDDocument, metadata *DIDMetadata) map[string]interface{} {
	trustMeta := map[string]interface{}{
		"@context": didDoc.Context,
		"id":       didDoc.ID,
	}

	if didDoc.Controller != nil {
		trustMeta["controller"] = didDoc.Controller
	}

	if len(didDoc.AlsoKnownAs) > 0 {
		trustMeta["alsoKnownAs"] = didDoc.AlsoKnownAs
	}

	if len(didDoc.VerificationMethod) > 0 {
		verificationMethods := make([]map[string]interface{}, len(didDoc.VerificationMethod))
		for i, vm := range didDoc.VerificationMethod {
			method := map[string]interface{}{
				"id":         vm.ID,
				"type":       vm.Type,
				"controller": vm.Controller,
			}
			if vm.PublicKeyJwk != nil {
				method["publicKeyJwk"] = vm.PublicKeyJwk
			}
			if vm.PublicKeyMultibase != "" {
				method["publicKeyMultibase"] = vm.PublicKeyMultibase
			}
			verificationMethods[i] = method
		}
		trustMeta["verificationMethod"] = verificationMethods
	}

	if didDoc.Authentication != nil {
		trustMeta["authentication"] = didDoc.Authentication
	}

	if didDoc.AssertionMethod != nil {
		trustMeta["assertionMethod"] = didDoc.AssertionMethod
	}

	if didDoc.KeyAgreement != nil {
		trustMeta["keyAgreement"] = didDoc.KeyAgreement
	}

	if didDoc.Service != nil {
		trustMeta["service"] = didDoc.Service
	}

	// Include did:webvh-specific metadata
	if metadata != nil {
		trustMeta["didResolutionMetadata"] = map[string]interface{}{
			"versionId":   metadata.VersionID,
			"versionTime": metadata.VersionTime,
			"created":     metadata.Created,
			"updated":     metadata.Updated,
			"scid":        metadata.SCID,
			"portable":    metadata.Portable,
			"deactivated": metadata.Deactivated,
		}
		if metadata.TTL != "" {
			trustMeta["didResolutionMetadata"].(map[string]interface{})["ttl"] = metadata.TTL
		}
	}

	return trustMeta
}

// resolveDID resolves a did:webvh identifier to a DID document.
// It fetches and verifies the DID Log, returning the current DID document and metadata.
func (r *DIDWebVHRegistry) resolveDID(ctx context.Context, did string) (*DIDDocument, *DIDMetadata, error) {
	// Parse the DID to extract SCID and location
	scid, httpURL, err := r.didToHTTPURL(did)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid did:webvh identifier: %w", err)
	}

	// For testing: allow HTTP instead of HTTPS
	if r.allowHTTP {
		httpURL = strings.Replace(httpURL, "https://", "http://", 1)
	}

	// Fetch the DID Log
	req, err := http.NewRequestWithContext(ctx, "GET", httpURL, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create HTTP request: %w", err)
	}

	req.Header.Set("Accept", "text/jsonl, application/json")
	req.Header.Set("User-Agent", "go-trust/1.0 (did:webvh)")

	resp, err := r.httpClient.Do(req)
	if err != nil {
		return nil, nil, fmt.Errorf("HTTP request failed: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck // Body close error is not actionable

	if resp.StatusCode != http.StatusOK {
		return nil, nil, fmt.Errorf("HTTP request returned status %d", resp.StatusCode)
	}

	// Parse and verify the DID Log
	return r.processDIDLog(resp.Body, scid, did)
}

// didToHTTPURL converts a did:webvh identifier to an HTTPS URL for the DID Log.
//
// Returns the SCID and the URL for the did.jsonl file.
//
// Format: did:webvh:<scid>:<domain>[:path]/
// Example: did:webvh:QmXYZ123:example.com -> https://example.com/.well-known/did.jsonl
// Example: did:webvh:QmXYZ123:example.com:dids:issuer -> https://example.com/dids/issuer/did.jsonl
func (r *DIDWebVHRegistry) didToHTTPURL(did string) (scid string, httpURL string, err error) {
	// Remove "did:webvh:" prefix
	if !strings.HasPrefix(did, "did:webvh:") {
		return "", "", fmt.Errorf("not a did:webvh identifier")
	}

	methodSpecificID := strings.TrimPrefix(did, "did:webvh:")

	// The SCID is the first segment (46 characters of base58btc)
	parts := strings.SplitN(methodSpecificID, ":", 2)
	if len(parts) < 2 {
		return "", "", fmt.Errorf("missing domain in did:webvh identifier")
	}

	scid = parts[0]
	remainder := parts[1]

	// Validate SCID format (should be base58btc encoded, typically 46 chars for SHA-256 multihash)
	if !isValidSCID(scid) {
		return "", "", fmt.Errorf("invalid SCID format: %s", scid)
	}

	// Handle percent-encoded port colons
	remainder = strings.ReplaceAll(remainder, "%3A", "___PORT___")
	remainder = strings.ReplaceAll(remainder, "%3a", "___PORT___")

	// Split by colon to separate domain and path components
	domainAndPath := strings.Split(remainder, ":")

	// First part is the domain name
	domain := strings.ReplaceAll(domainAndPath[0], "___PORT___", ":")

	// Build the path from remaining parts
	var path string
	if len(domainAndPath) > 1 {
		pathParts := []string{}
		for _, part := range domainAndPath[1:] {
			cleaned := strings.ReplaceAll(part, "___PORT___", ":")
			if cleaned != "" {
				pathParts = append(pathParts, cleaned)
			}
		}
		if len(pathParts) > 0 {
			path = "/" + strings.Join(pathParts, "/")
		} else {
			path = "/.well-known"
		}
	} else {
		path = "/.well-known"
	}

	// Construct the HTTPS URL for did.jsonl
	httpURL = fmt.Sprintf("https://%s%s/did.jsonl", domain, path)

	// Validate the URL
	if _, err := url.Parse(httpURL); err != nil {
		return "", "", fmt.Errorf("invalid URL: %w", err)
	}

	return scid, httpURL, nil
}

// isValidSCID validates the format of a Self-Certifying Identifier.
// SCIDs are base58btc-encoded multihashes, typically 46 characters for SHA-256.
func isValidSCID(scid string) bool {
	// Base58btc character set (no 0, O, I, l)
	base58Pattern := regexp.MustCompile(`^[1-9A-HJ-NP-Za-km-z]+$`)
	if !base58Pattern.MatchString(scid) {
		return false
	}
	// SHA-256 multihash in base58btc is typically 46 characters
	// Allow some flexibility for different hash algorithms
	return len(scid) >= 32 && len(scid) <= 64
}

// processDIDLog reads and verifies the DID Log, returning the current DID document and metadata.
func (r *DIDWebVHRegistry) processDIDLog(reader io.Reader, expectedSCID string, did string) (*DIDDocument, *DIDMetadata, error) {
	scanner := bufio.NewScanner(reader)

	var entries []DIDLogEntry
	var currentParams DIDParameters
	var metadata DIDMetadata
	var prevVersionID string
	versionNumber := 0

	for scanner.Scan() {
		line := scanner.Text()
		if strings.TrimSpace(line) == "" {
			continue
		}

		var entry DIDLogEntry
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			return nil, nil, fmt.Errorf("failed to parse DID Log entry %d: %w", versionNumber+1, err)
		}

		versionNumber++

		// Merge parameters (new values override previous)
		mergeParameters(&currentParams, &entry.Parameters)

		// Verify version number in versionId
		expectedVersionPrefix := fmt.Sprintf("%d-", versionNumber)
		if !strings.HasPrefix(entry.VersionID, expectedVersionPrefix) {
			return nil, nil, fmt.Errorf("invalid versionId at entry %d: expected prefix '%s', got '%s'", versionNumber, expectedVersionPrefix, entry.VersionID)
		}

		// Extract entryHash from versionId
		entryHash := strings.TrimPrefix(entry.VersionID, expectedVersionPrefix)

		// For the first entry, verify the SCID
		if versionNumber == 1 {
			if currentParams.SCID == "" {
				return nil, nil, fmt.Errorf("missing SCID in first log entry parameters")
			}
			if currentParams.SCID != expectedSCID {
				return nil, nil, fmt.Errorf("SCID mismatch: expected %s, got %s", expectedSCID, currentParams.SCID)
			}

			// Verify SCID derivation
			if err := r.verifySCID(&entry); err != nil {
				return nil, nil, fmt.Errorf("SCID verification failed: %w", err)
			}

			metadata.Created = entry.VersionTime
			metadata.SCID = currentParams.SCID
			prevVersionID = currentParams.SCID
		} else {
			prevVersionID = entries[len(entries)-1].VersionID
		}

		// Verify entry hash
		if err := r.verifyEntryHash(&entry, prevVersionID, entryHash); err != nil {
			return nil, nil, fmt.Errorf("entry hash verification failed at entry %d: %w", versionNumber, err)
		}

		// Verify Data Integrity proof
		if err := r.verifyProof(&entry, &currentParams); err != nil {
			return nil, nil, fmt.Errorf("proof verification failed at entry %d: %w", versionNumber, err)
		}

		// Verify pre-rotation if active
		if versionNumber > 1 && len(entries[len(entries)-1].Parameters.NextKeyHashes) > 0 {
			if err := r.verifyPreRotation(&entry, &entries[len(entries)-1].Parameters); err != nil {
				return nil, nil, fmt.Errorf("pre-rotation verification failed at entry %d: %w", versionNumber, err)
			}
		}

		// Validate versionTime
		if err := r.validateVersionTime(&entry, entries); err != nil {
			return nil, nil, fmt.Errorf("versionTime validation failed at entry %d: %w", versionNumber, err)
		}

		entries = append(entries, entry)
		metadata.Updated = entry.VersionTime
	}

	if err := scanner.Err(); err != nil {
		return nil, nil, fmt.Errorf("error reading DID Log: %w", err)
	}

	if len(entries) == 0 {
		return nil, nil, fmt.Errorf("empty DID Log")
	}

	// Get the current (last) DID document
	lastEntry := entries[len(entries)-1]
	didDoc := &lastEntry.State

	// Verify the DID matches the document ID
	if !strings.Contains(didDoc.ID, expectedSCID) {
		return nil, nil, fmt.Errorf("DID document ID does not contain expected SCID")
	}

	// Populate metadata
	metadata.VersionID = lastEntry.VersionID
	metadata.VersionTime = lastEntry.VersionTime
	metadata.Portable = currentParams.Portable
	metadata.Deactivated = currentParams.Deactivated
	if currentParams.TTL > 0 {
		metadata.TTL = fmt.Sprintf("%d", currentParams.TTL)
	}
	metadata.Witness = currentParams.Witness
	metadata.Watchers = currentParams.Watchers

	return didDoc, &metadata, nil
}

// mergeParameters merges new parameters into the current active parameters.
func mergeParameters(current *DIDParameters, new *DIDParameters) {
	if new.Method != "" {
		current.Method = new.Method
	}
	if new.SCID != "" {
		current.SCID = new.SCID
	}
	if len(new.UpdateKeys) > 0 {
		current.UpdateKeys = new.UpdateKeys
	}
	if new.NextKeyHashes != nil {
		current.NextKeyHashes = new.NextKeyHashes
	}
	if new.Witness != nil {
		current.Witness = new.Witness
	}
	if new.Watchers != nil {
		current.Watchers = new.Watchers
	}
	// Portable can only be set in first entry
	if new.Portable {
		current.Portable = true
	}
	if new.Deactivated {
		current.Deactivated = true
	}
	if new.TTL > 0 {
		current.TTL = new.TTL
	}
}

// verifySCID verifies that the SCID was correctly derived from the first log entry.
// Per did:webvh v1.0 spec, the SCID is calculated from the JCS-canonicalized JSON
// of the initial log entry with:
// - All occurrences of the SCID replaced with {SCID} placeholder (string replacement)
// - versionId set to "{SCID}"
// - Proof field removed
func (r *DIDWebVHRegistry) verifySCID(entry *DIDLogEntry) error {
	// Get SCID from parameters
	expectedSCID := entry.Parameters.SCID

	// Create a copy of the entry for SCID calculation
	entryCopy := *entry
	entryCopy.Proof = nil
	entryCopy.VersionID = "{SCID}"

	// Marshal to JSON first
	entryJSON, err := json.Marshal(&entryCopy)
	if err != nil {
		return fmt.Errorf("failed to marshal entry for SCID verification: %w", err)
	}

	// Replace ALL occurrences of the SCID with the placeholder
	// This is needed because the SCID appears in the DID document (state) as well
	entryStr := strings.ReplaceAll(string(entryJSON), expectedSCID, "{SCID}")

	// Parse back to map for proper JCS canonicalization
	// (passing []byte directly to jcs.Canonicalize would cause json.Marshal to
	// encode it as base64)
	var entryMap map[string]interface{}
	if err := json.Unmarshal([]byte(entryStr), &entryMap); err != nil {
		return fmt.Errorf("failed to parse entry for SCID verification: %w", err)
	}

	// Apply JCS canonicalization
	canonicalJSON, err := jcs.Canonicalize(entryMap)
	if err != nil {
		return fmt.Errorf("failed to canonicalize entry for SCID verification: %w", err)
	}

	// Calculate the expected SCID from the canonical JSON
	calculatedSCID, err := r.calculateMultihash(canonicalJSON)
	if err != nil {
		return fmt.Errorf("failed to calculate SCID: %w", err)
	}

	if calculatedSCID != expectedSCID {
		return fmt.Errorf("SCID mismatch: calculated %s, expected %s", calculatedSCID, expectedSCID)
	}

	return nil
}

// verifyEntryHash verifies that the entry hash was correctly derived.
// Per did:webvh v1.0 spec, the entry hash is calculated from the JCS-canonicalized JSON
// of the log entry with:
// - versionId set to the previous entry's versionId
// - Proof field removed
func (r *DIDWebVHRegistry) verifyEntryHash(entry *DIDLogEntry, prevVersionID string, expectedHash string) error {
	// Create a copy of the entry without the proof
	entryCopy := *entry
	entryCopy.Proof = nil
	entryCopy.VersionID = prevVersionID

	// Marshal to JSON
	entryJSON, err := json.Marshal(&entryCopy)
	if err != nil {
		return fmt.Errorf("failed to marshal entry for hash verification: %w", err)
	}

	// Parse back to map for proper JCS canonicalization
	// (passing []byte directly to jcs.Canonicalize would cause json.Marshal to
	// encode it as base64)
	var entryMap map[string]interface{}
	if err := json.Unmarshal(entryJSON, &entryMap); err != nil {
		return fmt.Errorf("failed to parse entry for hash verification: %w", err)
	}

	// Apply JCS canonicalization per did:webvh spec
	canonicalJSON, err := jcs.Canonicalize(entryMap)
	if err != nil {
		return fmt.Errorf("failed to canonicalize entry for hash verification: %w", err)
	}

	// Calculate the hash
	calculatedHash, err := r.calculateMultihash(canonicalJSON)
	if err != nil {
		return fmt.Errorf("failed to calculate entry hash: %w", err)
	}

	if calculatedHash != expectedHash {
		return fmt.Errorf("entry hash mismatch: calculated %s, expected %s", calculatedHash, expectedHash)
	}

	return nil
}

// calculateMultihash calculates a base58btc-encoded multihash of the input data.
// Uses SHA-256 as the hash algorithm per did:webvh v1.0 spec.
func (r *DIDWebVHRegistry) calculateMultihash(data []byte) (string, error) {
	// Calculate SHA-256 hash
	hash := sha256.Sum256(data)

	// Create multihash: prefix (0x12 = SHA-256, 0x20 = 32 bytes) + hash
	multihash := make([]byte, 34)
	multihash[0] = 0x12 // SHA-256 identifier
	multihash[1] = 0x20 // 32 bytes
	copy(multihash[2:], hash[:])

	// Encode as base58btc
	return base58btcEncode(multihash), nil
}

// base58btcEncode encodes bytes to base58btc string.
func base58btcEncode(data []byte) string {
	const alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

	// Count leading zeros
	zeros := 0
	for _, b := range data {
		if b == 0 {
			zeros++
		} else {
			break
		}
	}

	// Allocate enough space
	size := len(data)*138/100 + 1
	buf := make([]byte, size)

	var length int
	for _, b := range data {
		carry := int(b)
		for i := 0; i < length || carry != 0; i++ {
			if i < length {
				carry += 256 * int(buf[i])
			}
			buf[i] = byte(carry % 58)
			carry /= 58
			if i >= length {
				length = i + 1
			}
		}
	}

	// Build result
	result := make([]byte, zeros+length)
	for i := 0; i < zeros; i++ {
		result[i] = '1'
	}
	for i := 0; i < length; i++ {
		result[zeros+i] = alphabet[buf[length-1-i]]
	}

	return string(result)
}

// verifyProof verifies the Data Integrity proof on a log entry using eddsa-jcs-2022.
func (r *DIDWebVHRegistry) verifyProof(entry *DIDLogEntry, params *DIDParameters) error {
	if len(entry.Proof) == 0 {
		return fmt.Errorf("missing proof in log entry")
	}

	proof := entry.Proof[0]

	// Verify basic proof structure
	proofType, ok := proof["type"].(string)
	if !ok {
		return fmt.Errorf("missing or invalid proof type")
	}

	// did:webvh v1.0 requires eddsa-jcs-2022 cryptosuite
	if proofType != "DataIntegrityProof" {
		return fmt.Errorf("unexpected proof type: %s (expected DataIntegrityProof)", proofType)
	}

	cryptosuite, _ := proof["cryptosuite"].(string)
	if cryptosuite != jcs.CryptosuiteEdDSAJCS2022 {
		return fmt.Errorf("invalid cryptosuite: expected %s, got %s", jcs.CryptosuiteEdDSAJCS2022, cryptosuite)
	}

	// Verify proof purpose
	proofPurpose, _ := proof["proofPurpose"].(string)
	if proofPurpose != "assertionMethod" {
		return fmt.Errorf("invalid proofPurpose: expected 'assertionMethod', got '%s'", proofPurpose)
	}

	// Verify the verification method references an updateKey
	verificationMethod, _ := proof["verificationMethod"].(string)
	if verificationMethod == "" {
		return fmt.Errorf("missing verificationMethod in proof")
	}

	// Verify proof value exists
	proofValue, _ := proof["proofValue"].(string)
	if proofValue == "" {
		return fmt.Errorf("missing proofValue in proof")
	}

	// Find the public key for verification from updateKeys
	publicKey, err := r.findPublicKey(verificationMethod, params)
	if err != nil {
		return fmt.Errorf("failed to find verification key: %w", err)
	}

	// Convert the entry to a map for verification
	entryMap, err := r.entryToMap(entry)
	if err != nil {
		return fmt.Errorf("failed to convert entry to map: %w", err)
	}

	// Verify the signature using eddsa-jcs-2022
	suite := jcs.NewSuite()
	if err := suite.VerifyWithProof(entryMap, proof, publicKey); err != nil {
		return fmt.Errorf("signature verification failed: %w", err)
	}

	return nil
}

// findPublicKey finds the Ed25519 public key for the given verification method.
func (r *DIDWebVHRegistry) findPublicKey(verificationMethod string, params *DIDParameters) (ed25519.PublicKey, error) {
	// The verificationMethod in did:webvh proofs references one of the updateKeys
	// UpdateKeys are in multikey format: did:key:z... or just z... (multibase-encoded Ed25519 public key)

	for _, updateKey := range params.UpdateKeys {
		// Check if this updateKey matches the verification method
		// Verification method format: did:key:z... or #z...
		keyID := updateKey
		if strings.HasPrefix(updateKey, "did:key:") {
			keyID = strings.TrimPrefix(updateKey, "did:key:")
		}

		if strings.Contains(verificationMethod, keyID) || updateKey == verificationMethod {
			return r.decodeMultikey(updateKey)
		}
	}

	return nil, fmt.Errorf("no matching updateKey found for verification method: %s", verificationMethod)
}

// decodeMultikey decodes a multikey-formatted Ed25519 public key.
// Multikey format for Ed25519: z6Mk... (multibase base58btc + multicodec prefix 0xed01)
func (r *DIDWebVHRegistry) decodeMultikey(multikey string) (ed25519.PublicKey, error) {
	// Remove did:key: prefix if present
	key := strings.TrimPrefix(multikey, "did:key:")

	// Decode multibase
	_, data, err := multibase.Decode(key)
	if err != nil {
		return nil, fmt.Errorf("failed to decode multibase: %w", err)
	}

	// Check multicodec prefix for Ed25519 public key (0xed01)
	// Multicodec is varint-encoded: 0xed 0x01 for Ed25519 public key
	if len(data) < 2 || data[0] != 0xed || data[1] != 0x01 {
		return nil, fmt.Errorf("invalid multicodec prefix: expected Ed25519 public key (0xed01)")
	}

	// Extract the raw public key bytes (32 bytes for Ed25519)
	pubKeyBytes := data[2:]
	if len(pubKeyBytes) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("invalid Ed25519 public key length: expected %d, got %d", ed25519.PublicKeySize, len(pubKeyBytes))
	}

	return ed25519.PublicKey(pubKeyBytes), nil
}

// entryToMap converts a DIDLogEntry to a map[string]any for signature verification.
func (r *DIDWebVHRegistry) entryToMap(entry *DIDLogEntry) (map[string]any, error) {
	// Marshal to JSON and back to get a map representation
	jsonBytes, err := json.Marshal(entry)
	if err != nil {
		return nil, err
	}

	var result map[string]any
	if err := json.Unmarshal(jsonBytes, &result); err != nil {
		return nil, err
	}

	return result, nil
}

// verifyPreRotation verifies that updateKeys match the nextKeyHashes from the previous entry.
func (r *DIDWebVHRegistry) verifyPreRotation(entry *DIDLogEntry, prevParams *DIDParameters) error {
	if len(prevParams.NextKeyHashes) == 0 {
		return nil // Pre-rotation not active
	}

	if len(entry.Parameters.UpdateKeys) == 0 {
		return fmt.Errorf("updateKeys required when pre-rotation is active")
	}

	// Verify each updateKey has its hash in the previous nextKeyHashes
	for _, updateKey := range entry.Parameters.UpdateKeys {
		keyHash, err := r.calculateMultihash([]byte(updateKey))
		if err != nil {
			return fmt.Errorf("failed to hash updateKey: %w", err)
		}

		found := false
		for _, expectedHash := range prevParams.NextKeyHashes {
			if keyHash == expectedHash {
				found = true
				break
			}
		}

		if !found {
			return fmt.Errorf("updateKey hash not found in previous nextKeyHashes")
		}
	}

	return nil
}

// validateVersionTime validates that versionTime is properly ordered.
func (r *DIDWebVHRegistry) validateVersionTime(entry *DIDLogEntry, prevEntries []DIDLogEntry) error {
	entryTime, err := time.Parse(time.RFC3339, entry.VersionTime)
	if err != nil {
		return fmt.Errorf("invalid versionTime format: %w", err)
	}

	// Verify time is not in the future
	if entryTime.After(time.Now().Add(time.Minute)) {
		return fmt.Errorf("versionTime is in the future")
	}

	// Verify time is after previous entry
	if len(prevEntries) > 0 {
		prevTime, err := time.Parse(time.RFC3339, prevEntries[len(prevEntries)-1].VersionTime)
		if err == nil && !entryTime.After(prevTime) {
			return fmt.Errorf("versionTime must be after previous entry's time")
		}
	}

	return nil
}

// verifyKeyBinding checks if the key in the request matches a verification method in the DID document.
func (r *DIDWebVHRegistry) verifyKeyBinding(req *authzen.EvaluationRequest, didDoc *DIDDocument) (bool, *VerificationMethod, error) {
	if req.Resource.Type == "jwk" {
		return r.matchJWK(req.Resource.Key, didDoc)
	}
	return false, nil, fmt.Errorf("resource type %s not yet supported for did:webvh", req.Resource.Type)
}

// matchJWK attempts to match a JWK from the request against verification methods in the DID document.
func (r *DIDWebVHRegistry) matchJWK(keyArray []interface{}, didDoc *DIDDocument) (bool, *VerificationMethod, error) {
	if len(keyArray) == 0 {
		return false, nil, fmt.Errorf("empty key array")
	}

	requestJWK, ok := keyArray[0].(map[string]interface{})
	if !ok {
		return false, nil, fmt.Errorf("invalid JWK format")
	}

	for i := range didDoc.VerificationMethod {
		vm := &didDoc.VerificationMethod[i]
		if vm.PublicKeyJwk == nil {
			continue
		}
		if registry.JWKsMatch(requestJWK, vm.PublicKeyJwk) {
			return true, vm, nil
		}
	}

	return false, nil, nil
}

// SupportedResourceTypes returns the resource types this registry can handle.
// checkPolicyConstraints validates DID policy constraints from request context.
// These constraints are injected by the policy mapper based on role (action.name).
func (r *DIDWebVHRegistry) checkPolicyConstraints(req *authzen.EvaluationRequest, didDoc *DIDDocument, baseDID string, startTime time.Time) *authzen.EvaluationResponse {
	if req.Context == nil {
		return nil
	}

	// Check allowed_domains: restrict DIDs to specific domains
	if allowedDomains := extractStringSliceFromContext(req.Context, "allowed_domains"); len(allowedDomains) > 0 {
		domain := extractDomainFromDIDWebVH(baseDID)
		if !matchesDomainPattern(domain, allowedDomains) {
			return &authzen.EvaluationResponse{
				Decision: false,
				Context: &authzen.EvaluationResponseContext{
					Reason: map[string]interface{}{
						"error":           "DID domain not in allowed domains for this role",
						"domain":          domain,
						"allowed_domains": allowedDomains,
						"resolution_ms":   time.Since(startTime).Milliseconds(),
					},
				},
			}
		}
	}

	// Check required_services: DID document must have specific service types
	if requiredServices := extractStringSliceFromContext(req.Context, "required_services"); len(requiredServices) > 0 {
		if !didDocHasRequiredServices(didDoc.Service, requiredServices) {
			return &authzen.EvaluationResponse{
				Decision: false,
				Context: &authzen.EvaluationResponseContext{
					Reason: map[string]interface{}{
						"error":             "DID document missing required services for this role",
						"required_services": requiredServices,
						"resolution_ms":     time.Since(startTime).Milliseconds(),
					},
				},
			}
		}
	}

	return nil
}

// extractStringSliceFromContext extracts a []string from a context map value.
func extractStringSliceFromContext(ctx map[string]interface{}, key string) []string {
	v, ok := ctx[key]
	if !ok {
		return nil
	}
	switch s := v.(type) {
	case []string:
		return s
	case []interface{}:
		result := make([]string, 0, len(s))
		for _, item := range s {
			if str, ok := item.(string); ok {
				result = append(result, str)
			}
		}
		return result
	}
	return nil
}

// extractDomainFromDIDWebVH extracts the domain from a did:webvh identifier.
// Format: did:webvh:<scid>:<domain>[:path...]
func extractDomainFromDIDWebVH(did string) string {
	if !strings.HasPrefix(did, "did:webvh:") {
		return ""
	}
	rest := strings.TrimPrefix(did, "did:webvh:")
	// Skip SCID (first component), domain is second
	parts := strings.SplitN(rest, ":", 3)
	if len(parts) < 2 {
		return ""
	}
	domain := parts[1]
	domain = strings.ReplaceAll(domain, "%3A", ":")
	domain = strings.ReplaceAll(domain, "%3a", ":")
	return domain
}

// matchesDomainPattern checks if a domain matches any of the allowed domains.
// Supports wildcards: "*.example.com" matches "sub.example.com".
func matchesDomainPattern(domain string, allowedDomains []string) bool {
	for _, allowed := range allowedDomains {
		if allowed == domain {
			return true
		}
		if strings.HasPrefix(allowed, "*.") {
			suffix := allowed[1:] // ".example.com"
			if strings.HasSuffix(domain, suffix) && domain != suffix[1:] {
				return true
			}
		}
	}
	return false
}

// didDocHasRequiredServices checks if the DID document services include all required service types.
func didDocHasRequiredServices(service interface{}, requiredTypes []string) bool {
	if service == nil {
		return false
	}

	services, ok := service.([]interface{})
	if !ok {
		return false
	}

	presentTypes := make(map[string]bool)
	for _, svc := range services {
		if svcMap, ok := svc.(map[string]interface{}); ok {
			if svcType, ok := svcMap["type"].(string); ok {
				presentTypes[svcType] = true
			}
		}
	}

	for _, required := range requiredTypes {
		if !presentTypes[required] {
			return false
		}
	}
	return true
}

func (r *DIDWebVHRegistry) SupportedResourceTypes() []string {
	return []string{"jwk"}
}

// SupportsResolutionOnly returns true for did:webvh registry.
func (r *DIDWebVHRegistry) SupportsResolutionOnly() bool {
	return true
}

// Info returns metadata about this registry.
func (r *DIDWebVHRegistry) Info() registry.RegistryInfo {
	return registry.RegistryInfo{
		Name:        "didwebvh-registry",
		Type:        "did:webvh",
		Description: r.description,
		Version:     "1.0.0",
		TrustAnchors: []string{
			"Self-certifying identifier (SCID) verification",
			"Verifiable history chain validation",
			"Data Integrity proof verification",
			"HTTPS/TLS certificate validation",
		},
	}
}

// Healthy returns true if the registry is operational.
func (r *DIDWebVHRegistry) Healthy() bool {
	return r.httpClient != nil
}

// Refresh is a no-op for did:webvh since DIDs are resolved on-demand.
func (r *DIDWebVHRegistry) Refresh(ctx context.Context) error {
	return nil
}

// SetHTTPClient sets a custom HTTP client for the registry.
func (r *DIDWebVHRegistry) SetHTTPClient(client *http.Client) {
	r.httpClient = client
}
