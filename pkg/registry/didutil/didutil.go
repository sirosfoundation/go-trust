// Package didutil provides DID validation and parsing utilities according to
// the W3C DID Core 1.0 specification (https://www.w3.org/TR/did-1.0/).
//
// This package reduces attack surface by:
//   - Validating DID syntax before processing
//   - Rejecting malformed or potentially malicious DIDs early
//   - Preventing injection attacks through method-specific-id manipulation
//
// DID Syntax (ABNF from W3C DID Core 1.0):
//
//	did                = "did:" method-name ":" method-specific-id
//	method-name        = 1*method-char
//	method-char        = %x61-7A / DIGIT  ; lowercase a-z / 0-9
//	method-specific-id = *( *idchar ":" ) 1*idchar
//	idchar             = ALPHA / DIGIT / "." / "-" / "_" / pct-encoded
//	pct-encoded        = "%" HEXDIG HEXDIG
package didutil

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"unicode"
)

// DID represents a parsed and validated Decentralized Identifier.
type DID struct {
	// Raw is the original DID string, validated but not normalized.
	Raw string

	// Method is the DID method name (e.g., "web", "webvh", "jwks", "key").
	Method string

	// MethodSpecificID is the method-specific identifier portion.
	MethodSpecificID string

	// Fragment is the optional fragment identifier (without the '#').
	Fragment string

	// Query is the optional query string (without the '?').
	Query string

	// Path is the optional path component (without the leading '/').
	Path string

	// PathSegments are the colon-separated parts of the method-specific-id.
	PathSegments []string
}

// ValidationError represents a DID validation error with details.
type ValidationError struct {
	DID     string
	Field   string
	Message string
}

func (e *ValidationError) Error() string {
	return fmt.Sprintf("invalid DID %q: %s: %s", e.DID, e.Field, e.Message)
}

// Regular expressions for DID validation based on W3C DID Core 1.0 ABNF
var (
	// Method name must be lowercase letters and digits only
	methodNameRegex = regexp.MustCompile(`^[a-z0-9]+$`)

	// idchar = ALPHA / DIGIT / "." / "-" / "_" / pct-encoded
	// pct-encoded = "%" HEXDIG HEXDIG
	// We validate that only these characters appear (after splitting on colons)
	idcharRegex = regexp.MustCompile(`^[A-Za-z0-9._-]*(%[0-9A-Fa-f]{2})*[A-Za-z0-9._-]*$`)

	// More permissive regex for the entire method-specific-id (allows colons as separators)
	methodSpecificIDRegex = regexp.MustCompile(`^[A-Za-z0-9._:-]*(%[0-9A-Fa-f]{2})*[A-Za-z0-9._:-]*$`)

	// Known safe DID methods that we support
	knownMethods = map[string]bool{
		"web":   true,
		"webvh": true,
		"jwks":  true,
		"key":   true,
	}
)

// Parse parses and validates a DID string according to W3C DID Core 1.0.
// Returns a validated DID struct or an error if the DID is invalid.
//
// This function should be called early in request processing to reject
// malformed DIDs before any network requests or database operations.
func Parse(did string) (*DID, error) {
	if did == "" {
		return nil, &ValidationError{DID: did, Field: "did", Message: "empty DID string"}
	}

	// Check maximum length (reasonable limit to prevent DoS)
	const maxDIDLength = 2048
	if len(did) > maxDIDLength {
		return nil, &ValidationError{DID: did[:100] + "...", Field: "length", Message: fmt.Sprintf("DID exceeds maximum length of %d", maxDIDLength)}
	}

	// Extract fragment if present
	var fragment string
	if idx := strings.Index(did, "#"); idx != -1 {
		fragment = did[idx+1:]
		did = did[:idx]
	}

	// Extract query if present
	var query string
	if idx := strings.Index(did, "?"); idx != -1 {
		query = did[idx+1:]
		did = did[:idx]
	}

	// Extract path if present (DID URL path starts with '/')
	var path string
	if idx := strings.Index(did, "/"); idx != -1 {
		path = did[idx+1:]
		did = did[:idx]
	}

	// Must start with "did:"
	if !strings.HasPrefix(did, "did:") {
		return nil, &ValidationError{DID: did, Field: "scheme", Message: "DID must start with 'did:'"}
	}

	// Split into components
	parts := strings.SplitN(did, ":", 3)
	if len(parts) < 3 {
		return nil, &ValidationError{DID: did, Field: "structure", Message: "DID must have format 'did:method:method-specific-id'"}
	}

	method := parts[1]
	methodSpecificID := parts[2]

	// Validate method name
	if err := validateMethodName(method); err != nil {
		return nil, &ValidationError{DID: did, Field: "method", Message: err.Error()}
	}

	// Validate method-specific-id
	if err := validateMethodSpecificID(methodSpecificID); err != nil {
		return nil, &ValidationError{DID: did, Field: "method-specific-id", Message: err.Error()}
	}

	// Validate fragment if present
	if fragment != "" {
		if err := validateFragment(fragment); err != nil {
			return nil, &ValidationError{DID: did, Field: "fragment", Message: err.Error()}
		}
	}

	// Parse method-specific-id segments (colon-separated, handling percent-encoded colons)
	segments := parseMethodSpecificSegments(methodSpecificID)

	return &DID{
		Raw:              did,
		Method:           method,
		MethodSpecificID: methodSpecificID,
		Fragment:         fragment,
		Query:            query,
		Path:             path,
		PathSegments:     segments,
	}, nil
}

// ParseWithMethod parses a DID and validates that it uses the expected method.
func ParseWithMethod(did, expectedMethod string) (*DID, error) {
	parsed, err := Parse(did)
	if err != nil {
		return nil, err
	}

	if parsed.Method != expectedMethod {
		return nil, &ValidationError{
			DID:     did,
			Field:   "method",
			Message: fmt.Sprintf("expected method %q, got %q", expectedMethod, parsed.Method),
		}
	}

	return parsed, nil
}

// Validate checks if a DID string is valid according to W3C DID Core 1.0.
// Returns nil if valid, or a ValidationError if invalid.
func Validate(did string) error {
	_, err := Parse(did)
	return err
}

// IsKnownMethod returns true if the method is one of the known DID methods
// supported by this library.
func IsKnownMethod(method string) bool {
	return knownMethods[method]
}

// validateMethodName validates the DID method name according to spec.
// Method name must be 1 or more lowercase letters (a-z) and digits (0-9).
func validateMethodName(method string) error {
	if method == "" {
		return fmt.Errorf("method name cannot be empty")
	}

	if !methodNameRegex.MatchString(method) {
		return fmt.Errorf("method name must contain only lowercase letters (a-z) and digits (0-9), got %q", method)
	}

	return nil
}

// validateMethodSpecificID validates the method-specific identifier.
// It must conform to the idchar production with colons as separators.
func validateMethodSpecificID(msid string) error {
	if msid == "" {
		return fmt.Errorf("method-specific-id cannot be empty")
	}

	// Check for dangerous patterns
	if err := checkDangerousPatterns(msid); err != nil {
		return err
	}

	// Validate overall structure
	if !methodSpecificIDRegex.MatchString(msid) {
		return fmt.Errorf("method-specific-id contains invalid characters")
	}

	// Validate each segment individually
	segments := strings.Split(msid, ":")
	for i, seg := range segments {
		// Empty segments in the middle are not allowed
		if seg == "" && i > 0 && i < len(segments)-1 {
			return fmt.Errorf("empty segment in method-specific-id at position %d", i)
		}

		// Validate percent-encoding
		if err := validatePercentEncoding(seg); err != nil {
			return fmt.Errorf("invalid percent-encoding in segment %d: %w", i, err)
		}
	}

	return nil
}

// validateFragment validates the fragment identifier.
func validateFragment(fragment string) error {
	if fragment == "" {
		return nil // Empty fragment is allowed (but unusual)
	}

	// Fragment can contain idchar plus "/" and "?"
	for i, r := range fragment {
		if !isFragmentChar(r) {
			return fmt.Errorf("invalid character %q at position %d in fragment", r, i)
		}
	}

	return nil
}

// isFragmentChar checks if a rune is valid in a fragment.
func isFragmentChar(r rune) bool {
	// idchar plus "/" and "?"
	return unicode.IsLetter(r) || unicode.IsDigit(r) ||
		r == '.' || r == '-' || r == '_' || r == '/' || r == '?' ||
		r == '%' || r == ':' || r == '@' || r == '!' || r == '$' ||
		r == '&' || r == '\'' || r == '(' || r == ')' || r == '*' ||
		r == '+' || r == ',' || r == ';' || r == '='
}

// validatePercentEncoding checks that percent-encoding is valid.
func validatePercentEncoding(s string) error {
	for i := 0; i < len(s); i++ {
		if s[i] == '%' {
			if i+2 >= len(s) {
				return fmt.Errorf("incomplete percent-encoding at position %d", i)
			}
			if !isHexDigit(s[i+1]) || !isHexDigit(s[i+2]) {
				return fmt.Errorf("invalid hex digits in percent-encoding at position %d", i)
			}
			i += 2
		}
	}
	return nil
}

// isHexDigit checks if a byte is a valid hexadecimal digit.
func isHexDigit(b byte) bool {
	return (b >= '0' && b <= '9') || (b >= 'A' && b <= 'F') || (b >= 'a' && b <= 'f')
}

// checkDangerousPatterns checks for patterns that could indicate injection attacks.
func checkDangerousPatterns(msid string) error {
	// Decode percent-encoding for inspection
	decoded, err := url.QueryUnescape(msid)
	if err != nil {
		return fmt.Errorf("invalid percent-encoding: %w", err)
	}

	// Check for path traversal attempts
	if strings.Contains(decoded, "..") {
		return fmt.Errorf("path traversal pattern '..' not allowed")
	}

	// Check for null bytes
	if strings.ContainsRune(decoded, 0) {
		return fmt.Errorf("null bytes not allowed")
	}

	// Check for newlines (HTTP header injection)
	if strings.ContainsAny(decoded, "\r\n") {
		return fmt.Errorf("newline characters not allowed")
	}

	// Check for common shell metacharacters
	shellChars := "`$|;&<>"
	for _, char := range shellChars {
		if strings.ContainsRune(decoded, char) {
			return fmt.Errorf("shell metacharacter %q not allowed", char)
		}
	}

	return nil
}

// parseMethodSpecificSegments splits the method-specific-id on colons,
// handling percent-encoded colons (%3A) as literal colons within segments.
func parseMethodSpecificSegments(msid string) []string {
	// Replace %3A with a placeholder
	placeholder := "\x00PORT\x00"
	msid = strings.ReplaceAll(msid, "%3A", placeholder)
	msid = strings.ReplaceAll(msid, "%3a", placeholder)

	// Split on remaining colons
	segments := strings.Split(msid, ":")

	// Restore colons in each segment
	for i, seg := range segments {
		segments[i] = strings.ReplaceAll(seg, placeholder, ":")
	}

	return segments
}

// WithFragment returns the DID string with a fragment appended.
func (d *DID) WithFragment(fragment string) string {
	if fragment == "" {
		return d.String()
	}
	return d.String() + "#" + fragment
}

// String returns the canonical DID string (without fragment, query, or path).
func (d *DID) String() string {
	return fmt.Sprintf("did:%s:%s", d.Method, d.MethodSpecificID)
}

// FullString returns the complete DID URL including path, query, and fragment.
func (d *DID) FullString() string {
	result := d.String()
	if d.Path != "" {
		result += "/" + d.Path
	}
	if d.Query != "" {
		result += "?" + d.Query
	}
	if d.Fragment != "" {
		result += "#" + d.Fragment
	}
	return result
}

// Domain extracts the domain portion from method-specific-id.
// This is typically the first segment for did:web, did:webvh, and did:jwks methods.
// Returns the domain with any percent-encoded ports decoded.
func (d *DID) Domain() string {
	if len(d.PathSegments) == 0 {
		return ""
	}

	domain := d.PathSegments[0]

	// For did:webvh, the first segment is the SCID, domain is the second
	if d.Method == "webvh" && len(d.PathSegments) > 1 {
		domain = d.PathSegments[1]
	}

	// Decode percent-encoded port colon
	domain = strings.ReplaceAll(domain, "%3A", ":")
	domain = strings.ReplaceAll(domain, "%3a", ":")

	return domain
}

// PathFromSegments returns the path portion from method-specific-id segments.
// This joins segments after the domain with "/" for URL construction.
func (d *DID) PathFromSegments() string {
	startIdx := 1
	if d.Method == "webvh" {
		startIdx = 2 // Skip SCID and domain
	}

	if len(d.PathSegments) <= startIdx {
		return ""
	}

	pathParts := make([]string, 0, len(d.PathSegments)-startIdx)
	for _, seg := range d.PathSegments[startIdx:] {
		if seg != "" {
			// Decode any percent-encoded values in path segments
			decoded, err := url.QueryUnescape(seg)
			if err == nil {
				pathParts = append(pathParts, decoded)
			} else {
				pathParts = append(pathParts, seg)
			}
		}
	}

	return strings.Join(pathParts, "/")
}

// SCID extracts the Self-Certifying Identifier for did:webvh method.
// Returns empty string for other DID methods.
func (d *DID) SCID() string {
	if d.Method != "webvh" || len(d.PathSegments) == 0 {
		return ""
	}
	return d.PathSegments[0]
}

// ToHTTPURL converts the DID to an HTTPS URL for resolution.
// This handles the conversion logic for did:web, did:webvh, and did:jwks methods.
func (d *DID) ToHTTPURL(scheme, filename string) (string, error) {
	domain := d.Domain()
	if domain == "" {
		return "", fmt.Errorf("cannot extract domain from DID")
	}

	path := d.PathFromSegments()

	var urlStr string
	if path == "" {
		urlStr = fmt.Sprintf("%s://%s/.well-known/%s", scheme, domain, filename)
	} else {
		urlStr = fmt.Sprintf("%s://%s/%s/%s", scheme, domain, path, filename)
	}

	// Validate the constructed URL
	if _, err := url.Parse(urlStr); err != nil {
		return "", fmt.Errorf("constructed URL is invalid: %w", err)
	}

	return urlStr, nil
}
