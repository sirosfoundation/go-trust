# DID Validation and Sanitization Proposal

## Summary

This document proposes integrating the new `didutil` package into go-trust's DID registry implementations to validate and sanitize incoming DIDs according to the [W3C DID Core 1.0 specification](https://www.w3.org/TR/did-1.0/), thereby reducing the attack surface from user-controlled input.

## Problem Statement

Currently, DID parsing in go-trust registries uses simple string manipulation without comprehensive validation:

```go
// Current approach in didweb_registry.go
if !strings.HasPrefix(did, "did:web:") {
    return "", fmt.Errorf("not a did:web identifier")
}
methodSpecificID := strings.TrimPrefix(did, "did:web:")
```

This approach has several security concerns:

1. **No validation of method name** - DIDs with uppercase or special characters in method names pass through
2. **No validation of method-specific-id** - Arbitrary characters including injection payloads are accepted
3. **No defense against path traversal** - `did:web:example.com:..:..:etc:passwd` is accepted
4. **No protection against injection attacks** - Shell metacharacters, null bytes, newlines pass through
5. **No length limits** - Extremely long DIDs could cause DoS

## Proposed Solution

A new `didutil` package has been created at `pkg/registry/didutil/` that provides:

### 1. Strict DID Validation per W3C Spec

```
did                = "did:" method-name ":" method-specific-id
method-name        = 1*method-char
method-char        = %x61-7A / DIGIT  ; lowercase a-z / 0-9
method-specific-id = *( *idchar ":" ) 1*idchar
idchar             = ALPHA / DIGIT / "." / "-" / "_" / pct-encoded
```

### 2. Security Checks

The validator checks for:

| Check | Protection Against |
|-------|-------------------|
| Method name validation | Only lowercase a-z and digits 0-9 |
| Max length (2048) | DoS via extremely long DIDs |
| Path traversal (`..`) | Directory traversal attacks |
| Null bytes (`%00`) | C string termination attacks |
| Newlines (`%0d%0a`) | HTTP header injection |
| Shell metacharacters | Command injection (`$`, `` ` ``, `\|`, `;`, `&`, `<`, `>`) |
| Percent-encoding validation | Malformed URL encoding |

### 3. API

```go
// Parse and validate a DID
parsed, err := didutil.Parse("did:web:example.com:users:alice#key-1")
if err != nil {
    // Handle validation error (e.g., return 400 Bad Request)
    return err
}

// Access validated components
parsed.Method           // "web"
parsed.MethodSpecificID // "example.com:users:alice"
parsed.Fragment         // "key-1"
parsed.Domain()         // "example.com"
parsed.PathFromSegments() // "users/alice"

// Convert to HTTP URL for resolution
url, err := parsed.ToHTTPURL("https", "did.json")
// "https://example.com/users/alice/did.json"
```

## Integration Plan

### Phase 1: Add didutil.Parse() at Entry Points

Each registry's `Evaluate()` method should validate the DID early:

```go
// Before (didweb_registry.go)
func (r *DIDWebRegistry) Evaluate(ctx context.Context, req *authzen.EvaluationRequest) (*authzen.EvaluationResponse, error) {
    if !strings.HasPrefix(req.Subject.ID, "did:web:") {
        // ...
    }
    // ...
}

// After
func (r *DIDWebRegistry) Evaluate(ctx context.Context, req *authzen.EvaluationRequest) (*authzen.EvaluationResponse, error) {
    parsed, err := didutil.ParseWithMethod(req.Subject.ID, "web")
    if err != nil {
        return &authzen.EvaluationResponse{
            Decision: false,
            Context: &authzen.EvaluationResponseContext{
                Reason: map[string]interface{}{
                    "error": fmt.Sprintf("invalid DID: %v", err),
                },
            },
        }, nil
    }
    // Use parsed.Domain(), parsed.PathFromSegments(), etc.
    // ...
}
```

### Phase 2: Replace String Manipulation with DID Methods

Replace manual string manipulation with validated `DID` methods:

```go
// Before
methodSpecificID := strings.TrimPrefix(did, "did:web:")
methodSpecificID = strings.ReplaceAll(methodSpecificID, "%3A", "___PORT___")
parts := strings.Split(methodSpecificID, ":")
domain := strings.ReplaceAll(parts[0], "___PORT___", ":")

// After
parsed, _ := didutil.ParseWithMethod(did, "web")
domain := parsed.Domain()
path := parsed.PathFromSegments()
url, _ := parsed.ToHTTPURL("https", "did.json")
```

### Phase 3: Add Method-Specific Validators (Optional)

For methods with specific requirements (e.g., did:webvh SCID format), add method-specific validators:

```go
// In didutil package
func ValidateWebVHSCID(scid string) error {
    // Validate base58btc encoding, minimum length, etc.
}
```

## Files to Modify

| File | Changes Needed |
|------|----------------|
| `pkg/registry/didweb/didweb_registry.go` | Add `didutil.ParseWithMethod()` in `Evaluate()`, replace `didToHTTPURL()` |
| `pkg/registry/didwebvh/didwebvh_registry.go` | Add `didutil.ParseWithMethod()` in `Evaluate()`, use parsed SCID/domain |
| `pkg/registry/didjwks/didjwks_registry.go` | Add `didutil.ParseWithMethod()` in `Evaluate()`, replace `parseDID()` |
| `pkg/registry/did/resolver.go` | Add `didutil.Parse()` in generic resolver |

## Security Benefits

1. **Defense in Depth**: DID validation adds another layer before SSRF protections
2. **Early Rejection**: Invalid DIDs are rejected before any network requests
3. **Injection Prevention**: Shell, HTTP header, and path traversal attacks are blocked
4. **Standardization**: All registries use the same validation logic
5. **Audit Trail**: Validation errors are clearly logged with context

## Backwards Compatibility

- Valid DIDs per W3C spec will continue to work unchanged
- Some edge cases with non-standard characters will now be rejected (security improvement)
- Error messages are improved with specific validation context

## Testing

The `didutil` package includes comprehensive tests covering:
- Valid DIDs for all supported methods (web, webvh, jwks, key)
- Invalid DIDs with various attack payloads
- Fragment/query/path handling
- Domain and path extraction
- URL construction

Run tests with:
```bash
go test -v ./pkg/registry/didutil/...
```

## References

- [W3C DID Core 1.0 Specification](https://www.w3.org/TR/did-1.0/)
- [DID Syntax ABNF](https://www.w3.org/TR/did-1.0/#did-syntax)
- [OWASP Input Validation Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html)
- [ADR 0012: SSRF Mitigation](../adr/0012-ssrf-mitigation.md)
