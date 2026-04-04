# ADR 0012: SSRF Mitigation Strategy

## Status

Proposed

## Date

2026-04-04

## Context

GitHub CodeQL has flagged 5 critical SSRF (Server-Side Request Forgery) vulnerabilities in the go-trust codebase:

| Alert | File | Line | Description |
|-------|------|------|-------------|
| #1 | `pkg/registry/didweb/didweb_registry.go` | 308 | Uncontrolled data used in network request |
| #2 | `pkg/registry/didwebvh/didwebvh_registry.go` | 400 | Uncontrolled data used in network request |
| #3 | `pkg/registry/mdociaca/registry.go` | 382 | Uncontrolled data used in network request |
| #4 | `pkg/registry/didjwks/didjwks_registry.go` | 343 | Uncontrolled data used in network request |
| #5 | `pkg/registry/didjwks/didjwks_registry.go` | 378 | Uncontrolled data used in network request |

All alerts are in registry implementations that resolve trust information from DID identifiers, JWKS endpoints, or OIDC discovery documents. These protocols **inherently require** making HTTP requests to URLs derived from the identifiers being resolved.

### Current Mitigations

The codebase already implements several protections:
- ✅ **Response body size limits** via `ReadLimitedBody()` (10 MB default)
- ✅ **HTTPS enforcement** by default (`allowHTTP` is testing-only)
- ✅ **Request timeouts** (30 seconds default)
- ✅ **TLS 1.2+ with strong cipher suites**

### Missing Mitigations

- ❌ **Private IP address blocking** (RFC 1918, RFC 4193, link-local)
- ❌ **Localhost/loopback blocking** (127.0.0.0/8, ::1)
- ❌ **DNS rebinding protection**
- ❌ **Allowlist-based URL restriction** (optional but recommended)

## Decision

Implement a layered SSRF mitigation strategy:

### 1. Create a Safe HTTP Client

Add a new `SafeHTTPClient` in `pkg/registry/safeclient.go` that wraps `http.Client` with SSRF protections:

```go
package registry

import (
    "context"
    "fmt"
    "net"
    "net/http"
    "net/url"
    "strings"
    "time"
)

// SafeClientConfig configures SSRF protection for HTTP clients.
type SafeClientConfig struct {
    // AllowPrivateIPs permits requests to private/internal networks.
    // Default: false (private IPs blocked)
    AllowPrivateIPs bool

    // AllowedHosts restricts requests to specific hostnames.
    // Empty means all hosts are allowed (after other checks).
    AllowedHosts []string

    // AllowHTTP permits non-TLS connections.
    // Default: false (HTTPS required)
    AllowHTTP bool

    // Timeout for HTTP requests.
    Timeout time.Duration
}

// SafeHTTPClient wraps http.Client with SSRF protections.
type SafeHTTPClient struct {
    client        *http.Client
    config        SafeClientConfig
    allowedHosts  map[string]bool
}

// NewSafeHTTPClient creates an HTTP client with SSRF protections.
func NewSafeHTTPClient(config SafeClientConfig) *SafeHTTPClient {
    allowedHosts := make(map[string]bool)
    for _, h := range config.AllowedHosts {
        allowedHosts[strings.ToLower(h)] = true
    }

    timeout := config.Timeout
    if timeout == 0 {
        timeout = 30 * time.Second
    }

    // Create a custom dialer that validates IP addresses
    dialer := &net.Dialer{
        Timeout:   10 * time.Second,
        KeepAlive: 30 * time.Second,
    }

    transport := &http.Transport{
        DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
            host, port, err := net.SplitHostPort(addr)
            if err != nil {
                return nil, fmt.Errorf("invalid address: %w", err)
            }

            // Resolve DNS first to check the actual IP
            ips, err := net.DefaultResolver.LookupIP(ctx, "ip", host)
            if err != nil {
                return nil, fmt.Errorf("DNS lookup failed: %w", err)
            }

            // Check all resolved IPs
            if !config.AllowPrivateIPs {
                for _, ip := range ips {
                    if isPrivateIP(ip) {
                        return nil, fmt.Errorf("SSRF protection: refusing connection to private IP %s", ip)
                    }
                }
            }

            // Connect using the first resolved IP
            return dialer.DialContext(ctx, network, net.JoinHostPort(ips[0].String(), port))
        },
        TLSHandshakeTimeout: 10 * time.Second,
    }

    return &SafeHTTPClient{
        client: &http.Client{
            Timeout:   timeout,
            Transport: transport,
        },
        config:       config,
        allowedHosts: allowedHosts,
    }
}

// Do executes an HTTP request with SSRF validation.
func (c *SafeHTTPClient) Do(req *http.Request) (*http.Response, error) {
    if err := c.validateRequest(req); err != nil {
        return nil, fmt.Errorf("SSRF validation failed: %w", err)
    }
    return c.client.Do(req)
}

func (c *SafeHTTPClient) validateRequest(req *http.Request) error {
    u := req.URL

    // Scheme validation
    if !c.config.AllowHTTP && u.Scheme != "https" {
        return fmt.Errorf("HTTPS required, got %s", u.Scheme)
    }
    if u.Scheme != "http" && u.Scheme != "https" {
        return fmt.Errorf("unsupported scheme: %s", u.Scheme)
    }

    // Host allowlist check
    if len(c.allowedHosts) > 0 {
        host := strings.ToLower(u.Hostname())
        if !c.allowedHosts[host] {
            return fmt.Errorf("host %s not in allowlist", host)
        }
    }

    return nil
}

// isPrivateIP checks if an IP is private/internal/localhost.
func isPrivateIP(ip net.IP) bool {
    if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || 
       ip.IsLinkLocalMulticast() || ip.IsUnspecified() {
        return true
    }
    
    // Additional checks for cloud metadata endpoints
    // AWS: 169.254.169.254
    // GCP: metadata.google.internal resolves to 169.254.169.254
    // Azure: 169.254.169.254
    if ip.Equal(net.ParseIP("169.254.169.254")) {
        return true
    }

    return false
}
```

### 2. Annotate Intentional SSRF Cases

For cases where fetching from user-controlled URLs is the intended behavior (which is ALL our cases), add CodeQL suppression comments:

```go
// SSRF is intentional: DID resolution requires fetching from the derived URL.
// Mitigated by: HTTPS enforcement, private IP blocking, timeouts, response size limits.
resp, err := r.httpClient.Do(req) // lgtm[go/request-forgery]
```

Or use a `.github/codeql/codeql-config.yml` to suppress specific paths:

```yaml
query-filters:
  - exclude:
      id: go/request-forgery
      paths:
        - pkg/registry/did*/**
        - pkg/registry/mdociaca/**
```

### 3. Migration Path

1. **Phase 1**: Create `SafeHTTPClient` with private IP blocking
2. **Phase 2**: Migrate all registry implementations to use `SafeHTTPClient`
3. **Phase 3**: Add optional host allowlisting in configuration
4. **Phase 4**: Add suppression comments or CodeQL config for remaining alerts

## Implementation

### File Changes Required

| File | Change |
|------|--------|
| `pkg/registry/safeclient.go` | New file with `SafeHTTPClient` |
| `pkg/registry/safeclient_test.go` | Tests for SSRF protection |
| `pkg/registry/didweb/didweb_registry.go` | Use `SafeHTTPClient` |
| `pkg/registry/didwebvh/didwebvh_registry.go` | Use `SafeHTTPClient` |
| `pkg/registry/didjwks/didjwks_registry.go` | Use `SafeHTTPClient` |
| `pkg/registry/mdociaca/registry.go` | Use `SafeHTTPClient` |

### Configuration Extension

Add to registry configs:

```go
// SafeClientOptions configures SSRF protection (optional).
type SafeClientOptions struct {
    // AllowPrivateIPs permits requests to RFC1918/private addresses.
    // Use only in controlled environments (e.g., testing).
    AllowPrivateIPs bool `json:"allow_private_ips,omitempty"`
    
    // AllowedHosts restricts resolution to specific domains.
    // Empty means all public hosts are allowed.
    AllowedHosts []string `json:"allowed_hosts,omitempty"`
}
```

## Consequences

### Positive

- Addresses all 5 CodeQL critical alerts with defense-in-depth
- Protects against SSRF attacks targeting internal infrastructure
- Block cloud metadata endpoint attacks (AWS/GCP/Azure credential theft)
- Enables optional allowlisting for high-security deployments
- Maintains protocol compliance (DID resolution still works)

### Negative

- Additional complexity in HTTP handling
- Slight performance overhead (DNS resolution + IP validation)
- May require configuration changes for deployments using private registries

### Risks

- Legitimate private network registries will be blocked by default (mitigated by `AllowPrivateIPs` option)
- DNS rebinding attacks have a small window between validation and connection (mitigated by direct IP connection after validation)

## Alternatives Considered

### 1. Suppress all alerts without mitigation

**Rejected**: While the alerts are "expected" for these protocols, actual SSRF protection is valuable.

### 2. External proxy/gateway for all outbound requests

**Rejected**: Adds operational complexity; defense-in-depth in code is more maintainable.

### 3. Static allowlisting only

**Rejected**: Too restrictive for DID methods that resolve arbitrary identifiers.

## References

- [CWE-918: Server-Side Request Forgery (SSRF)](https://cwe.mitre.org/data/definitions/918.html)
- [OWASP SSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html)
- [CodeQL go/request-forgery](https://codeql.github.com/codeql-query-help/go/go-request-forgery/)
- RFC 1918 (Private IPv4 Address Allocation)
- RFC 4193 (Unique Local IPv6 Unicast Addresses)
