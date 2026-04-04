# Go-Trust

<div align="center">

[![CI](https://github.com/sirosfoundation/go-trust/actions/workflows/go.yml/badge.svg)](https://github.com/sirosfoundation/go-trust/actions/workflows/go.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/sirosfoundation/go-trust.svg)](https://pkg.go.dev/github.com/sirosfoundation/go-trust)
[![Go Report Card](https://goreportcard.com/badge/github.com/sirosfoundation/go-trust)](https://goreportcard.com/report/github.com/sirosfoundation/go-trust)
[![Coverage](https://raw.githubusercontent.com/sirosfoundation/go-trust/badges/.badges/main/coverage.svg)](https://github.com/sirosfoundation/go-trust/actions/workflows/go.yml)
[![Go Version](https://img.shields.io/github/go-mod/go-version/sirosfoundation/go-trust)](https://go.dev/)
[![Issues](https://img.shields.io/github/issues/sirosfoundation/go-trust)](https://github.com/sirosfoundation/go-trust/issues)
[![License](https://img.shields.io/badge/License-BSD_2--Clause-orange.svg)](LICENSE)

</div>

## Overview

Go-Trust is a multi-framework AuthZEN Trust Decision Point (PDP) server. It evaluates trust decisions across multiple trust registries including ETSI TS 119 612 Trust Status Lists (TSLs), ETSI TS 119 602 Lists of Trusted Entities (LoTEs), OpenID Federation, and DID Web.

Go-Trust is designed to run inside the same trust domain as the entity that relies on trust evaluation (for instance a wallet unit or an issuer). It promotes interoperability across implementations that rely on ETSI trust status lists such as the EUDI wallet.

> **Note:** For TSL and LoTE processing (load, transform, convert, sign, publish), use `tsl-tool` from [g119612](https://github.com/sirosfoundation/g119612). Go-trust consumes pre-processed TSL/LoTE data.

## Features

- **AuthZEN Compliant**: Implements the OASIS AuthZEN Trust Registry Profile for policy decisions
- **Multi-Registry Architecture**: Parallel evaluation across ETSI TSL, ETSI LoTE, OpenID Federation, and DID Web
- **Flexible Resolution Strategies**: First-match, all-registries, best-match, or sequential
- **Circuit Breaking**: Graceful handling of registry failures
- **Rate Limiting**: Per-IP rate limiting for API protection
- **Prometheus Metrics**: Comprehensive observability support
- **Kubernetes Native**: Liveness and readiness probes, ConfigMap support
- **Test Server**: Embedded test server for integration testing
- **High Quality**: >80% test coverage, comprehensive linting, security scanning

## Quick Start

### Installation

```bash
# Clone and build
git clone https://github.com/sirosfoundation/go-trust.git
cd go-trust
make build

# Or install directly
go install github.com/sirosfoundation/go-trust/cmd/gt@latest
```

### Running the Server

```bash
# With a PEM certificate bundle (recommended for production)
gt --etsi-cert-bundle /path/to/trusted-certs.pem

# With TSL XML files directly
gt --etsi-tsl-files eu-lotl.xml,se-tsl.xml

# With whitelist registry (for simple deployments)
gt --registry whitelist --whitelist /etc/go-trust/whitelist.yaml

# With always-trusted registry (development/testing only!)
gt --registry always-trusted

# With configuration file
gt --config /etc/go-trust/config.yaml

# With external URL for discovery (behind reverse proxy)
gt --external-url https://pdp.example.com --etsi-cert-bundle certs.pem

# Full configuration
gt \
  --host 0.0.0.0 \
  --port 6001 \
  --etsi-cert-bundle /etc/go-trust/trusted-certs.pem \
  --external-url https://pdp.example.com \
  --log-level info \
  --log-format json
```

### Command-Line Options

| Option | Description | Default |
|--------|-------------|---------|
| `--host` | Listen address | `127.0.0.1` |
| `--port` | Listen port | `6001` |
| `--external-url` | External URL for discovery | auto-detect |
| `--etsi-cert-bundle` | PEM file with trusted CA certs | - |
| `--etsi-tsl-files` | Comma-separated TSL XML files | - |
| `--registry` | Registry type: whitelist, always-trusted, never-trusted | - |
| `--whitelist` | Path to whitelist YAML/JSON config file | - |
| `--whitelist-watch` | Watch whitelist file for changes | `true` |
| `--log-level` | Log level: debug, info, warn, error | `info` |
| `--log-format` | Log format: text, json | `text` |
| `--config` | Configuration file (YAML) | - |

Environment variable: `GO_TRUST_EXTERNAL_URL` for external URL.

## API Endpoints

| Endpoint | Description |
|----------|-------------|
| `POST /evaluation` | AuthZEN trust evaluation |
| `GET /.well-known/authzen-configuration` | PDP discovery document |
| `GET /healthz` | Kubernetes liveness probe |
| `GET /readyz` | Kubernetes readiness probe (503 until TSLs loaded) |
| `GET /readyz?verbose=true` | Readiness with detailed TSL info |
| `GET /metrics` | Prometheus metrics |
| `GET /tsls` | List loaded Trust Status Lists |

### AuthZEN Evaluation Request

```json
{
  "subject": {
    "type": "key",
    "id": "https://issuer.example.com"
  },
  "resource": {
    "type": "x5c",
    "id": "https://issuer.example.com",
    "key": ["MIIDQjCCAiqgAwIBAgIUJlq+zz4..."]
  },
  "action": {
    "name": "credential-issuer"
  }
}
```

### AuthZEN Evaluation Response

```json
{
  "decision": true,
  "context": {
    "reason": {
      "registry": "etsi-tsl",
      "resolution_ms": 12,
      "service_type": "http://uri.etsi.org/TrstSvc/Svctype/CA/QC"
    }
  }
}
```

## Architecture

### Multi-Registry Design

Go-Trust implements a flexible multi-registry architecture that allows multiple trust frameworks to be queried simultaneously.

```
┌─────────────────┐     ┌─────────────────┐
│  AuthZEN Client │────▶│   Go-Trust PDP  │
└─────────────────┘     └────────┬────────┘
                                 │
    ┌────────────┬───────────────┼───────────────┬────────────┐
    ▼            ▼               ▼               ▼            ▼
┌────────┐ ┌────────┐   ┌─────────────┐ ┌───────────┐ ┌──────────┐
│  ETSI  │ │  ETSI  │   │  OpenID Fed │ │  DID Web  │ │   mDOC   │
│  TSL   │ │  LoTE  │   │  Registry   │ │  Registry │ │   IACA   │
└────────┘ └────────┘   └─────────────┘ └───────────┘ └──────────┘
```

### TrustRegistry Interface

All trust registries implement the same interface:

```go
type TrustRegistry interface {
    Evaluate(ctx context.Context, req *authzen.EvaluationRequest) (*authzen.EvaluationResponse, error)
    SupportedResourceTypes() []string
    Info() RegistryInfo
    Healthy() bool
    Refresh(ctx context.Context) error
}
```

### Resolution Strategies

| Strategy | Description |
|----------|-------------|
| `FirstMatch` | Returns as soon as any registry returns `decision=true` |
| `AllRegistries` | Queries all registries and aggregates results |
| `BestMatch` | Returns the result with highest confidence |
| `Sequential` | Tries registries in order until one succeeds |

### Supported Registry Types

#### ETSI TSL Registry

Evaluates X.509 certificates against ETSI TS 119 612 Trust Status Lists.

**Input sources:**
- `--etsi-cert-bundle`: PEM file with trusted CA certificates (processed by tsl-tool)
- `--etsi-tsl-files`: Raw TSL XML files

**Supported resource types:** `x5c`, `jwk`, `x509_san_dns`

**Configuration options (in YAML config file):**
- `lotl_signer_bundle`: PEM file containing trusted LOTL signer certificates for signature validation
- `require_signature`: When true, TSLs must have valid signatures (requires `lotl_signer_bundle`)

#### OpenID Federation Registry

Evaluates trust chains in OpenID Federation ecosystems.

**Supported resource types:** `entity`, `openid_federation`

#### DID Web Registry

Resolves and validates DID Web identifiers per W3C DID specification.

**DID Web URL Mapping:**
- `did:web:example.com` → `https://example.com/.well-known/did.json`
- `did:web:example.com:users:alice` → `https://example.com/users/alice/did.json`
- `did:web:example.com%3A3000` → `https://example.com:3000/.well-known/did.json`

**Supported resource types:** `key`, `jwk`

#### DID Web VH Registry

Resolves and validates DID Web VH (Verifiable History) identifiers with cryptographic integrity verification.

**Features:**
- Full DID:web:vh resolution per spec
- Cryptographic chain verification
- Version history traversal
- Pre-rotation key support

**Supported resource types:** `did_document`, `jwk`, `verification_method`

#### mDOC IACA Registry

Dynamically validates mDOC/mDL X.509 certificate chains against IACA (Issuing Authority Certificate Authority) certificates fetched from OpenID4VCI issuers.

**Architecture:**
1. Receives trust evaluation with issuer URL (`subject.id`) and X5C chain (`resource.key`)
2. Fetches issuer's OpenID4VCI metadata (discovers `mdoc_iacas_uri` endpoint)
3. Fetches IACA certificates from `mdoc_iacas_uri`
4. Validates X5C chain against fetched IACAs
5. Optionally enforces issuer allowlist

**Supported resource types:** `x5c`

```go
import "github.com/sirosfoundation/go-trust/pkg/registry/mdociaca"

reg, err := mdociaca.New(&mdociaca.Config{
    Name:            "mdoc-iaca",
    IssuerAllowlist: []string{"https://issuer.example.com"},  // Optional
    CacheTTL:        time.Hour,
})

// Evaluate trust for an mDOC issuer
req := &authzen.EvaluationRequest{
    Subject:  authzen.Subject{Type: "key", ID: "https://issuer.example.com"},
    Resource: authzen.Resource{Type: "x5c", Key: []interface{}{dsB64, iacaB64}},
}
resp, err := reg.Evaluate(ctx, req)
```

**Use cases:**
- Mobile driving license (mDL) issuer validation
- EUDI wallet mDOC credential issuance
- Any OpenID4VCI issuer publishing IACA certificates

#### LoTE Registry (ETSI TS 119 602)

Evaluates trust from ETSI TS 119 602 Lists of Trusted Entities (LoTE) — the JSON-based successor to XML Trust Status Lists. LoTE documents list trusted entities with their digital identities (X.509 certificates, JWK keys, or DIDs) and service descriptions.

**Features:**
- Loads LoTE JSON from URLs or local files
- Indexes entities by ID and digital identity fingerprint
- X.509 PKIX path validation against entity certificates
- JWK key matching via SHA-256 fingerprints
- Optional JWS signature verification on LoTE documents
- Periodic refresh with configurable interval

**Supported resource types:** `x5c`, `jwk`

**Configuration (YAML config file):**

```yaml
registries:
  lote:
    enabled: true
    name: "LoTE"
    description: "ETSI TS 119 602 List of Trusted Entities"
    sources:
      - "https://example.com/lote-se.json"
      - "https://example.com/lote-de.json"
      - "/etc/go-trust/local-lote.json"
    verify_jws: false
    fetch_timeout: "30s"
    refresh_interval: "1h"
```

**Programmatic usage:**

```go
import "github.com/sirosfoundation/go-trust/pkg/registry/lote"

reg, err := lote.New(lote.Config{
    Name:            "lote-eu",
    Sources:         []string{"https://example.com/lote.json"},
    RefreshInterval: time.Hour,
})

// Evaluate trust for an entity
req := &authzen.EvaluationRequest{
    Subject:  authzen.Subject{Type: "key", ID: "https://issuer.example.com"},
    Resource: authzen.Resource{Type: "x5c", Key: []interface{}{certB64}},
}
resp, err := reg.Evaluate(ctx, req)
```

**Use cases:**
- JSON-native trust evaluation for modern credential ecosystems
- LoTE-based trust where entities are identified by JWK, X.509, or DID
- Transition from XML TSL to JSON LoTE format

### Static Trust Registries

The `pkg/registry/static` package provides simple TrustRegistry implementations for testing, development, and basic use cases:

| Registry | Description | Use Case |
|----------|-------------|----------|
| `AlwaysTrustedRegistry` | Always returns `decision=true` | Testing, development, trust-all scenarios |
| `NeverTrustedRegistry` | Always returns `decision=false` | Testing trust rejection, deny-all scenarios |
| `SystemCertPoolRegistry` | Validates X509 against OS CA bundle | Simple TLS trust without ETSI TSL |
| `WhitelistRegistry` | URL-based whitelist with file watching | Simple issuer/verifier allowlisting |

```go
import "github.com/sirosfoundation/go-trust/pkg/registry/static"

// Accept all trust requests (testing only!)
registry := static.NewAlwaysTrustedRegistry("test-always-trusted")

// Reject all trust requests (testing only!)
registry := static.NewNeverTrustedRegistry("test-never-trusted")

// Validate against system CA bundle
registry, _ := static.NewSystemCertPoolRegistry(static.SystemCertPoolConfig{
    Name:        "system-ca",
    Description: "System root CA certificates",
})

// URL whitelist from config file (with auto-reload)
registry, _ := static.NewWhitelistRegistryFromFile("/etc/go-trust/whitelist.yaml", true)
defer registry.Close()

// URL whitelist configured programmatically
registry := static.NewWhitelistRegistry()
registry.AddIssuer("https://pid-issuer.example.com")
registry.AddVerifier("https://verifier.example.com")
```

#### WhitelistRegistry Configuration

The whitelist registry supports YAML or JSON configuration files:

```yaml
# whitelist.yaml
issuers:
  - https://pid-issuer.example.com
  - https://issuer.example.org
  - https://trusted-domain.com/*  # Wildcard prefix match

verifiers:
  - https://verifier.example.com
  - https://rp.example.org

trusted_subjects:
  - https://any-role.example.com  # Matches any role
```

**Features:**
- Role-based matching: `issuers` for credential issuers, `verifiers` for relying parties
- Wildcard support: `https://example.com/*` matches any path under that domain
- Global wildcard: `*` matches all subjects (use with caution)
- File watching: Automatically reloads config when file changes (when `watch=true`)
- Runtime updates: `AddIssuer()`, `RemoveIssuer()`, `AddVerifier()`, `RemoveVerifier()`

**Security Note:** WhitelistRegistry provides URL-based trust only. Signature verification must be performed at the application layer. For cryptographic trust verification, use ETSI TSL, OpenID Federation, or other advanced registries.

## Policy Configuration

Policies map action names (from AuthZEN requests) to registry-specific constraints. This enables role-based trust evaluation where different credential types or participant roles have different requirements.

### Configuration Structure

```yaml
policies:
  # Default policy when action.name doesn't match any specific policy
  default_policy: credential-verifier

  policies:
    # Policy for credential issuers
    credential-issuer:
      description: "Trust requirements for credential issuers"
      
      # ETSI TSL constraints
      etsi:
        service_types:
          - "http://uri.etsi.org/TrstSvc/Svctype/QCert"
          - "http://uri.etsi.org/TrstSvc/Svctype/QCertForESeal"
        service_statuses:
          - "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted"
      
      # OpenID Federation constraints
      oidfed:
        entity_types:
          - "openid_credential_issuer"
        required_trust_marks:
          - "https://dc4eu.eu/tm/issuer"
      
      # DID constraints (did:web and did:webvh)
      did:
        allowed_domains:
          - "*.eudiw.dev"
          - "*.example.com"
        require_verifiable_history: true

    # Policy for wallet providers
    wallet-provider:
      description: "Trust requirements for wallet providers"
      oidfed:
        entity_types:
          - "wallet_provider"
        required_trust_marks:
          - "https://dc4eu.eu/tm/wallet"
      # Override which registries to query
      registries:
        - "oidfed-registry"

    # Policy for mDL issuers
    mdl-issuer:
      description: "Trust requirements for mDL/mDOC issuers"
      mdociaca:
        issuer_allowlist:
          - "https://pid-issuer.eudiw.dev"
        require_iaca_endpoint: true
      registries:
        - "mdoc-iaca"
```

### Constraint Types

| Constraint Type | Description | Applicable Registries |
|-----------------|-------------|----------------------|
| `etsi` | Service types, statuses, countries | ETSI TSL |
| `lote` | Entity types, statuses, territories | ETSI LoTE |
| `oidfed` | Entity types, trust marks | OpenID Federation |
| `did` | Allowed domains, verifiable history | DID Web, DID Web VH |
| `mdociaca` | Issuer allowlist, IACA endpoint | mDOC IACA |

### Example Request

```bash
# Request with action.name to select policy
curl -X POST http://localhost:6001/evaluation \
  -H "Content-Type: application/json" \
  -d '{
    "subject": {"type": "key", "id": "https://issuer.example.com"},
    "resource": {"type": "x5c", "key": ["MIIC..."]},
    "action": {"name": "credential-issuer"}
  }'
```

## Deployment

### Docker

```bash
docker build -t go-trust:latest .

docker run -d \
  --name go-trust-server \
  -p 6001:6001 \
  -v /path/to/trusted-certs.pem:/app/certs.pem:ro \
  go-trust:latest --etsi-cert-bundle /app/certs.pem
```

### Kubernetes

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: go-trust
spec:
  replicas: 3
  selector:
    matchLabels:
      app: go-trust
  template:
    metadata:
      labels:
        app: go-trust
      annotations:
        prometheus.io/scrape: "true"
        prometheus.io/port: "6001"
    spec:
      containers:
      - name: go-trust
        image: go-trust:latest
        args:
        - --host=0.0.0.0
        - --port=6001
        - --etsi-cert-bundle=/config/trusted-certs.pem
        - --log-format=json
        ports:
        - containerPort: 6001
        livenessProbe:
          httpGet:
            path: /healthz
            port: 6001
          initialDelaySeconds: 10
          periodSeconds: 30
        readinessProbe:
          httpGet:
            path: /readyz
            port: 6001
          initialDelaySeconds: 5
          periodSeconds: 10
        volumeMounts:
        - name: config
          mountPath: /config
      volumes:
      - name: config
        configMap:
          name: go-trust-config
```

### Workflow: TSL Processing + PDP Server

For production deployment, use `tsl-tool` (from g119612) to process TSLs and generate certificate bundles:

```bash
# 1. Process TSLs with tsl-tool
tsl-tool --output trusted-certs.pem pipeline.yaml

# 2. Run gt with the generated certificate bundle
gt --etsi-cert-bundle trusted-certs.pem
```

Run tsl-tool via cron to update TSL data periodically:

```bash
# Crontab entry: Update TSLs daily at 2 AM
0 2 * * * /usr/local/bin/tsl-tool --output /etc/go-trust/trusted-certs.pem /etc/tsl-tool/pipeline.yaml
```

## Prometheus Metrics

The `/metrics` endpoint exposes:

| Metric | Description |
|--------|-------------|
| `api_requests_total` | HTTP requests by method, endpoint, status |
| `api_request_duration_seconds` | Request latency histogram |
| `api_requests_in_flight` | Current active requests |
| `cert_validation_total` | Certificate validations by result |
| `cert_validation_duration_seconds` | Validation latency |

Example Prometheus queries:

```promql
# Request rate by endpoint
rate(api_requests_total[5m])

# 95th percentile latency
histogram_quantile(0.95, rate(api_request_duration_seconds_bucket[5m]))

# Certificate validation error rate
rate(cert_validation_total{result="error"}[5m])
```

## Embedded Test Server

The `testserver` package provides an embedded test server for integration testing:

```go
import (
    "testing"
    "github.com/sirosfoundation/go-trust/pkg/testserver"
    "github.com/sirosfoundation/go-trust/pkg/registry/static"
)

func TestMyApplication(t *testing.T) {
    // Create a test server that accepts all trust requests
    srv := testserver.New(testserver.WithAcceptAll())
    defer srv.Close()

    // Or use static registries for more control
    srv := testserver.New(testserver.WithRegistry(static.NewAlwaysTrustedRegistry()))
    defer srv.Close()

    // Use srv.URL() to get the server address
    // Make AuthZEN requests to the server
}
```

### Test Server Options

| Option | Description |
|--------|-------------|
| `WithAcceptAll()` | Accept all trust requests |
| `WithRejectAll()` | Reject all trust requests |
| `WithRegistry(r)` | Use a specific TrustRegistry implementation |
| `WithMockRegistry(name, decision, types)` | Add a mock registry |
| `WithDecisionFunc(fn)` | Dynamic trust decisions |

### Using Static Registries in Tests

```go
// Test with always-trusted registry
srv := testserver.New(testserver.WithRegistry(static.NewAlwaysTrustedRegistry()))

// Test with never-trusted registry  
srv := testserver.New(testserver.WithRegistry(static.NewNeverTrustedRegistry()))

// Test with system CA validation
srv := testserver.New(testserver.WithRegistry(static.NewSystemCertPoolRegistry()))

// Test with specific whitelist
reg := static.NewWhitelistRegistry()
reg.AddIssuer("https://test-issuer.example.com")
srv := testserver.New(testserver.WithRegistry(reg))
```

## Development

### Requirements

- Go 1.25+ (check `go.mod` for exact version)
- CGO enabled (`CGO_ENABLED=1`)
- Make for build automation

### Building

```bash
make build          # Build the binary (./go-trust)
make test           # Run tests with race detection
make coverage       # Generate coverage report
make lint           # Run linters
make quick          # Quick pre-commit checks
```

### Project Structure

```
go-trust/
├── cmd/gt/         # Main application
├── pkg/
│   ├── api/        # HTTP API implementation
│   ├── authzen/    # AuthZEN protocol types
│   ├── registry/   # Trust registry interface and manager
│   │   ├── etsi/     # ETSI TSL registry (XML, TS 119 612)
│   │   ├── lote/     # ETSI LoTE registry (JSON, TS 119 602)
│   │   ├── oidfed/   # OpenID Federation registry
│   │   ├── didweb/   # DID Web registry
│   │   ├── didwebvh/ # DID Web VH registry
│   │   ├── mdociaca/ # mDOC IACA registry
│   │   └── static/   # Static registries (always/never/system/whitelist)
│   ├── logging/    # Structured logging
│   └── testserver/ # Embedded test server
├── example/        # Example configurations
└── docs/           # Architecture documentation
```

## Contributing

Contributions are welcome! Please read [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

```bash
# Development workflow
git checkout -b feature/amazing-feature
make quick && make test
git commit -m 'feat: Add amazing feature'
git push origin feature/amazing-feature
# Open a Pull Request
```

## Related Projects

- [g119612](https://github.com/sirosfoundation/g119612) - ETSI TSL and LoTE processing library and `tsl-tool` CLI
- [go-oidfed/lib](https://github.com/go-oidfed/lib) - OpenID Federation library
- [AuthZEN Specification](https://openid.net/wg/authzen/specifications/)
- [ETSI TS 119612](https://www.etsi.org/deliver/etsi_ts/119600_119699/119612/) - Trust Status Lists (XML)
- [ETSI TS 119602](https://www.etsi.org/deliver/etsi_ts/119600_119699/119602/) - Lists of Trusted Entities (JSON)

## License

This project is licensed under the BSD 2-Clause License - see [LICENSE.txt](LICENSE.txt) for details.

## Acknowledgments

- [ETSI TS 119612](https://www.etsi.org/deliver/etsi_ts/119600_119699/119612/) - Trust-service status list format
- [AuthZEN](https://openid.net/wg/authzen/specifications/) - Authorization framework
- [AuthZEN for Trust](https://datatracker.ietf.org/doc/draft-johansson-authzen-trust/)
- [SUNET](https://www.sunet.se/) - Swedish University Network
- [SIROS Foundation](https://siros.org/)
