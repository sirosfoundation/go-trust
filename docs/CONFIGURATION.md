<!-- Regenerate with: go run developer_tools/scripts/gen_config_docs/main.go -->

# Configuration Reference

This document describes all configuration options for go-trust (`gt`).
Configuration is loaded from a YAML file, then a handful of settings can be overridden by `GT_*` environment variables — most fields (all registries and policies) are YAML-only.

A few `server` settings can also be set via CLI flag (`gt -host`, `-port`, `-external-url`, `-log-level`, `-log-format`) — see `gt -h`.

## Table of Contents

- [server](#server)
- [logging](#logging)
- [security](#security)
- [policies](#policies)
- [registries.etsi](#registriesetsi)
- [registries.whitelist](#registrieswhitelist)
- [registries.oidfed](#registriesoidfed)
- [registries.didweb](#registriesdidweb)
- [registries.didwebvh](#registriesdidwebvh)
- [registries.didjwks](#registriesdidjwks)
- [registries.lote](#registrieslote)
- [registries.mdociaca](#registriesmdociaca)
- [registries.mdocrical](#registriesmdocrical)
- [registries.vical](#registriesvical)
- [registries.fidomds3](#registriesfidomds3)
- [registries.always_trusted](#registriesalways_trusted)
- [registries.never_trusted](#registriesnever_trusted)

---

## server

| YAML Key | Env Variable | Type | Description |
|----------|-------------|------|-------------|
| `server.host` | `GT_HOST` | string |  |
| `server.port` | `GT_PORT` | string |  |
| `server.frequency` | `GT_FREQUENCY` | duration |  |
| `server.external_url` | `GT_EXTERNAL_URL` | string | External URL for PDP discovery (e.g., https://pdp.example.com) |
| `server.tls.enabled` | `GT_TLS_ENABLED` | boolean | Enable TLS/HTTPS |
| `server.tls.cert_file` | `GT_TLS_CERT_FILE` | string | Path to TLS certificate file |
| `server.tls.key_file` | `GT_TLS_KEY_FILE` | string | Path to TLS private key file |

## logging

| YAML Key | Env Variable | Type | Description |
|----------|-------------|------|-------------|
| `logging.level` | `GT_LOG_LEVEL` | string |  |
| `logging.format` | `GT_LOG_FORMAT` | string |  |
| `logging.output` | `GT_LOG_OUTPUT` | string |  |

## security

| YAML Key | Env Variable | Type | Description |
|----------|-------------|------|-------------|
| `security.rate_limit_rps` | `GT_RATE_LIMIT_RPS` | integer |  |
| `security.enable_cors` | `GT_ENABLE_CORS` | boolean |  |
| `security.allowed_origins` | `GT_ALLOWED_ORIGINS` | string list |  |
| `security.max_response_body_bytes` | `GT_MAX_RESPONSE_BODY_BYTES` | integer | Max HTTP response body size in bytes (default: 10MB) |

## policies

| YAML Key | Env Variable | Type | Description |
|----------|-------------|------|-------------|
| `policies.default_policy` | — | string | DefaultPolicy is the name of the policy to use when action.name is not specified |
| `policies.policies` | — | map[string]*PolicyConfig (object) | Policies is a map of policy name to policy configuration |

## registries.etsi

| YAML Key | Env Variable | Type | Description |
|----------|-------------|------|-------------|
| `etsi.enabled` | — | boolean |  |
| `etsi.name` | — | string |  |
| `etsi.description` | — | string |  |
| `etsi.cert_bundle` | — | string |  |
| `etsi.tsl_files` | — | string list |  |
| `etsi.tsl_urls` | — | string list |  |
| `etsi.follow_refs` | — | boolean |  |
| `etsi.max_ref_depth` | — | integer |  |
| `etsi.allow_network_access` | — | boolean |  |
| `etsi.fetch_timeout` | — | string |  |
| `etsi.user_agent` | — | string |  |
| `etsi.lotl_signer_bundle` | — | string | LOTLSignerBundle is the path to a PEM file containing trusted LOTL signer certificates. These certificates are used to validate signatures on the List of Trusted Lists (LOTL). |
| `etsi.require_signature` | — | boolean | RequireSignature controls whether TSLs must have valid signatures. When true, LOTLSignerBundle must also be configured. |
| `etsi.follow_pivots` | — | boolean | FollowPivots enables ETSI TS 119 615 pivot LOTL processing for signer certificate rollover. When true, the registry will fetch pivot LOTLs to discover new signer certificates. |

## registries.whitelist

| YAML Key | Env Variable | Type | Description |
|----------|-------------|------|-------------|
| `whitelist.enabled` | — | boolean |  |
| `whitelist.name` | — | string |  |
| `whitelist.description` | — | string |  |
| `whitelist.config_file` | — | string |  |
| `whitelist.watch_file` | — | boolean |  |
| `whitelist.lists` | — | map[string][]string (object) | Named lists (new format) |
| `whitelist.actions` | — | map[string]string (object) |  |
| `whitelist.issuers` | — | string list | Legacy fields (backward compatible) |
| `whitelist.verifiers` | — | string list |  |
| `whitelist.trusted_subjects` | — | string list |  |
| `whitelist.allow_http` | — | boolean | AllowHTTP permits JWKS auto-discovery over plain HTTP instead of requiring HTTPS. Testing only - see pkg/registry/static.WhitelistConfig. |
| `whitelist.trust_x509_via_system_ca` | — | boolean | TrustX509ViaSystemCA enables the system-CA-pool fallback for whitelisted entities with no JWKS endpoint (e.g. OpenID4VP x509_san_dns or x509_hash client_id_scheme verifiers) - see pkg/registry/static.WhitelistConfig.TrustX509ViaSystemCA. |
| `whitelist.additional_trusted_roots` | — | string list | AdditionalTrustedRoots is a list of PEM-encoded CA certificates merged into TrustX509ViaSystemCA's chain-validation pool - see pkg/registry/static.WhitelistConfig.AdditionalTrustedRoots. |

## registries.oidfed

OpenID Federation registry

| YAML Key | Env Variable | Type | Description |
|----------|-------------|------|-------------|
| `oidfed.enabled` | — | boolean |  |
| `oidfed.name` | — | string |  |
| `oidfed.description` | — | string |  |
| `oidfed.trust_anchors` | — | OIDFedTrustAnchorConfig list |  |
| `oidfed.required_trust_marks` | — | string list |  |
| `oidfed.entity_types` | — | string list |  |
| `oidfed.cache_ttl` | — | string |  |
| `oidfed.max_cache_size` | — | integer |  |
| `oidfed.max_chain_depth` | — | integer |  |

## registries.didweb

DID method registries

| YAML Key | Env Variable | Type | Description |
|----------|-------------|------|-------------|
| `didweb.enabled` | — | boolean |  |
| `didweb.name` | — | string |  |
| `didweb.description` | — | string |  |
| `didweb.timeout` | — | string |  |
| `didweb.insecure_skip_verify` | — | boolean |  |
| `didweb.allow_http` | — | boolean |  |

## registries.didwebvh

| YAML Key | Env Variable | Type | Description |
|----------|-------------|------|-------------|
| `didwebvh.enabled` | — | boolean |  |
| `didwebvh.name` | — | string |  |
| `didwebvh.description` | — | string |  |
| `didwebvh.timeout` | — | string |  |
| `didwebvh.insecure_skip_verify` | — | boolean |  |
| `didwebvh.allow_http` | — | boolean |  |

## registries.didjwks

| YAML Key | Env Variable | Type | Description |
|----------|-------------|------|-------------|
| `didjwks.enabled` | — | boolean |  |
| `didjwks.name` | — | string |  |
| `didjwks.description` | — | string |  |
| `didjwks.timeout` | — | string |  |
| `didjwks.insecure_skip_verify` | — | boolean |  |
| `didjwks.allow_http` | — | boolean |  |
| `didjwks.disable_oidc_discovery` | — | boolean |  |

## registries.lote

ETSI TS 119 602 LoTE registry

| YAML Key | Env Variable | Type | Description |
|----------|-------------|------|-------------|
| `lote.enabled` | — | boolean |  |
| `lote.name` | — | string |  |
| `lote.description` | — | string |  |
| `lote.sources` | — | string list |  |
| `lote.lotl_sources` | — | string list |  |
| `lote.max_dereference_depth` | — | integer |  |
| `lote.verify_jws` | — | boolean |  |
| `lote.fetch_timeout` | — | string |  |
| `lote.refresh_interval` | — | string |  |

## registries.mdociaca

mDOC IACA registry

| YAML Key | Env Variable | Type | Description |
|----------|-------------|------|-------------|
| `mdociaca.enabled` | — | boolean |  |
| `mdociaca.name` | — | string |  |
| `mdociaca.description` | — | string |  |
| `mdociaca.issuer_allowlist` | — | string list |  |
| `mdociaca.cache_ttl` | — | string |  |
| `mdociaca.http_timeout` | — | string |  |

## registries.mdocrical

mDOC RICAL registry (reader authentication trust)

| YAML Key | Env Variable | Type | Description |
|----------|-------------|------|-------------|
| `mdocrical.enabled` | — | boolean |  |
| `mdocrical.name` | — | string |  |
| `mdocrical.description` | — | string |  |
| `mdocrical.rical_provider_url` | — | string |  |
| `mdocrical.rical_root_certificate_pem` | — | string |  |
| `mdocrical.cache_ttl` | — | string |  |
| `mdocrical.http_timeout` | — | string |  |

## registries.vical

VICAL registry (issuer authentication trust)

| YAML Key | Env Variable | Type | Description |
|----------|-------------|------|-------------|
| `vical.enabled` | — | boolean |  |
| `vical.name` | — | string |  |
| `vical.description` | — | string |  |
| `vical.vical_provider_url` | — | string |  |
| `vical.vical_root_certificate_pem` | — | string |  |
| `vical.cache_ttl` | — | string |  |
| `vical.http_timeout` | — | string |  |

## registries.fidomds3

FIDO Alliance MDS3 registry (FIDO2/CTAP2 hardware-key attestation trust)

| YAML Key | Env Variable | Type | Description |
|----------|-------------|------|-------------|
| `fidomds3.enabled` | — | boolean |  |
| `fidomds3.name` | — | string |  |
| `fidomds3.description` | — | string |  |
| `fidomds3.url` | — | string |  |
| `fidomds3.fetch_timeout` | — | string |  |
| `fidomds3.refresh_interval` | — | string |  |
| `fidomds3.root_certificate_pem` | — | string |  |
| `fidomds3.cache_path` | — | string | CachePath persists the raw MDS3 blob to disk so a restart doesn't have to block on (or fail because of) a live fetch - see fidomds3.Config.CachePath's doc for the load/refresh semantics. |

## registries.always_trusted

Static test registries

| YAML Key | Env Variable | Type | Description |
|----------|-------------|------|-------------|
| `always_trusted.enabled` | — | boolean |  |
| `always_trusted.name` | — | string |  |
| `always_trusted.description` | — | string |  |

## registries.never_trusted

| YAML Key | Env Variable | Type | Description |
|----------|-------------|------|-------------|
| `never_trusted.enabled` | — | boolean |  |
| `never_trusted.name` | — | string |  |
| `never_trusted.description` | — | string |  |

