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
- [registries.general](#registriesgeneral)
- [registries.etsi](#registriesetsi)
- [registries.whitelist](#registrieswhitelist)
- [registries.oidfed](#registriesoidfed)
- [registries.didlocal](#registriesdidlocal)
- [registries.didweb](#registriesdidweb)
- [registries.didwebvh](#registriesdidwebvh)
- [registries.didjwks](#registriesdidjwks)
- [registries.lote](#registrieslote)
- [registries.mdociaca](#registriesmdociaca)
- [registries.mdocrical](#registriesmdocrical)
- [registries.vical](#registriesvical)
- [registries.fidomds3](#registriesfidomds3)
- [registries.systemcertpool](#registriessystemcertpool)
- [registries.always_trusted](#registriesalways_trusted)
- [registries.never_trusted](#registriesnever_trusted)

---

## server

| YAML Key | Env Variable | Type | Description |
|----------|-------------|------|-------------|
| `server.host` | `GT_HOST` | string |  |
| `server.port` | `GT_PORT` | string |  |
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
| `security.trusted_proxies` | — | string list | TrustedProxies lists the CIDRs whose X-Forwarded-For and X-Real-IP headers may be believed when determining a client's address. Empty (the default) trusts none of them, so the peer address is used.  This matters because rate limiting keys on the client address: if a directly reachable client's forwarded headers were trusted, it could rotate X-Forwarded-For and get a fresh bucket on every request. Deployments behind a load balancer must list it here for per-client limiting to work at all. |

## policies

| YAML Key | Env Variable | Type | Description |
|----------|-------------|------|-------------|
| `policies.default_policy` | — | string | DefaultPolicy is the name of the policy to use when action.name is not specified |
| `policies.policies` | — | map[string]*PolicyConfig (object) | Policies is a map of policy name to policy configuration |
| `policies.policies.<name>.description` | — | string | Description provides human-readable documentation |
| `policies.policies.<name>.registries` | — | string list | Registries limits evaluation to specific registry names. If empty, all registries are considered. |
| `policies.policies.<name>.constraints.require_key_binding` | — | boolean | RequireKeyBinding requires that a key be provided and validated. |
| `policies.policies.<name>.constraints.allowed_key_types` | — | string list | AllowedKeyTypes restricts accepted key types (e.g., ["x5c", "jwk"]) |
| `policies.policies.<name>.oidfed.required_trust_marks` | — | string list | RequiredTrustMarks specifies trust mark types that MUST be present |
| `policies.policies.<name>.oidfed.entity_types` | — | string list | EntityTypes filters by OpenID Federation entity types |
| `policies.policies.<name>.oidfed.max_chain_depth` | — | integer | MaxChainDepth limits trust chain resolution depth |
| `policies.policies.<name>.oidfed.credential_type_trust_marks` | — | map[string][]string (object) | CredentialTypeTrustMarks maps credential type identifiers (VCT) to the trust marks required for that type. When a request carries credential_types, the matching trust marks are added to the required set. Example: {"eu.europa.ec.eudi.pid.1": ["https://trust.eu/wallet/pid-issuer"]} |
| `policies.policies.<name>.etsi.service_types` | — | string list | ServiceTypes filters by ETSI service type URIs |
| `policies.policies.<name>.etsi.service_statuses` | — | string list | ServiceStatuses filters by ETSI service status URIs |
| `policies.policies.<name>.etsi.countries` | — | string list | Countries filters by country codes (e.g., ["DE", "FR"]) |
| `policies.policies.<name>.etsi.credential_types` | — | string list | CredentialTypes specifies credential type identifiers (e.g., SD-JWT VCT values) that the policy scopes the evaluation to. |
| `policies.policies.<name>.etsi.required_cert_policy_oids` | — | string list | RequiredCertPolicyOIDs specifies certificate policy OIDs that MUST appear in the leaf certificate's Certificate Policies extension, used to distinguish access certificates (ETSI TS 119 411-8) from generic TLS certificates. |
| `policies.policies.<name>.etsi.extract_rp_identity` | — | boolean | ExtractRPIdentity controls whether RP identity information (Subject DN, SANs, serial number) is extracted from the leaf certificate and returned in the response trust metadata. |
| `policies.policies.<name>.etsi.allowed_attributes` | — | string list | AllowedAttributes lists the attribute names the RP is entitled to request. Over-request detection per TS 119 475 does not run at all unless this is set. |
| `policies.policies.<name>.etsi.strict_entitlement_check` | — | boolean | StrictEntitlementCheck rejects over-requesting RPs instead of returning warnings alongside an allow decision. |
| `policies.policies.<name>.etsi.allow_intermediaries` | — | boolean | AllowIntermediaries accepts intermediary/broker presentation requests and surfaces intermediary metadata. Defaults to false. |
| `policies.policies.<name>.did.allowed_domains` | — | string list | AllowedDomains restricts DIDs to specific domains. Supports wildcards: "*.example.com" matches "sub.example.com" |
| `policies.policies.<name>.did.required_verification_methods` | — | string list | RequiredVerificationMethods requires specific verification method types. |
| `policies.policies.<name>.did.required_services` | — | string list | RequiredServices requires specific service types in the DID document. |
| `policies.policies.<name>.did.require_verifiable_history` | — | boolean | RequireVerifiableHistory (did:webvh only) requires valid verifiable history. |
| `policies.policies.<name>.mdociaca.issuer_allowlist` | — | string list | IssuerAllowlist restricts to specific credential issuers. |
| `policies.policies.<name>.mdociaca.require_iaca_endpoint` | — | boolean | RequireIACAEndpoint requires the issuer to publish mdoc_iacas_uri. |
| `policies.policies.<name>.fidomds3.allowed_aaguids` | — | string list | AllowedAAGUIDs restricts trust to specific AAGUIDs, regardless of MDS3 certification status. |
| `policies.policies.<name>.fidomds3.blocked_aaguids` | — | string list | BlockedAAGUIDs denies specific AAGUIDs even if MDS3 certifies them. Only applied when AllowedAAGUIDs is empty. |

## registries.general

| YAML Key | Env Variable | Type | Description |
|----------|-------------|------|-------------|
| `registries.strategy` | — | string | Strategy selects how the registry manager combines registries: "first_match" (default), "all", "best_match" or "sequential". |
| `registries.composite` | — | CompositeRegistryConfig list | Composite combines already-configured registries with boolean logic. A registry named as a child is evaluated only through its composite, not also on its own. |
| `registries.composite[].name` | — | string | Name identifies the composite, and is what a policy's `registries` list refers to. |
| `registries.composite[].description` | — | string | Description provides human-readable documentation. |
| `registries.composite[].operator` | — | string | Operator is how child results combine: "AND", "OR", "MAJORITY" or "QUORUM". QUORUM requires Threshold children to agree. |
| `registries.composite[].threshold` | — | integer | Threshold is the number of children that must return decision=true. QUORUM only; ignored by the other operators. |
| `registries.composite[].timeout` | — | string | Timeout bounds the whole composite evaluation, as a duration string (e.g. "5s"). Empty uses the CompositeRegistry default. |
| `registries.composite[].registries` | — | string list | Registries names the child registries, which must already be configured elsewhere under `registries`. |

## registries.etsi

| YAML Key | Env Variable | Type | Description |
|----------|-------------|------|-------------|
| `registries.etsi.enabled` | — | boolean |  |
| `registries.etsi.name` | — | string |  |
| `registries.etsi.description` | — | string |  |
| `registries.etsi.cert_bundle` | — | string |  |
| `registries.etsi.tsl_files` | — | string list |  |
| `registries.etsi.tsl_urls` | — | string list |  |
| `registries.etsi.follow_refs` | — | boolean |  |
| `registries.etsi.max_ref_depth` | — | integer |  |
| `registries.etsi.allow_network_access` | — | boolean |  |
| `registries.etsi.fetch_timeout` | — | string |  |
| `registries.etsi.user_agent` | — | string |  |
| `registries.etsi.lotl_signer_bundle` | — | string | LOTLSignerBundle is the path to a PEM file containing trusted LOTL signer certificates. These certificates are used to validate signatures on the List of Trusted Lists (LOTL). |
| `registries.etsi.require_signature` | — | boolean | RequireSignature controls whether TSLs must have valid signatures. When true, LOTLSignerBundle must also be configured. |
| `registries.etsi.follow_pivots` | — | boolean | FollowPivots enables ETSI TS 119 615 pivot LOTL processing for signer certificate rollover. When true, the registry will fetch pivot LOTLs to discover new signer certificates. |
| `registries.etsi.refresh_interval` | — | string | RefreshInterval is how often to re-fetch TSL data in the background, as a duration string (e.g. "6h"). Empty or zero disables background refresh, leaving the registry on whatever it loaded at startup. |

## registries.whitelist

| YAML Key | Env Variable | Type | Description |
|----------|-------------|------|-------------|
| `registries.whitelist.enabled` | — | boolean |  |
| `registries.whitelist.name` | — | string |  |
| `registries.whitelist.description` | — | string |  |
| `registries.whitelist.config_file` | — | string |  |
| `registries.whitelist.watch_file` | — | boolean |  |
| `registries.whitelist.lists` | — | map[string][]string (object) | Named lists (new format) |
| `registries.whitelist.actions` | — | map[string]string (object) |  |
| `registries.whitelist.issuers` | — | string list | Legacy fields (backward compatible) |
| `registries.whitelist.verifiers` | — | string list |  |
| `registries.whitelist.trusted_subjects` | — | string list |  |
| `registries.whitelist.allow_http` | — | boolean | AllowHTTP permits JWKS auto-discovery over plain HTTP instead of requiring HTTPS. Testing only - see pkg/registry/static.WhitelistConfig. |
| `registries.whitelist.trust_x509_via_system_ca` | — | boolean | TrustX509ViaSystemCA enables the system-CA-pool fallback for whitelisted entities with no JWKS endpoint (e.g. OpenID4VP x509_san_dns or x509_hash client_id_scheme verifiers) - see pkg/registry/static.WhitelistConfig.TrustX509ViaSystemCA. |
| `registries.whitelist.additional_trusted_roots` | — | string list | AdditionalTrustedRoots is a list of PEM-encoded CA certificates merged into TrustX509ViaSystemCA's chain-validation pool - see pkg/registry/static.WhitelistConfig.AdditionalTrustedRoots. |

## registries.oidfed

OpenID Federation registry

| YAML Key | Env Variable | Type | Description |
|----------|-------------|------|-------------|
| `registries.oidfed.enabled` | — | boolean |  |
| `registries.oidfed.name` | — | string |  |
| `registries.oidfed.description` | — | string |  |
| `registries.oidfed.trust_anchors` | — | OIDFedTrustAnchorConfig list |  |
| `registries.oidfed.trust_anchors[].entity_id` | — | string |  |
| `registries.oidfed.trust_anchors[].jwks` | — | string | JWKS is optional explicit JWKS for the trust anchor (JSON string) If not provided, JWKS will be fetched from the entity configuration |
| `registries.oidfed.required_trust_marks` | — | string list |  |
| `registries.oidfed.entity_types` | — | string list |  |
| `registries.oidfed.cache_ttl` | — | string |  |
| `registries.oidfed.max_cache_size` | — | integer |  |
| `registries.oidfed.max_chain_depth` | — | integer |  |

## registries.didlocal

Self-contained DID methods (did:key, did:jwk), resolved locally

| YAML Key | Env Variable | Type | Description |
|----------|-------------|------|-------------|
| `registries.didlocal.enabled` | — | boolean |  |
| `registries.didlocal.description` | — | string |  |
| `registries.didlocal.methods` | — | string list | Methods lists the DID methods to resolve, e.g. ["key", "jwk"]. Empty enables every self-contained method. An unrecognised method is a startup error rather than a warning. |

## registries.didweb

DID method registries

| YAML Key | Env Variable | Type | Description |
|----------|-------------|------|-------------|
| `registries.didweb.enabled` | — | boolean |  |
| `registries.didweb.name` | — | string |  |
| `registries.didweb.description` | — | string |  |
| `registries.didweb.timeout` | — | string |  |
| `registries.didweb.insecure_skip_verify` | — | boolean |  |
| `registries.didweb.allow_http` | — | boolean |  |

## registries.didwebvh

| YAML Key | Env Variable | Type | Description |
|----------|-------------|------|-------------|
| `registries.didwebvh.enabled` | — | boolean |  |
| `registries.didwebvh.name` | — | string |  |
| `registries.didwebvh.description` | — | string |  |
| `registries.didwebvh.timeout` | — | string |  |
| `registries.didwebvh.insecure_skip_verify` | — | boolean |  |
| `registries.didwebvh.allow_http` | — | boolean |  |

## registries.didjwks

| YAML Key | Env Variable | Type | Description |
|----------|-------------|------|-------------|
| `registries.didjwks.enabled` | — | boolean |  |
| `registries.didjwks.name` | — | string |  |
| `registries.didjwks.description` | — | string |  |
| `registries.didjwks.timeout` | — | string |  |
| `registries.didjwks.insecure_skip_verify` | — | boolean |  |
| `registries.didjwks.allow_http` | — | boolean |  |
| `registries.didjwks.disable_oidc_discovery` | — | boolean |  |

## registries.lote

ETSI TS 119 602 LoTE registry

| YAML Key | Env Variable | Type | Description |
|----------|-------------|------|-------------|
| `registries.lote.enabled` | — | boolean |  |
| `registries.lote.name` | — | string |  |
| `registries.lote.description` | — | string |  |
| `registries.lote.sources` | — | string list |  |
| `registries.lote.lotl_sources` | — | string list |  |
| `registries.lote.max_dereference_depth` | — | integer |  |
| `registries.lote.verify_jws` | — | boolean |  |
| `registries.lote.fetch_timeout` | — | string |  |
| `registries.lote.refresh_interval` | — | string |  |

## registries.mdociaca

mDOC IACA registry

| YAML Key | Env Variable | Type | Description |
|----------|-------------|------|-------------|
| `registries.mdociaca.enabled` | — | boolean |  |
| `registries.mdociaca.name` | — | string |  |
| `registries.mdociaca.description` | — | string |  |
| `registries.mdociaca.issuer_allowlist` | — | string list |  |
| `registries.mdociaca.cache_ttl` | — | string |  |
| `registries.mdociaca.http_timeout` | — | string |  |

## registries.mdocrical

mDOC RICAL registry (reader authentication trust)

| YAML Key | Env Variable | Type | Description |
|----------|-------------|------|-------------|
| `registries.mdocrical.enabled` | — | boolean |  |
| `registries.mdocrical.name` | — | string |  |
| `registries.mdocrical.description` | — | string |  |
| `registries.mdocrical.rical_provider_url` | — | string |  |
| `registries.mdocrical.rical_root_certificate_pem` | — | string |  |
| `registries.mdocrical.cache_ttl` | — | string |  |
| `registries.mdocrical.http_timeout` | — | string |  |

## registries.vical

VICAL registry (issuer authentication trust)

| YAML Key | Env Variable | Type | Description |
|----------|-------------|------|-------------|
| `registries.vical.enabled` | — | boolean |  |
| `registries.vical.name` | — | string |  |
| `registries.vical.description` | — | string |  |
| `registries.vical.vical_provider_url` | — | string |  |
| `registries.vical.vical_root_certificate_pem` | — | string |  |
| `registries.vical.cache_ttl` | — | string |  |
| `registries.vical.http_timeout` | — | string |  |

## registries.fidomds3

FIDO Alliance MDS3 registry (FIDO2/CTAP2 hardware-key attestation trust)

| YAML Key | Env Variable | Type | Description |
|----------|-------------|------|-------------|
| `registries.fidomds3.enabled` | — | boolean |  |
| `registries.fidomds3.name` | — | string |  |
| `registries.fidomds3.description` | — | string |  |
| `registries.fidomds3.url` | — | string |  |
| `registries.fidomds3.fetch_timeout` | — | string |  |
| `registries.fidomds3.refresh_interval` | — | string |  |
| `registries.fidomds3.root_certificate_pem` | — | string |  |
| `registries.fidomds3.cache_path` | — | string | CachePath persists the raw MDS3 blob to disk so a restart doesn't have to block on (or fail because of) a live fetch - see fidomds3.Config.CachePath's doc for the load/refresh semantics. |

## registries.systemcertpool

System X.509 certificate pool (the host trust store)

| YAML Key | Env Variable | Type | Description |
|----------|-------------|------|-------------|
| `registries.systemcertpool.enabled` | — | boolean |  |
| `registries.systemcertpool.name` | — | string |  |
| `registries.systemcertpool.description` | — | string |  |

## registries.always_trusted

Static test registries

| YAML Key | Env Variable | Type | Description |
|----------|-------------|------|-------------|
| `registries.always_trusted.enabled` | — | boolean |  |
| `registries.always_trusted.name` | — | string |  |
| `registries.always_trusted.description` | — | string |  |

## registries.never_trusted

| YAML Key | Env Variable | Type | Description |
|----------|-------------|------|-------------|
| `registries.never_trusted.enabled` | — | boolean |  |
| `registries.never_trusted.name` | — | string |  |
| `registries.never_trusted.description` | — | string |  |

