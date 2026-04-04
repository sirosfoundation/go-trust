// Package oidfed provides the OpenID Federation trust registry implementation.
// This file defines internal context keys for OpenID Federation trust evaluation.
package oidfed

// OpenID Federation Context Keys (Internal)
//
// These context keys are used internally by the OIDF registry to interpret
// AuthZEN request context parameters. Clients should NOT use these directly -
// the go-trust architecture is protocol-agnostic and clients should use the
// generic AuthZEN interface.
//
// These keys are primarily for:
// 1. Server-side configuration mapping
// 2. Internal request processing
// 3. Future protocol extension proposals
//
// PROTOCOL CONSIDERATION: The AuthZEN Trust Registry Profile (draft-johansson-authzen-trust)
// does not currently define standard context keys for federation-specific constraints.
// These keys represent internal implementation that could inform future standardization.
const (
	// ContextKeyRequiredTrustMarks specifies trust mark types that MUST be present.
	// Value: []string of trust mark type URIs
	// Example: ["https://example.eu/trust-mark/wallet-provider"]
	ContextKeyRequiredTrustMarks = "required_trust_marks"

	// ContextKeyAllowedEntityTypes filters entities by OpenID Federation metadata types.
	// Value: []string of entity type identifiers
	// Example: ["openid_credential_issuer", "openid_provider"]
	// Standard entity types:
	//   - "openid_provider" - OpenID Connect Provider
	//   - "openid_relying_party" - OpenID Connect Relying Party
	//   - "oauth_authorization_server" - OAuth 2.0 Authorization Server
	//   - "oauth_client" - OAuth 2.0 Client
	//   - "oauth_resource" - OAuth 2.0 Resource Server
	//   - "openid_credential_issuer" - OpenID4VCI Credential Issuer
	//   - "federation_entity" - OpenID Federation Entity
	ContextKeyAllowedEntityTypes = "allowed_entity_types"

	// ContextKeyIncludeTrustChain requests the full trust chain in the response.
	// Value: bool
	// When true, response.context.trust_metadata will include:
	//   - "trust_chain": array of entity statements from leaf to anchor
	//   - "trust_anchor": entity ID of the trust anchor
	ContextKeyIncludeTrustChain = "include_trust_chain"

	// ContextKeyIncludeCertificates requests X.509 certificates from JWKS.
	// Value: bool
	// When true, certificates from x5c in entity JWKS are included in response.
	ContextKeyIncludeCertificates = "include_certificates"

	// ContextKeyMaxChainDepth limits trust chain resolution depth.
	// Value: int (default: 10)
	// Prevents excessive network requests for deeply nested federations.
	ContextKeyMaxChainDepth = "max_chain_depth"

	// ContextKeyCacheControl provides cache control hints.
	// Value: string ("no-cache", "no-store", "max-age=N")
	// Allows server-side caching behavior configuration.
	ContextKeyCacheControl = "cache_control"

	// ContextKeyCredentialTypes specifies credential type identifiers for filtering.
	// Value: []string of credential type identifiers (e.g., SD-JWT VCT values)
	// Example: ["eu.europa.ec.eudi.pid.1", "eu.europa.ec.eudi.mdl.1"]
	// When credential_type_trust_marks mapping is configured, the registry validates
	// that the entity has the required trust marks for each credential type.
	ContextKeyCredentialTypes = "credential_types"

	// ContextKeyCredentialTypeTrustMarks provides a mapping from credential types to trust marks.
	// Value: map[string][]string where keys are VCT identifiers and values are trust mark URIs
	// Example: {"eu.europa.ec.eudi.pid.1": ["https://trust.eu/wallet/pid-issuer"]}
	// When both credential_types and this mapping are present, the registry validates
	// that the entity has ALL mapped trust marks for the requested credential types.
	ContextKeyCredentialTypeTrustMarks = "credential_type_trust_marks"
)

// OpenID Federation Response Metadata Keys
// These keys are used in the trust_metadata field of the response context.
const (
	// MetadataKeyEntityConfiguration is the resolved entity configuration.
	MetadataKeyEntityConfiguration = "entity_configuration"

	// MetadataKeyTrustChain contains the validated trust chain.
	MetadataKeyTrustChain = "trust_chain"

	// MetadataKeyTrustAnchor is the entity ID of the trust anchor.
	MetadataKeyTrustAnchor = "trust_anchor"

	// MetadataKeyTrustMarks contains the validated trust marks.
	MetadataKeyTrustMarks = "trust_marks"

	// MetadataKeyEntityTypes contains the entity's metadata types.
	MetadataKeyEntityTypes = "entity_types"

	// MetadataKeyJWKS contains the entity's JWKS.
	MetadataKeyJWKS = "jwks"

	// MetadataKeyResolvedAt is the timestamp when metadata was resolved.
	MetadataKeyResolvedAt = "resolved_at"

	// MetadataKeyCachedUntil is the cache expiration timestamp.
	MetadataKeyCachedUntil = "cached_until"
)
