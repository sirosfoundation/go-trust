// Package config provides configuration management for the Go-Trust application.
// It supports loading configuration from YAML files and environment variables.
package config

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"

	"github.com/sirosfoundation/g119612/pkg/validation"
	"gopkg.in/yaml.v3"
)

// Config represents the application configuration structure.
// It includes settings for the server, logging, registries, and security.
type Config struct {
	Server     ServerConfig     `yaml:"server"`
	Logging    LoggingConfig    `yaml:"logging"`
	Security   SecurityConfig   `yaml:"security"`
	Registries RegistriesConfig `yaml:"registries"`
	Policies   PoliciesConfig   `yaml:"policies,omitempty"`

	// unknownKeys records keys present in the config file that no struct
	// field claims. Unexported, so neither the YAML decoder nor the
	// documentation generator sees it. Read it with UnknownKeys.
	unknownKeys []UnknownKey
}

// UnknownKey is one config-file key that no struct field claims.
type UnknownKey struct {
	// Line is the 1-based line in the config file the key appears on.
	Line int
	// Field is the key as written in the file, e.g. "did_local".
	Field string
	// Type is the Go type that was being decoded, e.g. "config.RegistriesConfig".
	Type string
}

// String renders an unknown key for a log line.
func (u UnknownKey) String() string {
	return fmt.Sprintf("%s (line %d, in %s)", u.Field, u.Line, u.Type)
}

// UnknownKeys returns the config-file keys that no struct field claims, in
// file order.
//
// Decoding is deliberately non-strict, so an unknown key is discarded rather
// than rejected. That is what makes a typo and a real-but-unwired key
// indistinguishable at runtime: both look exactly like a key that worked. A
// renamed key (did_local -> didlocal) simply stops taking effect, and the
// failure surfaces far from the config file — as an unresolvable DID, or a
// policy control that silently never applies.
//
// Callers should warn about anything returned here. From v0.24.0 an unknown
// key is intended to be a startup error, most likely behind a config gate so
// operators can adopt it on their own schedule.
func (c *Config) UnknownKeys() []UnknownKey {
	return c.unknownKeys
}

// unknownFieldRE matches yaml.v3's KnownFields error text, e.g.
// "line 42: field did_local not found in type config.RegistriesConfig".
var unknownFieldRE = regexp.MustCompile(`^line (\d+): field (\S+) not found in type (\S+)$`)

// findUnknownKeys re-decodes data with KnownFields(true) purely to collect the
// keys the authoritative decode threw away.
//
// Only "field X not found" errors are collected. A strict decode also reports
// type mismatches, but the non-strict decode in LoadConfig has already
// succeeded by the time this runs, so any such error describes a value yaml
// coerced rather than a key that went missing, and is not this function's
// business to report.
func findUnknownKeys(data []byte) []UnknownKey {
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)

	var probe Config
	err := dec.Decode(&probe)
	if err == nil {
		return nil
	}
	var typeErr *yaml.TypeError
	if !errors.As(err, &typeErr) {
		return nil
	}

	var keys []UnknownKey
	for _, msg := range typeErr.Errors {
		m := unknownFieldRE.FindStringSubmatch(msg)
		if m == nil {
			continue
		}
		line, convErr := strconv.Atoi(m[1])
		if convErr != nil {
			continue
		}
		keys = append(keys, UnknownKey{Line: line, Field: m[2], Type: m[3]})
	}
	return keys
}

// RegistriesConfig contains configuration for all trust registries.
type RegistriesConfig struct {
	ETSI      *ETSIRegistryConfig      `yaml:"etsi,omitempty"`
	Whitelist *WhitelistRegistryConfig `yaml:"whitelist,omitempty"`
	// OpenID Federation registry
	OIDFed *OIDFedRegistryConfig `yaml:"oidfed,omitempty"`
	// Self-contained DID methods (did:key, did:jwk), resolved locally
	DIDLocal *DIDLocalRegistryConfig `yaml:"didlocal,omitempty"`
	// DID method registries
	DIDWeb   *DIDWebRegistryConfig   `yaml:"didweb,omitempty"`
	DIDWebVH *DIDWebVHRegistryConfig `yaml:"didwebvh,omitempty"`
	DIDJWKS  *DIDJWKSRegistryConfig  `yaml:"didjwks,omitempty"`
	// ETSI TS 119 602 LoTE registry
	LoTE *LoTERegistryConfig `yaml:"lote,omitempty"`
	// mDOC IACA registry
	MDOCIACA *MDOCIACARegistryConfig `yaml:"mdociaca,omitempty"`
	// mDOC RICAL registry (reader authentication trust)
	MDOCRICAL *MDOCRICALRegistryConfig `yaml:"mdocrical,omitempty"`
	// VICAL registry (issuer authentication trust)
	VICAL *VICALRegistryConfig `yaml:"vical,omitempty"`
	// FIDO Alliance MDS3 registry (FIDO2/CTAP2 hardware-key attestation trust)
	FIDOMDS3 *FIDOMDS3RegistryConfig `yaml:"fidomds3,omitempty"`
	// System X.509 certificate pool (the host trust store)
	SystemCertPool *SystemCertPoolRegistryConfig `yaml:"systemcertpool,omitempty"`
	// Static test registries
	AlwaysTrusted *StaticRegistryConfig `yaml:"always_trusted,omitempty"`
	NeverTrusted  *StaticRegistryConfig `yaml:"never_trusted,omitempty"`
	// Strategy selects how the registry manager combines registries:
	// "first_match" (default), "all", "best_match" or "sequential".
	Strategy string `yaml:"strategy,omitempty"`
	// Composite combines already-configured registries with boolean logic.
	// A registry named as a child is evaluated only through its composite,
	// not also on its own.
	Composite []CompositeRegistryConfig `yaml:"composite,omitempty"`
}

// SystemCertPoolRegistryConfig configures the registry that validates X.509
// chains against the host's own trust store.
type SystemCertPoolRegistryConfig struct {
	Enabled     bool   `yaml:"enabled"`
	Name        string `yaml:"name,omitempty"`
	Description string `yaml:"description,omitempty"`
}

// CompositeRegistryConfig combines other configured registries with boolean
// logic, so a trust decision can require agreement between them.
type CompositeRegistryConfig struct {
	// Name identifies the composite, and is what a policy's `registries`
	// list refers to.
	Name string `yaml:"name"`
	// Description provides human-readable documentation.
	Description string `yaml:"description,omitempty"`
	// Operator is how child results combine: "AND", "OR", "MAJORITY" or
	// "QUORUM". QUORUM requires Threshold children to agree.
	Operator string `yaml:"operator"`
	// Threshold is the number of children that must return decision=true.
	// QUORUM only; ignored by the other operators.
	Threshold int `yaml:"threshold,omitempty"`
	// Timeout bounds the whole composite evaluation, as a duration string
	// (e.g. "5s"). Empty uses the CompositeRegistry default.
	Timeout string `yaml:"timeout,omitempty"`
	// Registries names the child registries, which must already be
	// configured elsewhere under `registries`.
	Registries []string `yaml:"registries"`
}

// ETSIRegistryConfig contains ETSI TSL registry configuration.
type ETSIRegistryConfig struct {
	Enabled            bool     `yaml:"enabled"`
	Name               string   `yaml:"name"`
	Description        string   `yaml:"description"`
	CertBundle         string   `yaml:"cert_bundle,omitempty"`
	TSLFiles           []string `yaml:"tsl_files,omitempty"`
	TSLURLs            []string `yaml:"tsl_urls,omitempty"`
	FollowRefs         bool     `yaml:"follow_refs"`
	MaxRefDepth        int      `yaml:"max_ref_depth"`
	AllowNetworkAccess bool     `yaml:"allow_network_access"`
	FetchTimeout       string   `yaml:"fetch_timeout"`
	UserAgent          string   `yaml:"user_agent"`
	// LOTLSignerBundle is the path to a PEM file containing trusted LOTL signer certificates.
	// These certificates are used to validate signatures on the List of Trusted Lists (LOTL).
	LOTLSignerBundle string `yaml:"lotl_signer_bundle,omitempty"`
	// RequireSignature controls whether TSLs must have valid signatures.
	// When true, LOTLSignerBundle must also be configured.
	RequireSignature bool `yaml:"require_signature"`
	// FollowPivots enables ETSI TS 119 615 pivot LOTL processing for signer certificate rollover.
	// When true, the registry will fetch pivot LOTLs to discover new signer certificates.
	FollowPivots bool `yaml:"follow_pivots"`
	// RefreshInterval is how often to re-fetch TSL data in the background,
	// as a duration string (e.g. "6h"). Empty or zero disables background
	// refresh, leaving the registry on whatever it loaded at startup.
	RefreshInterval string `yaml:"refresh_interval,omitempty"`
}

// WhitelistRegistryConfig contains whitelist registry configuration.
type WhitelistRegistryConfig struct {
	Enabled     bool   `yaml:"enabled"`
	Name        string `yaml:"name"`
	Description string `yaml:"description"`
	ConfigFile  string `yaml:"config_file,omitempty"`
	WatchFile   bool   `yaml:"watch_file"`
	// Named lists (new format)
	Lists   map[string][]string `yaml:"lists,omitempty"`
	Actions map[string]string   `yaml:"actions,omitempty"`
	// Legacy fields (backward compatible)
	Issuers         []string `yaml:"issuers,omitempty"`
	Verifiers       []string `yaml:"verifiers,omitempty"`
	TrustedSubjects []string `yaml:"trusted_subjects,omitempty"`
	// AllowHTTP permits JWKS auto-discovery over plain HTTP instead of
	// requiring HTTPS. Testing only - see pkg/registry/static.WhitelistConfig.
	AllowHTTP bool `yaml:"allow_http,omitempty"`
	// TrustX509ViaSystemCA enables the system-CA-pool fallback for whitelisted
	// entities with no JWKS endpoint (e.g. OpenID4VP x509_san_dns or x509_hash
	// client_id_scheme verifiers) - see
	// pkg/registry/static.WhitelistConfig.TrustX509ViaSystemCA.
	TrustX509ViaSystemCA bool `yaml:"trust_x509_via_system_ca,omitempty"`
	// AdditionalTrustedRoots is a list of PEM-encoded CA certificates merged
	// into TrustX509ViaSystemCA's chain-validation pool - see
	// pkg/registry/static.WhitelistConfig.AdditionalTrustedRoots.
	AdditionalTrustedRoots []string `yaml:"additional_trusted_roots,omitempty"`
}

// StaticRegistryConfig contains static (always/never trusted) registry configuration.
type StaticRegistryConfig struct {
	Enabled     bool   `yaml:"enabled"`
	Name        string `yaml:"name"`
	Description string `yaml:"description"`
}

// OIDFedRegistryConfig contains OpenID Federation registry configuration.
type OIDFedRegistryConfig struct {
	Enabled            bool                      `yaml:"enabled"`
	Name               string                    `yaml:"name,omitempty"`
	Description        string                    `yaml:"description,omitempty"`
	TrustAnchors       []OIDFedTrustAnchorConfig `yaml:"trust_anchors"`
	RequiredTrustMarks []string                  `yaml:"required_trust_marks,omitempty"`
	EntityTypes        []string                  `yaml:"entity_types,omitempty"`
	CacheTTL           string                    `yaml:"cache_ttl,omitempty"`
	MaxCacheSize       int                       `yaml:"max_cache_size,omitempty"`
	MaxChainDepth      int                       `yaml:"max_chain_depth,omitempty"`
}

// OIDFedTrustAnchorConfig defines a trust anchor for OpenID Federation.
type OIDFedTrustAnchorConfig struct {
	EntityID string `yaml:"entity_id"`
	// JWKS is optional explicit JWKS for the trust anchor (JSON string)
	// If not provided, JWKS will be fetched from the entity configuration
	JWKS string `yaml:"jwks,omitempty"`
}

// DIDWebRegistryConfig contains did:web registry configuration.
type DIDWebRegistryConfig struct {
	Enabled            bool   `yaml:"enabled"`
	Name               string `yaml:"name,omitempty"`
	Description        string `yaml:"description,omitempty"`
	Timeout            string `yaml:"timeout,omitempty"`
	InsecureSkipVerify bool   `yaml:"insecure_skip_verify,omitempty"`
	AllowHTTP          bool   `yaml:"allow_http,omitempty"`
}

// DIDWebVHRegistryConfig contains did:webvh registry configuration.
type DIDWebVHRegistryConfig struct {
	Enabled            bool   `yaml:"enabled"`
	Name               string `yaml:"name,omitempty"`
	Description        string `yaml:"description,omitempty"`
	Timeout            string `yaml:"timeout,omitempty"`
	InsecureSkipVerify bool   `yaml:"insecure_skip_verify,omitempty"`
	AllowHTTP          bool   `yaml:"allow_http,omitempty"`
}

// DIDLocalRegistryConfig contains configuration for the registry that resolves
// the self-contained DID methods -- those that encode their key in the
// identifier itself and so need no network access.
//
// The key is `didlocal` rather than `did` because this is one registry among
// several DID ones, not DID configuration in general: `policy.did` already
// means the latter. It is not named after a method either, unlike `didweb` or
// `didjwks`, because the `methods` list is the point -- the next
// self-contained method should need no new config block. The unpunctuated
// spelling matches its neighbours.
//
// did:web and did:webvh are configured separately, under `didweb` and
// `didwebvh`, because they fetch and cache documents.
type DIDLocalRegistryConfig struct {
	Enabled     bool   `yaml:"enabled"`
	Description string `yaml:"description,omitempty"`
	// Methods lists the DID methods to resolve, e.g. ["key", "jwk"].
	// Empty enables every self-contained method. An unrecognised method is a
	// startup error rather than a warning.
	Methods []string `yaml:"methods,omitempty"`
}

// DIDJWKSRegistryConfig contains did:jwks registry configuration.
type DIDJWKSRegistryConfig struct {
	Enabled              bool   `yaml:"enabled"`
	Name                 string `yaml:"name,omitempty"`
	Description          string `yaml:"description,omitempty"`
	Timeout              string `yaml:"timeout,omitempty"`
	InsecureSkipVerify   bool   `yaml:"insecure_skip_verify,omitempty"`
	AllowHTTP            bool   `yaml:"allow_http,omitempty"`
	DisableOIDCDiscovery bool   `yaml:"disable_oidc_discovery,omitempty"`
}

// MDOCIACARegistryConfig contains mDOC IACA registry configuration.
type MDOCIACARegistryConfig struct {
	Enabled         bool     `yaml:"enabled"`
	Name            string   `yaml:"name,omitempty"`
	Description     string   `yaml:"description,omitempty"`
	IssuerAllowlist []string `yaml:"issuer_allowlist,omitempty"`
	CacheTTL        string   `yaml:"cache_ttl,omitempty"`
	HTTPTimeout     string   `yaml:"http_timeout,omitempty"`
}

// MDOCRICALRegistryConfig contains mDOC RICAL (Reader Identity Certificate
// Authority List) registry configuration - authenticates mdoc readers per
// ISO/IEC 18013-5 second-edition Annex F, the reader-side mirror of
// MDOCIACARegistryConfig's issuer trust.
type MDOCRICALRegistryConfig struct {
	Enabled                 bool   `yaml:"enabled"`
	Name                    string `yaml:"name,omitempty"`
	Description             string `yaml:"description,omitempty"`
	RicalProviderURL        string `yaml:"rical_provider_url,omitempty"`
	RicalRootCertificatePEM string `yaml:"rical_root_certificate_pem,omitempty"`
	CacheTTL                string `yaml:"cache_ttl,omitempty"`
	HTTPTimeout             string `yaml:"http_timeout,omitempty"`
}

// VICALRegistryConfig contains VICAL (Verified Issuer Certificate Authority
// List) registry configuration - authenticates mdoc issuers per ISO/IEC
// 18013-5 Annex C, the issuer-trust counterpart to MDOCRICALRegistryConfig's
// reader trust.
type VICALRegistryConfig struct {
	Enabled                 bool   `yaml:"enabled"`
	Name                    string `yaml:"name,omitempty"`
	Description             string `yaml:"description,omitempty"`
	VicalProviderURL        string `yaml:"vical_provider_url,omitempty"`
	VicalRootCertificatePEM string `yaml:"vical_root_certificate_pem,omitempty"`
	CacheTTL                string `yaml:"cache_ttl,omitempty"`
	HTTPTimeout             string `yaml:"http_timeout,omitempty"`
}

// FIDOMDS3RegistryConfig contains FIDO Alliance Metadata Service v3
// registry configuration.
type FIDOMDS3RegistryConfig struct {
	Enabled            bool   `yaml:"enabled"`
	Name               string `yaml:"name,omitempty"`
	Description        string `yaml:"description,omitempty"`
	URL                string `yaml:"url,omitempty"`
	FetchTimeout       string `yaml:"fetch_timeout,omitempty"`
	RefreshInterval    string `yaml:"refresh_interval,omitempty"`
	RootCertificatePEM string `yaml:"root_certificate_pem,omitempty"`
	// CachePath persists the raw MDS3 blob to disk so a restart doesn't
	// have to block on (or fail because of) a live fetch - see
	// fidomds3.Config.CachePath's doc for the load/refresh semantics.
	CachePath string `yaml:"cache_path,omitempty"`
}

// LoTERegistryConfig contains ETSI TS 119 602 LoTE registry configuration.
type LoTERegistryConfig struct {
	Enabled             bool     `yaml:"enabled"`
	Name                string   `yaml:"name,omitempty"`
	Description         string   `yaml:"description,omitempty"`
	Sources             []string `yaml:"sources"`
	LoTLSources         []string `yaml:"lotl_sources,omitempty"`
	MaxDereferenceDepth int      `yaml:"max_dereference_depth,omitempty"`
	VerifyJWS           bool     `yaml:"verify_jws,omitempty"`
	FetchTimeout        string   `yaml:"fetch_timeout,omitempty"`
	RefreshInterval     string   `yaml:"refresh_interval,omitempty"`
}

// =============================================================================
// Policy Configuration
// =============================================================================

// PoliciesConfig contains trust policy configuration.
// Policies map action.name values to specific trust constraints.
type PoliciesConfig struct {
	// DefaultPolicy is the name of the policy to use when action.name is not specified
	DefaultPolicy string `yaml:"default_policy,omitempty"`

	// Policies is a map of policy name to policy configuration
	Policies map[string]*PolicyConfig `yaml:"policies,omitempty"`
}

// PolicyConfig defines a trust evaluation policy.
type PolicyConfig struct {
	// Description provides human-readable documentation
	Description string `yaml:"description,omitempty"`

	// Registries limits evaluation to specific registry names.
	// If empty, all registries are considered.
	Registries []string `yaml:"registries,omitempty"`

	// Constraints contains registry-agnostic constraints
	Constraints *PolicyConstraintsConfig `yaml:"constraints,omitempty"`

	// OIDFed contains OpenID Federation-specific constraints
	OIDFed *OIDFedPolicyConfig `yaml:"oidfed,omitempty"`

	// ETSI contains ETSI TSL-specific constraints
	ETSI *ETSIPolicyConfig `yaml:"etsi,omitempty"`

	// DID contains DID method-specific constraints (did:web, did:webvh)
	DID *DIDPolicyConfig `yaml:"did,omitempty"`

	// MDOCIACA contains mDOC IACA-specific constraints
	MDOCIACA *MDOCIACAPolicyConfig `yaml:"mdociaca,omitempty"`

	// FIDOMDS3 contains FIDO Alliance MDS3-specific constraints
	FIDOMDS3 *FIDOMDS3PolicyConfig `yaml:"fidomds3,omitempty"`
}

// PolicyConstraintsConfig contains registry-agnostic trust constraints.
type PolicyConstraintsConfig struct {
	// RequireKeyBinding requires that a key be provided and validated.
	RequireKeyBinding bool `yaml:"require_key_binding,omitempty"`

	// AllowedKeyTypes restricts accepted key types (e.g., ["x5c", "jwk"])
	AllowedKeyTypes []string `yaml:"allowed_key_types,omitempty"`
}

// OIDFedPolicyConfig contains OpenID Federation-specific policy constraints.
type OIDFedPolicyConfig struct {
	// RequiredTrustMarks specifies trust mark types that MUST be present
	RequiredTrustMarks []string `yaml:"required_trust_marks,omitempty"`

	// EntityTypes filters by OpenID Federation entity types
	EntityTypes []string `yaml:"entity_types,omitempty"`

	// MaxChainDepth limits trust chain resolution depth
	MaxChainDepth int `yaml:"max_chain_depth,omitempty"`

	// CredentialTypeTrustMarks maps credential type identifiers (VCT) to the
	// trust marks required for that type. When a request carries
	// credential_types, the matching trust marks are added to the required set.
	// Example: {"eu.europa.ec.eudi.pid.1": ["https://trust.eu/wallet/pid-issuer"]}
	CredentialTypeTrustMarks map[string][]string `yaml:"credential_type_trust_marks,omitempty"`
}

// ETSIPolicyConfig contains ETSI TSL-specific policy constraints.
// Every field here maps 1:1 onto registry.ETSIPolicyConstraints; keep the two
// in step, because a constraint with no field on this side is not rejected by
// the YAML decoder, it is silently discarded (see TestETSIPolicyConfigCoversConstraints).
type ETSIPolicyConfig struct {
	// ServiceTypes filters by ETSI service type URIs
	ServiceTypes []string `yaml:"service_types,omitempty"`

	// ServiceStatuses filters by ETSI service status URIs
	ServiceStatuses []string `yaml:"service_statuses,omitempty"`

	// Countries filters by country codes (e.g., ["DE", "FR"])
	Countries []string `yaml:"countries,omitempty"`

	// CredentialTypes specifies credential type identifiers (e.g., SD-JWT VCT
	// values) that the policy scopes the evaluation to.
	CredentialTypes []string `yaml:"credential_types,omitempty"`

	// RequiredCertPolicyOIDs specifies certificate policy OIDs that MUST appear
	// in the leaf certificate's Certificate Policies extension, used to
	// distinguish access certificates (ETSI TS 119 411-8) from generic TLS
	// certificates.
	RequiredCertPolicyOIDs []string `yaml:"required_cert_policy_oids,omitempty"`

	// ExtractRPIdentity controls whether RP identity information (Subject DN,
	// SANs, serial number) is extracted from the leaf certificate and returned
	// in the response trust metadata.
	ExtractRPIdentity bool `yaml:"extract_rp_identity,omitempty"`

	// AllowedAttributes lists the attribute names the RP is entitled to
	// request. Over-request detection per TS 119 475 does not run at all
	// unless this is set.
	AllowedAttributes []string `yaml:"allowed_attributes,omitempty"`

	// StrictEntitlementCheck rejects over-requesting RPs instead of returning
	// warnings alongside an allow decision.
	StrictEntitlementCheck bool `yaml:"strict_entitlement_check,omitempty"`

	// AllowIntermediaries accepts intermediary/broker presentation requests
	// and surfaces intermediary metadata. Defaults to false.
	AllowIntermediaries bool `yaml:"allow_intermediaries,omitempty"`
}

// DIDPolicyConfig contains DID method-specific policy constraints.
type DIDPolicyConfig struct {
	// AllowedDomains restricts DIDs to specific domains.
	// Supports wildcards: "*.example.com" matches "sub.example.com"
	AllowedDomains []string `yaml:"allowed_domains,omitempty"`

	// RequiredVerificationMethods requires specific verification method types.
	RequiredVerificationMethods []string `yaml:"required_verification_methods,omitempty"`

	// RequiredServices requires specific service types in the DID document.
	RequiredServices []string `yaml:"required_services,omitempty"`

	// RequireVerifiableHistory (did:webvh only) requires valid verifiable history.
	RequireVerifiableHistory bool `yaml:"require_verifiable_history,omitempty"`
}

// MDOCIACAPolicyConfig contains mDOC IACA-specific policy constraints.
type MDOCIACAPolicyConfig struct {
	// IssuerAllowlist restricts to specific credential issuers.
	IssuerAllowlist []string `yaml:"issuer_allowlist,omitempty"`

	// RequireIACAEndpoint requires the issuer to publish mdoc_iacas_uri.
	RequireIACAEndpoint bool `yaml:"require_iaca_endpoint,omitempty"`
}

// FIDOMDS3PolicyConfig contains FIDO Alliance MDS3-specific policy constraints.
type FIDOMDS3PolicyConfig struct {
	// AllowedAAGUIDs restricts trust to specific AAGUIDs, regardless of MDS3
	// certification status.
	AllowedAAGUIDs []string `yaml:"allowed_aaguids,omitempty"`

	// BlockedAAGUIDs denies specific AAGUIDs even if MDS3 certifies them.
	// Only applied when AllowedAAGUIDs is empty.
	BlockedAAGUIDs []string `yaml:"blocked_aaguids,omitempty"`
}

// ServerConfig contains HTTP server configuration settings.
type ServerConfig struct {
	Host        string    `yaml:"host"`
	Port        string    `yaml:"port"`
	ExternalURL string    `yaml:"external_url"` // External URL for PDP discovery (e.g., https://pdp.example.com)
	TLS         TLSConfig `yaml:"tls"`
}

// TLSConfig contains TLS/HTTPS server configuration settings.
type TLSConfig struct {
	Enabled  bool   `yaml:"enabled"`   // Enable TLS/HTTPS
	CertFile string `yaml:"cert_file"` // Path to TLS certificate file
	KeyFile  string `yaml:"key_file"`  // Path to TLS private key file
}

// LoggingConfig contains logging configuration settings.
type LoggingConfig struct {
	Level  string `yaml:"level"`
	Format string `yaml:"format"`
	Output string `yaml:"output"`
}

// SecurityConfig contains security-related configuration settings.
type SecurityConfig struct {
	RateLimitRPS         int      `yaml:"rate_limit_rps"`
	EnableCORS           bool     `yaml:"enable_cors"`
	AllowedOrigins       []string `yaml:"allowed_origins"`
	MaxResponseBodyBytes int      `yaml:"max_response_body_bytes,omitempty"` // Max HTTP response body size in bytes (default: 10MB)
}

// DefaultConfig returns a Config with sensible default values.
func DefaultConfig() *Config {
	return &Config{
		Server: ServerConfig{
			Host: "127.0.0.1",
			Port: "6001",
			TLS: TLSConfig{
				Enabled:  false,
				CertFile: "",
				KeyFile:  "",
			},
		},
		Logging: LoggingConfig{
			Level:  "info",
			Format: "text",
			Output: "stdout",
		},
		Security: SecurityConfig{
			RateLimitRPS:         100,
			EnableCORS:           false,
			AllowedOrigins:       []string{},
			MaxResponseBodyBytes: 10 * 1024 * 1024, // 10 MB
		},
	}
}

// LoadConfig loads configuration from a YAML file and applies environment variable overrides.
// It returns the merged configuration or an error if loading fails.
//
// Environment variables override configuration file values using the GT_ prefix:
//   - GT_HOST, GT_PORT for server settings
//   - GT_LOG_LEVEL, GT_LOG_FORMAT, GT_LOG_OUTPUT for logging
//   - GT_RATE_LIMIT_RPS for security settings
//
// If configPath is empty, only default values and environment variables are used.
func LoadConfig(configPath string) (*Config, error) {
	// Start with defaults
	cfg := DefaultConfig()

	// Load from file if path provided
	if configPath != "" {
		// Validate config path before loading
		if err := validation.ValidateConfigPath(configPath); err != nil {
			return nil, fmt.Errorf("invalid config path: %w", err)
		}

		data, err := os.ReadFile(configPath)
		if err != nil {
			return nil, fmt.Errorf("failed to read config file: %w", err)
		}

		if err := yaml.Unmarshal(data, cfg); err != nil {
			return nil, fmt.Errorf("failed to parse config file: %w", err)
		}

		cfg.unknownKeys = findUnknownKeys(data)
	}

	// Apply environment variable overrides
	applyEnvOverrides(cfg)

	return cfg, nil
}

// applyEnvOverrides applies environment variable overrides to the configuration.
// Environment variables take precedence over config file values.
func applyEnvOverrides(cfg *Config) {
	// Server configuration
	if v := os.Getenv("GT_HOST"); v != "" {
		cfg.Server.Host = v
	}
	if v := os.Getenv("GT_PORT"); v != "" {
		cfg.Server.Port = v
	}
	if v := os.Getenv("GT_EXTERNAL_URL"); v != "" {
		cfg.Server.ExternalURL = v
	}

	// TLS configuration
	if v := os.Getenv("GT_TLS_ENABLED"); v != "" {
		cfg.Server.TLS.Enabled = strings.ToLower(v) == "true" || v == "1"
	}
	if v := os.Getenv("GT_TLS_CERT_FILE"); v != "" {
		cfg.Server.TLS.CertFile = v
	}
	if v := os.Getenv("GT_TLS_KEY_FILE"); v != "" {
		cfg.Server.TLS.KeyFile = v
	}

	// Logging configuration
	if v := os.Getenv("GT_LOG_LEVEL"); v != "" {
		cfg.Logging.Level = v
	}
	if v := os.Getenv("GT_LOG_FORMAT"); v != "" {
		cfg.Logging.Format = v
	}
	if v := os.Getenv("GT_LOG_OUTPUT"); v != "" {
		cfg.Logging.Output = v
	}

	// Security configuration
	if v := os.Getenv("GT_RATE_LIMIT_RPS"); v != "" {
		if rps, err := strconv.Atoi(v); err == nil {
			cfg.Security.RateLimitRPS = rps
		}
	}
	if v := os.Getenv("GT_ENABLE_CORS"); v != "" {
		cfg.Security.EnableCORS = strings.ToLower(v) == "true" || v == "1"
	}
	if v := os.Getenv("GT_ALLOWED_ORIGINS"); v != "" {
		cfg.Security.AllowedOrigins = strings.Split(v, ",")
	}
	if v := os.Getenv("GT_MAX_RESPONSE_BODY_BYTES"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			cfg.Security.MaxResponseBodyBytes = n
		}
	}
}

// Validate checks if the configuration is valid.
// It returns an error if any configuration value is invalid.
func (c *Config) Validate() error {
	// Validate server configuration
	if c.Server.Port == "" {
		return fmt.Errorf("server port cannot be empty")
	}
	// Validate TLS configuration
	if c.Server.TLS.Enabled {
		if c.Server.TLS.CertFile == "" {
			return fmt.Errorf("TLS certificate file is required when TLS is enabled")
		}
		if c.Server.TLS.KeyFile == "" {
			return fmt.Errorf("TLS key file is required when TLS is enabled")
		}
		// Check if certificate and key files exist
		if err := validation.ValidateFilePath(c.Server.TLS.CertFile); err != nil {
			return fmt.Errorf("invalid TLS certificate file: %w", err)
		}
		if err := validation.ValidateFilePath(c.Server.TLS.KeyFile); err != nil {
			return fmt.Errorf("invalid TLS key file: %w", err)
		}
	}

	// Validate logging configuration
	validLevels := map[string]bool{"debug": true, "info": true, "warn": true, "error": true, "fatal": true}
	if !validLevels[strings.ToLower(c.Logging.Level)] {
		return fmt.Errorf("invalid log level: %s", c.Logging.Level)
	}

	validFormats := map[string]bool{"text": true, "json": true}
	if !validFormats[strings.ToLower(c.Logging.Format)] {
		return fmt.Errorf("invalid log format: %s", c.Logging.Format)
	}

	// Validate security configuration
	if c.Security.RateLimitRPS <= 0 {
		return fmt.Errorf("rate limit RPS must be positive")
	}

	// Validate ETSI registry configuration
	if c.Registries.ETSI != nil && c.Registries.ETSI.Enabled {
		if c.Registries.ETSI.RequireSignature && c.Registries.ETSI.LOTLSignerBundle == "" {
			return fmt.Errorf("ETSI registry: lotl_signer_bundle is required when require_signature is true")
		}
	}

	return nil
}
