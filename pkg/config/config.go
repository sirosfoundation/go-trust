// Package config provides configuration management for the Go-Trust application.
// It supports loading configuration from YAML files and environment variables.
package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

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
}

// RegistriesConfig contains configuration for all trust registries.
type RegistriesConfig struct {
	ETSI      *ETSIRegistryConfig      `yaml:"etsi,omitempty"`
	Whitelist *WhitelistRegistryConfig `yaml:"whitelist,omitempty"`
	// OpenID Federation registry
	OIDFed *OIDFedRegistryConfig `yaml:"oidfed,omitempty"`
	// DID method registries
	DIDWeb   *DIDWebRegistryConfig   `yaml:"didweb,omitempty"`
	DIDWebVH *DIDWebVHRegistryConfig `yaml:"didwebvh,omitempty"`
	DIDJWKS  *DIDJWKSRegistryConfig  `yaml:"didjwks,omitempty"`
	// ETSI TS 119 602 LoTE registry
	LoTE *LoTERegistryConfig `yaml:"lote,omitempty"`
	// mDOC IACA registry
	MDOCIACA *MDOCIACARegistryConfig `yaml:"mdociaca,omitempty"`
	// Static test registries
	AlwaysTrusted *StaticRegistryConfig `yaml:"always_trusted,omitempty"`
	NeverTrusted  *StaticRegistryConfig `yaml:"never_trusted,omitempty"`
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
}

// ETSIPolicyConfig contains ETSI TSL-specific policy constraints.
type ETSIPolicyConfig struct {
	// ServiceTypes filters by ETSI service type URIs
	ServiceTypes []string `yaml:"service_types,omitempty"`

	// ServiceStatuses filters by ETSI service status URIs
	ServiceStatuses []string `yaml:"service_statuses,omitempty"`

	// Countries filters by country codes (e.g., ["DE", "FR"])
	Countries []string `yaml:"countries,omitempty"`
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

// ServerConfig contains HTTP server configuration settings.
type ServerConfig struct {
	Host        string        `yaml:"host"`
	Port        string        `yaml:"port"`
	Frequency   time.Duration `yaml:"frequency"`
	ExternalURL string        `yaml:"external_url"` // External URL for PDP discovery (e.g., https://pdp.example.com)
	TLS         TLSConfig     `yaml:"tls"`
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
			Host:      "127.0.0.1",
			Port:      "6001",
			Frequency: 5 * time.Minute,
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
//   - GT_HOST, GT_PORT, GT_FREQUENCY for server settings
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
	if v := os.Getenv("GT_FREQUENCY"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			cfg.Server.Frequency = d
		}
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
	if c.Server.Frequency <= 0 {
		return fmt.Errorf("server frequency must be positive")
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
