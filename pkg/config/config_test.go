package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()

	// Test server defaults
	if cfg.Server.Host != "127.0.0.1" {
		t.Errorf("Default host = %v, want %v", cfg.Server.Host, "127.0.0.1")
	}
	if cfg.Server.Port != "6001" {
		t.Errorf("Default port = %v, want %v", cfg.Server.Port, "6001")
	}

	// Test logging defaults
	if cfg.Logging.Level != "info" {
		t.Errorf("Default log level = %v, want %v", cfg.Logging.Level, "info")
	}
	if cfg.Logging.Format != "text" {
		t.Errorf("Default log format = %v, want %v", cfg.Logging.Format, "text")
	}
	if cfg.Logging.Output != "stdout" {
		t.Errorf("Default log output = %v, want %v", cfg.Logging.Output, "stdout")
	}

	// Test security defaults
	if cfg.Security.RateLimitRPS != 100 {
		t.Errorf("Default rate limit = %v, want %v", cfg.Security.RateLimitRPS, 100)
	}
	if cfg.Security.EnableCORS {
		t.Error("Default CORS should be disabled")
	}
}

func TestLoadConfigFromFile(t *testing.T) {
	// Create temporary config file
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")

	configContent := `
server:
  host: "0.0.0.0"
  port: "8080"
  frequency: "10m"

logging:
  level: "debug"
  format: "json"
  output: "/var/log/go-trust.log"

security:
  rate_limit_rps: 200
  enable_cors: true
  allowed_origins:
    - "https://example.com"
    - "https://test.com"
`

	if err := os.WriteFile(configPath, []byte(configContent), 0644); err != nil {
		t.Fatalf("Failed to write config file: %v", err)
	}

	cfg, err := LoadConfig(configPath)
	if err != nil {
		t.Fatalf("LoadConfig() error = %v", err)
	}

	// Verify server configuration
	if cfg.Server.Host != "0.0.0.0" {
		t.Errorf("Host = %v, want %v", cfg.Server.Host, "0.0.0.0")
	}
	if cfg.Server.Port != "8080" {
		t.Errorf("Port = %v, want %v", cfg.Server.Port, "8080")
	}

	// Verify logging configuration
	if cfg.Logging.Level != "debug" {
		t.Errorf("Log level = %v, want %v", cfg.Logging.Level, "debug")
	}
	if cfg.Logging.Format != "json" {
		t.Errorf("Log format = %v, want %v", cfg.Logging.Format, "json")
	}
	if cfg.Logging.Output != "/var/log/go-trust.log" {
		t.Errorf("Log output = %v, want %v", cfg.Logging.Output, "/var/log/go-trust.log")
	}

	// Verify security configuration
	if cfg.Security.RateLimitRPS != 200 {
		t.Errorf("Rate limit RPS = %v, want %v", cfg.Security.RateLimitRPS, 200)
	}
	if !cfg.Security.EnableCORS {
		t.Error("CORS should be enabled")
	}
	if len(cfg.Security.AllowedOrigins) != 2 {
		t.Errorf("Allowed origins count = %v, want %v", len(cfg.Security.AllowedOrigins), 2)
	}
}

func TestLoadConfigWhitelistAdditionalTrustedRoots(t *testing.T) {
	// Regression test: pkg/registry/static.WhitelistConfig.AdditionalTrustedRoots
	// (go-trust#123) was never mirrored onto this package's YAML-facing
	// WhitelistRegistryConfig struct, so the field was silently dropped for
	// every YAML-config-based deployment - unit tests never caught this
	// because they construct static.WhitelistConfig directly in Go,
	// bypassing YAML entirely. Confirmed live: verifier.multipaz.org's
	// trusted root was never actually reaching the whitelist registry
	// despite correct-looking config.
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")

	configContent := `
server:
  host: "0.0.0.0"
  port: "8080"

registries:
  whitelist:
    enabled: true
    name: test
    lists:
      verifiers:
        - x509_san_dns:verifier.example.com
    actions:
      credential-verifier: verifiers
    trust_x509_via_system_ca: true
    additional_trusted_roots:
      - |
        -----BEGIN CERTIFICATE-----
        MIIBXXXXfakeXXXXXXcertXXXX
        -----END CERTIFICATE-----
`

	if err := os.WriteFile(configPath, []byte(configContent), 0644); err != nil {
		t.Fatalf("Failed to write config file: %v", err)
	}

	cfg, err := LoadConfig(configPath)
	if err != nil {
		t.Fatalf("LoadConfig() error = %v", err)
	}

	if cfg.Registries.Whitelist == nil {
		t.Fatal("expected whitelist registry config to be present")
	}
	if !cfg.Registries.Whitelist.TrustX509ViaSystemCA {
		t.Error("expected TrustX509ViaSystemCA to be true")
	}
	if len(cfg.Registries.Whitelist.AdditionalTrustedRoots) != 1 {
		t.Fatalf("AdditionalTrustedRoots count = %d, want 1 - the field was dropped during YAML parsing",
			len(cfg.Registries.Whitelist.AdditionalTrustedRoots))
	}
	if !strings.Contains(cfg.Registries.Whitelist.AdditionalTrustedRoots[0], "BEGIN CERTIFICATE") {
		t.Errorf("AdditionalTrustedRoots[0] doesn't look like a PEM cert: %q",
			cfg.Registries.Whitelist.AdditionalTrustedRoots[0])
	}
}

func TestLoadConfigDIDLocalRegistry(t *testing.T) {
	// Regression test: config is decoded with a non-strict yaml.Unmarshal, so
	// a wrong or stale key on DIDLocal leaves the field nil and the registry
	// simply absent. Nothing errors; did:key and did:jwk just stop resolving,
	// and the failure surfaces far away as an unresolvable DID. The key was
	// renamed from did_local to didlocal, which is exactly the kind of change
	// that fails this way.
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")

	configContent := `
server:
  host: "0.0.0.0"
  port: "8080"

registries:
  didlocal:
    enabled: true
    description: "Self-contained DID methods"
    methods:
      - "key"
      - "jwk"
`

	if err := os.WriteFile(configPath, []byte(configContent), 0644); err != nil {
		t.Fatalf("Failed to write config file: %v", err)
	}

	cfg, err := LoadConfig(configPath)
	if err != nil {
		t.Fatalf("LoadConfig() error = %v", err)
	}

	if cfg.Registries.DIDLocal == nil {
		t.Fatal("registries.didlocal was not parsed - the yaml tag and this key have diverged")
	}
	if !cfg.Registries.DIDLocal.Enabled {
		t.Error("expected didlocal registry to be enabled")
	}
	if got := cfg.Registries.DIDLocal.Methods; len(got) != 2 || got[0] != "key" || got[1] != "jwk" {
		t.Errorf("Methods = %v, want [key jwk]", got)
	}
}

func TestLoadConfigDIDLocalIgnoresTheOldKey(t *testing.T) {
	// The previous spelling is not an alias. Pinning the behaviour so the
	// silent-ignore is a stated property rather than a surprise: a deployment
	// still using did_local gets no registry and no error.
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")

	configContent := `
server:
  host: "0.0.0.0"
  port: "8080"

registries:
  did_local:
    enabled: true
    methods:
      - "jwk"
`

	if err := os.WriteFile(configPath, []byte(configContent), 0644); err != nil {
		t.Fatalf("Failed to write config file: %v", err)
	}

	cfg, err := LoadConfig(configPath)
	if err != nil {
		t.Fatalf("LoadConfig() error = %v", err)
	}

	if cfg.Registries.DIDLocal != nil {
		t.Error("did_local should no longer populate DIDLocal; if it does, the rename was incomplete")
	}
}

func TestLoadConfigWithEnvOverrides(t *testing.T) {
	// Set environment variables
	os.Setenv("GT_HOST", "192.168.1.1")
	os.Setenv("GT_PORT", "9000")
	os.Setenv("GT_FREQUENCY", "15m")
	os.Setenv("GT_LOG_LEVEL", "warn")
	os.Setenv("GT_LOG_FORMAT", "json")
	os.Setenv("GT_LOG_OUTPUT", "stderr")
	os.Setenv("GT_RATE_LIMIT_RPS", "500")
	os.Setenv("GT_ENABLE_CORS", "true")

	defer func() {
		// Clean up environment variables
		os.Unsetenv("GT_HOST")
		os.Unsetenv("GT_PORT")
		os.Unsetenv("GT_FREQUENCY")
		os.Unsetenv("GT_LOG_LEVEL")
		os.Unsetenv("GT_LOG_FORMAT")
		os.Unsetenv("GT_LOG_OUTPUT")
		os.Unsetenv("GT_RATE_LIMIT_RPS")
		os.Unsetenv("GT_ENABLE_CORS")
	}()

	cfg, err := LoadConfig("")
	if err != nil {
		t.Fatalf("LoadConfig() error = %v", err)
	}

	// Verify environment variables were applied
	if cfg.Server.Host != "192.168.1.1" {
		t.Errorf("Host = %v, want %v", cfg.Server.Host, "192.168.1.1")
	}
	if cfg.Server.Port != "9000" {
		t.Errorf("Port = %v, want %v", cfg.Server.Port, "9000")
	}
	if cfg.Logging.Level != "warn" {
		t.Errorf("Log level = %v, want %v", cfg.Logging.Level, "warn")
	}
	if cfg.Logging.Format != "json" {
		t.Errorf("Log format = %v, want %v", cfg.Logging.Format, "json")
	}
	if cfg.Logging.Output != "stderr" {
		t.Errorf("Log output = %v, want %v", cfg.Logging.Output, "stderr")
	}
	if cfg.Security.RateLimitRPS != 500 {
		t.Errorf("Rate limit RPS = %v, want %v", cfg.Security.RateLimitRPS, 500)
	}
	if !cfg.Security.EnableCORS {
		t.Error("CORS should be enabled")
	}
}

func TestLoadConfigInvalidFile(t *testing.T) {
	_, err := LoadConfig("/nonexistent/config.yaml")
	if err == nil {
		t.Error("LoadConfig() should fail with nonexistent file")
	}
}

func TestLoadConfigInvalidYAML(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "invalid.yaml")

	if err := os.WriteFile(configPath, []byte("invalid: yaml: content: ["), 0644); err != nil {
		t.Fatalf("Failed to write config file: %v", err)
	}

	_, err := LoadConfig(configPath)
	if err == nil {
		t.Error("LoadConfig() should fail with invalid YAML")
	}
}

func TestValidateConfig(t *testing.T) {
	tests := []struct {
		name    string
		config  *Config
		wantErr bool
	}{
		{
			name:    "Valid default config",
			config:  DefaultConfig(),
			wantErr: false,
		},
		{
			name: "Empty port",
			config: &Config{
				Server:   ServerConfig{Host: "127.0.0.1", Port: ""},
				Logging:  LoggingConfig{Level: "info", Format: "text", Output: "stdout"},
				Security: SecurityConfig{RateLimitRPS: 100},
			},
			wantErr: true,
		},
		{
			name: "Invalid log level",
			config: &Config{
				Server:   ServerConfig{Host: "127.0.0.1", Port: "6001"},
				Logging:  LoggingConfig{Level: "invalid", Format: "text", Output: "stdout"},
				Security: SecurityConfig{RateLimitRPS: 100},
			},
			wantErr: true,
		},
		{
			name: "Invalid log format",
			config: &Config{
				Server:   ServerConfig{Host: "127.0.0.1", Port: "6001"},
				Logging:  LoggingConfig{Level: "info", Format: "invalid", Output: "stdout"},
				Security: SecurityConfig{RateLimitRPS: 100},
			},
			wantErr: true,
		},
		{
			// 0 is the documented way to disable rate limiting. It used to be
			// rejected, which made "0 disables" impossible to configure.
			name: "Zero rate limit disables rather than failing",
			config: &Config{
				Server:   ServerConfig{Host: "127.0.0.1", Port: "6001"},
				Logging:  LoggingConfig{Level: "info", Format: "text", Output: "stdout"},
				Security: SecurityConfig{RateLimitRPS: 0},
			},
			wantErr: false,
		},
		{
			name: "Negative rate limit",
			config: &Config{
				Server:   ServerConfig{Host: "127.0.0.1", Port: "6001"},
				Logging:  LoggingConfig{Level: "info", Format: "text", Output: "stdout"},
				Security: SecurityConfig{RateLimitRPS: -1},
			},
			wantErr: true,
		},
		{
			name: "ETSI RequireSignature without LOTLSignerBundle",
			config: &Config{
				Server:   ServerConfig{Host: "127.0.0.1", Port: "6001"},
				Logging:  LoggingConfig{Level: "info", Format: "text", Output: "stdout"},
				Security: SecurityConfig{RateLimitRPS: 100},
				Registries: RegistriesConfig{
					ETSI: &ETSIRegistryConfig{
						Enabled:          true,
						RequireSignature: true,
						LOTLSignerBundle: "",
					},
				},
			},
			wantErr: true,
		},
		{
			name: "ETSI RequireSignature with LOTLSignerBundle",
			config: &Config{
				Server:   ServerConfig{Host: "127.0.0.1", Port: "6001"},
				Logging:  LoggingConfig{Level: "info", Format: "text", Output: "stdout"},
				Security: SecurityConfig{RateLimitRPS: 100},
				Registries: RegistriesConfig{
					ETSI: &ETSIRegistryConfig{
						Enabled:          true,
						RequireSignature: true,
						LOTLSignerBundle: "/path/to/signers.pem",
					},
				},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestEnvOverridesWithSecurityConfig(t *testing.T) {
	// Set security environment variables
	os.Setenv("GT_ALLOWED_ORIGINS", "https://app1.com,https://app2.com")

	defer func() {
		os.Unsetenv("GT_ALLOWED_ORIGINS")
	}()

	cfg, err := LoadConfig("")
	if err != nil {
		t.Fatalf("LoadConfig() error = %v", err)
	}

	// Verify security environment variables
	if len(cfg.Security.AllowedOrigins) != 2 {
		t.Errorf("Allowed origins count = %v, want %v", len(cfg.Security.AllowedOrigins), 2)
	}
}

func TestLoadConfigWithPolicies(t *testing.T) {
	// Create temporary config file with policies
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")

	configContent := `
server:
  host: "127.0.0.1"
  port: "6001"

policies:
  default_policy: credential-verifier

  policies:
    credential-issuer:
      description: "Trust requirements for credential issuers"
      etsi:
        service_types:
          - "http://uri.etsi.org/TrstSvc/Svctype/QCert"
          - "http://uri.etsi.org/TrstSvc/Svctype/QCertForESeal"
        service_statuses:
          - "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted"
      oidfed:
        entity_types:
          - "openid_credential_issuer"
        required_trust_marks:
          - "https://dc4eu.eu/tm/issuer"
      did:
        allowed_domains:
          - "*.example.com"
        require_verifiable_history: true

    credential-verifier:
      description: "Trust requirements for credential verifiers"
      registries:
        - "oidfed-registry"
        - "etsi-registry"
      constraints:
        require_key_binding: true
        allowed_key_types:
          - "x5c"
          - "jwk"
      oidfed:
        entity_types:
          - "openid_relying_party"

    mdl-issuer:
      description: "Trust requirements for mDL issuers"
      mdociaca:
        issuer_allowlist:
          - "https://mdl-issuer.example.com"
        require_iaca_endpoint: true

    wscd-previewsign-provision:
      description: "Trust requirements for WSCD previewSign provisioning"
      fidomds3:
        allowed_aaguids:
          - "0132d110-bf4e-4208-a403-ab4f5f12efe5"
`

	if err := os.WriteFile(configPath, []byte(configContent), 0644); err != nil {
		t.Fatalf("Failed to write config file: %v", err)
	}

	cfg, err := LoadConfig(configPath)
	if err != nil {
		t.Fatalf("LoadConfig() error = %v", err)
	}

	// Verify default policy
	if cfg.Policies.DefaultPolicy != "credential-verifier" {
		t.Errorf("DefaultPolicy = %v, want %v", cfg.Policies.DefaultPolicy, "credential-verifier")
	}

	// Verify policies count
	if len(cfg.Policies.Policies) != 4 {
		t.Errorf("Policies count = %v, want %v", len(cfg.Policies.Policies), 4)
	}

	// Verify credential-issuer policy
	issuerPolicy := cfg.Policies.Policies["credential-issuer"]
	if issuerPolicy == nil {
		t.Fatal("credential-issuer policy not found")
	}
	if issuerPolicy.Description != "Trust requirements for credential issuers" {
		t.Errorf("Description = %v, want %v", issuerPolicy.Description, "Trust requirements for credential issuers")
	}

	// Verify ETSI constraints
	if issuerPolicy.ETSI == nil {
		t.Fatal("ETSI constraints not found")
	}
	if len(issuerPolicy.ETSI.ServiceTypes) != 2 {
		t.Errorf("ETSI ServiceTypes count = %v, want %v", len(issuerPolicy.ETSI.ServiceTypes), 2)
	}

	// Verify OIDFED constraints
	if issuerPolicy.OIDFed == nil {
		t.Fatal("OIDFed constraints not found")
	}
	if len(issuerPolicy.OIDFed.EntityTypes) != 1 {
		t.Errorf("OIDFed EntityTypes count = %v, want %v", len(issuerPolicy.OIDFed.EntityTypes), 1)
	}
	if len(issuerPolicy.OIDFed.RequiredTrustMarks) != 1 {
		t.Errorf("OIDFed RequiredTrustMarks count = %v, want %v", len(issuerPolicy.OIDFed.RequiredTrustMarks), 1)
	}

	// Verify DID constraints
	if issuerPolicy.DID == nil {
		t.Fatal("DID constraints not found")
	}
	if len(issuerPolicy.DID.AllowedDomains) != 1 {
		t.Errorf("DID AllowedDomains count = %v, want %v", len(issuerPolicy.DID.AllowedDomains), 1)
	}
	if !issuerPolicy.DID.RequireVerifiableHistory {
		t.Error("DID RequireVerifiableHistory should be true")
	}

	// Verify credential-verifier policy
	verifierPolicy := cfg.Policies.Policies["credential-verifier"]
	if verifierPolicy == nil {
		t.Fatal("credential-verifier policy not found")
	}
	if len(verifierPolicy.Registries) != 2 {
		t.Errorf("Registries count = %v, want %v", len(verifierPolicy.Registries), 2)
	}
	if verifierPolicy.Constraints == nil {
		t.Fatal("Constraints not found")
	}
	if !verifierPolicy.Constraints.RequireKeyBinding {
		t.Error("RequireKeyBinding should be true")
	}
	if len(verifierPolicy.Constraints.AllowedKeyTypes) != 2 {
		t.Errorf("AllowedKeyTypes count = %v, want %v", len(verifierPolicy.Constraints.AllowedKeyTypes), 2)
	}

	// Verify mdl-issuer policy
	mdlPolicy := cfg.Policies.Policies["mdl-issuer"]
	if mdlPolicy == nil {
		t.Fatal("mdl-issuer policy not found")
	}
	if mdlPolicy.MDOCIACA == nil {
		t.Fatal("MDOCIACA constraints not found")
	}
	if len(mdlPolicy.MDOCIACA.IssuerAllowlist) != 1 {
		t.Errorf("MDOCIACA IssuerAllowlist count = %v, want %v", len(mdlPolicy.MDOCIACA.IssuerAllowlist), 1)
	}
	if !mdlPolicy.MDOCIACA.RequireIACAEndpoint {
		t.Error("MDOCIACA RequireIACAEndpoint should be true")
	}

	// Verify wscd-previewsign-provision policy
	wscdPolicy := cfg.Policies.Policies["wscd-previewsign-provision"]
	if wscdPolicy == nil {
		t.Fatal("wscd-previewsign-provision policy not found")
	}
	if wscdPolicy.FIDOMDS3 == nil {
		t.Fatal("FIDOMDS3 constraints not found")
	}
	if len(wscdPolicy.FIDOMDS3.AllowedAAGUIDs) != 1 {
		t.Errorf("FIDOMDS3 AllowedAAGUIDs count = %v, want %v", len(wscdPolicy.FIDOMDS3.AllowedAAGUIDs), 1)
	}
}

func TestLoadConfigPolicyEnrichmentKeys(t *testing.T) {
	// Regression test for the six ETSI enrichment keys (and the OIDFed
	// credential-type trust marks) that pkg/registry implemented but
	// pkg/config had no field for. Because decoding is non-strict, writing
	// them produced silence and no enforcement rather than an error — in
	// particular over-request detection, which does not run at all unless
	// allowed_attributes is set.
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")

	configContent := `
server:
  host: "0.0.0.0"
  port: "8080"

policies:
  default_policy: credential-verifier
  policies:
    credential-verifier:
      description: "Relying parties"
      constraints:
        allowed_key_types: ["x5c"]
        require_key_binding: true
      etsi:
        credential_types: ["eu.europa.ec.eudi.pid.1"]
        required_cert_policy_oids: ["0.4.0.194112.1.0"]
        extract_rp_identity: true
        allowed_attributes: ["given_name", "family_name"]
        strict_entitlement_check: true
        allow_intermediaries: true
      oidfed:
        credential_type_trust_marks:
          eu.europa.ec.eudi.pid.1:
            - "https://trust.eu/wallet/pid-issuer"
`

	if err := os.WriteFile(configPath, []byte(configContent), 0644); err != nil {
		t.Fatalf("Failed to write config file: %v", err)
	}

	cfg, err := LoadConfig(configPath)
	if err != nil {
		t.Fatalf("LoadConfig() error = %v", err)
	}

	policy, ok := cfg.Policies.Policies["credential-verifier"]
	if !ok || policy == nil {
		t.Fatal("policies.credential-verifier was not parsed")
	}

	if policy.Constraints == nil || !policy.Constraints.RequireKeyBinding {
		t.Error("constraints.require_key_binding was not parsed")
	}

	etsi := policy.ETSI
	if etsi == nil {
		t.Fatal("policies.credential-verifier.etsi was not parsed")
	}
	if got := etsi.CredentialTypes; len(got) != 1 || got[0] != "eu.europa.ec.eudi.pid.1" {
		t.Errorf("credential_types = %v, want [eu.europa.ec.eudi.pid.1]", got)
	}
	if got := etsi.RequiredCertPolicyOIDs; len(got) != 1 || got[0] != "0.4.0.194112.1.0" {
		t.Errorf("required_cert_policy_oids = %v, want [0.4.0.194112.1.0]", got)
	}
	if !etsi.ExtractRPIdentity {
		t.Error("extract_rp_identity was not parsed")
	}
	if got := etsi.AllowedAttributes; len(got) != 2 || got[0] != "given_name" {
		t.Errorf("allowed_attributes = %v, want [given_name family_name]", got)
	}
	if !etsi.StrictEntitlementCheck {
		t.Error("strict_entitlement_check was not parsed")
	}
	if !etsi.AllowIntermediaries {
		t.Error("allow_intermediaries was not parsed")
	}

	if policy.OIDFed == nil {
		t.Fatal("policies.credential-verifier.oidfed was not parsed")
	}
	marks := policy.OIDFed.CredentialTypeTrustMarks["eu.europa.ec.eudi.pid.1"]
	if len(marks) != 1 || marks[0] != "https://trust.eu/wallet/pid-issuer" {
		t.Errorf("credential_type_trust_marks = %v, want one pid-issuer entry",
			policy.OIDFed.CredentialTypeTrustMarks)
	}
}

func TestLoadConfigReportsUnknownKeys(t *testing.T) {
	// Item 5 of #176: decoding is non-strict, so an unknown key is discarded
	// rather than rejected, and a typo is indistinguishable from a real key.
	// The keys below are the three shapes that actually bite: a renamed key
	// (did_local -> didlocal, #173), a misspelling, and a typo nested inside
	// map[string]*PolicyConfig, which is the case a naive strict decode of
	// only the top level would miss.
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")

	configContent := `
server:
  host: "0.0.0.0"
  port: "8080"

registries:
  did_local:
    enabled: true
    methods: ["key", "jwk"]

security:
  enable_crs: true

policies:
  policies:
    credential-verifier:
      etsi:
        strict_entitlment_check: true
`

	if err := os.WriteFile(configPath, []byte(configContent), 0644); err != nil {
		t.Fatalf("Failed to write config file: %v", err)
	}

	cfg, err := LoadConfig(configPath)
	if err != nil {
		t.Fatalf("LoadConfig() error = %v; unknown keys must warn, not fail", err)
	}

	unknown := cfg.UnknownKeys()
	byField := make(map[string]UnknownKey, len(unknown))
	for _, k := range unknown {
		byField[k.Field] = k
	}

	for _, want := range []struct {
		field   string
		line    int
		section string
	}{
		{"did_local", 7, "config.RegistriesConfig"},
		{"enable_crs", 12, "config.SecurityConfig"},
		{"strict_entitlment_check", 18, "config.ETSIPolicyConfig"},
	} {
		got, ok := byField[want.field]
		if !ok {
			t.Errorf("%s was not reported as unknown", want.field)
			continue
		}
		if got.Line != want.line {
			t.Errorf("%s reported at line %d, want %d", want.field, got.Line, want.line)
		}
		if got.Type != want.section {
			t.Errorf("%s reported in %s, want %s", want.field, got.Type, want.section)
		}
	}

	if len(unknown) != 3 {
		t.Errorf("UnknownKeys() = %v, want exactly 3 entries", unknown)
	}
}

func TestLoadConfigCleanConfigReportsNothing(t *testing.T) {
	// The converse, and the one that matters for the eventual flip to a hard
	// error: a correct config must produce no warnings at all, or the warning
	// becomes noise operators learn to ignore.
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")

	configContent := `
server:
  host: "0.0.0.0"
  port: "8080"

registries:
  didlocal:
    enabled: true
    methods: ["key", "jwk"]

security:
  enable_cors: true

policies:
  policies:
    credential-verifier:
      etsi:
        strict_entitlement_check: true
`

	if err := os.WriteFile(configPath, []byte(configContent), 0644); err != nil {
		t.Fatalf("Failed to write config file: %v", err)
	}

	cfg, err := LoadConfig(configPath)
	if err != nil {
		t.Fatalf("LoadConfig() error = %v", err)
	}
	if got := cfg.UnknownKeys(); len(got) != 0 {
		t.Errorf("UnknownKeys() = %v, want none for a correct config", got)
	}
}

func TestExampleConfigHasNoUnknownKeys(t *testing.T) {
	// example/config.yaml is what operators copy. If it carries a key the
	// decoder throws away, everyone who starts from it inherits the problem.
	// Absolute, so the path validator's traversal check does not trip on the
	// "../.." this test needs to reach the repo root.
	path, err := filepath.Abs(filepath.Join("..", "..", "example", "config.yaml"))
	if err != nil {
		t.Fatalf("resolving example/config.yaml: %v", err)
	}
	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("LoadConfig(example/config.yaml) error = %v", err)
	}
	for _, key := range cfg.UnknownKeys() {
		t.Errorf("example/config.yaml carries an unknown key: %s", key)
	}
}

func TestUnknownKeyString(t *testing.T) {
	key := UnknownKey{Line: 42, Field: "did_local", Type: "config.RegistriesConfig"}
	if got, want := key.String(), "did_local (line 42, in config.RegistriesConfig)"; got != want {
		t.Errorf("String() = %q, want %q", got, want)
	}
}

func TestFindUnknownKeysIgnoresNonFieldErrors(t *testing.T) {
	// A strict decode reports type mismatches alongside unknown fields.
	// findUnknownKeys must return only the latter: a coerced value is not a
	// discarded key, and reporting it as one would send an operator looking
	// for a typo that is not there.
	//
	// Tested against findUnknownKeys directly rather than through
	// LoadConfig, because the non-strict decode rejects a type mismatch too,
	// so LoadConfig never reaches this function with such input. The filter
	// is defensive, which is exactly why it needs pinning.
	data := []byte(`
registries:
  etsi:
    enabled: true
    max_ref_depth: "not-a-number"
  did_local:
    enabled: true
`)

	keys := findUnknownKeys(data)
	if len(keys) != 1 {
		t.Fatalf("findUnknownKeys() = %v, want exactly the did_local entry", keys)
	}
	if keys[0].Field != "did_local" {
		t.Errorf("Field = %q, want did_local", keys[0].Field)
	}
}

func TestFindUnknownKeysOnUnparseableYAMLIsQuiet(t *testing.T) {
	// Not valid YAML at all: LoadConfig fails first, and findUnknownKeys
	// must not be the thing that reports it.
	if got := findUnknownKeys([]byte("this: [is: not: yaml")); got != nil {
		t.Errorf("findUnknownKeys() = %v, want nil", got)
	}
	if got := findUnknownKeys(nil); got != nil {
		t.Errorf("findUnknownKeys(nil) = %v, want nil", got)
	}
}

func TestLoadConfigEMRTDRegistry(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "config.yaml")
	content := `
registries:
  emrtd:
    enabled: true
    name: emrtd-csca
    anchors_dir: /etc/go-trust/emrtd/anchors
    crls_dir: /etc/go-trust/emrtd/crls
    watch: true
policies:
  policies:
    emrtd-document-signer:
      registries: [emrtd-csca]
      constraints: {require_key_binding: true, allowed_key_types: [x5c]}
`
	if err := os.WriteFile(configPath, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadConfig(configPath)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	e := cfg.Registries.EMRTD
	if e == nil || !e.Enabled || e.Name != "emrtd-csca" || e.AnchorsDir != "/etc/go-trust/emrtd/anchors" ||
		e.CRLsDir != "/etc/go-trust/emrtd/crls" || !e.Watch {
		t.Fatalf("unexpected emrtd config: %+v", e)
	}
	if u := cfg.UnknownKeys(); len(u) != 0 {
		t.Fatalf("emrtd keys reported unknown: %v", u)
	}
	p := cfg.Policies.Policies["emrtd-document-signer"]
	if p == nil || p.Constraints == nil || !p.Constraints.RequireKeyBinding || len(p.Constraints.AllowedKeyTypes) != 1 {
		t.Fatalf("unexpected policy: %+v", p)
	}
}

func TestValidateEMRTDPolicy(t *testing.T) {
	n := func(v int) *int { return &v }
	cases := []struct {
		name    string
		e       *EMRTDPolicyConfig
		wantErr string
	}{
		{"absent", nil, ""},
		{"default", &EMRTDPolicyConfig{}, ""},
		{"ignore", &EMRTDPolicyConfig{PathLenMode: "ignore"}, ""},
		{"enforce", &EMRTDPolicyConfig{PathLenMode: "enforce"}, ""},
		{"override zero", &EMRTDPolicyConfig{PathLenOverride: n(0)}, ""},
		{"unknown mode", &EMRTDPolicyConfig{PathLenMode: "strict"}, "path_len_mode"},
		{"negative override", &EMRTDPolicyConfig{PathLenOverride: n(-2)}, "path_len_override"},
		{"ignore with override", &EMRTDPolicyConfig{PathLenMode: "ignore", PathLenOverride: n(1)}, "conflicts"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := DefaultConfig()
			cfg.Policies.Policies = map[string]*PolicyConfig{
				"nil-policy":            nil,
				"emrtd-document-signer": {Registries: []string{"emrtd-csca"}, EMRTD: tc.e},
			}
			err := cfg.Validate()
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("Validate() = %v, want nil", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) || !strings.Contains(err.Error(), "emrtd-document-signer") {
				t.Fatalf("Validate() = %v, want error naming the policy and containing %q", err, tc.wantErr)
			}
		})
	}
}

func TestLoadConfigEMRTDPolicyKeys(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	content := `
policies:
  policies:
    emrtd-document-signer:
      registries: [emrtd-csca]
      emrtd:
        path_len_mode: enforce
        path_len_override: 1
`
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	e := cfg.Policies.Policies["emrtd-document-signer"].EMRTD
	if e == nil || e.PathLenMode != "enforce" || e.PathLenOverride == nil || *e.PathLenOverride != 1 {
		t.Fatalf("emrtd policy = %+v, want enforce/1", e)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
}
