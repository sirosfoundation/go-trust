package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
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
	if cfg.Server.Frequency != 5*time.Minute {
		t.Errorf("Default frequency = %v, want %v", cfg.Server.Frequency, 5*time.Minute)
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
	if cfg.Server.Frequency != 10*time.Minute {
		t.Errorf("Frequency = %v, want %v", cfg.Server.Frequency, 10*time.Minute)
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
	if cfg.Server.Frequency != 15*time.Minute {
		t.Errorf("Frequency = %v, want %v", cfg.Server.Frequency, 15*time.Minute)
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
				Server:   ServerConfig{Host: "127.0.0.1", Port: "", Frequency: 5 * time.Minute},
				Logging:  LoggingConfig{Level: "info", Format: "text", Output: "stdout"},
				Security: SecurityConfig{RateLimitRPS: 100},
			},
			wantErr: true,
		},
		{
			name: "Negative frequency",
			config: &Config{
				Server:   ServerConfig{Host: "127.0.0.1", Port: "6001", Frequency: -1 * time.Minute},
				Logging:  LoggingConfig{Level: "info", Format: "text", Output: "stdout"},
				Security: SecurityConfig{RateLimitRPS: 100},
			},
			wantErr: true,
		},
		{
			name: "Invalid log level",
			config: &Config{
				Server:   ServerConfig{Host: "127.0.0.1", Port: "6001", Frequency: 5 * time.Minute},
				Logging:  LoggingConfig{Level: "invalid", Format: "text", Output: "stdout"},
				Security: SecurityConfig{RateLimitRPS: 100},
			},
			wantErr: true,
		},
		{
			name: "Invalid log format",
			config: &Config{
				Server:   ServerConfig{Host: "127.0.0.1", Port: "6001", Frequency: 5 * time.Minute},
				Logging:  LoggingConfig{Level: "info", Format: "invalid", Output: "stdout"},
				Security: SecurityConfig{RateLimitRPS: 100},
			},
			wantErr: true,
		},
		{
			name: "Non-positive rate limit",
			config: &Config{
				Server:   ServerConfig{Host: "127.0.0.1", Port: "6001", Frequency: 5 * time.Minute},
				Logging:  LoggingConfig{Level: "info", Format: "text", Output: "stdout"},
				Security: SecurityConfig{RateLimitRPS: 0},
			},
			wantErr: true,
		},
		{
			name: "ETSI RequireSignature without LOTLSignerBundle",
			config: &Config{
				Server:   ServerConfig{Host: "127.0.0.1", Port: "6001", Frequency: 5 * time.Minute},
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
				Server:   ServerConfig{Host: "127.0.0.1", Port: "6001", Frequency: 5 * time.Minute},
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
