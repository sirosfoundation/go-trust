package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	oidfedjwx "github.com/go-oidfed/lib/jwx"
	"github.com/sirosfoundation/g119612/pkg/logging"
	gocryptoutil "github.com/sirosfoundation/go-cryptoutil"
	"github.com/sirosfoundation/go-cryptoutil/brainpool"
	_ "github.com/sirosfoundation/go-trust/docs/swagger" // Import generated docs
	"github.com/sirosfoundation/go-trust/pkg/api"
	"github.com/sirosfoundation/go-trust/pkg/config"
	"github.com/sirosfoundation/go-trust/pkg/registry"
	"github.com/sirosfoundation/go-trust/pkg/registry/did"
	"github.com/sirosfoundation/go-trust/pkg/registry/didjwks"
	"github.com/sirosfoundation/go-trust/pkg/registry/didweb"
	"github.com/sirosfoundation/go-trust/pkg/registry/didwebvh"
	"github.com/sirosfoundation/go-trust/pkg/registry/etsi"
	"github.com/sirosfoundation/go-trust/pkg/registry/fidomds3"
	"github.com/sirosfoundation/go-trust/pkg/registry/lote"
	"github.com/sirosfoundation/go-trust/pkg/registry/mdociaca"
	"github.com/sirosfoundation/go-trust/pkg/registry/mdocrical"
	"github.com/sirosfoundation/go-trust/pkg/registry/oidfed"
	"github.com/sirosfoundation/go-trust/pkg/registry/static"
	"github.com/sirosfoundation/go-trust/pkg/registry/vical"
	swaggerFiles "github.com/swaggo/files"
	ginSwagger "github.com/swaggo/gin-swagger"
)

// @title Go-Trust API
// @version 2.0
// @description Multi-framework trust decision engine providing AuthZEN-based trust evaluation
// @description
// @description Go-Trust is a Policy Decision Point (PDP) that evaluates trust across multiple frameworks:
// @description - ETSI TS 119612 Trust Status Lists (for X.509 certificates)
// @description - OpenID Federation (for entity trust chains)
// @description - DID Web (for decentralized identifiers)
// @description
// @description The service provides health/metrics endpoints for production deployment.
// @termsOfService https://github.com/sirosfoundation/go-trust

// @contact.name sirosfoundation
// @contact.url https://github.com/sirosfoundation/go-trust
// @contact.email noreply@sunet.se

// @license.name BSD-2-Clause
// @license.url https://opensource.org/licenses/BSD-2-Clause

// @host localhost:6001
// @BasePath /

// @schemes http https

// @tag.name Health
// @tag.description Health check and readiness endpoints for Kubernetes and monitoring systems

// @tag.name Status
// @tag.description Server status and registry information endpoints

// @tag.name AuthZEN
// @tag.description AuthZEN protocol endpoints for trust decision evaluation

// Version is set at build time using -ldflags
var Version = "2.0.0-dev"

func usage() {
	prog := os.Args[0]
	fmt.Fprintf(os.Stderr, "\nUsage: %s [options]\n", prog)
	fmt.Fprintln(os.Stderr, "\nGo-Trust: Multi-framework AuthZEN Trust Decision Point (PDP)")
	fmt.Fprintln(os.Stderr, "\nOptions:")
	fmt.Fprintln(os.Stderr, "  --help         Show this help message and exit")
	fmt.Fprintln(os.Stderr, "  --version      Show version information and exit")
	fmt.Fprintln(os.Stderr, "  --config       Configuration file path (YAML format)")
	fmt.Fprintln(os.Stderr, "                 Can also be set via GT_CONFIG environment variable (overrides --config)")
	fmt.Fprintln(os.Stderr, "  --host         API server hostname (default: 127.0.0.1)")
	fmt.Fprintln(os.Stderr, "  --port         API server port (default: 6001)")
	fmt.Fprintln(os.Stderr, "  --external-url External URL for PDP discovery (e.g., https://pdp.example.com)")
	fmt.Fprintln(os.Stderr, "                 Can also be set via GT_EXTERNAL_URL environment variable")
	fmt.Fprintln(os.Stderr, "\nETSI TSL Registry Options:")
	fmt.Fprintln(os.Stderr, "  --etsi-cert-bundle   Path to PEM file with trusted CA certificates")
	fmt.Fprintln(os.Stderr, "  --etsi-tsl-files     Comma-separated list of local TSL XML files")
	fmt.Fprintln(os.Stderr, "\nWhitelist Registry Options:")
	fmt.Fprintln(os.Stderr, "  --registry           Registry type: whitelist, always-trusted, never-trusted")
	fmt.Fprintln(os.Stderr, "  --whitelist          Path to whitelist YAML/JSON config file")
	fmt.Fprintln(os.Stderr, "  --whitelist-watch    Watch whitelist file for changes (default: true)")
	fmt.Fprintln(os.Stderr, "\nLogging Options:")
	fmt.Fprintln(os.Stderr, "  --log-level    Logging level: debug, info, warn, error (default: info)")
	fmt.Fprintln(os.Stderr, "  --log-format   Logging format: text or json (default: text)")
	fmt.Fprintln(os.Stderr, "\nNotes:")
	fmt.Fprintln(os.Stderr, "  - For TSL processing (load, transform, sign, publish), use tsl-tool from g119612")
	fmt.Fprintln(os.Stderr, "  - This server consumes pre-processed TSL data (PEM bundles or XML files)")
	fmt.Fprintln(os.Stderr, "  - Run tsl-tool via cron to update TSL data periodically")
	fmt.Fprintln(os.Stderr, "  - Use --registry=whitelist --whitelist=/path/to/whitelist.yaml for simple deployments")
	fmt.Fprintln(os.Stderr, "")
}

func main() {
	showHelp := flag.Bool("help", false, "Show help message")
	showVersion := flag.Bool("version", false, "Show version information")
	configFile := flag.String("config", "", "Configuration file path (YAML format). Overridden by GT_CONFIG environment variable.")
	host := flag.String("host", "127.0.0.1", "API server hostname")
	port := flag.String("port", "6001", "API server port")
	externalURL := flag.String("external-url", "", "External URL for PDP discovery")

	// ETSI registry options
	etsiCertBundle := flag.String("etsi-cert-bundle", "", "Path to PEM file with trusted CA certificates")
	etsiTSLFiles := flag.String("etsi-tsl-files", "", "Comma-separated list of local TSL XML files")

	// Whitelist/static registry options
	registryType := flag.String("registry", "", "Registry type: whitelist, always-trusted, never-trusted")
	whitelistFile := flag.String("whitelist", "", "Path to whitelist YAML/JSON config file")
	whitelistWatch := flag.Bool("whitelist-watch", true, "Watch whitelist file for changes")

	// Logging options
	logLevel := flag.String("log-level", "info", "Logging level: debug, info, warn, error")
	logFormat := flag.String("log-format", "text", "Logging format: text or json")

	flag.Parse()

	// GT_CONFIG environment variable overrides the --config flag.
	if envConfig := os.Getenv("GT_CONFIG"); envConfig != "" {
		*configFile = envConfig
	}

	if *showHelp {
		usage()
		os.Exit(0)
	}
	if *showVersion {
		fmt.Printf("go-trust version %s\n", Version)
		fmt.Println("Multi-framework AuthZEN Trust Decision Point")
		os.Exit(0)
	}

	// Configure logger
	var level logging.LogLevel
	switch *logLevel {
	case "debug":
		level = logging.DebugLevel
	case "info":
		level = logging.InfoLevel
	case "warn":
		level = logging.WarnLevel
	case "error":
		level = logging.ErrorLevel
	default:
		fmt.Fprintf(os.Stderr, "Invalid log level: %s\n", *logLevel)
		os.Exit(1)
	}

	var logger logging.Logger
	if *logFormat == "json" {
		logger = logging.JSONLogger(level)
	} else {
		logger = logging.NewLogger(level)
	}

	// Always load configuration to apply environment variable overrides,
	// even when no config file is provided.
	cfg, err := config.LoadConfig(*configFile)
	if err != nil {
		logger.Fatal("Failed to load configuration file",
			logging.F("file", *configFile),
			logging.F("error", err.Error()))
	}

	if *configFile != "" {
		logger.Info("Loaded configuration from file",
			logging.F("file", *configFile))

		warnUnknownConfigKeys(cfg, *configFile, logger)

		// Validate configuration
		if err := cfg.Validate(); err != nil {
			logger.Fatal("Configuration validation failed",
				logging.F("file", *configFile),
				logging.F("error", err.Error()))
		}
	}

	// Use config values if CLI flags weren't explicitly set.
	// This applies both config file values and environment variable overrides.
	if *host == "127.0.0.1" && cfg.Server.Host != "" {
		*host = cfg.Server.Host
	}
	if *port == "6001" && cfg.Server.Port != "" {
		*port = cfg.Server.Port
	}
	if *externalURL == "" && cfg.Server.ExternalURL != "" {
		*externalURL = cfg.Server.ExternalURL
	}
	if *logLevel == "info" && cfg.Logging.Level != "" {
		*logLevel = cfg.Logging.Level
	}
	if *logFormat == "text" && cfg.Logging.Format != "" {
		*logFormat = cfg.Logging.Format
	}

	// Reconfigure logger in case log settings were updated by config.
	switch *logLevel {
	case "debug", "DEBUG", "Debug":
		*logLevel = "debug"
		level = logging.DebugLevel
	case "info", "INFO", "Info":
		*logLevel = "info"
		level = logging.InfoLevel
	case "warn", "WARN", "Warn":
		*logLevel = "warn"
		level = logging.WarnLevel
	case "error", "ERROR", "Error":
		*logLevel = "error"
		level = logging.ErrorLevel
	case "fatal", "FATAL", "Fatal":
		*logLevel = "fatal"
		level = logging.FatalLevel
	default:
		fmt.Fprintf(os.Stderr, "Invalid log level: %s\n", *logLevel)
		os.Exit(1)
	}
	switch *logFormat {
	case "json", "JSON", "Json":
		*logFormat = "json"
		logger = logging.JSONLogger(level)
	case "text", "TEXT", "Text":
		*logFormat = "text"
		logger = logging.NewLogger(level)
	default:
		fmt.Fprintf(os.Stderr, "Invalid log format: %s\n", *logFormat)
		os.Exit(1)
	}

	logger.Info("Starting go-trust server",
		logging.F("version", Version),
		logging.F("host", *host),
		logging.F("port", *port))

	// Create server context
	serverCtx := api.NewServerContext(logger)

	// Apply global HTTP response body size limit from config
	if cfg != nil && cfg.Security.MaxResponseBodyBytes > 0 {
		registry.SetMaxResponseBodyBytes(cfg.Security.MaxResponseBodyBytes)
	}

	// Initialize RegistryManager
	registryMgr := registry.NewRegistryManager(resolutionStrategy(cfg, logger), 30*time.Second)
	registryMgr.SetLogger(logger)

	// Configure registries from config file
	if cfg != nil {
		configureRegistriesFromConfig(cfg, registryMgr, logger)
	}

	// CLI flags override config file - Configure ETSI TSL registry if cert bundle or TSL files provided
	if *etsiCertBundle != "" || *etsiTSLFiles != "" {
		logger.Info("Configuring ETSI TSL registry")

		config := etsi.TSLConfig{
			Name:        "ETSI-TSL",
			Description: "ETSI TS 119612 Trust Status List Registry",
		}

		if *etsiCertBundle != "" {
			config.CertBundle = *etsiCertBundle
			logger.Info("Loading ETSI certificates from PEM bundle",
				logging.F("path", *etsiCertBundle))
		}

		if *etsiTSLFiles != "" {
			// Split comma-separated file list
			files := splitCSV(*etsiTSLFiles)
			config.TSLFiles = files
			logger.Info("Loading ETSI TSL files",
				logging.F("count", len(files)))
		}

		tslRegistry, err := etsi.NewTSLRegistry(config)
		if err != nil {
			logger.Fatal("Failed to create ETSI TSL registry",
				logging.F("error", err.Error()))
		}

		registryMgr.Register(tslRegistry)
		logger.Info("ETSI TSL registry registered")
	}

	// Configure whitelist/static registry if requested via CLI
	switch *registryType {
	case "whitelist":
		if *whitelistFile != "" {
			logger.Info("Configuring whitelist registry from file",
				logging.F("path", *whitelistFile),
				logging.F("watch", *whitelistWatch))
			cryptoExt := gocryptoutil.New()
			brainpool.Register(cryptoExt)
			whitelistReg, err := static.NewWhitelistRegistryFromFile(*whitelistFile, *whitelistWatch,
				static.WithWhitelistName("whitelist"),
				static.WithWhitelistDescription("URL whitelist from "+*whitelistFile),
				static.WithWhitelistCryptoExt(cryptoExt))
			if err != nil {
				logger.Fatal("Failed to create whitelist registry",
					logging.F("error", err.Error()))
			}
			// Start background JWKS refresh if configured
			if err := whitelistReg.StartRefreshLoop(context.Background()); err != nil {
				logger.Fatal("Failed to start whitelist refresh loop",
					logging.F("error", err.Error()))
			}
			registryMgr.Register(whitelistReg)
			logger.Info("Whitelist registry registered")
		} else {
			logger.Fatal("--whitelist flag required when using --registry=whitelist")
		}
	case "always-trusted":
		logger.Warn("Using always-trusted registry - ALL trust requests will be approved")
		logger.Warn("This is only suitable for development/testing!")
		registryMgr.Register(static.NewAlwaysTrustedRegistry("always-trusted"))
	case "never-trusted":
		logger.Info("Using never-trusted registry - ALL trust requests will be denied")
		registryMgr.Register(static.NewNeverTrustedRegistry("never-trusted"))
	case "":
		// No static registry configured
	default:
		logger.Fatal("Unknown registry type",
			logging.F("type", *registryType),
			logging.F("valid", "whitelist, always-trusted, never-trusted"))
	}

	// Composite registries last: children are resolved by name out of the
	// manager, so every registry that can be one must already be registered,
	// including those configured via CLI flags above.
	if cfg != nil && len(cfg.Registries.Composite) > 0 {
		if err := configureCompositeRegistriesFromConfig(cfg, registryMgr, logger); err != nil {
			logger.Fatal("Failed to configure composite registries",
				logging.F("error", err.Error()))
		}
	}

	// Configure policies from config file
	if cfg != nil && cfg.Policies.Policies != nil {
		configurePoliciesFromConfig(cfg, registryMgr, logger)
	}

	serverCtx.RegistryManager = registryMgr

	// Set BaseURL for .well-known discovery
	baseURL := *externalURL
	if baseURL == "" {
		baseURL = os.Getenv("GT_EXTERNAL_URL")
	}
	if baseURL == "" {
		baseURL = fmt.Sprintf("http://%s:%s", *host, *port)
	}
	serverCtx.BaseURL = baseURL

	logger.Info("AuthZEN PDP base URL configured",
		logging.F("url", baseURL))

	// Gin API server
	debugMode := *logLevel == "debug"
	if !debugMode {
		gin.SetMode(gin.ReleaseMode)
	}
	r := gin.New()
	r.Use(gin.LoggerWithConfig(gin.LoggerConfig{
		Skip: func(c *gin.Context) bool {
			// In debug mode, always log everything
			if debugMode {
				return false
			}
			// Skip successful health check requests to reduce log noise
			return c.Request.URL.Path == "/healthz" && c.Writer.Status() == 200
		},
	}))
	r.Use(gin.Recovery())

	installSecurityMiddleware(r, cfg, logger)

	// Initialize metrics
	metrics := api.NewMetrics()
	serverCtx.Metrics = metrics
	api.RegisterMetricsEndpoint(r, metrics)

	// Register Swagger UI endpoint
	r.GET("/swagger/*any", ginSwagger.WrapHandler(swaggerFiles.Handler))

	api.RegisterAPIRoutes(r, serverCtx)

	listenAddr := fmt.Sprintf("%s:%s", *host, *port)
	logger.Info("Starting API server",
		logging.F("address", listenAddr),
		logging.F("swagger", fmt.Sprintf("http://%s/swagger/index.html", listenAddr)))

	// Start server with or without TLS
	if cfg != nil && cfg.Server.TLS.Enabled {
		logger.Info("TLS enabled",
			logging.F("cert", cfg.Server.TLS.CertFile),
			logging.F("key", cfg.Server.TLS.KeyFile))
		if err := r.RunTLS(listenAddr, cfg.Server.TLS.CertFile, cfg.Server.TLS.KeyFile); err != nil {
			logger.Fatal("API server error", logging.F("error", err.Error()))
		}
	} else {
		if err := r.Run(listenAddr); err != nil {
			logger.Fatal("API server error", logging.F("error", err.Error()))
		}
	}
}

// configureRegistriesFromConfig configures registries from the loaded config file.
func configureRegistriesFromConfig(cfg *config.Config, registryMgr *registry.RegistryManager, logger logging.Logger) {
	// cryptoExt extends certificate parsing/signature verification beyond
	// what crypto/x509 supports natively - currently brainpool curves, used
	// by real-world root CAs (e.g. the Geneva 2026 interop event's RICAL/
	// VICAL root) that stdlib's x509.ParseCertificate rejects outright with
	// "unsupported elliptic curve". Shared across every registry below that
	// accepts a CryptoExt field.
	cryptoExt := gocryptoutil.New()
	brainpool.Register(cryptoExt)

	// Configure ETSI TSL registry from config
	if cfg.Registries.ETSI != nil && cfg.Registries.ETSI.Enabled {
		logger.Info("Configuring ETSI TSL registry from config file")
		etsiCfg := cfg.Registries.ETSI

		tslConfig := etsiTSLConfig(etsiCfg, cryptoExt, logger)

		tslRegistry, err := etsi.NewTSLRegistry(tslConfig)
		if err != nil {
			logger.Fatal("Failed to create ETSI TSL registry from config",
				logging.F("error", err.Error()))
		}

		registryMgr.Register(tslRegistry)

		startETSIRefreshLoop(tslRegistry, tslConfig.RefreshInterval, logger)

		logger.Info("ETSI TSL registry registered from config")
	}

	// Configure whitelist registry from config
	if cfg.Registries.Whitelist != nil && cfg.Registries.Whitelist.Enabled {
		logger.Info("Configuring whitelist registry from config file")
		wlCfg := cfg.Registries.Whitelist

		name := wlCfg.Name
		if name == "" {
			name = "whitelist"
		}
		desc := wlCfg.Description
		if desc == "" {
			desc = "Static URL Whitelist"
		}

		var whitelistReg *static.WhitelistRegistry
		var err error

		if wlCfg.ConfigFile != "" {
			// Load from external config file
			whitelistReg, err = static.NewWhitelistRegistryFromFile(
				wlCfg.ConfigFile,
				wlCfg.WatchFile,
				static.WithWhitelistName(name),
				static.WithWhitelistDescription(desc),
				static.WithWhitelistCryptoExt(cryptoExt),
			)
			if err != nil {
				logger.Fatal("Failed to create whitelist registry from config file",
					logging.F("config_file", wlCfg.ConfigFile),
					logging.F("error", err.Error()))
			}
		} else {
			// Use inline configuration
			whitelistReg = static.NewWhitelistRegistry(
				static.WithWhitelistName(name),
				static.WithWhitelistDescription(desc),
				static.WithWhitelistCryptoExt(cryptoExt),
				static.WithWhitelistConfig(static.WhitelistConfig{
					Lists:                  wlCfg.Lists,
					Actions:                wlCfg.Actions,
					Issuers:                wlCfg.Issuers,
					Verifiers:              wlCfg.Verifiers,
					TrustedSubjects:        wlCfg.TrustedSubjects,
					AllowHTTP:              wlCfg.AllowHTTP,
					TrustX509ViaSystemCA:   wlCfg.TrustX509ViaSystemCA,
					AdditionalTrustedRoots: wlCfg.AdditionalTrustedRoots,
				}),
			)
		}

		// Start background JWKS refresh (always runs, uses DefaultRefreshInterval if not configured)
		if err := whitelistReg.StartRefreshLoop(context.Background()); err != nil {
			logger.Fatal("Failed to start whitelist refresh loop",
				logging.F("error", err.Error()))
		}

		registryMgr.Register(whitelistReg)
		logger.Info("Whitelist registry registered from config",
			logging.F("lists", len(wlCfg.Lists)),
			logging.F("actions", len(wlCfg.Actions)),
			logging.F("issuers", len(wlCfg.Issuers)),
			logging.F("verifiers", len(wlCfg.Verifiers)))
	}

	// Configure always-trusted registry from config
	if cfg.Registries.AlwaysTrusted != nil && cfg.Registries.AlwaysTrusted.Enabled {
		logger.Warn("Configuring always-trusted registry from config")
		logger.Warn("ALL trust requests will be approved - only suitable for development/testing!")
		name := cfg.Registries.AlwaysTrusted.Name
		if name == "" {
			name = "always-trusted"
		}
		registryMgr.Register(static.NewAlwaysTrustedRegistry(name))
	}

	if err := configureSystemCertPoolRegistry(cfg, registryMgr, logger); err != nil {
		logger.Fatal("Failed to configure system certificate pool registry",
			logging.F("error", err.Error()))
	}

	// Configure never-trusted registry from config
	if cfg.Registries.NeverTrusted != nil && cfg.Registries.NeverTrusted.Enabled {
		logger.Info("Configuring never-trusted registry from config")
		name := cfg.Registries.NeverTrusted.Name
		if name == "" {
			name = "never-trusted"
		}
		registryMgr.Register(static.NewNeverTrustedRegistry(name))
	}

	// Configure OpenID Federation registry from config
	if cfg.Registries.OIDFed != nil && cfg.Registries.OIDFed.Enabled {
		logger.Info("Configuring OpenID Federation registry from config file")
		oidfedCfg := cfg.Registries.OIDFed

		// Build trust anchor configs
		trustAnchors := make([]oidfed.TrustAnchorConfig, len(oidfedCfg.TrustAnchors))
		for i, ta := range oidfedCfg.TrustAnchors {
			taCfg := oidfed.TrustAnchorConfig{
				EntityID: ta.EntityID,
			}
			if ta.JWKS != "" {
				var jwks oidfedjwx.JWKS
				if err := json.Unmarshal([]byte(ta.JWKS), &jwks); err != nil {
					logger.Warn("Failed to parse JWKS for trust anchor, will fetch from entity configuration",
						logging.F("entity_id", ta.EntityID),
						logging.F("error", err.Error()))
				} else {
					taCfg.JWKS = &jwks
				}
			}
			trustAnchors[i] = taCfg
		}

		oidfedConfig := oidfed.Config{
			TrustAnchors:       trustAnchors,
			RequiredTrustMarks: oidfedCfg.RequiredTrustMarks,
			EntityTypes:        oidfedCfg.EntityTypes,
			Description:        oidfedCfg.Description,
			MaxCacheSize:       oidfedCfg.MaxCacheSize,
			MaxChainDepth:      oidfedCfg.MaxChainDepth,
			CryptoExt:          cryptoExt,
		}

		// Parse CacheTTL if provided
		if oidfedCfg.CacheTTL != "" {
			if ttl, err := time.ParseDuration(oidfedCfg.CacheTTL); err == nil {
				oidfedConfig.CacheTTL = ttl
			} else {
				logger.Warn("Invalid cache_ttl for oidfed registry, using default",
					logging.F("value", oidfedCfg.CacheTTL),
					logging.F("error", err.Error()))
			}
		}

		oidfedReg, err := oidfed.NewOIDFedRegistry(oidfedConfig)
		if err != nil {
			logger.Fatal("Failed to create OpenID Federation registry from config",
				logging.F("error", err.Error()))
		}

		registryMgr.Register(oidfedReg)
		logger.Info("OpenID Federation registry registered from config",
			logging.F("trust_anchors", len(trustAnchors)))
	}

	// Configure did:web registry from config
	if cfg.Registries.DIDWeb != nil && cfg.Registries.DIDWeb.Enabled {
		logger.Info("Configuring did:web registry from config file")
		dwCfg := cfg.Registries.DIDWeb

		didwebConfig := didweb.Config{
			Description:        dwCfg.Description,
			InsecureSkipVerify: dwCfg.InsecureSkipVerify,
			AllowHTTP:          dwCfg.AllowHTTP,
		}

		// Parse Timeout if provided
		if dwCfg.Timeout != "" {
			if timeout, err := time.ParseDuration(dwCfg.Timeout); err == nil {
				didwebConfig.Timeout = timeout
			} else {
				logger.Warn("Invalid timeout for didweb registry, using default",
					logging.F("value", dwCfg.Timeout),
					logging.F("error", err.Error()))
			}
		}

		didwebReg, err := didweb.NewDIDWebRegistry(didwebConfig)
		if err != nil {
			logger.Fatal("Failed to create did:web registry from config",
				logging.F("error", err.Error()))
		}

		registryMgr.Register(didwebReg)
		logger.Info("did:web registry registered from config")
	}

	// Configure did:webvh registry from config
	if cfg.Registries.DIDWebVH != nil && cfg.Registries.DIDWebVH.Enabled {
		logger.Info("Configuring did:webvh registry from config file")
		dwvhCfg := cfg.Registries.DIDWebVH

		didwebvhConfig := didwebvh.Config{
			Description:        dwvhCfg.Description,
			InsecureSkipVerify: dwvhCfg.InsecureSkipVerify,
			AllowHTTP:          dwvhCfg.AllowHTTP,
		}

		// Parse Timeout if provided
		if dwvhCfg.Timeout != "" {
			if timeout, err := time.ParseDuration(dwvhCfg.Timeout); err == nil {
				didwebvhConfig.Timeout = timeout
			} else {
				logger.Warn("Invalid timeout for didwebvh registry, using default",
					logging.F("value", dwvhCfg.Timeout),
					logging.F("error", err.Error()))
			}
		}

		didwebvhReg, err := didwebvh.NewDIDWebVHRegistry(didwebvhConfig)
		if err != nil {
			logger.Fatal("Failed to create did:webvh registry from config",
				logging.F("error", err.Error()))
		}

		registryMgr.Register(didwebvhReg)
		logger.Info("did:webvh registry registered from config")
	}

	// Configure the local DID registry (self-contained methods) from config
	if cfg.Registries.DIDLocal != nil && cfg.Registries.DIDLocal.Enabled {
		logger.Info("Configuring local DID registry from config file")
		didCfg := cfg.Registries.DIDLocal

		didReg, err := did.NewGenericDIDRegistryForMethods(
			did.GenericDIDRegistryConfig{Description: didCfg.Description},
			didCfg.Methods,
		)
		if err != nil {
			logger.Fatal("Failed to create local DID registry from config",
				logging.F("error", err.Error()))
		}

		registryMgr.Register(didReg)
		logger.Info("Local DID registry registered from config",
			logging.F("methods", didReg.Info().TrustAnchors))
	}

	// Configure did:jwks registry from config
	if cfg.Registries.DIDJWKS != nil && cfg.Registries.DIDJWKS.Enabled {
		logger.Info("Configuring did:jwks registry from config file")
		djCfg := cfg.Registries.DIDJWKS

		didjwksConfig := didjwks.Config{
			Description:          djCfg.Description,
			InsecureSkipVerify:   djCfg.InsecureSkipVerify,
			AllowHTTP:            djCfg.AllowHTTP,
			DisableOIDCDiscovery: djCfg.DisableOIDCDiscovery,
		}

		// Parse Timeout if provided
		if djCfg.Timeout != "" {
			if timeout, err := time.ParseDuration(djCfg.Timeout); err == nil {
				didjwksConfig.Timeout = timeout
			} else {
				logger.Warn("Invalid timeout for didjwks registry, using default",
					logging.F("value", djCfg.Timeout),
					logging.F("error", err.Error()))
			}
		}

		didjwksReg, err := didjwks.NewRegistry(didjwksConfig)
		if err != nil {
			logger.Fatal("Failed to create did:jwks registry from config",
				logging.F("error", err.Error()))
		}

		registryMgr.Register(didjwksReg)
		logger.Info("did:jwks registry registered from config")
	}

	// Configure LoTE registry from config
	if cfg.Registries.LoTE != nil && cfg.Registries.LoTE.Enabled {
		logger.Info("Configuring LoTE registry from config file")
		loteCfg := cfg.Registries.LoTE

		loteConfig := lote.Config{
			Name:                loteCfg.Name,
			Description:         loteCfg.Description,
			Sources:             loteCfg.Sources,
			LoTLSources:         loteCfg.LoTLSources,
			MaxDereferenceDepth: loteCfg.MaxDereferenceDepth,
			VerifyJWS:           loteCfg.VerifyJWS,
			Logger:              slog.Default(),
			CryptoExt:           cryptoExt,
		}

		if loteCfg.FetchTimeout != "" {
			if timeout, err := time.ParseDuration(loteCfg.FetchTimeout); err == nil {
				loteConfig.FetchTimeout = timeout
			} else {
				logger.Warn("Invalid fetch_timeout for lote registry, using default",
					logging.F("value", loteCfg.FetchTimeout),
					logging.F("error", err.Error()))
			}
		}

		if loteCfg.RefreshInterval != "" {
			if interval, err := time.ParseDuration(loteCfg.RefreshInterval); err == nil {
				loteConfig.RefreshInterval = interval
			} else {
				logger.Warn("Invalid refresh_interval for lote registry, using default",
					logging.F("value", loteCfg.RefreshInterval),
					logging.F("error", err.Error()))
			}
		}

		loteReg, err := lote.New(loteConfig)
		if err != nil {
			logger.Fatal("Failed to create LoTE registry from config",
				logging.F("error", err.Error()))
		}

		if err := loteReg.StartRefreshLoop(context.Background()); err != nil {
			logger.Fatal("Failed to start LoTE refresh loop",
				logging.F("error", err.Error()))
		}

		registryMgr.Register(loteReg)
		logger.Info("LoTE registry registered from config",
			logging.F("sources", len(loteCfg.Sources)))
	}

	// Configure mDOC IACA registry from config
	if cfg.Registries.MDOCIACA != nil && cfg.Registries.MDOCIACA.Enabled {
		logger.Info("Configuring mDOC IACA registry from config file")
		mdocCfg := cfg.Registries.MDOCIACA

		mdocConfig := &mdociaca.Config{
			Name:            mdocCfg.Name,
			Description:     mdocCfg.Description,
			IssuerAllowlist: mdocCfg.IssuerAllowlist,
			CryptoExt:       cryptoExt,
		}

		// Parse CacheTTL if provided
		if mdocCfg.CacheTTL != "" {
			if ttl, err := time.ParseDuration(mdocCfg.CacheTTL); err == nil {
				mdocConfig.CacheTTL = ttl
			} else {
				logger.Warn("Invalid cache_ttl for mdociaca registry, using default",
					logging.F("value", mdocCfg.CacheTTL),
					logging.F("error", err.Error()))
			}
		}

		// Parse HTTPTimeout if provided
		if mdocCfg.HTTPTimeout != "" {
			if timeout, err := time.ParseDuration(mdocCfg.HTTPTimeout); err == nil {
				mdocConfig.HTTPTimeout = timeout
			} else {
				logger.Warn("Invalid http_timeout for mdociaca registry, using default",
					logging.F("value", mdocCfg.HTTPTimeout),
					logging.F("error", err.Error()))
			}
		}

		mdocReg, err := mdociaca.New(mdocConfig)
		if err != nil {
			logger.Fatal("Failed to create mDOC IACA registry from config",
				logging.F("error", err.Error()))
		}

		registryMgr.Register(mdocReg)
		logger.Info("mDOC IACA registry registered from config",
			logging.F("issuer_allowlist", len(mdocCfg.IssuerAllowlist)))
	}

	// Configure mDOC RICAL registry from config
	if cfg.Registries.MDOCRICAL != nil && cfg.Registries.MDOCRICAL.Enabled {
		logger.Info("Configuring mDOC RICAL registry from config file")
		ricalCfg := cfg.Registries.MDOCRICAL

		ricalConfig := &mdocrical.Config{
			Name:                    ricalCfg.Name,
			Description:             ricalCfg.Description,
			RicalProviderURL:        ricalCfg.RicalProviderURL,
			RicalRootCertificatePEM: ricalCfg.RicalRootCertificatePEM,
			CryptoExt:               cryptoExt,
		}

		if ricalCfg.CacheTTL != "" {
			if ttl, err := time.ParseDuration(ricalCfg.CacheTTL); err == nil {
				ricalConfig.CacheTTL = ttl
			} else {
				logger.Warn("Invalid cache_ttl for mdocrical registry, using default",
					logging.F("value", ricalCfg.CacheTTL),
					logging.F("error", err.Error()))
			}
		}

		if ricalCfg.HTTPTimeout != "" {
			if timeout, err := time.ParseDuration(ricalCfg.HTTPTimeout); err == nil {
				ricalConfig.HTTPTimeout = timeout
			} else {
				logger.Warn("Invalid http_timeout for mdocrical registry, using default",
					logging.F("value", ricalCfg.HTTPTimeout),
					logging.F("error", err.Error()))
			}
		}

		ricalReg, err := mdocrical.New(ricalConfig)
		if err != nil {
			logger.Fatal("Failed to create mDOC RICAL registry from config",
				logging.F("error", err.Error()))
		}

		registryMgr.Register(ricalReg)
		logger.Info("mDOC RICAL registry registered from config",
			logging.F("provider_url", ricalCfg.RicalProviderURL))
	}

	// Configure VICAL registry from config
	if cfg.Registries.VICAL != nil && cfg.Registries.VICAL.Enabled {
		logger.Info("Configuring VICAL registry from config file")
		vicalCfg := cfg.Registries.VICAL

		vicalConfig := &vical.Config{
			Name:                    vicalCfg.Name,
			Description:             vicalCfg.Description,
			VicalProviderURL:        vicalCfg.VicalProviderURL,
			VicalRootCertificatePEM: vicalCfg.VicalRootCertificatePEM,
			CryptoExt:               cryptoExt,
		}

		if vicalCfg.CacheTTL != "" {
			if ttl, err := time.ParseDuration(vicalCfg.CacheTTL); err == nil {
				vicalConfig.CacheTTL = ttl
			} else {
				logger.Warn("Invalid cache_ttl for vical registry, using default",
					logging.F("value", vicalCfg.CacheTTL),
					logging.F("error", err.Error()))
			}
		}

		if vicalCfg.HTTPTimeout != "" {
			if timeout, err := time.ParseDuration(vicalCfg.HTTPTimeout); err == nil {
				vicalConfig.HTTPTimeout = timeout
			} else {
				logger.Warn("Invalid http_timeout for vical registry, using default",
					logging.F("value", vicalCfg.HTTPTimeout),
					logging.F("error", err.Error()))
			}
		}

		vicalReg, err := vical.New(vicalConfig)
		if err != nil {
			logger.Fatal("Failed to create VICAL registry from config",
				logging.F("error", err.Error()))
		}

		registryMgr.Register(vicalReg)
		logger.Info("VICAL registry registered from config",
			logging.F("provider_url", vicalCfg.VicalProviderURL))
	}

	// Configure FIDO MDS3 registry from config
	if cfg.Registries.FIDOMDS3 != nil && cfg.Registries.FIDOMDS3.Enabled {
		logger.Info("Configuring FIDO MDS3 registry from config file")
		mdsCfg := cfg.Registries.FIDOMDS3

		mdsConfig := fidomds3.Config{
			Name:               mdsCfg.Name,
			Description:        mdsCfg.Description,
			URL:                mdsCfg.URL,
			RootCertificatePEM: mdsCfg.RootCertificatePEM,
			CachePath:          mdsCfg.CachePath,
			Logger:             slog.Default(),
		}

		if mdsCfg.FetchTimeout != "" {
			if timeout, err := time.ParseDuration(mdsCfg.FetchTimeout); err == nil {
				mdsConfig.FetchTimeout = timeout
			} else {
				logger.Warn("Invalid fetch_timeout for fidomds3 registry, using default",
					logging.F("value", mdsCfg.FetchTimeout),
					logging.F("error", err.Error()))
			}
		}

		if mdsCfg.RefreshInterval != "" {
			if interval, err := time.ParseDuration(mdsCfg.RefreshInterval); err == nil {
				mdsConfig.RefreshInterval = interval
			} else {
				logger.Warn("Invalid refresh_interval for fidomds3 registry, using default",
					logging.F("value", mdsCfg.RefreshInterval),
					logging.F("error", err.Error()))
			}
		}

		mdsReg, err := fidomds3.New(mdsConfig)
		if err != nil {
			logger.Fatal("Failed to create FIDO MDS3 registry from config",
				logging.F("error", err.Error()))
		}

		if err := mdsReg.StartRefreshLoop(context.Background()); err != nil {
			logger.Fatal("Failed to start FIDO MDS3 refresh loop",
				logging.F("error", err.Error()))
		}

		registryMgr.Register(mdsReg)
		logger.Info("FIDO MDS3 registry registered from config")
	}

}

// warnUnknownConfigKeys reports config-file keys the decoder threw away.
//
// Decoding is non-strict, so a stale or misspelled key is discarded rather
// than rejected, and the consequence surfaces far from the config file — as
// an unresolvable DID, or a policy control that silently never applies.
// Warning is not the end state: from v0.24.0 this is intended to be a startup
// error, most likely behind a config gate.
func warnUnknownConfigKeys(cfg *config.Config, configFile string, logger logging.Logger) {
	if cfg == nil {
		return
	}
	unknown := cfg.UnknownKeys()
	if len(unknown) == 0 {
		return
	}
	for _, key := range unknown {
		logger.Warn("Unknown config key ignored",
			logging.F("key", key.Field),
			logging.F("line", key.Line),
			logging.F("section", key.Type))
	}
	logger.Warn("Unknown config keys were ignored; they configure nothing. These will be startup errors in v0.24.0",
		logging.F("count", len(unknown)),
		logging.F("file", configFile))
}

// installSecurityMiddleware adds CORS and rate limiting when configured.
//
// CORS goes on first so a rate-limited request still carries the headers a
// browser needs to surface the real status rather than an opaque network
// error.
func installSecurityMiddleware(r *gin.Engine, cfg *config.Config, logger logging.Logger) {
	if cfg == nil {
		return
	}

	if cfg.Security.EnableCORS {
		if len(cfg.Security.AllowedOrigins) == 0 {
			logger.Warn("CORS is enabled but security.allowed_origins is empty; no cross-origin request can succeed")
		}
		r.Use(api.CORSMiddleware(cfg.Security.AllowedOrigins))
		logger.Info("CORS enabled",
			logging.F("allowed_origins", cfg.Security.AllowedOrigins))
	}

	if cfg.Security.RateLimitRPS > 0 {
		// Decide whose X-Forwarded-For to believe before anything reads a
		// client address. Gin trusts 0.0.0.0/0 by default, which would let a
		// directly reachable client rotate the header and get a fresh bucket
		// on every request — a rate limit that anyone can opt out of.
		if err := r.SetTrustedProxies(cfg.Security.TrustedProxies); err != nil {
			logger.Warn("Invalid security.trusted_proxies; trusting none",
				logging.F("value", cfg.Security.TrustedProxies),
				logging.F("error", err.Error()))
			_ = r.SetTrustedProxies(nil)
		}
		if len(cfg.Security.TrustedProxies) == 0 {
			logger.Info("Rate limiting keys on the peer address; no proxies are trusted",
				logging.F("hint", "set security.trusted_proxies when running behind a load balancer"))
		}

		burst := rateLimitBurst(cfg.Security.RateLimitRPS)
		limiter := api.NewRateLimiter(cfg.Security.RateLimitRPS, burst)
		// Without this the per-IP map grows for the life of the process.
		limiter.StartCleanupLoop(time.Hour, time.Hour, make(chan struct{}))
		r.Use(exemptOperationalEndpoints(limiter.Middleware()))
		logger.Info("Rate limiting enabled",
			logging.F("rps", cfg.Security.RateLimitRPS),
			logging.F("burst", burst),
			logging.F("exempt", operationalEndpoints()))
	}
}

// operationalEndpoints are the paths an orchestrator and a metrics scraper
// poll, which must never be rate limited.
func operationalEndpoints() []string {
	return []string{"/healthz", "/readyz", "/metrics"}
}

// exemptOperationalEndpoints wraps a middleware so liveness, readiness and
// metrics bypass it.
//
// Without this, a client that exhausts its bucket makes /healthz return 429
// even though the handler guarantees 200 while the process is running, and an
// orchestrator reading that will restart a perfectly healthy server.
func exemptOperationalEndpoints(next gin.HandlerFunc) gin.HandlerFunc {
	exempt := make(map[string]bool)
	for _, path := range operationalEndpoints() {
		exempt[path] = true
	}
	return func(c *gin.Context) {
		if exempt[c.Request.URL.Path] {
			c.Next()
			return
		}
		next(c)
	}
}

// rateLimitBurst is a tenth of the sustained rate, minimum 1, so a client can
// absorb a short spike without being able to bank a full second's allowance
// and spend it at once.
func rateLimitBurst(rps int) int {
	if burst := rps / 10; burst >= 1 {
		return burst
	}
	return 1
}

// configureSystemCertPoolRegistry registers the host trust store as a registry.
func configureSystemCertPoolRegistry(cfg *config.Config, registryMgr *registry.RegistryManager, logger logging.Logger) error {
	if cfg == nil || cfg.Registries.SystemCertPool == nil || !cfg.Registries.SystemCertPool.Enabled {
		return nil
	}
	logger.Info("Configuring system certificate pool registry from config")
	scpCfg := cfg.Registries.SystemCertPool
	scpReg, err := static.NewSystemCertPoolRegistry(static.SystemCertPoolConfig{
		Name:        scpCfg.Name,
		Description: scpCfg.Description,
	})
	if err != nil {
		return fmt.Errorf("creating system certificate pool registry: %w", err)
	}
	registryMgr.Register(scpReg)
	logger.Info("System certificate pool registry registered",
		logging.F("name", scpReg.Info().Name))
	return nil
}

// startETSIRefreshLoop starts background TSL refresh, matching what lote,
// whitelist and fidomds3 already do. Without it the registry serves whatever
// it loaded at startup until the process restarts, so a service revoked
// upstream stays trusted for as long as gt happens to stay up.
//
// A zero interval disables refresh, and a failure to start is a warning
// rather than fatal: stale trust data still answers, no trust data does not.
func startETSIRefreshLoop(reg *etsi.TSLRegistry, interval time.Duration, logger logging.Logger) {
	if reg == nil || interval <= 0 {
		return
	}
	if err := reg.StartRefreshLoop(context.Background()); err != nil {
		logger.Warn("Failed to start ETSI TSL background refresh",
			logging.F("error", err.Error()))
		return
	}
	logger.Info("ETSI TSL background refresh started",
		logging.F("interval", interval.String()))
}

// resolutionStrategy maps registries.strategy onto a ResolutionStrategy.
//
// main.go previously passed registry.FirstMatch as a literal, so the three
// other strategies in pkg/registry/strategies.go were implemented, tested and
// unreachable.
func resolutionStrategy(cfg *config.Config, logger logging.Logger) registry.ResolutionStrategy {
	if cfg == nil || cfg.Registries.Strategy == "" {
		return registry.FirstMatch
	}
	switch strategy := registry.ResolutionStrategy(cfg.Registries.Strategy); strategy {
	case registry.FirstMatch, registry.AllRegistries, registry.BestMatch, registry.Sequential:
		if logger != nil && strategy != registry.FirstMatch {
			logger.Info("Registry resolution strategy set from config",
				logging.F("strategy", string(strategy)))
		}
		return strategy
	default:
		if logger != nil {
			logger.Warn("Unknown registries.strategy, falling back to first_match",
				logging.F("value", cfg.Registries.Strategy),
				logging.F("valid", []string{
					string(registry.FirstMatch), string(registry.AllRegistries),
					string(registry.BestMatch), string(registry.Sequential),
				}))
		}
		return registry.FirstMatch
	}
}

// configureCompositeRegistriesFromConfig builds CompositeRegistry instances
// from config and swaps them in for their children.
//
// It must run after every other registry is registered, because children are
// resolved by name out of the manager. Each child is unregistered as it is
// taken: left in place it would also be evaluated standalone, and under
// first_match could return decision=true on its own — precisely the agreement
// an AND composite exists to require.
//
// Returns an error rather than exiting, so the validation below is reachable
// from tests; the caller decides that a bad composite is fatal.
func configureCompositeRegistriesFromConfig(cfg *config.Config, registryMgr *registry.RegistryManager, logger logging.Logger) error {
	for _, compCfg := range cfg.Registries.Composite {
		if compCfg.Name == "" {
			return fmt.Errorf("composite registry has no name")
		}
		operator, ok := compositeOperator(compCfg.Operator)
		if !ok {
			return fmt.Errorf("composite registry %q has unknown operator %q (want AND, OR, MAJORITY or QUORUM)",
				compCfg.Name, compCfg.Operator)
		}
		if len(compCfg.Registries) == 0 {
			return fmt.Errorf("composite registry %q names no child registries", compCfg.Name)
		}

		children := make([]registry.TrustRegistry, 0, len(compCfg.Registries))
		for _, childName := range compCfg.Registries {
			// Registry names are not guaranteed unique — a config-file ETSI
			// registry and a CLI-configured one both default to "ETSI-TSL",
			// for instance. Taking one of two would leave the other
			// top-level, able to allow a request on its own, which is the
			// bypass this whole mechanism exists to prevent. There is no
			// safe way to guess which was meant, so say so.
			switch registryMgr.CountRegistries(childName) {
			case 0:
				// An error rather than a skip: a composite quietly missing a
				// child is a weaker trust rule than the operator wrote.
				return fmt.Errorf("composite registry %q names registry %q, which is not configured",
					compCfg.Name, childName)
			case 1:
			default:
				return fmt.Errorf("composite registry %q names registry %q, but %d registries share that name; give them distinct names",
					compCfg.Name, childName, registryMgr.CountRegistries(childName))
			}
			child := registryMgr.GetRegistry(childName)
			registryMgr.Unregister(childName)
			children = append(children, child)
		}

		opts := []registry.CompositeOption{}
		if compCfg.Description != "" {
			opts = append(opts, registry.WithDescription(compCfg.Description))
		}
		if operator == registry.LogicQUORUM {
			if compCfg.Threshold < 1 || compCfg.Threshold > len(children) {
				return fmt.Errorf("composite registry %q is QUORUM with threshold %d; want between 1 and %d, the number of children",
					compCfg.Name, compCfg.Threshold, len(children))
			}
			opts = append(opts, registry.WithThreshold(compCfg.Threshold))
		}
		if compCfg.Timeout != "" {
			// ParseDuration accepts "0" and negatives, and either would
			// install an already-expired context: context-aware children
			// would then fail instantly and turn every evaluation into a
			// denial. Not fatal, because falling back to the default
			// weakens nothing.
			if timeout, err := time.ParseDuration(compCfg.Timeout); err != nil {
				logger.Warn("Invalid timeout for composite registry, using default",
					logging.F("composite", compCfg.Name),
					logging.F("value", compCfg.Timeout),
					logging.F("error", err.Error()))
			} else if timeout <= 0 {
				logger.Warn("Non-positive timeout for composite registry, using default",
					logging.F("composite", compCfg.Name),
					logging.F("value", compCfg.Timeout))
			} else {
				opts = append(opts, registry.WithTimeout(timeout))
			}
		}

		registryMgr.Register(registry.NewCompositeRegistryWithOptions(
			compCfg.Name, operator, children, opts...))
		logger.Info("Composite registry registered from config",
			logging.F("name", compCfg.Name),
			logging.F("operator", string(operator)),
			logging.F("children", compCfg.Registries))
	}
	return nil
}

// compositeOperator parses an operator name, accepting any case so "and" and
// "AND" both work in a config file.
func compositeOperator(name string) (registry.LogicOperator, bool) {
	switch registry.LogicOperator(strings.ToUpper(strings.TrimSpace(name))) {
	case registry.LogicAND:
		return registry.LogicAND, true
	case registry.LogicOR:
		return registry.LogicOR, true
	case registry.LogicMAJORITY:
		return registry.LogicMAJORITY, true
	case registry.LogicQUORUM:
		return registry.LogicQUORUM, true
	default:
		return "", false
	}
}

// configurePoliciesFromConfig configures trust policies from the loaded config file.
func configurePoliciesFromConfig(cfg *config.Config, registryMgr *registry.RegistryManager, logger logging.Logger) {
	policyMgr := registry.NewPolicyManager()
	policyCount := 0

	for name, policyCfg := range cfg.Policies.Policies {
		policy := &registry.Policy{
			Name:        name,
			Description: policyCfg.Description,
			Registries:  policyCfg.Registries,
		}

		// Convert constraints
		if policyCfg.Constraints != nil {
			policy.Constraints = registry.PolicyConstraints{
				AllowedKeyTypes:   policyCfg.Constraints.AllowedKeyTypes,
				RequireKeyBinding: policyCfg.Constraints.RequireKeyBinding,
			}
		}

		// Convert ETSI constraints
		if policyCfg.ETSI != nil {
			policy.ETSI = &registry.ETSIPolicyConstraints{
				ServiceTypes:           policyCfg.ETSI.ServiceTypes,
				ServiceStatuses:        policyCfg.ETSI.ServiceStatuses,
				Countries:              policyCfg.ETSI.Countries,
				CredentialTypes:        policyCfg.ETSI.CredentialTypes,
				RequiredCertPolicyOIDs: policyCfg.ETSI.RequiredCertPolicyOIDs,
				ExtractRPIdentity:      policyCfg.ETSI.ExtractRPIdentity,
				AllowedAttributes:      policyCfg.ETSI.AllowedAttributes,
				StrictEntitlementCheck: policyCfg.ETSI.StrictEntitlementCheck,
				AllowIntermediaries:    policyCfg.ETSI.AllowIntermediaries,
			}
		}

		// Convert OpenID Federation constraints
		if policyCfg.OIDFed != nil {
			policy.OIDFed = &registry.OIDFedPolicyConstraints{
				RequiredTrustMarks:       policyCfg.OIDFed.RequiredTrustMarks,
				EntityTypes:              policyCfg.OIDFed.EntityTypes,
				MaxChainDepth:            policyCfg.OIDFed.MaxChainDepth,
				CredentialTypeTrustMarks: policyCfg.OIDFed.CredentialTypeTrustMarks,
			}
		}

		// Convert DID constraints
		if policyCfg.DID != nil {
			policy.DID = &registry.DIDPolicyConstraints{
				AllowedDomains:              policyCfg.DID.AllowedDomains,
				RequiredVerificationMethods: policyCfg.DID.RequiredVerificationMethods,
				RequiredServices:            policyCfg.DID.RequiredServices,
				RequireVerifiableHistory:    policyCfg.DID.RequireVerifiableHistory,
			}
		}

		// Convert mDOC IACA constraints
		if policyCfg.MDOCIACA != nil {
			policy.MDOCIACA = &registry.MDOCIACAPolicyConstraints{
				IssuerAllowlist:     policyCfg.MDOCIACA.IssuerAllowlist,
				RequireIACAEndpoint: policyCfg.MDOCIACA.RequireIACAEndpoint,
			}
		}

		// Convert FIDO MDS3 constraints
		if policyCfg.FIDOMDS3 != nil {
			policy.FIDOMDS3 = &registry.FIDOMDS3PolicyConstraints{
				AllowedAAGUIDs: policyCfg.FIDOMDS3.AllowedAAGUIDs,
				BlockedAAGUIDs: policyCfg.FIDOMDS3.BlockedAAGUIDs,
			}
		}

		policyMgr.RegisterPolicy(policy)
		policyCount++

		logger.Debug("Registered policy from config",
			logging.F("name", name),
			logging.F("description", policyCfg.Description))
	}

	// Set default policy if specified
	if cfg.Policies.DefaultPolicy != "" {
		defaultPolicy := policyMgr.GetPolicy(cfg.Policies.DefaultPolicy)
		if defaultPolicy != nil {
			policyMgr.SetDefaultPolicy(defaultPolicy)
			logger.Info("Default policy set from config",
				logging.F("policy", cfg.Policies.DefaultPolicy))
		} else {
			logger.Warn("Default policy not found in policies",
				logging.F("policy", cfg.Policies.DefaultPolicy))
		}
	}

	if policyCount > 0 {
		registryMgr.SetPolicyManager(policyMgr)
		logger.Info("Trust policies configured from config file",
			logging.F("count", policyCount),
			logging.F("policies", policyMgr.ListPolicies()))
	}
}

// splitCSV splits a comma-separated string and trims whitespace
func splitCSV(s string) []string {
	if s == "" {
		return nil
	}
	parts := []string{}
	for _, part := range splitString(s, ',') {
		trimmed := trimSpace(part)
		if trimmed != "" {
			parts = append(parts, trimmed)
		}
	}
	return parts
}

func splitString(s string, sep rune) []string {
	var parts []string
	var current []rune
	for _, r := range s {
		if r == sep {
			parts = append(parts, string(current))
			current = nil
		} else {
			current = append(current, r)
		}
	}
	if len(current) > 0 || len(parts) > 0 {
		parts = append(parts, string(current))
	}
	return parts
}

func trimSpace(s string) string {
	start := 0
	end := len(s)
	for start < end && isSpace(rune(s[start])) {
		start++
	}
	for start < end && isSpace(rune(s[end-1])) {
		end--
	}
	return s[start:end]
}

func isSpace(r rune) bool {
	return r == ' ' || r == '\t' || r == '\n' || r == '\r'
}

// etsiTSLConfig maps the ETSI registry's configuration onto the registry's own
// config struct.
//
// Extracted so the mapping can be tested. Every field here was once dropped on
// the floor: TSLURLs, FollowRefs, MaxRefDepth, UserAgent, AllowNetworkAccess
// and FetchTimeout were all absent, so configuring an ETSI registry from a file
// with tsl_urls left it with nothing to load and the process exited with
// "no trust data loaded" - a message that points at the configuration rather
// than at the code that ignored it.
func etsiTSLConfig(etsiCfg *config.ETSIRegistryConfig, cryptoExt *gocryptoutil.Extensions, logger logging.Logger) etsi.TSLConfig {
	tslConfig := etsi.TSLConfig{
		Name:               etsiCfg.Name,
		Description:        etsiCfg.Description,
		CryptoExt:          cryptoExt,
		CertBundle:         etsiCfg.CertBundle,
		TSLFiles:           etsiCfg.TSLFiles,
		TSLURLs:            etsiCfg.TSLURLs,
		FollowRefs:         etsiCfg.FollowRefs,
		MaxRefDepth:        etsiCfg.MaxRefDepth,
		UserAgent:          etsiCfg.UserAgent,
		AllowNetworkAccess: etsiCfg.AllowNetworkAccess,
		LOTLSignerBundle:   etsiCfg.LOTLSignerBundle,
		RequireSignature:   etsiCfg.RequireSignature,
		FollowPivots:       etsiCfg.FollowPivots,
	}

	if etsiCfg.FetchTimeout != "" {
		if timeout, err := time.ParseDuration(etsiCfg.FetchTimeout); err == nil {
			tslConfig.FetchTimeout = timeout
		} else if logger != nil {
			logger.Warn("Invalid fetch_timeout for etsi registry, using default",
				logging.F("value", etsiCfg.FetchTimeout),
				logging.F("error", err.Error()))
		}
	}

	if etsiCfg.RefreshInterval != "" {
		if interval, err := time.ParseDuration(etsiCfg.RefreshInterval); err == nil {
			tslConfig.RefreshInterval = interval
		} else if logger != nil {
			logger.Warn("Invalid refresh_interval for etsi registry, background refresh disabled",
				logging.F("value", etsiCfg.RefreshInterval),
				logging.F("error", err.Error()))
		}
	}

	if tslConfig.Name == "" {
		tslConfig.Name = "ETSI-TSL"
	}
	if tslConfig.Description == "" {
		tslConfig.Description = "ETSI TS 119612 Trust Status List Registry"
	}
	return tslConfig
}
