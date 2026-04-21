package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/sirosfoundation/g119612/pkg/logging"
	_ "github.com/sirosfoundation/go-trust/docs/swagger" // Import generated docs
	"github.com/sirosfoundation/go-trust/pkg/api"
	"github.com/sirosfoundation/go-trust/pkg/config"
	"github.com/sirosfoundation/go-trust/pkg/registry"
	"github.com/sirosfoundation/go-trust/pkg/registry/didjwks"
	"github.com/sirosfoundation/go-trust/pkg/registry/didweb"
	"github.com/sirosfoundation/go-trust/pkg/registry/didwebvh"
	"github.com/sirosfoundation/go-trust/pkg/registry/etsi"
	"github.com/sirosfoundation/go-trust/pkg/registry/lote"
	"github.com/sirosfoundation/go-trust/pkg/registry/mdociaca"
	"github.com/sirosfoundation/go-trust/pkg/registry/oidfed"
	"github.com/sirosfoundation/go-trust/pkg/registry/static"
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
	fmt.Fprintln(os.Stderr, "  --host         API server hostname (default: 127.0.0.1)")
	fmt.Fprintln(os.Stderr, "  --port         API server port (default: 6001)")
	fmt.Fprintln(os.Stderr, "  --external-url External URL for PDP discovery (e.g., https://pdp.example.com)")
	fmt.Fprintln(os.Stderr, "                 Can also be set via GO_TRUST_EXTERNAL_URL environment variable")
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
	configFile := flag.String("config", "", "Configuration file path (YAML format)")
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

	logger.Info("Starting go-trust server",
		logging.F("version", Version),
		logging.F("host", *host),
		logging.F("port", *port))

	// Load configuration file if provided
	var cfg *config.Config
	if *configFile != "" {
		var err error
		cfg, err = config.LoadConfig(*configFile)
		if err != nil {
			logger.Fatal("Failed to load configuration file",
				logging.F("file", *configFile),
				logging.F("error", err.Error()))
		}
		logger.Info("Loaded configuration from file",
			logging.F("file", *configFile))

		// Validate configuration
		if err := cfg.Validate(); err != nil {
			logger.Fatal("Configuration validation failed",
				logging.F("file", *configFile),
				logging.F("error", err.Error()))
		}

		// Use config file values if CLI flags weren't explicitly set
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
	}

	// Create server context
	serverCtx := api.NewServerContext(logger)

	// Apply global HTTP response body size limit from config
	if cfg != nil && cfg.Security.MaxResponseBodyBytes > 0 {
		registry.SetMaxResponseBodyBytes(cfg.Security.MaxResponseBodyBytes)
	}

	// Initialize RegistryManager
	registryMgr := registry.NewRegistryManager(registry.FirstMatch, 30*time.Second)
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
			whitelistReg, err := static.NewWhitelistRegistryFromFile(*whitelistFile, *whitelistWatch,
				static.WithWhitelistName("whitelist"),
				static.WithWhitelistDescription("URL whitelist from "+*whitelistFile))
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

	// Configure policies from config file
	if cfg != nil && cfg.Policies.Policies != nil {
		configurePoliciesFromConfig(cfg, registryMgr, logger)
	}

	serverCtx.RegistryManager = registryMgr

	// Set BaseURL for .well-known discovery
	baseURL := *externalURL
	if baseURL == "" {
		baseURL = os.Getenv("GO_TRUST_EXTERNAL_URL")
	}
	if baseURL == "" {
		baseURL = fmt.Sprintf("http://%s:%s", *host, *port)
	}
	serverCtx.BaseURL = baseURL

	logger.Info("AuthZEN PDP base URL configured",
		logging.F("url", baseURL))

	// Gin API server
	if *logLevel != "debug" {
		gin.SetMode(gin.ReleaseMode)
	}
	r := gin.Default()

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
	// Configure ETSI TSL registry from config
	if cfg.Registries.ETSI != nil && cfg.Registries.ETSI.Enabled {
		logger.Info("Configuring ETSI TSL registry from config file")
		etsiCfg := cfg.Registries.ETSI

		tslConfig := etsi.TSLConfig{
			Name:             etsiCfg.Name,
			Description:      etsiCfg.Description,
			CertBundle:       etsiCfg.CertBundle,
			TSLFiles:         etsiCfg.TSLFiles,
			LOTLSignerBundle: etsiCfg.LOTLSignerBundle,
			RequireSignature: etsiCfg.RequireSignature,
			FollowPivots:     etsiCfg.FollowPivots,
		}

		if tslConfig.Name == "" {
			tslConfig.Name = "ETSI-TSL"
		}
		if tslConfig.Description == "" {
			tslConfig.Description = "ETSI TS 119612 Trust Status List Registry"
		}

		tslRegistry, err := etsi.NewTSLRegistry(tslConfig)
		if err != nil {
			logger.Fatal("Failed to create ETSI TSL registry from config",
				logging.F("error", err.Error()))
		}

		registryMgr.Register(tslRegistry)
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
				static.WithWhitelistConfig(static.WhitelistConfig{
					Lists:           wlCfg.Lists,
					Actions:         wlCfg.Actions,
					Issuers:         wlCfg.Issuers,
					Verifiers:       wlCfg.Verifiers,
					TrustedSubjects: wlCfg.TrustedSubjects,
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
			trustAnchors[i] = oidfed.TrustAnchorConfig{
				EntityID: ta.EntityID,
				// JWKS parsing would need additional handling if provided as string
			}
		}

		oidfedConfig := oidfed.Config{
			TrustAnchors:       trustAnchors,
			RequiredTrustMarks: oidfedCfg.RequiredTrustMarks,
			EntityTypes:        oidfedCfg.EntityTypes,
			Description:        oidfedCfg.Description,
			MaxCacheSize:       oidfedCfg.MaxCacheSize,
			MaxChainDepth:      oidfedCfg.MaxChainDepth,
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
			Name:        loteCfg.Name,
			Description: loteCfg.Description,
			Sources:     loteCfg.Sources,
			VerifyJWS:   loteCfg.VerifyJWS,
			Logger:      slog.Default(),
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
		if policyCfg.Constraints != nil && len(policyCfg.Constraints.AllowedKeyTypes) > 0 {
			policy.Constraints = registry.PolicyConstraints{
				AllowedKeyTypes: policyCfg.Constraints.AllowedKeyTypes,
			}
		}

		// Convert ETSI constraints
		if policyCfg.ETSI != nil {
			policy.ETSI = &registry.ETSIPolicyConstraints{
				ServiceTypes:    policyCfg.ETSI.ServiceTypes,
				ServiceStatuses: policyCfg.ETSI.ServiceStatuses,
				Countries:       policyCfg.ETSI.Countries,
			}
		}

		// Convert OpenID Federation constraints
		if policyCfg.OIDFed != nil {
			policy.OIDFed = &registry.OIDFedPolicyConstraints{
				RequiredTrustMarks: policyCfg.OIDFed.RequiredTrustMarks,
				EntityTypes:        policyCfg.OIDFed.EntityTypes,
				MaxChainDepth:      policyCfg.OIDFed.MaxChainDepth,
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
