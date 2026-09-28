package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/sirosfoundation/g119612/pkg/logging"
	"github.com/sirosfoundation/go-trust/pkg/config"
	"github.com/sirosfoundation/go-trust/pkg/registry"
)

func TestRateLimitBurst(t *testing.T) {
	cases := []struct{ rps, want int }{
		{1000, 100},
		{100, 10},
		{10, 1},
		{5, 1}, // a tenth rounds to zero, which would block every request
		{1, 1},
	}
	for _, tc := range cases {
		if got := rateLimitBurst(tc.rps); got != tc.want {
			t.Errorf("rateLimitBurst(%d) = %d, want %d", tc.rps, got, tc.want)
		}
	}
}

func TestInstallSecurityMiddlewareCORS(t *testing.T) {
	gin.SetMode(gin.TestMode)

	cfg := &config.Config{}
	cfg.Security.EnableCORS = true
	cfg.Security.AllowedOrigins = []string{"https://wallet.example.com"}

	r := gin.New()
	installSecurityMiddleware(r, cfg, logging.SilentLogger())
	r.GET("/healthz", func(c *gin.Context) { c.Status(http.StatusOK) })

	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	req.Header.Set("Origin", "https://wallet.example.com")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if got := w.Header().Get("Access-Control-Allow-Origin"); got != "https://wallet.example.com" {
		t.Errorf("Allow-Origin = %q; CORS middleware was not installed", got)
	}
}

func TestInstallSecurityMiddlewareRateLimit(t *testing.T) {
	gin.SetMode(gin.TestMode)

	cfg := &config.Config{}
	cfg.Security.RateLimitRPS = 1 // burst 1: the second request must be refused

	r := gin.New()
	installSecurityMiddleware(r, cfg, logging.SilentLogger())
	r.GET("/healthz", func(c *gin.Context) { c.Status(http.StatusOK) })

	call := func() int {
		req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
		req.RemoteAddr = "203.0.113.7:1234"
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		return w.Code
	}

	if got := call(); got != http.StatusOK {
		t.Fatalf("first request = %d, want 200", got)
	}
	if got := call(); got != http.StatusTooManyRequests {
		t.Errorf("second request = %d, want 429; rate limiter was not installed", got)
	}
}

func TestInstallSecurityMiddlewareDisabledByDefault(t *testing.T) {
	gin.SetMode(gin.TestMode)

	r := gin.New()
	installSecurityMiddleware(r, &config.Config{}, logging.SilentLogger())
	r.GET("/healthz", func(c *gin.Context) { c.Status(http.StatusOK) })

	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	req.Header.Set("Origin", "https://anything.example")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if got := w.Header().Get("Access-Control-Allow-Origin"); got != "" {
		t.Errorf("Allow-Origin = %q; CORS must stay off unless enabled", got)
	}
	if w.Code != http.StatusOK {
		t.Errorf("status = %d; nothing should be limited when rps is 0", w.Code)
	}

	// A nil config must not panic: gt loads config even with no file given.
	installSecurityMiddleware(gin.New(), nil, logging.SilentLogger())
}

func TestConfigureSystemCertPoolRegistry(t *testing.T) {
	mgr := registry.NewRegistryManager(registry.FirstMatch, 0)

	cfg := &config.Config{}
	cfg.Registries.SystemCertPool = &config.SystemCertPoolRegistryConfig{
		Enabled: true,
		Name:    "syspool",
	}
	if err := configureSystemCertPoolRegistry(cfg, mgr, logging.SilentLogger()); err != nil {
		t.Fatalf("configureSystemCertPoolRegistry: %v", err)
	}

	if mgr.GetRegistry("syspool") == nil {
		t.Error("system cert pool registry was not registered")
	}

	// Disabled and absent must both be no-ops.
	off := registry.NewRegistryManager(registry.FirstMatch, 0)
	cfg.Registries.SystemCertPool.Enabled = false
	_ = configureSystemCertPoolRegistry(cfg, off, logging.SilentLogger())
	_ = configureSystemCertPoolRegistry(&config.Config{}, off, logging.SilentLogger())
	_ = configureSystemCertPoolRegistry(nil, off, logging.SilentLogger())
	if len(off.ListRegistries()) != 0 {
		t.Errorf("registries = %v, want none", off.ListRegistries())
	}
}

func TestStartETSIRefreshLoopIgnoresZeroInterval(t *testing.T) {
	// A nil registry and a zero interval must both be quiet no-ops rather
	// than a nil dereference during startup.
	startETSIRefreshLoop(nil, 0, logging.SilentLogger())
	startETSIRefreshLoop(nil, time.Hour, logging.SilentLogger())
}

func TestWarnUnknownConfigKeys(t *testing.T) {
	// Exercised for its guard clauses; the reporting itself is covered by
	// pkg/config's TestLoadConfigReportsUnknownKeys.
	warnUnknownConfigKeys(nil, "", logging.SilentLogger())
	warnUnknownConfigKeys(&config.Config{}, "none.yaml", logging.SilentLogger())

	tmp := t.TempDir()
	path := filepath.Join(tmp, "config.yaml")
	if err := os.WriteFile(path, []byte("server:\n  host: \"0.0.0.0\"\nregistries:\n  did_local:\n    enabled: true\n"), 0644); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.LoadConfig(path)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if len(cfg.UnknownKeys()) == 0 {
		t.Fatal("expected did_local to be reported as unknown")
	}
	warnUnknownConfigKeys(cfg, path, logging.SilentLogger())
}

func TestETSITSLConfigParsesRefreshInterval(t *testing.T) {
	cfg := &config.ETSIRegistryConfig{RefreshInterval: "6h"}
	if got := etsiTSLConfig(cfg, nil, logging.SilentLogger()).RefreshInterval; got != 6*time.Hour {
		t.Errorf("RefreshInterval = %v, want 6h", got)
	}

	// An unparseable value disables refresh rather than failing startup.
	bad := &config.ETSIRegistryConfig{RefreshInterval: "every other tuesday"}
	if got := etsiTSLConfig(bad, nil, logging.SilentLogger()).RefreshInterval; got != 0 {
		t.Errorf("RefreshInterval = %v, want 0 for an invalid value", got)
	}
}

func TestInstallSecurityMiddlewareCORSEnabledWithNoOrigins(t *testing.T) {
	gin.SetMode(gin.TestMode)

	cfg := &config.Config{}
	cfg.Security.EnableCORS = true // deliberately no AllowedOrigins

	r := gin.New()
	installSecurityMiddleware(r, cfg, logging.SilentLogger())
	r.GET("/healthz", func(c *gin.Context) { c.Status(http.StatusOK) })

	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	req.Header.Set("Origin", "https://wallet.example.com")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if got := w.Header().Get("Access-Control-Allow-Origin"); got != "" {
		t.Errorf("Allow-Origin = %q; an empty allowlist must allow nothing", got)
	}
}
