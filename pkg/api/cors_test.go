package api

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

func corsRouter(origins []string) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(CORSMiddleware(origins))
	r.POST("/evaluation", func(c *gin.Context) { c.JSON(http.StatusOK, gin.H{"decision": true}) })
	return r
}

func do(r *gin.Engine, method, origin string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, "/evaluation", nil)
	if origin != "" {
		req.Header.Set("Origin", origin)
	}
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

func TestCORSAllowedOriginIsEchoed(t *testing.T) {
	r := corsRouter([]string{"https://wallet.example.com"})
	w := do(r, http.MethodPost, "https://wallet.example.com")

	if got := w.Header().Get("Access-Control-Allow-Origin"); got != "https://wallet.example.com" {
		t.Errorf("Allow-Origin = %q, want the request origin", got)
	}
	if got := w.Header().Get("Vary"); got != "Origin" {
		t.Errorf("Vary = %q, want Origin; a shared cache must not reuse one origin's response", got)
	}
	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", w.Code)
	}
}

// TestCORSUnlistedOriginGetsNoHeader is the one that matters: an allowlist
// that echoes whatever Origin arrives is decorative, and would let any site
// read PDP responses.
func TestCORSUnlistedOriginGetsNoHeader(t *testing.T) {
	r := corsRouter([]string{"https://wallet.example.com"})
	w := do(r, http.MethodPost, "https://attacker.example")

	if got := w.Header().Get("Access-Control-Allow-Origin"); got != "" {
		t.Errorf("Allow-Origin = %q, want empty for an unlisted origin", got)
	}
}

func TestCORSPreflight(t *testing.T) {
	r := corsRouter([]string{"https://wallet.example.com"})
	w := do(r, http.MethodOptions, "https://wallet.example.com")

	if w.Code != http.StatusNoContent {
		t.Errorf("preflight status = %d, want 204", w.Code)
	}
	if got := w.Header().Get("Access-Control-Allow-Methods"); got == "" {
		t.Error("preflight did not advertise allowed methods")
	}
	if got := w.Header().Get("Access-Control-Max-Age"); got == "" {
		t.Error("preflight did not set Max-Age")
	}
}

func TestCORSPreflightFromUnlistedOriginIsRefused(t *testing.T) {
	r := corsRouter([]string{"https://wallet.example.com"})
	w := do(r, http.MethodOptions, "https://attacker.example")

	if w.Code != http.StatusForbidden {
		t.Errorf("preflight status = %d, want 403", w.Code)
	}
}

func TestCORSMatchIsCaseInsensitive(t *testing.T) {
	r := corsRouter([]string{"https://Wallet.Example.COM"})
	w := do(r, http.MethodPost, "https://wallet.example.com")

	if got := w.Header().Get("Access-Control-Allow-Origin"); got == "" {
		t.Error("host comparison should be case-insensitive")
	}
}

func TestCORSWildcard(t *testing.T) {
	r := corsRouter([]string{"*"})
	w := do(r, http.MethodPost, "https://anything.example")

	if got := w.Header().Get("Access-Control-Allow-Origin"); got != "*" {
		t.Errorf("Allow-Origin = %q, want *", got)
	}
	// Credentials must never be enabled, least of all alongside "*".
	if got := w.Header().Get("Access-Control-Allow-Credentials"); got != "" {
		t.Errorf("Allow-Credentials = %q, want unset", got)
	}
}

func TestCORSEmptyAllowlistAllowsNothing(t *testing.T) {
	r := corsRouter(nil)
	w := do(r, http.MethodPost, "https://wallet.example.com")

	if got := w.Header().Get("Access-Control-Allow-Origin"); got != "" {
		t.Errorf("Allow-Origin = %q, want empty when no origins are configured", got)
	}
}

func TestCORSSameOriginRequestUntouched(t *testing.T) {
	r := corsRouter([]string{"https://wallet.example.com"})
	w := do(r, http.MethodPost, "")

	if got := w.Header().Get("Vary"); got != "" {
		t.Errorf("Vary = %q, want unset for a request with no Origin", got)
	}
	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", w.Code)
	}
}

func TestCORSWildcardSubdomain(t *testing.T) {
	patterns := []string{"https://*.example.com"}
	cases := []struct {
		origin string
		want   bool
		why    string
	}{
		{"https://sub.example.com", true, "a subdomain is the point of the wildcard"},
		{"https://deep.sub.example.com", true, "any depth of subdomain"},
		{"https://example.com", false, "the apex is not a subdomain; list it explicitly"},
		{"https://notexample.com", false, "the leading dot must stop suffix-splicing"},
		{"https://evilexample.com", false, "same, without a dot boundary"},
		{"http://sub.example.com", false, "scheme is part of the origin"},
		{"https://sub.example.com:8443", false, "port is part of the origin; list it explicitly"},
		{"https://sub.example.com.attacker.test", false, "suffix must be at the end"},
	}

	for _, tc := range cases {
		if got := originAllowed(tc.origin, patterns); got != tc.want {
			t.Errorf("originAllowed(%q) = %v, want %v — %s", tc.origin, got, tc.want, tc.why)
		}
	}
}

func TestCORSWildcardEndToEnd(t *testing.T) {
	r := corsRouter([]string{"https://*.example.com"})

	if got := do(r, http.MethodPost, "https://wallet.example.com").
		Header().Get("Access-Control-Allow-Origin"); got != "https://wallet.example.com" {
		t.Errorf("Allow-Origin = %q, want the subdomain echoed", got)
	}
	if got := do(r, http.MethodPost, "https://attacker.test").
		Header().Get("Access-Control-Allow-Origin"); got != "" {
		t.Errorf("Allow-Origin = %q, want empty", got)
	}
}

func TestCORSMalformedPatternNeverMatches(t *testing.T) {
	// A pattern with no scheme cannot be split into scheme and host, so the
	// wildcard branch must decline rather than fall through to a partial
	// comparison that could over-match.
	for _, pattern := range []string{"*.example.com", "example.com", "://*.example.com"} {
		if originAllowed("https://sub.example.com", []string{pattern}) {
			t.Errorf("pattern %q matched; a wildcard pattern must carry a scheme", pattern)
		}
	}

	// An Origin header that is not a well-formed origin must not match a
	// wildcard pattern either.
	if originAllowed("sub.example.com", []string{"https://*.example.com"}) {
		t.Error("a schemeless Origin matched a wildcard pattern")
	}
}

func TestCORSEnabledWithEmptyAllowlistRefusesPreflight(t *testing.T) {
	// enable_cors true with no origins configured rejects everything. gt
	// warns about this at startup; the behaviour itself is pinned here.
	r := corsRouter([]string{})
	if got := do(r, http.MethodOptions, "https://wallet.example.com").Code; got != http.StatusForbidden {
		t.Errorf("preflight = %d, want 403", got)
	}
}
