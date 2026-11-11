package static

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// More startup-behaviour tests for the whitelist's JWKS cache (issue #245); see
// whitelist_startup_test.go.

// A transient failure of one discovery step is not hidden by the 404 of the
// steps after it: the entity is retried. All-404 stays permanent.
func TestRefresh_TransientDiscoveryFailureIsRetryableDespiteLater404(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/jwt-vc-issuer") {
			http.Error(w, "starting", http.StatusServiceUnavailable)
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	reg := NewWhitelistRegistry(WithWhitelistConfig(WhitelistConfig{Issuers: []string{srv.URL}, AllowHTTP: true}))
	defer func() { _ = reg.Close() }()
	_ = reg.Refresh(context.Background())

	reg.mu.RLock()
	f, failed := reg.fetchErrs[normalizeEntityID(srv.URL)]
	reg.mu.RUnlock()
	if !failed || !f.retryable {
		t.Fatalf("a 503 from jwt-vc-issuer followed by 404s must stay retryable, got %+v (failed=%v)", f, failed)
	}
}

// An entry added after a completed refresh has not been fetched: its denial is
// could-not-evaluate until it is, whatever the registry-wide refresh state.
func TestEvaluate_EntryAddedAfterRefreshIsPendingUntilFetched(t *testing.T) {
	ok := httptest.NewServer(jwksHandler(testJWKSBody(t, "ok")))
	defer ok.Close()
	added := httptest.NewServer(jwksHandler(testJWKSBody(t, "added")))
	defer added.Close()

	reg := NewWhitelistRegistry(WithWhitelistConfig(WhitelistConfig{Issuers: []string{ok.URL}, AllowHTTP: true}))
	defer func() { _ = reg.Close() }()
	if err := reg.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}

	reg.AddIssuer(added.URL)
	resp, err := reg.Evaluate(context.Background(), keyedRequest(added.URL))
	if err != nil {
		t.Fatal(err)
	}
	if resp.Decision || !resp.CouldNotEvaluate() {
		t.Fatalf("an unfetched entry must be could-not-evaluate, got %+v", resp.Context.Reason)
	}

	if err := reg.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	if cachedKeys(reg, added.URL) == 0 {
		t.Fatal("the added entry's keys should be cached after the next refresh")
	}
}

// With an explicit JWKSEndpointPattern a scheme-less id is fetched (the pattern
// makes the URL), as before.
func TestRefresh_SchemelessIDWithExplicitPattern(t *testing.T) {
	srv := httptest.NewServer(jwksHandler(testJWKSBody(t, "pattern")))
	defer srv.Close()
	host := strings.TrimPrefix(srv.URL, "http://")

	reg := NewWhitelistRegistry(WithWhitelistConfig(WhitelistConfig{
		Issuers:             []string{host},
		JWKSEndpointPattern: "http://{entity}/keys.json",
		AllowHTTP:           true,
	}))
	defer func() { _ = reg.Close() }()
	if err := reg.Refresh(context.Background()); err != nil {
		t.Fatalf("a scheme-less id with a JWKS endpoint pattern must be fetched: %v", err)
	}
	if cachedKeys(reg, host) == 0 {
		t.Fatal("no keys cached for the scheme-less id")
	}
}

// The periodic tick and the startup retry publish concurrently (run with -race).
func TestRefreshLoop_TickAndRetryAreRaceFree(t *testing.T) {
	var up atomic.Bool
	ok := jwksHandler(testJWKSBody(t, "k"))
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !up.Load() {
			http.Error(w, "down", http.StatusServiceUnavailable)
			return
		}
		ok(w, r)
	}))
	defer srv.Close()

	reg := NewWhitelistRegistry(
		WithWhitelistConfig(WhitelistConfig{Issuers: []string{srv.URL}, AllowHTTP: true}),
		WithRefreshInterval(5*time.Millisecond),
	)
	reg.retryBackoff = []time.Duration{time.Millisecond, time.Millisecond, time.Millisecond}
	if err := reg.StartRefreshLoop(context.Background()); err != nil {
		t.Fatal(err)
	}
	up.Store(true)
	time.Sleep(300 * time.Millisecond)
	_ = reg.Close()
}
