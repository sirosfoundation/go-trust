package static

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sirosfoundation/go-trust/pkg/authzen"
	"github.com/sirosfoundation/go-trust/pkg/registry"
)

// Tests for the startup behaviour of the whitelist's JWKS cache (issue #245):
// per-entity publishing, bounded per-entity time, retry of transient failures,
// not fetching ids that cannot be fetched, and the could-not-evaluate marker.

func testJWKSBody(t *testing.T, kid string) map[string]interface{} {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return map[string]interface{}{"keys": []interface{}{ecdsaPubKeyToJWK(&key.PublicKey, kid)}}
}

func jwksHandler(body map[string]interface{}) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(body)
	}
}

func cachedKeys(r *WhitelistRegistry, entityURL string) int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.keyHashes[normalizeEntityID(entityURL)])
}

func waitFor(t *testing.T, d time.Duration, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

func keyedRequest(subject string) *authzen.EvaluationRequest {
	return &authzen.EvaluationRequest{
		Subject:  authzen.Subject{Type: "key", ID: subject},
		Action:   &authzen.Action{Name: "issuer"},
		Resource: authzen.Resource{Type: "x5c", ID: subject, Key: []interface{}{"AAAA"}},
	}
}

// A slow entity must not hold back the keys of the others: each entity's keys
// are published as soon as they arrive.
func TestRefresh_PublishesPerEntityWhileASlowEntityBlocks(t *testing.T) {
	fast := httptest.NewServer(jwksHandler(testJWKSBody(t, "fast")))
	defer fast.Close()

	release := make(chan struct{})
	slow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-release
		jwksHandler(testJWKSBody(t, "slow"))(w, r)
	}))
	defer slow.Close()
	defer close(release)

	reg := NewWhitelistRegistry(WithWhitelistConfig(WhitelistConfig{
		Issuers:   []string{fast.URL, slow.URL},
		AllowHTTP: true,
	}))
	defer func() { _ = reg.Close() }()

	done := make(chan error, 1)
	go func() { done <- reg.Refresh(context.Background()) }()

	waitFor(t, 2*time.Second, "the fast entity's keys while the slow fetch is still blocked", func() bool {
		return cachedKeys(reg, fast.URL) > 0
	})
	if cachedKeys(reg, slow.URL) != 0 {
		t.Fatal("slow entity has keys although its fetch is still blocked")
	}
	select {
	case <-done:
		t.Fatal("Refresh returned while the slow fetch was blocked")
	default:
	}
}

// One entity that never answers occupies its fetch slot only for the per-entity
// timeout, and the failure is recorded as transient.
func TestRefresh_PerEntityTimeout(t *testing.T) {
	stop := make(chan struct{})
	hang := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { <-stop }))
	defer hang.Close()
	defer close(stop)

	reg := NewWhitelistRegistry(WithWhitelistConfig(WhitelistConfig{
		Issuers:   []string{hang.URL},
		AllowHTTP: true,
	}))
	defer func() { _ = reg.Close() }()
	reg.entityTimeout = 150 * time.Millisecond

	start := time.Now()
	if err := reg.Refresh(context.Background()); err == nil {
		t.Fatal("expected an error for an entity that never answers")
	}
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Fatalf("Refresh took %v; the per-entity timeout did not bound it", elapsed)
	}
	reg.mu.RLock()
	f, failed := reg.fetchErrs[normalizeEntityID(hang.URL)]
	reg.mu.RUnlock()
	if !failed || !f.retryable {
		t.Fatalf("timeout should be recorded as a retryable failure, got %+v (failed=%v)", f, failed)
	}
}

// Ids that cannot be fetched (other schemes) are not fetched and are not
// failures; the registry is healthy without them.
func TestRefresh_SkipsNonHTTPEntities(t *testing.T) {
	reg := NewWhitelistRegistry(WithWhitelistConfig(WhitelistConfig{
		Lists: map[string][]string{"verifiers": {
			"x509_hash:f1drGLOIT4kDBlJVsD-_33igSf5uwRnq3yO2NvcXEW0",
			"did:web:verifier.example.com",
			"x509_san_dns:verifier.example.com",
		}},
		Actions: map[string]string{"verifier": "verifiers"},
	}))
	defer func() { _ = reg.Close() }()

	if err := reg.Refresh(context.Background()); err != nil {
		t.Fatalf("non-HTTP(S) ids must not be fetched or counted as failures: %v", err)
	}
	if !reg.Healthy() {
		t.Error("registry should be healthy when every fetchable entity (none) loaded")
	}
	reg.mu.RLock()
	defer reg.mu.RUnlock()
	if len(reg.fetchErrs) != 0 {
		t.Errorf("fetchErrs = %v, want none", reg.fetchErrs)
	}
}

// An entity that failed transiently is retried on the short backoff instead of
// waiting for the next periodic refresh.
func TestStartRefreshLoop_RetriesTransientFailuresQuickly(t *testing.T) {
	var up atomic.Bool
	ok := jwksHandler(testJWKSBody(t, "late"))
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Down (503 on every discovery endpoint) for the first refresh, up after.
		if !up.Load() {
			http.Error(w, "starting", http.StatusServiceUnavailable)
			return
		}
		ok(w, r)
	}))
	defer srv.Close()

	reg := NewWhitelistRegistry(
		WithWhitelistConfig(WhitelistConfig{Issuers: []string{srv.URL}, AllowHTTP: true}),
		WithRefreshInterval(time.Hour), // the tick must not be what recovers it
	)
	reg.retryBackoff = []time.Duration{20 * time.Millisecond, 20 * time.Millisecond, 20 * time.Millisecond}
	defer func() { _ = reg.Close() }()

	if err := reg.StartRefreshLoop(context.Background()); err != nil {
		t.Fatal(err)
	}
	if cachedKeys(reg, srv.URL) != 0 {
		t.Fatal("test setup: the first refresh should have failed")
	}
	up.Store(true)
	waitFor(t, 5*time.Second, "the retry to load the entity's keys", func() bool {
		return cachedKeys(reg, srv.URL) > 0
	})
	waitFor(t, time.Second, "the registry to become healthy", reg.Healthy)
}

// A failure that cannot clear by itself (4xx) is not retried.
func TestStartRefreshLoop_DoesNotRetryPermanentFailures(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		http.NotFound(w, nil)
	}))
	defer srv.Close()

	reg := NewWhitelistRegistry(
		WithWhitelistConfig(WhitelistConfig{Issuers: []string{srv.URL}, AllowHTTP: true}),
		WithRefreshInterval(time.Hour),
	)
	reg.retryBackoff = []time.Duration{10 * time.Millisecond, 10 * time.Millisecond}
	defer func() { _ = reg.Close() }()

	if err := reg.StartRefreshLoop(context.Background()); err != nil {
		t.Fatal(err)
	}
	after := hits.Load()
	time.Sleep(200 * time.Millisecond)
	if got := hits.Load(); got != after {
		t.Fatalf("a 404 entity was fetched again (%d -> %d requests)", after, got)
	}
}

// Close stops the retry sequence; no goroutine is left running.
func TestStartRefreshLoop_CloseStopsRetry(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "down", http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	reg := NewWhitelistRegistry(
		WithWhitelistConfig(WhitelistConfig{Issuers: []string{srv.URL}, AllowHTTP: true}),
		WithRefreshInterval(time.Hour),
	)
	delays := make([]time.Duration, 200)
	for i := range delays {
		delays[i] = 20 * time.Millisecond
	}
	reg.retryBackoff = delays

	if err := reg.StartRefreshLoop(context.Background()); err != nil {
		t.Fatal(err)
	}
	waitFor(t, time.Second, "the retry sequence to start", reg.retrying.Load)
	_ = reg.Close()
	waitFor(t, time.Second, "the retry sequence to stop after Close", func() bool { return !reg.retrying.Load() })
}

// A denial for keys that could not be loaded is not a trust verdict: it is
// marked could-not-evaluate, directly and through the manager.
func TestEvaluate_KeysNotLoaded_IsCouldNotEvaluate(t *testing.T) {
	down := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "down", http.StatusServiceUnavailable)
	}))
	defer down.Close()

	cfg := WhitelistConfig{Issuers: []string{down.URL}, AllowHTTP: true}

	t.Run("before_any_refresh", func(t *testing.T) {
		reg := NewWhitelistRegistry(WithWhitelistConfig(cfg))
		resp, err := reg.Evaluate(context.Background(), keyedRequest(down.URL))
		if err != nil {
			t.Fatal(err)
		}
		if resp.Decision || !resp.CouldNotEvaluate() {
			t.Fatalf("want a could-not-evaluate denial before the first refresh, got %+v", resp.Context.Reason)
		}
	})

	t.Run("after_failed_fetch", func(t *testing.T) {
		reg := NewWhitelistRegistry(WithWhitelistConfig(cfg))
		_ = reg.Refresh(context.Background())
		resp, err := reg.Evaluate(context.Background(), keyedRequest(down.URL))
		if err != nil {
			t.Fatal(err)
		}
		if resp.Decision || !resp.CouldNotEvaluate() {
			t.Fatalf("want a could-not-evaluate denial after a failed fetch, got %+v", resp.Context.Reason)
		}
		if got, _ := resp.Context.Reason["error"].(string); !strings.Contains(got, "could not be loaded") {
			t.Errorf("reason should name the cause, got %q", got)
		}
	})

	t.Run("through_the_manager", func(t *testing.T) {
		reg := NewWhitelistRegistry(WithWhitelistConfig(cfg))
		_ = reg.Refresh(context.Background())
		m := registry.NewRegistryManager(registry.FirstMatch, 5*time.Second)
		m.Register(reg)
		resp, err := m.Evaluate(context.Background(), keyedRequest(down.URL))
		if err != nil {
			t.Fatal(err)
		}
		if resp.Decision || !resp.CouldNotEvaluate() {
			t.Fatalf("manager must mark the aggregated denial, got %+v", resp.Context.Reason)
		}
		errs, _ := resp.Context.Reason[authzen.ReasonKeyEvaluationErrors].([]map[string]interface{})
		if len(errs) != 1 || !strings.Contains(errs[0]["error"].(string), "could not be loaded") {
			t.Errorf("evaluation_errors should carry the cause, got %v", errs)
		}
	})

	t.Run("a_settled_no_keys_state_is_a_verdict", func(t *testing.T) {
		// An id that was never fetchable has no keys by design: not an outage.
		reg := NewWhitelistRegistry(WithWhitelistConfig(WhitelistConfig{
			Lists:   map[string][]string{"verifiers": {"x509_san_dns:verifier.example.com"}},
			Actions: map[string]string{"issuer": "verifiers"},
		}))
		_ = reg.Refresh(context.Background())
		resp, err := reg.Evaluate(context.Background(), keyedRequest("x509_san_dns:verifier.example.com"))
		if err != nil {
			t.Fatal(err)
		}
		if resp.Decision || resp.CouldNotEvaluate() {
			t.Fatalf("want a plain denial, got %+v", resp.Context.Reason)
		}
	})
}

// Concurrent evaluation during refreshes is race-free (run with -race).
func TestRefresh_ConcurrentWithEvaluate(t *testing.T) {
	var servers []*httptest.Server
	var issuers []string
	for i := 0; i < 12; i++ {
		s := httptest.NewServer(jwksHandler(testJWKSBody(t, "k")))
		servers = append(servers, s)
		issuers = append(issuers, s.URL)
	}
	defer func() {
		for _, s := range servers {
			s.Close()
		}
	}()

	reg := NewWhitelistRegistry(WithWhitelistConfig(WhitelistConfig{Issuers: issuers, AllowHTTP: true}))
	defer func() { _ = reg.Close() }()

	var wg sync.WaitGroup
	for i := 0; i < 3; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = reg.Refresh(context.Background())
		}()
	}
	for i := 0; i < 50; i++ {
		_, _ = reg.Evaluate(context.Background(), keyedRequest(issuers[i%len(issuers)]))
	}
	wg.Wait()
	for _, u := range issuers {
		if cachedKeys(reg, u) == 0 {
			t.Fatalf("no keys cached for %s after refresh", u)
		}
	}
}
