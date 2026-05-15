package resilience

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

// testPayload is a simple type for testing Fetcher.
type testPayload struct {
	Keys []string `json:"keys"`
}

func parseTestPayload(body []byte) (*testPayload, error) {
	var p testPayload
	if err := json.Unmarshal(body, &p); err != nil {
		return nil, err
	}
	if len(p.Keys) == 0 {
		return nil, fmt.Errorf("no keys")
	}
	return &p, nil
}

func TestFetcher_Success(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"keys":["a","b"]}`)
	}))
	defer server.Close()

	f := NewFetcher(server.Client(), parseTestPayload, FetcherConfig{})
	result, stale, err := f.Fetch(context.Background(), server.URL)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if stale {
		t.Error("expected fresh result, got stale")
	}
	if len(result.Keys) != 2 {
		t.Errorf("expected 2 keys, got %d", len(result.Keys))
	}
}

func TestFetcher_RetryOnTransientFailure(t *testing.T) {
	var attempts int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt32(&attempts, 1)
		if n < 3 {
			http.Error(w, "Service Unavailable", http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"keys":["ok"]}`)
	}))
	defer server.Close()

	f := NewFetcher(server.Client(), parseTestPayload, FetcherConfig{
		MaxAttempts:    3,
		RetryBaseDelay: 1 * time.Millisecond,
	})

	result, stale, err := f.Fetch(context.Background(), server.URL)
	if err != nil {
		t.Fatalf("expected success after retries, got: %v", err)
	}
	if stale {
		t.Error("expected fresh result")
	}
	if result.Keys[0] != "ok" {
		t.Errorf("unexpected key: %s", result.Keys[0])
	}
	if got := atomic.LoadInt32(&attempts); got != 3 {
		t.Errorf("expected 3 attempts, got %d", got)
	}
}

func TestFetcher_NoRetryOn4xx(t *testing.T) {
	var attempts int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&attempts, 1)
		http.Error(w, "Not Found", http.StatusNotFound)
	}))
	defer server.Close()

	f := NewFetcher(server.Client(), parseTestPayload, FetcherConfig{
		MaxAttempts:    3,
		RetryBaseDelay: 1 * time.Millisecond,
	})

	_, _, err := f.Fetch(context.Background(), server.URL)
	if err == nil {
		t.Fatal("expected error for 404")
	}
	if got := atomic.LoadInt32(&attempts); got != 1 {
		t.Errorf("expected 1 attempt (no retry on 404), got %d", got)
	}
}

func TestFetcher_StaleCacheOnFailure(t *testing.T) {
	var requestCount int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt32(&requestCount, 1)
		if n == 1 {
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{"keys":["cached"]}`)
			return
		}
		http.Error(w, "Service Unavailable", http.StatusServiceUnavailable)
	}))
	defer server.Close()

	f := NewFetcher(server.Client(), parseTestPayload, FetcherConfig{
		MaxAttempts:    1,
		RetryBaseDelay: 1 * time.Millisecond,
	})

	// Warm the cache.
	result1, stale1, err := f.Fetch(context.Background(), server.URL)
	if err != nil {
		t.Fatalf("initial fetch: %v", err)
	}
	if stale1 {
		t.Error("initial should be fresh")
	}
	if result1.Keys[0] != "cached" {
		t.Errorf("unexpected key: %s", result1.Keys[0])
	}

	// Second call: server fails, should get stale cache.
	result2, stale2, err := f.Fetch(context.Background(), server.URL)
	if err != nil {
		t.Fatalf("expected stale fallback, got error: %v", err)
	}
	if !stale2 {
		t.Error("expected stale result")
	}
	if result2.Keys[0] != "cached" {
		t.Errorf("unexpected stale key: %s", result2.Keys[0])
	}
}

func TestFetcher_NoStaleCache_ReturnsError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "Service Unavailable", http.StatusServiceUnavailable)
	}))
	defer server.Close()

	f := NewFetcher(server.Client(), parseTestPayload, FetcherConfig{
		MaxAttempts:    1,
		RetryBaseDelay: 1 * time.Millisecond,
	})

	_, _, err := f.Fetch(context.Background(), server.URL)
	if err == nil {
		t.Fatal("expected error when no stale cache exists")
	}
}

func TestFetcher_ContextCancellation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "Service Unavailable", http.StatusServiceUnavailable)
	}))
	defer server.Close()

	f := NewFetcher(server.Client(), parseTestPayload, FetcherConfig{
		MaxAttempts:    5,
		RetryBaseDelay: 100 * time.Millisecond,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	_, _, err := f.Fetch(ctx, server.URL)
	if err == nil {
		t.Fatal("expected error on context cancellation")
	}
}

func TestFetcher_ParseError_NoRetry(t *testing.T) {
	var attempts int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&attempts, 1)
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `not json`)
	}))
	defer server.Close()

	f := NewFetcher(server.Client(), parseTestPayload, FetcherConfig{
		MaxAttempts:    3,
		RetryBaseDelay: 1 * time.Millisecond,
	})

	_, _, err := f.Fetch(context.Background(), server.URL)
	if err == nil {
		t.Fatal("expected parse error")
	}
	if got := atomic.LoadInt32(&attempts); got != 1 {
		t.Errorf("expected 1 attempt (no retry on parse error), got %d", got)
	}
}

func TestFetcher_InvalidateCache(t *testing.T) {
	var requestCount int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt32(&requestCount, 1)
		if n == 1 {
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{"keys":["first"]}`)
			return
		}
		http.Error(w, "Service Unavailable", http.StatusServiceUnavailable)
	}))
	defer server.Close()

	f := NewFetcher(server.Client(), parseTestPayload, FetcherConfig{
		MaxAttempts:    1,
		RetryBaseDelay: 1 * time.Millisecond,
	})

	// Warm cache.
	_, _, err := f.Fetch(context.Background(), server.URL)
	if err != nil {
		t.Fatalf("initial: %v", err)
	}

	// Invalidate.
	f.Invalidate(server.URL)

	// Now fetch fails with no stale cache.
	_, _, err = f.Fetch(context.Background(), server.URL)
	if err == nil {
		t.Fatal("expected error after invalidation with failing server")
	}
}

func TestIsRetryable(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected bool
	}{
		{"transport error", &TransportError{Err: fmt.Errorf("connection refused")}, true},
		{"500", &HTTPStatusError{StatusCode: 500, URL: "x"}, true},
		{"503", &HTTPStatusError{StatusCode: 503, URL: "x"}, true},
		{"404", &HTTPStatusError{StatusCode: 404, URL: "x"}, false},
		{"400", &HTTPStatusError{StatusCode: 400, URL: "x"}, false},
		{"wrapped transport", fmt.Errorf("outer: %w", &TransportError{Err: fmt.Errorf("inner")}), true},
		{"generic error", fmt.Errorf("something"), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsRetryable(tt.err); got != tt.expected {
				t.Errorf("IsRetryable() = %v, want %v", got, tt.expected)
			}
		})
	}
}
