package issuermetadata

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func newTestResolver(t *testing.T) *Resolver {
	t.Helper()
	r, err := New(Config{
		CacheTTL:        5 * time.Minute,
		HTTPTimeout:     5 * time.Second,
		AllowHTTP:       true,
		AllowPrivateIPs: true,
	})
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}
	return r
}

func TestResolve_Success(t *testing.T) {
	meta := map[string]interface{}{
		"credential_issuer": "https://issuer.example.com",
		"signed_metadata":   "eyJhbGciOiJSUzI1NiJ9.test.signature",
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/.well-known/openid-credential-issuer" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(meta) //nolint:errcheck
	}))
	defer server.Close()

	r := newTestResolver(t)
	got, err := r.Resolve(context.Background(), server.URL)
	if err != nil {
		t.Fatalf("Resolve() error: %v", err)
	}
	if got["credential_issuer"] != "https://issuer.example.com" {
		t.Errorf("credential_issuer: got %v", got["credential_issuer"])
	}
	if got["signed_metadata"] != "eyJhbGciOiJSUzI1NiJ9.test.signature" {
		t.Errorf("signed_metadata not preserved: got %v", got["signed_metadata"])
	}
}

func TestResolve_Cached(t *testing.T) {
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"credential_issuer": "https://test.com"}) //nolint:errcheck
	}))
	defer server.Close()

	r := newTestResolver(t)

	if _, err := r.Resolve(context.Background(), server.URL); err != nil {
		t.Fatalf("first Resolve() error: %v", err)
	}
	if _, err := r.Resolve(context.Background(), server.URL); err != nil {
		t.Fatalf("second Resolve() error: %v", err)
	}
	if calls != 1 {
		t.Errorf("expected 1 HTTP request, got %d", calls)
	}
}

func TestResolve_TrailingSlashStripped(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"credential_issuer": "https://test.com"}) //nolint:errcheck
	}))
	defer server.Close()

	r := newTestResolver(t)
	// URL with trailing slash should work the same
	if _, err := r.Resolve(context.Background(), server.URL+"/"); err != nil {
		t.Fatalf("Resolve() with trailing slash error: %v", err)
	}
}

func TestResolve_RejectsHTTPByDefault(t *testing.T) {
	r, _ := New(Config{}) // AllowHTTP = false
	_, err := r.Resolve(context.Background(), "http://issuer.example.com")
	if err == nil {
		t.Error("expected error for HTTP URL, got nil")
	}
}

func TestResolve_RejectsNonHTTPScheme(t *testing.T) {
	r := newTestResolver(t)
	_, err := r.Resolve(context.Background(), "ftp://issuer.example.com")
	if err == nil {
		t.Error("expected error for ftp:// URL, got nil")
	}
}

func TestResolve_RejectsMissingHost(t *testing.T) {
	r := newTestResolver(t)
	_, err := r.Resolve(context.Background(), "https://")
	if err == nil {
		t.Error("expected error for URL without host, got nil")
	}
}

func TestResolve_RejectsInvalidJSON(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte("not json")) //nolint:errcheck
	}))
	defer server.Close()

	r := newTestResolver(t)
	_, err := r.Resolve(context.Background(), server.URL)
	if err == nil {
		t.Error("expected error for invalid JSON response")
	}
}

func TestResolve_RejectsNonOKStatus(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	r := newTestResolver(t)
	_, err := r.Resolve(context.Background(), server.URL)
	if err == nil {
		t.Error("expected error for HTTP 404 response")
	}
}

func TestResolve_CacheTTLExpiry(t *testing.T) {
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]int{"call": calls}) //nolint:errcheck
	}))
	defer server.Close()

	r, _ := New(Config{
		CacheTTL:        1 * time.Millisecond, // very short TTL
		HTTPTimeout:     5 * time.Second,
		AllowHTTP:       true,
		AllowPrivateIPs: true,
	})

	if _, err := r.Resolve(context.Background(), server.URL); err != nil {
		t.Fatalf("first Resolve() error: %v", err)
	}

	time.Sleep(5 * time.Millisecond) // let TTL expire

	if _, err := r.Resolve(context.Background(), server.URL); err != nil {
		t.Fatalf("second Resolve() error: %v", err)
	}

	if calls != 2 {
		t.Errorf("expected 2 HTTP requests after TTL expiry, got %d", calls)
	}
}
