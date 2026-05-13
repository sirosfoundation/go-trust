// Package resilience provides retry and resilience utilities for HTTP fetch
// operations used by trust registry implementations.
//
// The core abstraction is [Fetcher], which wraps an HTTP fetch function with:
//   - Exponential backoff retry for transient failures (transport errors, 5xx)
//   - Stale-cache fallback: on fetch failure, return the previous result if available
//   - Configurable retry count, base delay, and cache TTL
//
// Registry implementations use Fetcher by providing a parse function that converts
// an HTTP response body into a typed result. The Fetcher handles all retry,
// caching, and error classification logic.
package resilience

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"
)

// TransportError wraps a network/transport-level error (DNS, TCP, TLS).
type TransportError struct {
	Err error
}

func (e *TransportError) Error() string { return e.Err.Error() }
func (e *TransportError) Unwrap() error { return e.Err }

// HTTPStatusError represents a non-200 HTTP response.
type HTTPStatusError struct {
	StatusCode int
	URL        string
}

func (e *HTTPStatusError) Error() string {
	return fmt.Sprintf("HTTP %d from %s", e.StatusCode, e.URL)
}

// IsRetryable reports whether err is a transient error worth retrying:
// transport errors and 5xx HTTP responses.
func IsRetryable(err error) bool {
	var te *TransportError
	if errors.As(err, &te) {
		return true
	}
	var se *HTTPStatusError
	if errors.As(err, &se) {
		return se.StatusCode >= http.StatusInternalServerError
	}
	return false
}

// FetcherConfig configures a [Fetcher].
type FetcherConfig struct {
	// MaxAttempts is the maximum number of fetch attempts (1 = no retry).
	// Default: 3 (1 initial + 2 retries).
	MaxAttempts int

	// RetryBaseDelay is the initial backoff duration; doubled after each attempt.
	// Default: 500ms.
	RetryBaseDelay time.Duration

	// MaxBodyBytes limits the response body size. Returns an error if the
	// response exceeds this limit. Default: 10MB.
	MaxBodyBytes int64
}

func (c *FetcherConfig) defaults() {
	if c.MaxAttempts <= 0 {
		c.MaxAttempts = 3
	}
	if c.RetryBaseDelay <= 0 {
		c.RetryBaseDelay = 500 * time.Millisecond
	}
	if c.MaxBodyBytes <= 0 {
		c.MaxBodyBytes = 10 << 20 // 10 MB
	}
}

// HTTPDoer is the minimal interface for executing HTTP requests.
type HTTPDoer interface {
	Do(req *http.Request) (*http.Response, error)
}

// cachedEntry holds a cached fetch result with its timestamp.
type cachedEntry[T any] struct {
	value     T
	fetchedAt time.Time
}

// Fetcher performs HTTP fetches with retry and stale-cache fallback.
// T is the parsed result type (e.g. *JWKS, []crypto.PublicKey).
type Fetcher[T any] struct {
	client HTTPDoer
	config FetcherConfig
	parse  func(body []byte) (T, error)

	mu    sync.RWMutex
	cache map[string]*cachedEntry[T]
}

// NewFetcher creates a Fetcher.
//
// client: HTTP client (e.g. SafeHTTPClient or *http.Client).
// parse: converts the response body into the result type T.
// config: retry/size settings (zero-value fields use defaults).
func NewFetcher[T any](client HTTPDoer, parse func(body []byte) (T, error), config FetcherConfig) *Fetcher[T] {
	config.defaults()
	return &Fetcher[T]{
		client: client,
		config: config,
		parse:  parse,
		cache:  make(map[string]*cachedEntry[T]),
	}
}

// Fetch retrieves and parses a resource from url.
//
// If the fetch succeeds, the result is cached and returned.
// On transient failure, the fetch is retried with exponential backoff.
// If all retries fail and a previously cached result exists for this url,
// the stale cached value is returned (no error).
// If no cached value exists, the last error is returned.
func (f *Fetcher[T]) Fetch(ctx context.Context, url string) (T, bool, error) {
	result, err := f.fetchWithRetry(ctx, url)
	if err == nil {
		f.mu.Lock()
		f.cache[url] = &cachedEntry[T]{value: result, fetchedAt: time.Now()}
		f.mu.Unlock()
		return result, false, nil // fresh
	}

	// Fetch failed — try stale cache
	f.mu.RLock()
	entry := f.cache[url]
	f.mu.RUnlock()

	if entry != nil {
		return entry.value, true, nil // stale
	}

	return *new(T), false, err
}

// Invalidate removes a cached entry for the given URL.
func (f *Fetcher[T]) Invalidate(url string) {
	f.mu.Lock()
	delete(f.cache, url)
	f.mu.Unlock()
}

// InvalidateAll clears the entire cache.
func (f *Fetcher[T]) InvalidateAll() {
	f.mu.Lock()
	f.cache = make(map[string]*cachedEntry[T])
	f.mu.Unlock()
}

// Config returns a copy of the fetcher's configuration.
func (f *Fetcher[T]) Config() FetcherConfig {
	return f.config
}

// fetchWithRetry performs the HTTP fetch with exponential backoff retry.
func (f *Fetcher[T]) fetchWithRetry(ctx context.Context, url string) (T, error) {
	var lastErr error
	backoff := f.config.RetryBaseDelay

	for attempt := 0; attempt < f.config.MaxAttempts; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return *new(T), ctx.Err()
			case <-time.After(backoff):
			}
			backoff *= 2
		}

		result, err := f.doFetch(ctx, url)
		if err == nil {
			return result, nil
		}
		lastErr = err

		if !IsRetryable(err) {
			return *new(T), err
		}
	}

	return *new(T), fmt.Errorf("fetch failed after %d attempts: %w", f.config.MaxAttempts, lastErr)
}

// doFetch performs a single HTTP GET, reads the body, and parses it.
func (f *Fetcher[T]) doFetch(ctx context.Context, url string) (T, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return *new(T), fmt.Errorf("creating request: %w", err)
	}
	req.Header.Set("Accept", "application/json")

	resp, err := f.client.Do(req)
	if err != nil {
		return *new(T), &TransportError{Err: err}
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return *new(T), &HTTPStatusError{StatusCode: resp.StatusCode, URL: url}
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, f.config.MaxBodyBytes+1))
	if err != nil {
		return *new(T), &TransportError{Err: fmt.Errorf("reading body: %w", err)}
	}
	if int64(len(body)) > f.config.MaxBodyBytes {
		return *new(T), fmt.Errorf("response body from %s exceeds maximum size of %d bytes", url, f.config.MaxBodyBytes)
	}

	result, err := f.parse(body)
	if err != nil {
		// Parse errors are not retryable
		return *new(T), fmt.Errorf("parsing response from %s: %w", url, err)
	}

	return result, nil
}
