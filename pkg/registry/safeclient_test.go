package registry

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIsPrivateIP(t *testing.T) {
	tests := []struct {
		name     string
		ip       string
		expected bool
	}{
		// Loopback addresses
		{"IPv4 loopback", "127.0.0.1", true},
		{"IPv4 loopback alt", "127.1.2.3", true},
		{"IPv6 loopback", "::1", true},

		// Private addresses (RFC 1918)
		{"10.0.0.0/8 start", "10.0.0.1", true},
		{"10.0.0.0/8 middle", "10.255.255.255", true},
		{"172.16.0.0/12 start", "172.16.0.1", true},
		{"172.16.0.0/12 end", "172.31.255.255", true},
		{"192.168.0.0/16", "192.168.1.1", true},

		// Link-local addresses
		{"IPv4 link-local", "169.254.1.1", true},
		{"IPv6 link-local", "fe80::1", true},

		// Cloud metadata endpoint
		{"cloud metadata", "169.254.169.254", true},

		// Unspecified
		{"IPv4 unspecified", "0.0.0.0", true},
		{"IPv6 unspecified", "::", true},

		// Public addresses (should NOT be private)
		{"public 8.8.8.8", "8.8.8.8", false},
		{"public 1.1.1.1", "1.1.1.1", false},
		{"public 93.184.216.34", "93.184.216.34", false},
		{"public IPv6", "2607:f8b0:4000:800::200e", false},

		// Edge cases around RFC 1918 boundaries
		{"just outside 10.x", "11.0.0.1", false},
		{"just outside 172.16.x", "172.15.255.255", false},
		{"just outside 172.31.x", "172.32.0.0", false},
		{"just outside 192.168.x", "192.167.255.255", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ip := net.ParseIP(tt.ip)
			require.NotNil(t, ip, "failed to parse IP: %s", tt.ip)
			result := IsPrivateIP(ip)
			assert.Equal(t, tt.expected, result, "IsPrivateIP(%s) = %v, want %v", tt.ip, result, tt.expected)
		})
	}
}

func TestIsPrivateIP_NilIP(t *testing.T) {
	assert.True(t, IsPrivateIP(nil), "nil IP should be treated as private")
}

func TestSafeHTTPClient_RequireHTTPS(t *testing.T) {
	client := NewSafeHTTPClient(SafeClientConfig{
		AllowHTTP: false, // Require HTTPS
		Timeout:   5 * time.Second,
	})

	// HTTP URL should be rejected
	req, err := http.NewRequestWithContext(context.Background(), "GET", "http://example.com", nil)
	require.NoError(t, err)

	_, err = client.Do(req)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "HTTPS required")
}

func TestSafeHTTPClient_AllowHTTP(t *testing.T) {
	// Start a local HTTP test server
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	client := NewSafeHTTPClient(SafeClientConfig{
		AllowHTTP:       true, // Allow HTTP
		AllowPrivateIPs: true, // Allow localhost for testing
		Timeout:         5 * time.Second,
	})

	req, err := http.NewRequestWithContext(context.Background(), "GET", ts.URL, nil)
	require.NoError(t, err)

	resp, err := client.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

func TestSafeHTTPClient_BlockPrivateIPs(t *testing.T) {
	// Start a local test server (which runs on localhost - a private IP)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	client := NewSafeHTTPClient(SafeClientConfig{
		AllowHTTP:       true,  // Allow HTTP for this test
		AllowPrivateIPs: false, // Block private IPs
		Timeout:         5 * time.Second,
	})

	req, err := http.NewRequestWithContext(context.Background(), "GET", ts.URL, nil)
	require.NoError(t, err)

	_, err = client.Do(req)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "SSRF protection")
	assert.Contains(t, err.Error(), "private")
}

func TestSafeHTTPClient_HostAllowlist(t *testing.T) {
	client := NewSafeHTTPClient(SafeClientConfig{
		AllowedHosts: []string{"allowed.example.com"},
		Timeout:      5 * time.Second,
	})

	tests := []struct {
		name        string
		url         string
		shouldError bool
	}{
		{"allowed host", "https://allowed.example.com/path", false},
		{"allowed host case insensitive", "https://ALLOWED.EXAMPLE.COM/path", false},
		{"disallowed host", "https://evil.example.com/path", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, err := http.NewRequestWithContext(context.Background(), "GET", tt.url, nil)
			require.NoError(t, err)

			_, err = client.Do(req)
			if tt.shouldError {
				require.Error(t, err)
				assert.Contains(t, err.Error(), "not in allowlist")
			}
			// Note: requests to allowed hosts will fail DNS lookup in tests,
			// but we're testing the allowlist validation, not actual connectivity
		})
	}
}

func TestSafeHTTPClient_UnsupportedScheme(t *testing.T) {
	client := NewSafeHTTPClient(SafeClientConfig{
		AllowHTTP: true,
		Timeout:   5 * time.Second,
	})

	schemes := []string{"ftp", "file", "gopher", "data"}

	for _, scheme := range schemes {
		t.Run(scheme, func(t *testing.T) {
			req, err := http.NewRequestWithContext(context.Background(), "GET", scheme+"://example.com", nil)
			require.NoError(t, err)

			_, err = client.Do(req)
			require.Error(t, err)
			assert.Contains(t, strings.ToLower(err.Error()), "unsupported")
		})
	}
}

func TestSafeHTTPClient_DefaultTimeout(t *testing.T) {
	client := NewSafeHTTPClient(SafeClientConfig{})

	// Should have default timeout of 30 seconds
	assert.Equal(t, 30*time.Second, client.client.Timeout)
}

func TestSafeHTTPClient_CustomTimeout(t *testing.T) {
	customTimeout := 10 * time.Second
	client := NewSafeHTTPClient(SafeClientConfig{
		Timeout: customTimeout,
	})

	assert.Equal(t, customTimeout, client.client.Timeout)
}
