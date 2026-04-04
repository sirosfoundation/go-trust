package didutil

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParse_ValidDIDs(t *testing.T) {
	tests := []struct {
		name           string
		did            string
		expectedMethod string
		expectedMSID   string
	}{
		{
			name:           "simple did:web",
			did:            "did:web:example.com",
			expectedMethod: "web",
			expectedMSID:   "example.com",
		},
		{
			name:           "did:web with path",
			did:            "did:web:example.com:users:alice",
			expectedMethod: "web",
			expectedMSID:   "example.com:users:alice",
		},
		{
			name:           "did:web with port",
			did:            "did:web:localhost%3A8080",
			expectedMethod: "web",
			expectedMSID:   "localhost%3A8080",
		},
		{
			name:           "did:webvh with SCID",
			did:            "did:webvh:QmXYZ123456789abcdef:example.com",
			expectedMethod: "webvh",
			expectedMSID:   "QmXYZ123456789abcdef:example.com",
		},
		{
			name:           "did:webvh with path",
			did:            "did:webvh:QmXYZ123456789abcdef:example.com:issuers:main",
			expectedMethod: "webvh",
			expectedMSID:   "QmXYZ123456789abcdef:example.com:issuers:main",
		},
		{
			name:           "did:jwks",
			did:            "did:jwks:issuer.example.com",
			expectedMethod: "jwks",
			expectedMSID:   "issuer.example.com",
		},
		{
			name:           "did:key",
			did:            "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
			expectedMethod: "key",
			expectedMSID:   "z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
		},
		{
			name:           "did with underscores",
			did:            "did:web:example_domain.com",
			expectedMethod: "web",
			expectedMSID:   "example_domain.com",
		},
		{
			name:           "did with hyphens",
			did:            "did:web:my-example.com",
			expectedMethod: "web",
			expectedMSID:   "my-example.com",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parsed, err := Parse(tt.did)
			require.NoError(t, err)
			assert.Equal(t, tt.expectedMethod, parsed.Method)
			assert.Equal(t, tt.expectedMSID, parsed.MethodSpecificID)
		})
	}
}

func TestParse_WithFragment(t *testing.T) {
	tests := []struct {
		name             string
		did              string
		expectedMethod   string
		expectedFragment string
	}{
		{
			name:             "did:web with fragment",
			did:              "did:web:example.com#key-1",
			expectedMethod:   "web",
			expectedFragment: "key-1",
		},
		{
			name:             "did:key with fragment",
			did:              "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK#z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
			expectedMethod:   "key",
			expectedFragment: "z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
		},
		{
			name:             "fragment with slashes",
			did:              "did:web:example.com#keys/main",
			expectedMethod:   "web",
			expectedFragment: "keys/main",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parsed, err := Parse(tt.did)
			require.NoError(t, err)
			assert.Equal(t, tt.expectedMethod, parsed.Method)
			assert.Equal(t, tt.expectedFragment, parsed.Fragment)
		})
	}
}

func TestParse_InvalidDIDs(t *testing.T) {
	tests := []struct {
		name        string
		did         string
		errContains string
	}{
		{
			name:        "empty string",
			did:         "",
			errContains: "empty DID",
		},
		{
			name:        "missing did: prefix",
			did:         "web:example.com",
			errContains: "must start with 'did:'",
		},
		{
			name:        "missing method",
			did:         "did::example.com",
			errContains: "method name cannot be empty",
		},
		{
			name:        "missing method-specific-id",
			did:         "did:web",
			errContains: "must have format",
		},
		{
			name:        "uppercase method",
			did:         "did:WEB:example.com",
			errContains: "lowercase",
		},
		{
			name:        "method with special chars",
			did:         "did:web-v2:example.com",
			errContains: "lowercase letters",
		},
		{
			name:        "path traversal attempt",
			did:         "did:web:example.com:..:..:etc:passwd",
			errContains: "path traversal",
		},
		{
			name:        "null byte injection",
			did:         "did:web:example.com%00malicious",
			errContains: "null bytes",
		},
		{
			name:        "newline injection",
			did:         "did:web:example.com%0d%0aX-Injected:header",
			errContains: "newline",
		},
		{
			name:        "shell metacharacter $",
			did:         "did:web:example.com:$(whoami)",
			errContains: "shell metacharacter",
		},
		{
			name:        "shell metacharacter backtick",
			did:         "did:web:example.com:`id`",
			errContains: "shell metacharacter",
		},
		{
			name:        "shell metacharacter pipe",
			did:         "did:web:example.com|cat",
			errContains: "shell metacharacter",
		},
		{
			name:        "incomplete percent encoding",
			did:         "did:web:example.com%3",
			errContains: "invalid",
		},
		{
			name:        "invalid percent encoding hex",
			did:         "did:web:example.com%GG",
			errContains: "invalid",
		},
		{
			name:        "exceeds max length",
			did:         "did:web:" + strings.Repeat("a", 2100),
			errContains: "exceeds maximum length",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Parse(tt.did)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.errContains)
		})
	}
}

func TestParseWithMethod(t *testing.T) {
	t.Run("correct method", func(t *testing.T) {
		parsed, err := ParseWithMethod("did:web:example.com", "web")
		require.NoError(t, err)
		assert.Equal(t, "web", parsed.Method)
	})

	t.Run("wrong method", func(t *testing.T) {
		_, err := ParseWithMethod("did:web:example.com", "webvh")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "expected method")
	})
}

func TestValidate(t *testing.T) {
	assert.NoError(t, Validate("did:web:example.com"))
	assert.Error(t, Validate("not-a-did"))
}

func TestIsKnownMethod(t *testing.T) {
	assert.True(t, IsKnownMethod("web"))
	assert.True(t, IsKnownMethod("webvh"))
	assert.True(t, IsKnownMethod("jwks"))
	assert.True(t, IsKnownMethod("key"))
	assert.False(t, IsKnownMethod("unknown"))
	assert.False(t, IsKnownMethod("ethr"))
}

func TestDID_Domain(t *testing.T) {
	tests := []struct {
		name           string
		did            string
		expectedDomain string
	}{
		{
			name:           "did:web simple",
			did:            "did:web:example.com",
			expectedDomain: "example.com",
		},
		{
			name:           "did:web with path",
			did:            "did:web:example.com:users:alice",
			expectedDomain: "example.com",
		},
		{
			name:           "did:web with port",
			did:            "did:web:localhost%3A8080",
			expectedDomain: "localhost:8080",
		},
		{
			name:           "did:webvh (SCID is first, domain is second)",
			did:            "did:webvh:QmSCID12345:example.com:path",
			expectedDomain: "example.com",
		},
		{
			name:           "did:jwks",
			did:            "did:jwks:issuer.example.com",
			expectedDomain: "issuer.example.com",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parsed, err := Parse(tt.did)
			require.NoError(t, err)
			assert.Equal(t, tt.expectedDomain, parsed.Domain())
		})
	}
}

func TestDID_PathFromSegments(t *testing.T) {
	tests := []struct {
		name         string
		did          string
		expectedPath string
	}{
		{
			name:         "did:web no path",
			did:          "did:web:example.com",
			expectedPath: "",
		},
		{
			name:         "did:web with path",
			did:          "did:web:example.com:users:alice",
			expectedPath: "users/alice",
		},
		{
			name:         "did:webvh with path",
			did:          "did:webvh:QmSCID12345:example.com:issuers:main",
			expectedPath: "issuers/main",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parsed, err := Parse(tt.did)
			require.NoError(t, err)
			assert.Equal(t, tt.expectedPath, parsed.PathFromSegments())
		})
	}
}

func TestDID_SCID(t *testing.T) {
	t.Run("did:webvh has SCID", func(t *testing.T) {
		parsed, err := Parse("did:webvh:QmSCID12345:example.com")
		require.NoError(t, err)
		assert.Equal(t, "QmSCID12345", parsed.SCID())
	})

	t.Run("did:web has no SCID", func(t *testing.T) {
		parsed, err := Parse("did:web:example.com")
		require.NoError(t, err)
		assert.Equal(t, "", parsed.SCID())
	})
}

func TestDID_ToHTTPURL(t *testing.T) {
	tests := []struct {
		name        string
		did         string
		scheme      string
		filename    string
		expectedURL string
	}{
		{
			name:        "did:web root",
			did:         "did:web:example.com",
			scheme:      "https",
			filename:    "did.json",
			expectedURL: "https://example.com/.well-known/did.json",
		},
		{
			name:        "did:web with path",
			did:         "did:web:example.com:users:alice",
			scheme:      "https",
			filename:    "did.json",
			expectedURL: "https://example.com/users/alice/did.json",
		},
		{
			name:        "did:jwks root",
			did:         "did:jwks:issuer.example.com",
			scheme:      "https",
			filename:    "jwks.json",
			expectedURL: "https://issuer.example.com/.well-known/jwks.json",
		},
		{
			name:        "did:webvh",
			did:         "did:webvh:QmSCID12345:example.com:issuers",
			scheme:      "https",
			filename:    "did.jsonl",
			expectedURL: "https://example.com/issuers/did.jsonl",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parsed, err := Parse(tt.did)
			require.NoError(t, err)
			url, err := parsed.ToHTTPURL(tt.scheme, tt.filename)
			require.NoError(t, err)
			assert.Equal(t, tt.expectedURL, url)
		})
	}
}

func TestDID_String(t *testing.T) {
	parsed, err := Parse("did:web:example.com#key-1")
	require.NoError(t, err)

	assert.Equal(t, "did:web:example.com", parsed.String())
	assert.Equal(t, "did:web:example.com#key-1", parsed.FullString())
	assert.Equal(t, "did:web:example.com#custom", parsed.WithFragment("custom"))
}

func TestValidateMethodName(t *testing.T) {
	assert.NoError(t, validateMethodName("web"))
	assert.NoError(t, validateMethodName("webvh"))
	assert.NoError(t, validateMethodName("key"))
	assert.NoError(t, validateMethodName("jwks"))
	assert.NoError(t, validateMethodName("method123"))

	assert.Error(t, validateMethodName(""))
	assert.Error(t, validateMethodName("WEB"))       // uppercase
	assert.Error(t, validateMethodName("web-v2"))    // hyphen
	assert.Error(t, validateMethodName("web_v2"))    // underscore
	assert.Error(t, validateMethodName("web.v2"))    // dot
	assert.Error(t, validateMethodName("web:extra")) // colon
}

func TestCheckDangerousPatterns(t *testing.T) {
	// Safe patterns
	assert.NoError(t, checkDangerousPatterns("example.com"))
	assert.NoError(t, checkDangerousPatterns("example.com:users:alice"))
	assert.NoError(t, checkDangerousPatterns("localhost%3A8080"))

	// Dangerous patterns
	assert.Error(t, checkDangerousPatterns(".."))
	assert.Error(t, checkDangerousPatterns("../etc/passwd"))
	assert.Error(t, checkDangerousPatterns("example.com%00evil"))
	assert.Error(t, checkDangerousPatterns("example.com%0d%0aHeader:inject"))
	assert.Error(t, checkDangerousPatterns("example.com|cat"))
	assert.Error(t, checkDangerousPatterns("example.com;ls"))
	assert.Error(t, checkDangerousPatterns("$(whoami)"))
	assert.Error(t, checkDangerousPatterns("`id`"))
	assert.Error(t, checkDangerousPatterns("$PATH"))
	assert.Error(t, checkDangerousPatterns("file>output"))
	assert.Error(t, checkDangerousPatterns("file<input"))
	assert.Error(t, checkDangerousPatterns("cmd&background"))
}

func TestParseMethodSpecificSegments(t *testing.T) {
	tests := []struct {
		name     string
		msid     string
		expected []string
	}{
		{
			name:     "simple domain",
			msid:     "example.com",
			expected: []string{"example.com"},
		},
		{
			name:     "domain with path",
			msid:     "example.com:users:alice",
			expected: []string{"example.com", "users", "alice"},
		},
		{
			name:     "domain with encoded port",
			msid:     "localhost%3A8080:path",
			expected: []string{"localhost:8080", "path"},
		},
		{
			name:     "multiple encoded ports",
			msid:     "host%3A8080:server%3A9090",
			expected: []string{"host:8080", "server:9090"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			segments := parseMethodSpecificSegments(tt.msid)
			assert.Equal(t, tt.expected, segments)
		})
	}
}

// Benchmark tests
func BenchmarkParse(b *testing.B) {
	did := "did:web:example.com:users:alice#key-1"
	for i := 0; i < b.N; i++ {
		_, _ = Parse(did)
	}
}

func BenchmarkValidate(b *testing.B) {
	did := "did:webvh:QmSCID12345:example.com:issuers:main"
	for i := 0; i < b.N; i++ {
		_ = Validate(did)
	}
}
