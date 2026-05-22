package registry

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/sirosfoundation/go-trust/pkg/authzen"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// Circuit breaker: half-open and edge cases
// ---------------------------------------------------------------------------

func TestCircuitBreaker_HalfOpenTransition(t *testing.T) {
	cb := NewCircuitBreaker(2, 10*time.Millisecond)

	// Drive to open
	cb.RecordFailure()
	cb.RecordFailure()
	assert.Equal(t, CircuitOpen, cb.GetState())
	assert.False(t, cb.CanAttempt())

	// Wait for reset timeout
	time.Sleep(15 * time.Millisecond)
	assert.True(t, cb.CanAttempt(), "should allow attempt after reset timeout")

	// One more failure from half-open goes straight to open
	cb.RecordFailure()
	assert.Equal(t, CircuitOpen, cb.GetState())

	// Wait again, then succeed → should close
	time.Sleep(15 * time.Millisecond)
	assert.True(t, cb.CanAttempt())
	cb.RecordSuccess()
	assert.Equal(t, CircuitClosed, cb.GetState())
	assert.Equal(t, 0, cb.GetFailureCount())
}

func TestCircuitBreaker_ManualReset(t *testing.T) {
	cb := NewCircuitBreaker(1, time.Hour)
	cb.RecordFailure()
	assert.Equal(t, CircuitOpen, cb.GetState())

	cb.Reset()
	assert.Equal(t, CircuitClosed, cb.GetState())
	assert.Equal(t, 0, cb.GetFailureCount())
	assert.True(t, cb.CanAttempt())
}

// ---------------------------------------------------------------------------
// NormalizeSubjectID
// ---------------------------------------------------------------------------

func TestNormalizeSubjectID_Coverage(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"x509_san_dns:example.com", "https://example.com"},
		{"x509_san_uri:https://example.com", "https://example.com"},
		{"https://example.com", "https://example.com"},
		{"did:web:example.com", "did:web:example.com"},
	}
	for _, tt := range tests {
		assert.Equal(t, tt.want, NormalizeSubjectID(tt.input), tt.input)
	}
}

// ---------------------------------------------------------------------------
// extractDecisionReason coverage
// ---------------------------------------------------------------------------

func TestExtractDecisionReason(t *testing.T) {
	tests := []struct {
		name string
		resp *authzen.EvaluationResponse
		want string
	}{
		{"nil context", &authzen.EvaluationResponse{Decision: true}, ""},
		{"nil reason", &authzen.EvaluationResponse{Decision: true, Context: &authzen.EvaluationResponseContext{}}, ""},
		{"admin reason", &authzen.EvaluationResponse{Decision: false, Context: &authzen.EvaluationResponseContext{
			Reason: map[string]interface{}{"admin": "detailed info"},
		}}, "detailed info"},
		{"allow with user reason", &authzen.EvaluationResponse{Decision: true, Context: &authzen.EvaluationResponseContext{
			Reason: map[string]interface{}{"user": "trusted via whitelist"},
		}}, "trusted via whitelist"},
		{"allow with error fallback", &authzen.EvaluationResponse{Decision: true, Context: &authzen.EvaluationResponseContext{
			Reason: map[string]interface{}{"error": "some error"},
		}}, "some error"},
		{"deny with error", &authzen.EvaluationResponse{Decision: false, Context: &authzen.EvaluationResponseContext{
			Reason: map[string]interface{}{"error": "not found"},
		}}, "not found"},
		{"deny with user fallback", &authzen.EvaluationResponse{Decision: false, Context: &authzen.EvaluationResponseContext{
			Reason: map[string]interface{}{"user": "denied"},
		}}, "denied"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, extractDecisionReason(tt.resp))
		})
	}
}

// ---------------------------------------------------------------------------
// Strategy edge cases: AllRegistries with mixed results
// ---------------------------------------------------------------------------

func TestManager_AllRegistries_MixedResults(t *testing.T) {
	mgr := NewRegistryManager(AllRegistries, 5*time.Second)
	mgr.Register(&MockRegistry{name: "approve", decision: true, types: []string{"x5c"}})
	mgr.Register(&MockRegistry{name: "deny", decision: false, types: []string{"x5c"}})

	resp, err := mgr.Evaluate(context.Background(), &authzen.EvaluationRequest{
		Subject:  authzen.Subject{Type: "key", ID: "test"},
		Resource: authzen.Resource{Type: "x5c", ID: "test", Key: []interface{}{"cert"}},
	})
	require.NoError(t, err)
	// AllRegistries returns true if ANY registry approves
	assert.True(t, resp.Decision)
}

func TestManager_AllRegistries_AllApprove(t *testing.T) {
	mgr := NewRegistryManager(AllRegistries, 5*time.Second)
	mgr.Register(&MockRegistry{name: "reg-1", decision: true, types: []string{"x5c"}})
	mgr.Register(&MockRegistry{name: "reg-2", decision: true, types: []string{"x5c"}})

	resp, err := mgr.Evaluate(context.Background(), &authzen.EvaluationRequest{
		Subject:  authzen.Subject{Type: "key", ID: "test"},
		Resource: authzen.Resource{Type: "x5c", ID: "test", Key: []interface{}{"cert"}},
	})
	require.NoError(t, err)
	assert.True(t, resp.Decision)
}

func TestManager_Sequential_FirstDeniesSecondApproves(t *testing.T) {
	mgr := NewRegistryManager(Sequential, 5*time.Second)
	mgr.Register(&MockRegistry{name: "deny-first", decision: false, types: []string{"x5c"}})
	mgr.Register(&MockRegistry{name: "approve-second", decision: true, types: []string{"x5c"}})

	resp, err := mgr.Evaluate(context.Background(), &authzen.EvaluationRequest{
		Subject:  authzen.Subject{Type: "key", ID: "test"},
		Resource: authzen.Resource{Type: "x5c", ID: "test", Key: []interface{}{"cert"}},
	})
	require.NoError(t, err)
	// Sequential stops on first match; deny-first returns false, so it continues to approve-second
	assert.True(t, resp.Decision)
}

func TestManager_BestMatch_MultipleApprovals(t *testing.T) {
	mgr := NewRegistryManager(BestMatch, 5*time.Second)
	mgr.Register(&MockRegistry{name: "reg-a", decision: true, types: []string{"x5c"}})
	mgr.Register(&MockRegistry{name: "reg-b", decision: true, types: []string{"x5c"}})

	resp, err := mgr.Evaluate(context.Background(), &authzen.EvaluationRequest{
		Subject:  authzen.Subject{Type: "key", ID: "test"},
		Resource: authzen.Resource{Type: "x5c", ID: "test", Key: []interface{}{"cert"}},
	})
	require.NoError(t, err)
	assert.True(t, resp.Decision)
}

// ---------------------------------------------------------------------------
// Policy-aware registry filtering
// ---------------------------------------------------------------------------

func TestManager_PolicyFilteredRegistries(t *testing.T) {
	mgr := NewRegistryManager(FirstMatch, 5*time.Second)
	mgr.Register(&MockRegistry{name: "allowed-reg", decision: true, types: []string{"x5c"}})
	mgr.Register(&MockRegistry{name: "blocked-reg", decision: true, types: []string{"x5c"}})

	pm := NewPolicyManager()
	pm.RegisterPolicy(&Policy{
		Name:       "issuer",
		Registries: []string{"allowed-reg"},
	})
	mgr.SetPolicyManager(pm)

	resp, err := mgr.Evaluate(context.Background(), &authzen.EvaluationRequest{
		Subject:  authzen.Subject{Type: "key", ID: "test"},
		Resource: authzen.Resource{Type: "x5c", ID: "test", Key: []interface{}{"cert"}},
		Action:   &authzen.Action{Name: "issuer"},
	})
	require.NoError(t, err)
	assert.True(t, resp.Decision)
	// Response should come from allowed-reg only
	if resp.Context != nil && resp.Context.Reason != nil {
		assert.Equal(t, "allowed-reg", resp.Context.Reason["registry"])
	}
}

func TestManager_PolicyAllowedKeyTypesRejection(t *testing.T) {
	mgr := NewRegistryManager(FirstMatch, 5*time.Second)
	mgr.Register(&MockRegistry{name: "reg", decision: true, types: []string{"*"}})

	pm := NewPolicyManager()
	pm.RegisterPolicy(&Policy{
		Name: "issuer",
		Constraints: PolicyConstraints{
			AllowedKeyTypes: []string{"x5c"},
		},
	})
	mgr.SetPolicyManager(pm)

	// JWK not allowed by policy
	resp, err := mgr.Evaluate(context.Background(), &authzen.EvaluationRequest{
		Subject:  authzen.Subject{Type: "key", ID: "test"},
		Resource: authzen.Resource{Type: "jwk", ID: "test", Key: []interface{}{map[string]interface{}{"kty": "EC"}}},
		Action:   &authzen.Action{Name: "issuer"},
	})
	require.NoError(t, err)
	assert.False(t, resp.Decision)
	assert.Contains(t, resp.Context.Reason["error"], "resource type not allowed by policy")
}

// ---------------------------------------------------------------------------
// No applicable registries
// ---------------------------------------------------------------------------

func TestManager_NoApplicableRegistries(t *testing.T) {
	mgr := NewRegistryManager(FirstMatch, 5*time.Second)
	mgr.Register(&MockRegistry{name: "jwk-only", decision: true, types: []string{"jwk"}})

	resp, err := mgr.Evaluate(context.Background(), &authzen.EvaluationRequest{
		Subject:  authzen.Subject{Type: "key", ID: "test"},
		Resource: authzen.Resource{Type: "x5c", ID: "test", Key: []interface{}{"cert"}},
	})
	require.NoError(t, err)
	assert.False(t, resp.Decision)
}

// ---------------------------------------------------------------------------
// Registry error during evaluation
// ---------------------------------------------------------------------------

func TestManager_RegistryError(t *testing.T) {
	mgr := NewRegistryManager(FirstMatch, 5*time.Second)
	mgr.Register(&MockRegistry{name: "failing", decision: false, types: []string{"x5c"}, err: errors.New("connection refused")})

	resp, err := mgr.Evaluate(context.Background(), &authzen.EvaluationRequest{
		Subject:  authzen.Subject{Type: "key", ID: "test"},
		Resource: authzen.Resource{Type: "x5c", ID: "test", Key: []interface{}{"cert"}},
	})
	require.NoError(t, err)
	assert.False(t, resp.Decision)
}

// ---------------------------------------------------------------------------
// Resolution-only request routing
// ---------------------------------------------------------------------------

func TestManager_ResolutionOnlyRouting(t *testing.T) {
	mgr := NewRegistryManager(FirstMatch, 5*time.Second)
	mgr.Register(&MockRegistry{
		name:                   "resolver",
		decision:               true,
		types:                  []string{"jwk"},
		supportsResolutionOnly: true,
		trustMetadata:          map[string]interface{}{"id": "did:web:x"},
	})
	mgr.Register(&MockRegistry{name: "non-resolver", decision: true, types: []string{"x5c"}})

	// Resolution-only: no resource type or key
	resp, err := mgr.Evaluate(context.Background(), &authzen.EvaluationRequest{
		Subject:  authzen.Subject{Type: "key", ID: "did:web:x"},
		Resource: authzen.Resource{ID: "did:web:x"},
	})
	require.NoError(t, err)
	assert.True(t, resp.Decision)
}

// ---------------------------------------------------------------------------
// JWKsMatch utility
// ---------------------------------------------------------------------------

func TestJWKsMatch(t *testing.T) {
	tests := []struct {
		name  string
		jwk1  map[string]interface{}
		jwk2  map[string]interface{}
		match bool
	}{
		{"EC match", map[string]interface{}{"kty": "EC", "crv": "P-256", "x": "a", "y": "b"}, map[string]interface{}{"kty": "EC", "crv": "P-256", "x": "a", "y": "b"}, true},
		{"EC different x", map[string]interface{}{"kty": "EC", "crv": "P-256", "x": "a", "y": "b"}, map[string]interface{}{"kty": "EC", "crv": "P-256", "x": "c", "y": "b"}, false},
		{"OKP match", map[string]interface{}{"kty": "OKP", "crv": "Ed25519", "x": "a"}, map[string]interface{}{"kty": "OKP", "crv": "Ed25519", "x": "a"}, true},
		{"OKP different", map[string]interface{}{"kty": "OKP", "crv": "Ed25519", "x": "a"}, map[string]interface{}{"kty": "OKP", "crv": "Ed25519", "x": "b"}, false},
		{"RSA match", map[string]interface{}{"kty": "RSA", "n": "n1", "e": "e1"}, map[string]interface{}{"kty": "RSA", "n": "n1", "e": "e1"}, true},
		{"RSA different", map[string]interface{}{"kty": "RSA", "n": "n1", "e": "e1"}, map[string]interface{}{"kty": "RSA", "n": "n2", "e": "e1"}, false},
		{"different kty", map[string]interface{}{"kty": "EC"}, map[string]interface{}{"kty": "RSA"}, false},
		{"unknown kty", map[string]interface{}{"kty": "unknown"}, map[string]interface{}{"kty": "unknown"}, false},
		{"missing kty", map[string]interface{}{}, map[string]interface{}{}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.match, JWKsMatch(tt.jwk1, tt.jwk2))
		})
	}
}

// ---------------------------------------------------------------------------
// HTTP utility functions
// ---------------------------------------------------------------------------

func TestHTTPUtil_SetAndGetMaxResponseBodyBytes(t *testing.T) {
	original := GetMaxResponseBodyBytes()
	defer SetMaxResponseBodyBytes(original) // restore

	SetMaxResponseBodyBytes(1024)
	assert.Equal(t, 1024, GetMaxResponseBodyBytes())

	SetMaxResponseBodyBytes(0) // should reset to default
	assert.Equal(t, DefaultMaxResponseBodyBytes, GetMaxResponseBodyBytes())

	SetMaxResponseBodyBytes(-1) // should reset to default
	assert.Equal(t, DefaultMaxResponseBodyBytes, GetMaxResponseBodyBytes())
}

func TestReadLimitedBody(t *testing.T) {
	original := GetMaxResponseBodyBytes()
	defer SetMaxResponseBodyBytes(original)

	SetMaxResponseBodyBytes(10)

	// Under limit
	data, err := ReadLimitedBody(strings.NewReader("hello"))
	require.NoError(t, err)
	assert.Equal(t, "hello", string(data))

	// At limit
	data, err = ReadLimitedBody(strings.NewReader("0123456789"))
	require.NoError(t, err)
	assert.Len(t, data, 10)

	// Over limit
	_, err = ReadLimitedBody(strings.NewReader("01234567890"))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "exceeds maximum size")
}

func TestLimitedReader(t *testing.T) {
	original := GetMaxResponseBodyBytes()
	defer SetMaxResponseBodyBytes(original)

	SetMaxResponseBodyBytes(5)
	r := LimitedReader(strings.NewReader("abcdefghij"))
	var buf bytes.Buffer
	_, _ = buf.ReadFrom(r)
	// LimitedReader allows limit+1 bytes to detect overflow
	assert.LessOrEqual(t, buf.Len(), 6)
}

// ---------------------------------------------------------------------------
// ParseCertificate / ParseCertificatesPEM
// ---------------------------------------------------------------------------

func TestParseCertificate_NilExtensions(t *testing.T) {
	_, err := ParseCertificate([]byte("not-a-cert"), nil)
	assert.Error(t, err)
}

func TestParseCertificatesPEM_NilExtensions(t *testing.T) {
	// Valid PEM with invalid DER body → should skip gracefully
	pem := []byte("-----BEGIN CERTIFICATE-----\nnotvalid\n-----END CERTIFICATE-----\n")
	certs, err := ParseCertificatesPEM(pem, nil)
	require.NoError(t, err)
	assert.Empty(t, certs)
}

func TestParseCertificatesPEM_ValidSelfSigned(t *testing.T) {
	// Generate a real self-signed cert at test time
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test"},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour),
		BasicConstraintsValid: true,
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)
	pemBlock := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})

	certs, err := ParseCertificatesPEM(pemBlock, nil)
	require.NoError(t, err)
	assert.Len(t, certs, 1)
}

// ---------------------------------------------------------------------------
// PolicyContext helper coverage
// ---------------------------------------------------------------------------

func TestPolicyContext_Getters(t *testing.T) {
	// nil policy
	pc := &PolicyContext{}
	assert.Nil(t, pc.GetOIDFedEntityTypes())
	assert.Nil(t, pc.GetETSIServiceTypes())
	assert.Nil(t, pc.GetDIDRequiredServices())
	assert.Nil(t, pc.GetDIDAllowedDomains())
	assert.Nil(t, pc.GetMDOCIACAIssuerAllowlist())
	assert.False(t, pc.HasETSIConstraints())
	assert.False(t, pc.HasDIDConstraints())
	assert.False(t, pc.HasMDOCIACAConstraints())
	assert.False(t, pc.RequiresVerifiableHistory())

	// policy with OIDFed
	pc = &PolicyContext{Policy: &Policy{
		OIDFed: &OIDFedPolicyConstraints{
			EntityTypes:        []string{"openid_relying_party"},
			RequiredTrustMarks: []string{"tm1"},
		},
	}}
	assert.Equal(t, []string{"openid_relying_party"}, pc.GetOIDFedEntityTypes())
	assert.Equal(t, []string{"tm1"}, pc.GetOIDFedTrustMarks())

	// policy with ETSI
	pc = &PolicyContext{Policy: &Policy{
		ETSI: &ETSIPolicyConstraints{ServiceTypes: []string{"QCert"}},
	}}
	assert.True(t, pc.HasETSIConstraints())
	assert.Equal(t, []string{"QCert"}, pc.GetETSIServiceTypes())

	// policy with DID
	pc = &PolicyContext{Policy: &Policy{
		DID: &DIDPolicyConstraints{
			AllowedDomains:           []string{"example.com"},
			RequiredServices:         []string{"LinkedDomains"},
			RequireVerifiableHistory: true,
		},
	}}
	assert.True(t, pc.HasDIDConstraints())
	assert.Equal(t, []string{"example.com"}, pc.GetDIDAllowedDomains())
	assert.Equal(t, []string{"LinkedDomains"}, pc.GetDIDRequiredServices())
	assert.True(t, pc.RequiresVerifiableHistory())

	// policy with MDOCIACA
	pc = &PolicyContext{Policy: &Policy{
		MDOCIACA: &MDOCIACAPolicyConstraints{IssuerAllowlist: []string{"SE"}},
	}}
	assert.True(t, pc.HasMDOCIACAConstraints())
	assert.Equal(t, []string{"SE"}, pc.GetMDOCIACAIssuerAllowlist())
}

// ---------------------------------------------------------------------------
// ListRegistries
// ---------------------------------------------------------------------------

func TestManager_ListRegistries(t *testing.T) {
	mgr := NewRegistryManager(FirstMatch, 5*time.Second)
	mgr.Register(&MockRegistry{name: "reg-a", decision: true, types: []string{"x5c"}})
	mgr.Register(&MockRegistry{name: "reg-b", decision: true, types: []string{"jwk"}, supportsResolutionOnly: true})

	infos := mgr.ListRegistries()
	require.Len(t, infos, 2)
	assert.Equal(t, "reg-a", infos[0].Name)
	assert.Equal(t, []string{"x5c"}, infos[0].ResourceTypes)
	assert.False(t, infos[0].ResolutionOnly)
	assert.Equal(t, "reg-b", infos[1].Name)
	assert.True(t, infos[1].ResolutionOnly)
}

// ---------------------------------------------------------------------------
// Refresh
// ---------------------------------------------------------------------------

func TestManager_Refresh_Errors(t *testing.T) {
	mgr := NewRegistryManager(FirstMatch, 5*time.Second)
	mgr.Register(&MockRegistry{name: "ok", decision: true, types: []string{"x5c"}})
	mgr.Register(&MockRegistry{name: "fail", decision: true, types: []string{"x5c"}, refreshErr: errors.New("timeout")})

	err := mgr.Refresh(context.Background())
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "timeout")
}

func TestManager_Refresh_AllOK(t *testing.T) {
	mgr := NewRegistryManager(FirstMatch, 5*time.Second)
	mgr.Register(&MockRegistry{name: "ok1", decision: true, types: []string{"x5c"}})
	mgr.Register(&MockRegistry{name: "ok2", decision: true, types: []string{"x5c"}})

	err := mgr.Refresh(context.Background())
	assert.NoError(t, err)
}
