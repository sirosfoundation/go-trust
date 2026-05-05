package registry

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/sirosfoundation/g119612/pkg/logging"
	"github.com/sirosfoundation/go-trust/pkg/authzen"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockRegistry is a configurable mock TrustRegistry for testing
type mockRegistry struct {
	name             string
	resourceTypes    []string
	resolutionOnly   bool
	healthy          bool
	evaluateResponse *authzen.EvaluationResponse
	evaluateError    error
	refreshError     error
}

func (m *mockRegistry) Evaluate(ctx context.Context, req *authzen.EvaluationRequest) (*authzen.EvaluationResponse, error) {
	if m.evaluateError != nil {
		return nil, m.evaluateError
	}
	if m.evaluateResponse != nil {
		return m.evaluateResponse, nil
	}
	return &authzen.EvaluationResponse{Decision: false}, nil
}

func (m *mockRegistry) Refresh(ctx context.Context) error {
	return m.refreshError
}

func (m *mockRegistry) SupportedResourceTypes() []string {
	return m.resourceTypes
}

func (m *mockRegistry) SupportsResolutionOnly() bool {
	return m.resolutionOnly
}

func (m *mockRegistry) Info() RegistryInfo {
	return RegistryInfo{
		Name:        m.name,
		Type:        "mock",
		Description: "Mock registry for testing",
	}
}

func (m *mockRegistry) Healthy() bool {
	return m.healthy
}

func TestNewRegistryManager(t *testing.T) {
	mgr := NewRegistryManager(FirstMatch, 10*time.Second)
	require.NotNil(t, mgr)
	assert.Equal(t, FirstMatch, mgr.strategy)
	assert.Equal(t, 10*time.Second, mgr.timeout)
	assert.Empty(t, mgr.registries)
}

func TestRegistryManager_Register(t *testing.T) {
	mgr := NewRegistryManager(FirstMatch, 10*time.Second)

	reg := &mockRegistry{
		name:          "test-registry",
		resourceTypes: []string{"x5c"},
		healthy:       true,
	}

	mgr.Register(reg)
	assert.Len(t, mgr.registries, 1)

	// Register another
	reg2 := &mockRegistry{
		name:          "test-registry-2",
		resourceTypes: []string{"jwk"},
		healthy:       true,
	}
	mgr.Register(reg2)
	assert.Len(t, mgr.registries, 2)
}

func TestRegistryManager_ListRegistries(t *testing.T) {
	mgr := NewRegistryManager(FirstMatch, 10*time.Second)

	reg1 := &mockRegistry{
		name:          "registry-1",
		resourceTypes: []string{"x5c"},
		healthy:       true,
	}
	reg2 := &mockRegistry{
		name:           "registry-2",
		resourceTypes:  []string{"jwk"},
		resolutionOnly: true,
		healthy:        false,
	}

	mgr.Register(reg1)
	mgr.Register(reg2)

	infos := mgr.ListRegistries()
	assert.Len(t, infos, 2)

	// Check first registry info
	assert.Equal(t, "registry-1", infos[0].Name)
	assert.Equal(t, []string{"x5c"}, infos[0].ResourceTypes)
	assert.False(t, infos[0].ResolutionOnly)
	assert.True(t, infos[0].Healthy)

	// Check second registry info
	assert.Equal(t, "registry-2", infos[1].Name)
	assert.Equal(t, []string{"jwk"}, infos[1].ResourceTypes)
	assert.True(t, infos[1].ResolutionOnly)
	assert.False(t, infos[1].Healthy)
}

func TestRegistryManager_Evaluate_FirstMatch_Success(t *testing.T) {
	mgr := NewRegistryManager(FirstMatch, 10*time.Second)

	// First registry returns false
	reg1 := &mockRegistry{
		name:          "registry-1",
		resourceTypes: []string{"x5c"},
		healthy:       true,
		evaluateResponse: &authzen.EvaluationResponse{
			Decision: false,
		},
	}

	// Second registry returns true
	reg2 := &mockRegistry{
		name:          "registry-2",
		resourceTypes: []string{"x5c"},
		healthy:       true,
		evaluateResponse: &authzen.EvaluationResponse{
			Decision: true,
		},
	}

	mgr.Register(reg1)
	mgr.Register(reg2)

	req := &authzen.EvaluationRequest{
		Subject: authzen.Subject{
			Type: "key",
			ID:   "did:example:123",
		},
		Resource: authzen.Resource{
			Type: "x5c",
			ID:   "did:example:123",
			Key:  []interface{}{"test"},
		},
	}

	ctx := context.Background()
	resp, err := mgr.Evaluate(ctx, req)
	require.NoError(t, err)
	assert.True(t, resp.Decision)
}

func TestRegistryManager_Evaluate_NoMatchingRegistry(t *testing.T) {
	mgr := NewRegistryManager(FirstMatch, 10*time.Second)

	// Registry only supports jwk
	reg := &mockRegistry{
		name:          "registry-1",
		resourceTypes: []string{"jwk"},
		healthy:       true,
	}
	mgr.Register(reg)

	req := &authzen.EvaluationRequest{
		Subject: authzen.Subject{
			Type: "key",
			ID:   "did:example:123",
		},
		Resource: authzen.Resource{
			Type: "x5c", // Not supported by registry
			ID:   "did:example:123",
			Key:  []interface{}{"test"},
		},
	}

	ctx := context.Background()
	resp, err := mgr.Evaluate(ctx, req)
	require.NoError(t, err)
	assert.False(t, resp.Decision)
	assert.Contains(t, resp.Context.Reason["error"], "no applicable registries")
}

func TestRegistryManager_Evaluate_ValidationError(t *testing.T) {
	mgr := NewRegistryManager(FirstMatch, 10*time.Second)

	// Invalid request - subject.type must be "key"
	req := &authzen.EvaluationRequest{
		Subject: authzen.Subject{
			Type: "user", // Invalid - should be "key"
			ID:   "did:example:123",
		},
		Resource: authzen.Resource{
			Type: "x5c",
			ID:   "did:example:123",
			Key:  []interface{}{"test"},
		},
	}

	ctx := context.Background()
	resp, err := mgr.Evaluate(ctx, req)
	require.NoError(t, err)
	assert.False(t, resp.Decision)
	assert.Contains(t, resp.Context.Reason["error"], "invalid request")
}

func TestRegistryManager_Refresh(t *testing.T) {
	mgr := NewRegistryManager(FirstMatch, 10*time.Second)

	refreshCalled := false
	reg := &mockRegistry{
		name:          "test-registry",
		resourceTypes: []string{"x5c"},
		healthy:       true,
		refreshError:  nil,
	}
	// Override refresh to track calls
	mgr.Register(reg)

	ctx := context.Background()
	err := mgr.Refresh(ctx)
	require.NoError(t, err)
	// The mock's Refresh was called (no error)
	_ = refreshCalled
}

func TestRegistryManager_Refresh_WithError(t *testing.T) {
	mgr := NewRegistryManager(FirstMatch, 10*time.Second)

	reg := &mockRegistry{
		name:          "test-registry",
		resourceTypes: []string{"x5c"},
		healthy:       true,
		refreshError:  errors.New("refresh failed"),
	}
	mgr.Register(reg)

	ctx := context.Background()
	err := mgr.Refresh(ctx)
	// Should return the error from the registry
	require.Error(t, err)
	assert.Contains(t, err.Error(), "refresh failed")
}

func TestRegistryManager_SetPolicyManager(t *testing.T) {
	mgr := NewRegistryManager(FirstMatch, 10*time.Second)

	assert.Nil(t, mgr.GetPolicyManager())

	pm := NewPolicyManager()
	mgr.SetPolicyManager(pm)

	assert.Equal(t, pm, mgr.GetPolicyManager())
}

func TestRegistryInfo_Fields(t *testing.T) {
	info := RegistryInfo{
		Name:           "test-registry",
		Type:           "etsi_tsl",
		Description:    "Test registry",
		Version:        "1.0.0",
		TrustAnchors:   []string{"https://example.com/tsl.xml"},
		ResourceTypes:  []string{"x5c", "jwk"},
		ResolutionOnly: false,
		Healthy:        true,
	}

	assert.Equal(t, "test-registry", info.Name)
	assert.Equal(t, "etsi_tsl", info.Type)
	assert.Equal(t, "Test registry", info.Description)
	assert.Equal(t, "1.0.0", info.Version)
	assert.Equal(t, []string{"https://example.com/tsl.xml"}, info.TrustAnchors)
	assert.Equal(t, []string{"x5c", "jwk"}, info.ResourceTypes)
	assert.False(t, info.ResolutionOnly)
	assert.True(t, info.Healthy)
}

func TestResolutionStrategies(t *testing.T) {
	assert.Equal(t, ResolutionStrategy("first_match"), FirstMatch)
	assert.Equal(t, ResolutionStrategy("all"), AllRegistries)
	assert.Equal(t, ResolutionStrategy("best_match"), BestMatch)
	assert.Equal(t, ResolutionStrategy("sequential"), Sequential)
}

func TestRegistryManager_Evaluate_AllRegistries(t *testing.T) {
	mgr := NewRegistryManager(AllRegistries, 10*time.Second)

	// Both registries return false
	reg1 := &mockRegistry{
		name:          "registry-1",
		resourceTypes: []string{"x5c"},
		healthy:       true,
		evaluateResponse: &authzen.EvaluationResponse{
			Decision: false,
		},
	}
	reg2 := &mockRegistry{
		name:          "registry-2",
		resourceTypes: []string{"x5c"},
		healthy:       true,
		evaluateResponse: &authzen.EvaluationResponse{
			Decision: false,
		},
	}

	mgr.Register(reg1)
	mgr.Register(reg2)

	req := &authzen.EvaluationRequest{
		Subject: authzen.Subject{
			Type: "key",
			ID:   "did:example:123",
		},
		Resource: authzen.Resource{
			Type: "x5c",
			ID:   "did:example:123",
			Key:  []interface{}{"test"},
		},
	}

	ctx := context.Background()
	resp, err := mgr.Evaluate(ctx, req)
	require.NoError(t, err)
	// Both registries returned false, so decision should be false
	assert.False(t, resp.Decision)
}

func TestRegistryManager_Evaluate_BestMatch(t *testing.T) {
	mgr := NewRegistryManager(BestMatch, 10*time.Second)

	reg := &mockRegistry{
		name:          "registry-1",
		resourceTypes: []string{"x5c"},
		healthy:       true,
		evaluateResponse: &authzen.EvaluationResponse{
			Decision: true,
		},
	}
	mgr.Register(reg)

	req := &authzen.EvaluationRequest{
		Subject: authzen.Subject{
			Type: "key",
			ID:   "did:example:123",
		},
		Resource: authzen.Resource{
			Type: "x5c",
			ID:   "did:example:123",
			Key:  []interface{}{"test"},
		},
	}

	ctx := context.Background()
	resp, err := mgr.Evaluate(ctx, req)
	require.NoError(t, err)
	assert.True(t, resp.Decision)
}

func TestRegistryManager_Evaluate_Sequential(t *testing.T) {
	mgr := NewRegistryManager(Sequential, 10*time.Second)

	// First registry returns false
	reg1 := &mockRegistry{
		name:          "registry-1",
		resourceTypes: []string{"x5c"},
		healthy:       true,
		evaluateResponse: &authzen.EvaluationResponse{
			Decision: false,
		},
	}
	// Second registry returns true
	reg2 := &mockRegistry{
		name:          "registry-2",
		resourceTypes: []string{"x5c"},
		healthy:       true,
		evaluateResponse: &authzen.EvaluationResponse{
			Decision: true,
		},
	}

	mgr.Register(reg1)
	mgr.Register(reg2)

	req := &authzen.EvaluationRequest{
		Subject: authzen.Subject{
			Type: "key",
			ID:   "did:example:123",
		},
		Resource: authzen.Resource{
			Type: "x5c",
			ID:   "did:example:123",
			Key:  []interface{}{"test"},
		},
	}

	ctx := context.Background()
	resp, err := mgr.Evaluate(ctx, req)
	require.NoError(t, err)
	assert.True(t, resp.Decision)
}

func TestRegistryManager_SupportedResourceTypes(t *testing.T) {
	mgr := NewRegistryManager(FirstMatch, 10*time.Second)

	reg1 := &mockRegistry{
		name:          "registry-1",
		resourceTypes: []string{"x5c", "jwk"},
		healthy:       true,
	}
	reg2 := &mockRegistry{
		name:          "registry-2",
		resourceTypes: []string{"jwk", "entity"},
		healthy:       true,
	}

	mgr.Register(reg1)
	mgr.Register(reg2)

	types := mgr.SupportedResourceTypes()
	// Should have unique types from both registries
	assert.Contains(t, types, "x5c")
	assert.Contains(t, types, "jwk")
	assert.Contains(t, types, "entity")
}

func TestRegistryManager_Info(t *testing.T) {
	mgr := NewRegistryManager(FirstMatch, 10*time.Second)

	reg := &mockRegistry{
		name:          "test-registry",
		resourceTypes: []string{"x5c"},
		healthy:       true,
	}
	mgr.Register(reg)

	info := mgr.Info()
	assert.Equal(t, "Registry Manager", info.Name)
	assert.Equal(t, "manager", info.Type)
	assert.Contains(t, info.Description, "first_match")
	assert.Equal(t, "1.0.0", info.Version)
}

func TestRegistryManager_Healthy_NoRegistries(t *testing.T) {
	mgr := NewRegistryManager(FirstMatch, 10*time.Second)

	// No registries = healthy (for startup)
	assert.True(t, mgr.Healthy())
}

func TestRegistryManager_Healthy_AllUnhealthy(t *testing.T) {
	mgr := NewRegistryManager(FirstMatch, 10*time.Second)

	reg := &mockRegistry{
		name:          "unhealthy-registry",
		resourceTypes: []string{"x5c"},
		healthy:       false,
	}
	mgr.Register(reg)

	assert.False(t, mgr.Healthy())
}

func TestRegistryManager_Healthy_MixedHealth(t *testing.T) {
	mgr := NewRegistryManager(FirstMatch, 10*time.Second)

	reg1 := &mockRegistry{
		name:          "unhealthy-registry",
		resourceTypes: []string{"x5c"},
		healthy:       false,
	}
	reg2 := &mockRegistry{
		name:          "healthy-registry",
		resourceTypes: []string{"x5c"},
		healthy:       true,
	}

	mgr.Register(reg1)
	mgr.Register(reg2)

	// At least one healthy = overall healthy
	assert.True(t, mgr.Healthy())
}

func TestCircuitBreaker_NewCircuitBreaker(t *testing.T) {
	cb := NewCircuitBreaker(5, 30*time.Second)
	assert.Equal(t, CircuitClosed, cb.GetState())
	assert.Equal(t, 0, cb.GetFailureCount())
}

func TestCircuitBreaker_CanAttempt_Closed(t *testing.T) {
	cb := NewCircuitBreaker(5, 30*time.Second)
	assert.True(t, cb.CanAttempt())
}

func TestCircuitBreaker_OpenOnFailures(t *testing.T) {
	cb := NewCircuitBreaker(3, 30*time.Second)

	// Record failures until circuit opens
	cb.RecordFailure()
	assert.Equal(t, CircuitClosed, cb.GetState())

	cb.RecordFailure()
	assert.Equal(t, CircuitClosed, cb.GetState())

	cb.RecordFailure()
	assert.Equal(t, CircuitOpen, cb.GetState())

	// After opening, CanAttempt should be false
	assert.False(t, cb.CanAttempt())
}

func TestCircuitBreaker_RecordSuccess_ResetFailures(t *testing.T) {
	cb := NewCircuitBreaker(5, 30*time.Second)

	cb.RecordFailure()
	cb.RecordFailure()
	assert.Equal(t, 2, cb.GetFailureCount())

	cb.RecordSuccess()
	assert.Equal(t, 0, cb.GetFailureCount())
	assert.Equal(t, CircuitClosed, cb.GetState())
}

func TestCircuitBreaker_Reset(t *testing.T) {
	cb := NewCircuitBreaker(2, 30*time.Second)

	// Open the circuit
	cb.RecordFailure()
	cb.RecordFailure()
	assert.Equal(t, CircuitOpen, cb.GetState())

	// Manual reset
	cb.Reset()
	assert.Equal(t, CircuitClosed, cb.GetState())
	assert.Equal(t, 0, cb.GetFailureCount())
	assert.True(t, cb.CanAttempt())
}

func TestCircuitBreaker_HalfOpenAfterTimeout(t *testing.T) {
	cb := NewCircuitBreaker(1, 10*time.Millisecond)

	// Open the circuit
	cb.RecordFailure()
	assert.Equal(t, CircuitOpen, cb.GetState())
	assert.False(t, cb.CanAttempt())

	// Wait for reset timeout
	time.Sleep(20 * time.Millisecond)

	// Should now allow attempt (will transition to half-open)
	assert.True(t, cb.CanAttempt())
}

func TestRegistryManager_ResolutionOnlyRequest(t *testing.T) {
	mgr := NewRegistryManager(FirstMatch, 10*time.Second)

	reg := &mockRegistry{
		name:           "resolution-registry",
		resourceTypes:  []string{"x5c"},
		resolutionOnly: true,
		healthy:        true,
		evaluateResponse: &authzen.EvaluationResponse{
			Decision: true,
		},
	}
	mgr.Register(reg)

	// Resolution-only request (empty resource.key)
	req := &authzen.EvaluationRequest{
		Subject: authzen.Subject{
			Type: "key",
			ID:   "did:example:123",
		},
		Resource: authzen.Resource{
			Type: "x5c",
			ID:   "did:example:123",
			Key:  nil, // Empty key = resolution only
		},
	}

	ctx := context.Background()
	resp, err := mgr.Evaluate(ctx, req)
	require.NoError(t, err)
	// Registry supports resolution-only and returned true
	assert.True(t, resp.Decision)
}

func TestRegistryManager_UnknownStrategy(t *testing.T) {
	// Use an unknown strategy value
	mgr := &RegistryManager{
		registries:      make([]TrustRegistry, 0),
		strategy:        ResolutionStrategy("unknown"),
		timeout:         10 * time.Second,
		circuitBreakers: make(map[string]*CircuitBreaker),
	}

	reg := &mockRegistry{
		name:          "test-registry",
		resourceTypes: []string{"x5c"},
		healthy:       true,
		evaluateResponse: &authzen.EvaluationResponse{
			Decision: true,
		},
	}
	mgr.Register(reg)

	req := &authzen.EvaluationRequest{
		Subject: authzen.Subject{
			Type: "key",
			ID:   "did:example:123",
		},
		Resource: authzen.Resource{
			Type: "x5c",
			ID:   "did:example:123",
			Key:  []interface{}{"test"},
		},
	}

	ctx := context.Background()
	resp, err := mgr.Evaluate(ctx, req)
	require.NoError(t, err)
	// Unknown strategy defaults to FirstMatch
	assert.True(t, resp.Decision)
}

func TestRegistryManager_Evaluate_WithPolicy(t *testing.T) {
	mgr := NewRegistryManager(FirstMatch, 10*time.Second)

	reg := &mockRegistry{
		name:          "test-registry",
		resourceTypes: []string{"x5c"},
		healthy:       true,
		evaluateResponse: &authzen.EvaluationResponse{
			Decision: true,
		},
	}
	mgr.Register(reg)

	// Set up policy manager with a policy
	pm := NewPolicyManager()
	pm.RegisterPolicy(&Policy{
		Name:       "test-action",
		Registries: []string{"test-registry"},
	})
	mgr.SetPolicyManager(pm)

	req := &authzen.EvaluationRequest{
		Subject: authzen.Subject{
			Type: "key",
			ID:   "did:example:123",
		},
		Action: &authzen.Action{
			Name: "test-action",
		},
		Resource: authzen.Resource{
			Type: "x5c",
			ID:   "did:example:123",
			Key:  []interface{}{"test"},
		},
	}

	ctx := context.Background()
	resp, err := mgr.Evaluate(ctx, req)
	require.NoError(t, err)
	assert.True(t, resp.Decision)
}

func TestNormalizeSubjectID(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"https://example.com", "https://example.com"},
		{"x509_san_dns:example.com", "https://example.com"},
		{"x509_san_uri:https://example.com", "https://example.com"},
		{"x509_san_dns:sub.example.com", "https://sub.example.com"},
		{"plain-id", "plain-id"},
		{"did:web:example.com", "did:web:example.com"},
		{"", ""},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := NormalizeSubjectID(tt.input)
			assert.Equal(t, tt.expected, got)
		})
	}
}

// captureMockRegistry wraps a mockRegistry to capture the request before evaluation.
type captureMockRegistry struct {
	*mockRegistry
	onEvaluate func(req *authzen.EvaluationRequest)
}

func (c *captureMockRegistry) Evaluate(ctx context.Context, req *authzen.EvaluationRequest) (*authzen.EvaluationResponse, error) {
	if c.onEvaluate != nil {
		c.onEvaluate(req)
	}
	return c.mockRegistry.Evaluate(ctx, req)
}

func TestRegistryManager_Evaluate_NormalizesSubjectID(t *testing.T) {
	var capturedSubjectID string
	reg := &captureMockRegistry{
		mockRegistry: &mockRegistry{
			name:          "capture-registry",
			resourceTypes: []string{"x5c"},
			healthy:       true,
			evaluateResponse: &authzen.EvaluationResponse{
				Decision: true,
			},
		},
		onEvaluate: func(req *authzen.EvaluationRequest) {
			capturedSubjectID = req.Subject.ID
		},
	}

	mgr := NewRegistryManager(FirstMatch, 10*time.Second)
	mgr.Register(reg)

	req := &authzen.EvaluationRequest{
		Subject: authzen.Subject{
			Type: "key",
			ID:   "x509_san_dns:verifier.example.com",
		},
		Resource: authzen.Resource{
			Type: "x5c",
			ID:   "x509_san_dns:verifier.example.com",
			Key:  []interface{}{"test"},
		},
	}

	ctx := context.Background()
	resp, err := mgr.Evaluate(ctx, req)
	require.NoError(t, err)
	assert.True(t, resp.Decision)
	assert.Equal(t, "https://verifier.example.com", capturedSubjectID)
}

// logEntry records a single log call.
type logEntry struct {
	level  logging.LogLevel
	msg    string
	fields []logging.Field
}

// capturingLogger records log calls for test assertions.
type capturingLogger struct {
	mu      sync.Mutex
	entries []logEntry
	level   logging.LogLevel
}

func (l *capturingLogger) log(level logging.LogLevel, msg string, fields ...logging.Field) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.entries = append(l.entries, logEntry{level: level, msg: msg, fields: fields})
}

func (l *capturingLogger) Debug(msg string, fields ...logging.Field) {
	l.log(logging.DebugLevel, msg, fields...)
}
func (l *capturingLogger) Info(msg string, fields ...logging.Field) {
	l.log(logging.InfoLevel, msg, fields...)
}
func (l *capturingLogger) Warn(msg string, fields ...logging.Field) {
	l.log(logging.WarnLevel, msg, fields...)
}
func (l *capturingLogger) Error(msg string, fields ...logging.Field) {
	l.log(logging.ErrorLevel, msg, fields...)
}
func (l *capturingLogger) Fatal(msg string, fields ...logging.Field) {
	l.log(logging.FatalLevel, msg, fields...)
}
func (l *capturingLogger) WithContext(_ context.Context) logging.Logger { return l }
func (l *capturingLogger) WithField(_ string, _ interface{}) logging.Logger { return l }
func (l *capturingLogger) WithFields(_ ...logging.Field) logging.Logger    { return l }
func (l *capturingLogger) GetLevel() logging.LogLevel                      { return l.level }
func (l *capturingLogger) SetLevel(level logging.LogLevel)                  { l.level = level }

func (l *capturingLogger) findEntry(msg string) *logEntry {
	l.mu.Lock()
	defer l.mu.Unlock()
	for i := range l.entries {
		if l.entries[i].msg == msg {
			return &l.entries[i]
		}
	}
	return nil
}

func TestRegistryManager_DecisionLogging_DenyAtInfo(t *testing.T) {
	logger := &capturingLogger{level: logging.DebugLevel}
	mgr := NewRegistryManager(FirstMatch, 10*time.Second)
	mgr.SetLogger(logger)

	// Registry that denies
	reg := &mockRegistry{
		name:          "deny-registry",
		resourceTypes: []string{"x5c"},
		healthy:       true,
		evaluateResponse: &authzen.EvaluationResponse{
			Decision: false,
			Context: &authzen.EvaluationResponseContext{
				Reason: map[string]interface{}{
					"error": "subject not in whitelist",
				},
			},
		},
	}
	mgr.Register(reg)

	req := &authzen.EvaluationRequest{
		Subject:  authzen.Subject{Type: "key", ID: "https://untrusted.example.com"},
		Resource: authzen.Resource{Type: "x5c", ID: "https://untrusted.example.com", Key: []interface{}{"test"}},
		Action:   &authzen.Action{Name: "verifier"},
	}

	resp, err := mgr.Evaluate(context.Background(), req)
	require.NoError(t, err)
	assert.False(t, resp.Decision)

	entry := logger.findEntry("trust decision: deny")
	require.NotNil(t, entry, "expected 'trust decision: deny' log entry")
	assert.Equal(t, logging.InfoLevel, entry.level, "deny decisions should log at Info level")
}

func TestRegistryManager_DecisionLogging_AllowAtDebug(t *testing.T) {
	logger := &capturingLogger{level: logging.DebugLevel}
	mgr := NewRegistryManager(FirstMatch, 10*time.Second)
	mgr.SetLogger(logger)

	// Registry that allows
	reg := &mockRegistry{
		name:          "allow-registry",
		resourceTypes: []string{"x5c"},
		healthy:       true,
		evaluateResponse: &authzen.EvaluationResponse{
			Decision: true,
			Context: &authzen.EvaluationResponseContext{
				Reason: map[string]interface{}{
					"user":     "trusted via whitelist (issuers)",
					"registry": "test-whitelist",
				},
			},
		},
	}
	mgr.Register(reg)

	req := &authzen.EvaluationRequest{
		Subject:  authzen.Subject{Type: "key", ID: "https://trusted.example.com"},
		Resource: authzen.Resource{Type: "x5c", ID: "https://trusted.example.com", Key: []interface{}{"test"}},
		Action:   &authzen.Action{Name: "issuer"},
	}

	resp, err := mgr.Evaluate(context.Background(), req)
	require.NoError(t, err)
	assert.True(t, resp.Decision)

	entry := logger.findEntry("trust decision: allow")
	require.NotNil(t, entry, "expected 'trust decision: allow' log entry")
	assert.Equal(t, logging.DebugLevel, entry.level, "allow decisions should log at Debug level")
}
