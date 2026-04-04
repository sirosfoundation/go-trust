package mdociaca

import (
	"context"
	"crypto/x509"
	"testing"

	"github.com/sirosfoundation/go-trust/pkg/authzen"
)

// TestExtractIssuerAllowlist tests the extraction of issuer_allowlist from request context.
func TestExtractIssuerAllowlist(t *testing.T) {
	tests := []struct {
		name   string
		ctx    map[string]interface{}
		expect int
	}{
		{
			"string slice",
			map[string]interface{}{"issuer_allowlist": []string{"https://issuer.example.com"}},
			1,
		},
		{
			"interface slice",
			map[string]interface{}{"issuer_allowlist": []interface{}{"https://a.com", "https://b.com"}},
			2,
		},
		{
			"interface slice with non-strings",
			map[string]interface{}{"issuer_allowlist": []interface{}{"https://a.com", 42}},
			1,
		},
		{
			"missing key",
			map[string]interface{}{},
			0,
		},
		{
			"wrong type",
			map[string]interface{}{"issuer_allowlist": 42},
			0,
		},
		{
			"empty slice",
			map[string]interface{}{"issuer_allowlist": []string{}},
			0,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := extractIssuerAllowlist(tc.ctx)
			if len(result) != tc.expect {
				t.Errorf("extractIssuerAllowlist() returned %d items, want %d", len(result), tc.expect)
			}
		})
	}
}

// TestEvaluate_PolicyAllowlist_Allowed verifies that an issuer in the policy allowlist is accepted.
func TestEvaluate_PolicyAllowlist_Allowed(t *testing.T) {
	iaca, iacaKey := generateIACACertificate(t, "SE", "Test", "Policy Allowlist IACA")
	ds, _ := generateDSCertificate(t, iaca, iacaKey, "Policy Allowlist DS")

	mock := newMockIssuerServer(t, []*x509.Certificate{iaca})
	defer mock.Close()

	reg, _ := New(&Config{AllowPrivateIPs: true, AllowHTTP: true})

	req := &authzen.EvaluationRequest{
		Subject: authzen.Subject{
			ID: mock.URL(),
		},
		Context: map[string]interface{}{
			"issuer_allowlist": []string{mock.URL()},
		},
		Resource: authzen.Resource{
			Type: "x5c",
			Key:  []interface{}{certToBase64(ds), certToBase64(iaca)},
		},
	}

	resp, err := reg.Evaluate(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !resp.Decision {
		t.Errorf("expected true decision for issuer in policy allowlist, got false")
	}
}

// TestEvaluate_PolicyAllowlist_Denied verifies that an issuer not in the policy allowlist is denied.
func TestEvaluate_PolicyAllowlist_Denied(t *testing.T) {
	iaca, _ := generateIACACertificate(t, "SE", "Test", "Policy Deny IACA")

	mock := newMockIssuerServer(t, []*x509.Certificate{iaca})
	defer mock.Close()

	reg, _ := New(&Config{AllowPrivateIPs: true, AllowHTTP: true})

	req := &authzen.EvaluationRequest{
		Subject: authzen.Subject{
			ID: mock.URL(),
		},
		Context: map[string]interface{}{
			"issuer_allowlist": []string{"https://other-issuer.example.com"},
		},
		Resource: authzen.Resource{
			Type: "x5c",
			Key:  []interface{}{"dummybase64"},
		},
	}

	resp, err := reg.Evaluate(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if resp.Decision {
		t.Error("expected false decision for issuer not in policy allowlist")
	}

	// Verify reason mentions policy allowlist
	if resp.Context != nil && resp.Context.Reason != nil {
		if msg, ok := resp.Context.Reason["error"].(string); ok {
			if msg != "issuer not in policy allowlist for this role" {
				t.Errorf("unexpected reason: %s", msg)
			}
		}
	}
}

// TestEvaluate_PolicyAllowlist_TrailingSlash verifies that trailing slashes are normalized.
func TestEvaluate_PolicyAllowlist_TrailingSlash(t *testing.T) {
	iaca, iacaKey := generateIACACertificate(t, "SE", "Test", "Trailing Slash IACA")
	ds, _ := generateDSCertificate(t, iaca, iacaKey, "Trailing Slash DS")

	mock := newMockIssuerServer(t, []*x509.Certificate{iaca})
	defer mock.Close()

	reg, _ := New(&Config{AllowPrivateIPs: true, AllowHTTP: true})

	// Policy allowlist with trailing slash, issuer without
	req := &authzen.EvaluationRequest{
		Subject: authzen.Subject{
			ID: mock.URL(),
		},
		Context: map[string]interface{}{
			"issuer_allowlist": []string{mock.URL() + "/"},
		},
		Resource: authzen.Resource{
			Type: "x5c",
			Key:  []interface{}{certToBase64(ds), certToBase64(iaca)},
		},
	}

	resp, err := reg.Evaluate(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !resp.Decision {
		t.Error("expected true decision with trailing slash normalization")
	}
}

// TestEvaluate_NoPolicyAllowlist_Passes verifies that evaluation proceeds normally
// when no policy allowlist is present in context.
func TestEvaluate_NoPolicyAllowlist_Passes(t *testing.T) {
	iaca, iacaKey := generateIACACertificate(t, "SE", "Test", "No Policy IACA")
	ds, _ := generateDSCertificate(t, iaca, iacaKey, "No Policy DS")

	mock := newMockIssuerServer(t, []*x509.Certificate{iaca})
	defer mock.Close()

	reg, _ := New(&Config{AllowPrivateIPs: true, AllowHTTP: true})

	// No issuer_allowlist in context
	req := &authzen.EvaluationRequest{
		Subject: authzen.Subject{
			ID: mock.URL(),
		},
		Context: map[string]interface{}{},
		Resource: authzen.Resource{
			Type: "x5c",
			Key:  []interface{}{certToBase64(ds), certToBase64(iaca)},
		},
	}

	resp, err := reg.Evaluate(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !resp.Decision {
		t.Error("expected true decision when no policy allowlist is set")
	}
}

// TestEvaluate_PolicyAllowlist_WithStaticAllowlist tests interaction between
// static config allowlist and dynamic policy allowlist.
func TestEvaluate_PolicyAllowlist_WithStaticAllowlist(t *testing.T) {
	iaca, iacaKey := generateIACACertificate(t, "SE", "Test", "Combined IACA")
	ds, _ := generateDSCertificate(t, iaca, iacaKey, "Combined DS")

	mock := newMockIssuerServer(t, []*x509.Certificate{iaca})
	defer mock.Close()

	// Create registry with static allowlist that includes the server
	reg, _ := New(&Config{
		Name:            "combined-allowlist-test",
		IssuerAllowlist: []string{mock.URL()},
		AllowPrivateIPs: true,
		AllowHTTP:       true,
	})

	// Policy allowlist that does NOT include the server
	req := &authzen.EvaluationRequest{
		Subject: authzen.Subject{
			ID: mock.URL(),
		},
		Context: map[string]interface{}{
			"issuer_allowlist": []string{"https://other.example.com"},
		},
		Resource: authzen.Resource{
			Type: "x5c",
			Key:  []interface{}{certToBase64(ds), certToBase64(iaca)},
		},
	}

	resp, err := reg.Evaluate(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should be denied by policy allowlist even though static allowlist allows it
	if resp.Decision {
		t.Error("expected false: policy allowlist should deny even with static allowlist allowing")
	}
}

// TestEvaluate_NilContext_NoPolicyCheck verifies that nil context skips policy
// allowlist checking entirely.
func TestEvaluate_NilContext_NoPolicyCheck(t *testing.T) {
	iaca, iacaKey := generateIACACertificate(t, "SE", "Test", "Nil Context IACA")
	ds, _ := generateDSCertificate(t, iaca, iacaKey, "Nil Context DS")

	mock := newMockIssuerServer(t, []*x509.Certificate{iaca})
	defer mock.Close()

	reg, _ := New(&Config{AllowPrivateIPs: true, AllowHTTP: true})

	req := &authzen.EvaluationRequest{
		Subject: authzen.Subject{
			ID: mock.URL(),
		},
		Context: nil, // nil context
		Resource: authzen.Resource{
			Type: "x5c",
			Key:  []interface{}{certToBase64(ds), certToBase64(iaca)},
		},
	}

	resp, err := reg.Evaluate(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !resp.Decision {
		t.Error("expected true decision when context is nil (no policy filtering)")
	}
}
