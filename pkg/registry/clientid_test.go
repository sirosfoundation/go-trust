package registry

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"math/big"
	"testing"
	"time"

	"github.com/sirosfoundation/go-trust/pkg/authzen"
)

func TestParseClientIDScheme(t *testing.T) {
	tests := []struct {
		id            string
		expectScheme  ClientIDScheme
		expectValue   string
		expectMatched bool
	}{
		{"x509_san_dns:example.com", ClientIDSchemeX509SANDNS, "example.com", true},
		{"x509_san_uri:https://rp.example.com/cb", ClientIDSchemeX509SANURI, "https://rp.example.com/cb", true},
		{"x509_hash:deadbeef", ClientIDSchemeX509Hash, "deadbeef", true},
		{"https://example.com", "", "", false},
		{"did:web:example.com", "", "", false},
		{"", "", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.id, func(t *testing.T) {
			scheme, value, ok := ParseClientIDScheme(tt.id)
			if ok != tt.expectMatched {
				t.Fatalf("expected matched=%v, got %v", tt.expectMatched, ok)
			}
			if scheme != tt.expectScheme || value != tt.expectValue {
				t.Errorf("expected (%q, %q), got (%q, %q)", tt.expectScheme, tt.expectValue, scheme, value)
			}
		})
	}
}

func TestDNSSANMatches(t *testing.T) {
	tests := []struct {
		name     string
		clientID string
		dnsNames []string
		want     bool
	}{
		{"exact match", "example.com", []string{"example.com"}, true},
		{"no match", "attacker.com", []string{"example.com"}, false},
		{"wildcard match", "sub.example.com", []string{"*.example.com"}, true},
		{"wildcard does not match base domain", "example.com", []string{"*.example.com"}, false},
		{"wildcard does not match nested subdomain", "deep.sub.example.com", []string{"*.example.com"}, false},
		{"empty SAN list", "example.com", nil, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := DNSSANMatches(tt.clientID, tt.dnsNames); got != tt.want {
				t.Errorf("DNSSANMatches(%q, %v) = %v, want %v", tt.clientID, tt.dnsNames, got, tt.want)
			}
		})
	}
}

func TestVerifyLeafBinding(t *testing.T) {
	leaf := generateLeafCertForBindingTest(t, []string{"verifier.example.com"})
	digest := sha256.Sum256(leaf.Raw)
	hexDigest := hex.EncodeToString(digest[:])
	b64Digest := base64.RawURLEncoding.EncodeToString(digest[:])

	t.Run("dns_san matches", func(t *testing.T) {
		if err := VerifyLeafBinding(ClientIDSchemeX509SANDNS, "verifier.example.com", leaf); err != nil {
			t.Errorf("expected binding to succeed, got: %v", err)
		}
	})

	t.Run("dns_san mismatch is rejected - this is the actual vulnerability this check closes", func(t *testing.T) {
		// Without this check, a certificate valid for ANY domain (chaining
		// to any public CA) would be accepted for ANY claimed identity, as
		// long as the caller asserted a whitelisted subject ID string. The
		// certificate itself was never checked against the claim.
		if err := VerifyLeafBinding(ClientIDSchemeX509SANDNS, "not-the-real-verifier.example.com", leaf); err == nil {
			t.Error("expected binding to fail for a certificate with no matching DNS SAN")
		}
	})

	t.Run("hash matches (hex)", func(t *testing.T) {
		if err := VerifyLeafBinding(ClientIDSchemeX509Hash, hexDigest, leaf); err != nil {
			t.Errorf("expected hex hash binding to succeed, got: %v", err)
		}
	})

	t.Run("hash matches (base64url)", func(t *testing.T) {
		if err := VerifyLeafBinding(ClientIDSchemeX509Hash, b64Digest, leaf); err != nil {
			t.Errorf("expected base64url hash binding to succeed, got: %v", err)
		}
	})

	t.Run("hash mismatch is rejected", func(t *testing.T) {
		if err := VerifyLeafBinding(ClientIDSchemeX509Hash, "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef", leaf); err == nil {
			t.Error("expected binding to fail for a mismatched hash")
		}
	})

	t.Run("unrecognized scheme is rejected, not silently accepted", func(t *testing.T) {
		if err := VerifyLeafBinding(ClientIDScheme("did"), "web:example.com", leaf); err == nil {
			t.Error("expected an unrecognized scheme to fail closed")
		}
	})
}

func TestOriginalSubjectID(t *testing.T) {
	t.Run("falls back to Subject.ID when never stashed", func(t *testing.T) {
		req := &authzen.EvaluationRequest{Subject: authzen.Subject{ID: "x509_san_dns:example.com"}}
		if got := OriginalSubjectID(req); got != "x509_san_dns:example.com" {
			t.Errorf("expected fallback to Subject.ID, got %q", got)
		}
	})

	t.Run("recovers the pre-normalization value after Subject.ID is rewritten", func(t *testing.T) {
		req := &authzen.EvaluationRequest{Subject: authzen.Subject{ID: "x509_san_dns:example.com"}}
		StashOriginalSubjectID(req, req.Subject.ID)
		req.Subject.ID = "https://example.com" // simulates NormalizeSubjectID's rewrite
		if got := OriginalSubjectID(req); got != "x509_san_dns:example.com" {
			t.Errorf("expected original pre-normalization value, got %q", got)
		}
	})
}

// generateLeafCertForBindingTest creates a minimal self-signed certificate
// carrying the given DNS SANs, for exercising VerifyLeafBinding independent
// of any chain-validation concerns.
func generateLeafCertForBindingTest(t *testing.T, dnsNames []string) *x509.Certificate {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test-leaf"},
		DNSNames:     dnsNames,
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("failed to create certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("failed to parse certificate: %v", err)
	}
	return cert
}
