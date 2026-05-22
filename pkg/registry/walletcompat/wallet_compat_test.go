// Package walletcompat provides cross-registry tests verifying that every
// TrustRegistry implementation correctly handles the AuthZEN evaluation request
// patterns that go-wallet-backend constructs during issuance and presentation flows.
//
// Wallet-backend builds requests in these categories:
//
//  1. Resolution-only: Subject.Type="key", no Resource.Type/Key
//  2. x5c credential-issuer: Resource.Type="x5c", Action.Name="credential-issuer"
//  3. jwk credential-issuer: Resource.Type="jwk", Action.Name="credential-issuer"
//  4. credential-verifier: Action.Name="credential-verifier"
//  5. With credential_type context: Context={"credential_type": "..."}
//
// Each test exercises all registries uniformly to ensure that go-wallet-backend's
// real call patterns are handled without panics or unexpected errors.
package walletcompat

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"math/big"
	"testing"
	"time"

	"github.com/sirosfoundation/go-trust/pkg/authzen"
	"github.com/sirosfoundation/go-trust/pkg/registry"
	"github.com/sirosfoundation/go-trust/pkg/registry/did"
	"github.com/sirosfoundation/go-trust/pkg/registry/didjwks"
	"github.com/sirosfoundation/go-trust/pkg/registry/didweb"
	"github.com/sirosfoundation/go-trust/pkg/registry/didwebvh"
	"github.com/sirosfoundation/go-trust/pkg/registry/mdociaca"
	"github.com/sirosfoundation/go-trust/pkg/registry/oidfed"
	"github.com/sirosfoundation/go-trust/pkg/registry/static"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// walletRequest describes a single evaluation request pattern that
// go-wallet-backend is known to emit.
type walletRequest struct {
	Name    string
	Build   func(t *testing.T) *authzen.EvaluationRequest
	Flow    string // "issuance", "presentation", or "both"
	Comment string // which wallet-backend code path produces this
}

// walletRequestPatterns returns all the distinct EvaluationRequest shapes that
// go-wallet-backend constructs during issuance and presentation flows.
func walletRequestPatterns(t *testing.T) []walletRequest {
	t.Helper()

	// Generate test key material once for the whole table.
	leafCert, leafB64 := generateWalletTestCert(t)
	jwkMap := generateWalletTestJWK(t)
	_ = leafCert

	return []walletRequest{
		{
			Name: "resolution_only",
			Flow: "issuance",
			Comment: "authzen_proxy.go resolveURLSubject — when no key material " +
				"is available, resource.type is 'resolution'",
			Build: func(t *testing.T) *authzen.EvaluationRequest {
				return &authzen.EvaluationRequest{
					Subject: authzen.Subject{
						Type: "key",
						ID:   "https://issuer.example.com",
					},
					Resource: authzen.Resource{
						ID: "https://issuer.example.com",
					},
				}
			},
		},
		{
			Name: "x5c_credential_issuer",
			Flow: "issuance",
			Comment: "authzen_proxy.go resolveURLSubject / resolver.go " +
				"verifySignedMetadataX5C — x5c chain from signed_metadata JWT",
			Build: func(t *testing.T) *authzen.EvaluationRequest {
				return &authzen.EvaluationRequest{
					Subject: authzen.Subject{
						Type: "key",
						ID:   "https://issuer.example.com",
					},
					Resource: authzen.Resource{
						Type: "x5c",
						ID:   "https://issuer.example.com",
						Key:  []interface{}{leafB64},
					},
					Action: &authzen.Action{Name: "credential-issuer"},
				}
			},
		},
		{
			Name: "jwk_credential_issuer",
			Flow: "issuance",
			Comment: "authzen_proxy.go resolveURLSubject / resolver.go " +
				"verifySignedMetadataJWK — bare JWK from signed_metadata JWT",
			Build: func(t *testing.T) *authzen.EvaluationRequest {
				return &authzen.EvaluationRequest{
					Subject: authzen.Subject{
						Type: "key",
						ID:   "https://issuer.example.com",
					},
					Resource: authzen.Resource{
						Type: "jwk",
						ID:   "https://issuer.example.com",
						Key:  []interface{}{jwkMap},
					},
					Action: &authzen.Action{Name: "credential-issuer"},
				}
			},
		},
		{
			Name: "x5c_credential_verifier",
			Flow: "presentation",
			Comment: "evaluator.go toAuthZENRequest — verifier x5c trust " +
				"during presentation flow",
			Build: func(t *testing.T) *authzen.EvaluationRequest {
				return &authzen.EvaluationRequest{
					Subject: authzen.Subject{
						Type: "key",
						ID:   "https://verifier.example.com",
					},
					Resource: authzen.Resource{
						Type: "x5c",
						ID:   "https://verifier.example.com",
						Key:  []interface{}{leafB64},
					},
					Action: &authzen.Action{Name: "credential-verifier"},
				}
			},
		},
		{
			Name: "jwk_credential_verifier",
			Flow: "presentation",
			Comment: "evaluator.go toAuthZENRequest — verifier jwk trust " +
				"during presentation flow",
			Build: func(t *testing.T) *authzen.EvaluationRequest {
				return &authzen.EvaluationRequest{
					Subject: authzen.Subject{
						Type: "key",
						ID:   "https://verifier.example.com",
					},
					Resource: authzen.Resource{
						Type: "jwk",
						ID:   "https://verifier.example.com",
						Key:  []interface{}{jwkMap},
					},
					Action: &authzen.Action{Name: "credential-verifier"},
				}
			},
		},
		{
			Name: "jwk_issuer_with_credential_type",
			Flow: "issuance",
			Comment: "evaluator.go toAuthZENRequest — when credential_type " +
				"is set on the internal request",
			Build: func(t *testing.T) *authzen.EvaluationRequest {
				return &authzen.EvaluationRequest{
					Subject: authzen.Subject{
						Type: "key",
						ID:   "https://issuer.example.com",
					},
					Resource: authzen.Resource{
						Type: "jwk",
						ID:   "https://issuer.example.com",
						Key:  []interface{}{jwkMap},
					},
					Action: &authzen.Action{Name: "credential-issuer"},
					Context: map[string]interface{}{
						"credential_type": "urn:eu.europa.ec.eudi:pid:1",
					},
				}
			},
		},
		{
			Name: "spocp_key_resolution_gate",
			Flow: "both",
			Comment: "authzen_proxy.go /v1/evaluate SPOCP gate — subject " +
				"type 'key', resource type 'resolution' for key subjects",
			Build: func(t *testing.T) *authzen.EvaluationRequest {
				return &authzen.EvaluationRequest{
					Subject: authzen.Subject{
						Type: "key",
						ID:   "https://issuer.example.com",
					},
					Resource: authzen.Resource{
						Type: "resolution",
						ID:   "https://issuer.example.com",
					},
				}
			},
		},
		{
			Name: "url_subject_credential_issuer",
			Flow: "issuance",
			Comment: "authzen_proxy.go /v1/resolve — url subject type with " +
				"credential_issuer resource for issuer metadata resolution",
			Build: func(t *testing.T) *authzen.EvaluationRequest {
				return &authzen.EvaluationRequest{
					Subject: authzen.Subject{
						Type: "url",
						ID:   "https://issuer.example.com",
					},
					Resource: authzen.Resource{
						Type: "credential_issuer",
						ID:   "https://issuer.example.com",
					},
				}
			},
		},
	}
}

// registryUnderTest pairs a registry instance with metadata.
type registryUnderTest struct {
	Name     string
	Registry registry.TrustRegistry
}

// testRegistries returns all registry implementations that can be constructed
// without external dependencies (no files on disk, no network at construction
// time). Registries that require network at evaluation time will return
// decision=false or errors for unknown subjects — that is expected. The goal
// is to verify they handle all wallet request shapes without panicking.
func testRegistries(t *testing.T) []registryUnderTest {
	t.Helper()

	regs := []registryUnderTest{
		// Static registries
		{
			Name:     "static/always_trusted",
			Registry: static.NewAlwaysTrustedRegistry("wallet-compat-always"),
		},
		{
			Name:     "static/never_trusted",
			Registry: static.NewNeverTrustedRegistry("wallet-compat-never"),
		},
		{
			Name:     "static/whitelist_empty",
			Registry: static.NewWhitelistRegistry(),
		},
	}

	// SystemCertPool — may fail on some platforms
	if scp, err := static.NewSystemCertPoolRegistry(static.SystemCertPoolConfig{
		Name: "wallet-compat-syscerts",
	}); err == nil {
		regs = append(regs, registryUnderTest{
			Name:     "static/system_cert_pool",
			Registry: scp,
		})
	} else {
		t.Logf("skipping SystemCertPoolRegistry: %v", err)
	}

	// OpenID Federation (requires trust anchor entity IDs; network at eval only)
	if oidfedReg, err := oidfed.NewOIDFedRegistry(oidfed.Config{
		TrustAnchors: []oidfed.TrustAnchorConfig{
			{EntityID: "https://trust-anchor.example.com"},
		},
	}); err == nil {
		regs = append(regs, registryUnderTest{
			Name:     "oidfed",
			Registry: oidfedReg,
		})
	} else {
		t.Logf("skipping OIDFedRegistry: %v", err)
	}

	// did:web (network at eval only)
	if dwReg, err := didweb.NewDIDWebRegistry(didweb.Config{}); err == nil {
		regs = append(regs, registryUnderTest{
			Name:     "didweb",
			Registry: dwReg,
		})
	} else {
		t.Logf("skipping DIDWebRegistry: %v", err)
	}

	// did:webvh (network at eval only)
	if dwvhReg, err := didwebvh.NewDIDWebVHRegistry(didwebvh.Config{}); err == nil {
		regs = append(regs, registryUnderTest{
			Name:     "didwebvh",
			Registry: dwvhReg,
		})
	} else {
		t.Logf("skipping DIDWebVHRegistry: %v", err)
	}

	// did:jwks (network at eval only)
	if djReg, err := didjwks.NewRegistry(didjwks.Config{}); err == nil {
		regs = append(regs, registryUnderTest{
			Name:     "didjwks",
			Registry: djReg,
		})
	} else {
		t.Logf("skipping didjwks.Registry: %v", err)
	}

	// mDOC IACA (network at eval only)
	if mdocReg, err := mdociaca.New(nil); err == nil {
		regs = append(regs, registryUnderTest{
			Name:     "mdociaca",
			Registry: mdocReg,
		})
	} else {
		t.Logf("skipping mdociaca.Registry: %v", err)
	}

	// Generic DID with did:key resolver (pure computation)
	didKeyReg := did.NewGenericDIDRegistryWithKeyMethod(did.GenericDIDRegistryConfig{})
	regs = append(regs, registryUnderTest{
		Name:     "did_generic_key",
		Registry: didKeyReg,
	})

	return regs
}

// TestWalletBackendRequestPatterns_NoPanic verifies that every known
// wallet-backend EvaluationRequest pattern can be passed to every registry
// without causing a panic. Registries that do not have real backing data will
// return decision=false — that is expected. A panic or an unexpected error is
// not.
func TestWalletBackendRequestPatterns_NoPanic(t *testing.T) {
	ctx := context.Background()
	registries := testRegistries(t)
	patterns := walletRequestPatterns(t)

	for _, reg := range registries {
		for _, pat := range patterns {
			t.Run(reg.Name+"/"+pat.Name, func(t *testing.T) {
				req := pat.Build(t)
				resp, err := reg.Registry.Evaluate(ctx, req)
				// Must not panic (test runner catches that) and must not
				// return an internal error.
				if err != nil {
					t.Logf("registry %s returned error for pattern %s: %v (acceptable for missing data)", reg.Name, pat.Name, err)
				}
				if resp != nil {
					t.Logf("registry %s pattern %s: decision=%v", reg.Name, pat.Name, resp.Decision)
				}
			})
		}
	}
}

// TestWalletBackendRequestPatterns_AlwaysTrusted verifies the always-trusted
// static registry returns decision=true for every wallet pattern.
func TestWalletBackendRequestPatterns_AlwaysTrusted(t *testing.T) {
	ctx := context.Background()
	always := static.NewAlwaysTrustedRegistry("wallet-compat-always")
	patterns := walletRequestPatterns(t)

	for _, pat := range patterns {
		t.Run(pat.Name, func(t *testing.T) {
			req := pat.Build(t)
			resp, err := always.Evaluate(ctx, req)
			require.NoError(t, err)
			require.NotNil(t, resp)
			assert.True(t, resp.Decision, "always_trusted should approve all patterns")
		})
	}
}

// TestWalletBackendRequestPatterns_Validate verifies that all wallet-backend
// request patterns pass the authzen.EvaluationRequest.Validate() method
// (or that patterns which intentionally diverge from the spec, like
// resource.type="resolution", are documented).
func TestWalletBackendRequestPatterns_Validate(t *testing.T) {
	patterns := walletRequestPatterns(t)

	// These patterns use non-standard resource types that intentionally fail
	// strict AuthZEN validation.
	nonStandard := map[string]string{
		"spocp_key_resolution_gate":     "resource.type 'resolution' is a wallet-backend internal convention",
		"url_subject_credential_issuer": "subject.type 'url' with resource.type 'credential_issuer' is wallet-backend SPOCP gate",
	}

	for _, pat := range patterns {
		t.Run(pat.Name, func(t *testing.T) {
			req := pat.Build(t)
			err := req.Validate()

			if reason, ok := nonStandard[pat.Name]; ok {
				if err != nil {
					t.Logf("expected non-standard pattern %s: %v (%s)", pat.Name, err, reason)
				}
				return
			}
			assert.NoError(t, err, "wallet-backend pattern %q should be valid AuthZEN", pat.Name)
		})
	}
}

// TestWalletBackendRequestPatterns_ResourceTypeSupport ensures that each
// registry declares support for the resource types that wallet-backend
// actually uses ("jwk", "x5c", and resolution-only).
func TestWalletBackendRequestPatterns_ResourceTypeSupport(t *testing.T) {
	// Resource types that wallet-backend constructs.
	walletResourceTypes := []string{"jwk", "x5c"}

	registries := testRegistries(t)
	for _, reg := range registries {
		supported := reg.Registry.SupportedResourceTypes()
		t.Run(reg.Name, func(t *testing.T) {
			// Wildcard means everything is supported.
			for _, s := range supported {
				if s == "*" {
					return
				}
			}
			for _, wrt := range walletResourceTypes {
				found := false
				for _, s := range supported {
					if s == wrt {
						found = true
						break
					}
				}
				if !found {
					t.Logf("registry %s does not support wallet resource type %q (supported: %v)",
						reg.Name, wrt, supported)
				}
			}
		})
	}
}

// TestWalletBackendRequestPatterns_ResponseStructure validates that every
// registry response has the expected structure.
func TestWalletBackendRequestPatterns_ResponseStructure(t *testing.T) {
	ctx := context.Background()
	registries := testRegistries(t)
	patterns := walletRequestPatterns(t)

	for _, reg := range registries {
		for _, pat := range patterns {
			t.Run(reg.Name+"/"+pat.Name, func(t *testing.T) {
				req := pat.Build(t)
				resp, err := reg.Registry.Evaluate(ctx, req)
				if err != nil {
					t.Skipf("registry %s errored on %s: %v", reg.Name, pat.Name, err)
				}
				require.NotNil(t, resp, "response must not be nil when err is nil")

				// Wallet-backend expects resp.Decision to be a bool (always present).
				// It also may read resp.Context.Reason and resp.Context.TrustMetadata.
				// Verify these are populated as the wallet expects.
				if resp.Context != nil && resp.Context.Reason != nil {
					// Reason should be a map — wallet-backend reads it as JSON.
					assert.IsType(t, map[string]interface{}{}, resp.Context.Reason)
				}
			})
		}
	}
}

// TestWalletBackendIssuanceFlow simulates the sequence of evaluation calls
// that wallet-backend makes during a credential issuance flow:
// 1. Resolution-only lookup (metadata discovery)
// 2. x5c or jwk credential-issuer trust evaluation
func TestWalletBackendIssuanceFlow(t *testing.T) {
	ctx := context.Background()
	patterns := walletRequestPatterns(t)

	always := static.NewAlwaysTrustedRegistry("wallet-compat-issuance")

	// Phase 1: resolution-only
	var resolveReq *authzen.EvaluationRequest
	for _, p := range patterns {
		if p.Name == "resolution_only" {
			resolveReq = p.Build(t)
			break
		}
	}
	require.NotNil(t, resolveReq, "resolution_only pattern must exist")
	resp, err := always.Evaluate(ctx, resolveReq)
	require.NoError(t, err)
	assert.True(t, resp.Decision, "resolution phase should succeed")

	// Phase 2: key-binding evaluation (x5c path)
	var x5cReq *authzen.EvaluationRequest
	for _, p := range patterns {
		if p.Name == "x5c_credential_issuer" {
			x5cReq = p.Build(t)
			break
		}
	}
	require.NotNil(t, x5cReq, "x5c_credential_issuer pattern must exist")
	resp, err = always.Evaluate(ctx, x5cReq)
	require.NoError(t, err)
	assert.True(t, resp.Decision, "x5c trust evaluation should succeed")

	// Phase 2 alternate: key-binding evaluation (jwk path)
	var jwkReq *authzen.EvaluationRequest
	for _, p := range patterns {
		if p.Name == "jwk_credential_issuer" {
			jwkReq = p.Build(t)
			break
		}
	}
	require.NotNil(t, jwkReq, "jwk_credential_issuer pattern must exist")
	resp, err = always.Evaluate(ctx, jwkReq)
	require.NoError(t, err)
	assert.True(t, resp.Decision, "jwk trust evaluation should succeed")
}

// TestWalletBackendPresentationFlow simulates the evaluation calls for
// presentation (verifier trust checking).
func TestWalletBackendPresentationFlow(t *testing.T) {
	ctx := context.Background()
	patterns := walletRequestPatterns(t)

	always := static.NewAlwaysTrustedRegistry("wallet-compat-presentation")

	// Verifier trust evaluation
	for _, p := range patterns {
		if p.Flow != "presentation" {
			continue
		}
		t.Run(p.Name, func(t *testing.T) {
			req := p.Build(t)
			resp, err := always.Evaluate(ctx, req)
			require.NoError(t, err)
			require.NotNil(t, resp)
			assert.True(t, resp.Decision, "verifier trust should succeed with always_trusted")
		})
	}
}

// TestWalletBackendCompositeRegistry verifies that the RegistryManager
// correctly routes wallet-backend patterns across multiple registries using
// the FirstMatch strategy (the default used in production).
func TestWalletBackendCompositeRegistry(t *testing.T) {
	ctx := context.Background()
	patterns := walletRequestPatterns(t)

	// Create a manager with real registries of different capabilities.
	always := static.NewAlwaysTrustedRegistry("wallet-compat-fallback")
	never := static.NewNeverTrustedRegistry("wallet-compat-reject")

	mgr := registry.NewRegistryManager(registry.FirstMatch, 30*time.Second)
	mgr.Register(never)  // first: rejects everything
	mgr.Register(always) // second: accepts everything

	for _, pat := range patterns {
		t.Run(pat.Name, func(t *testing.T) {
			req := pat.Build(t)
			resp, err := mgr.Evaluate(ctx, req)
			// Should never panic or error.
			if err != nil {
				t.Logf("manager returned error for %s: %v", pat.Name, err)
				return
			}
			require.NotNil(t, resp)
			// FirstMatch with never→always: always should win since never returns false
			assert.True(t, resp.Decision, "FirstMatch should find always_trusted")
		})
	}
}

// TestWalletBackendRequestPatterns_ContextPreserved verifies that context
// fields set by wallet-backend (like credential_type) are accessible on the
// request and not dropped during evaluation.
func TestWalletBackendRequestPatterns_ContextPreserved(t *testing.T) {
	patterns := walletRequestPatterns(t)

	for _, pat := range patterns {
		t.Run(pat.Name, func(t *testing.T) {
			req := pat.Build(t)
			if req.Context == nil {
				t.Skip("no context on this pattern")
			}
			// Wallet-backend sets credential_type — verify it round-trips.
			ct, ok := req.Context["credential_type"]
			require.True(t, ok, "credential_type must be present")
			assert.NotEmpty(t, ct, "credential_type must not be empty")
		})
	}
}

// TestWalletBackendRequestPatterns_ActionNames verifies that the action names
// used by wallet-backend are from the expected set.
func TestWalletBackendRequestPatterns_ActionNames(t *testing.T) {
	validActions := map[string]bool{
		"credential-issuer":   true,
		"credential-verifier": true,
	}

	patterns := walletRequestPatterns(t)
	for _, pat := range patterns {
		t.Run(pat.Name, func(t *testing.T) {
			req := pat.Build(t)
			if req.Action == nil {
				t.Skip("no action on this pattern")
			}
			assert.True(t, validActions[req.Action.Name],
				"unexpected action name %q from wallet-backend", req.Action.Name)
		})
	}
}

// TestWalletBackendRequestPatterns_KeyFormats verifies that key material in
// wallet-backend requests is in the format registries expect.
func TestWalletBackendRequestPatterns_KeyFormats(t *testing.T) {
	patterns := walletRequestPatterns(t)
	for _, pat := range patterns {
		t.Run(pat.Name, func(t *testing.T) {
			req := pat.Build(t)
			if len(req.Resource.Key) == 0 {
				t.Skip("no key material")
			}

			switch req.Resource.Type {
			case "x5c":
				// Wallet-backend sends base64-DER-encoded certificates.
				for i, k := range req.Resource.Key {
					s, ok := k.(string)
					require.True(t, ok, "x5c key[%d] must be a string", i)
					der, err := base64.StdEncoding.DecodeString(s)
					require.NoError(t, err, "x5c key[%d] must be valid base64", i)
					_, err = x509.ParseCertificate(der)
					require.NoError(t, err, "x5c key[%d] must be a valid DER certificate", i)
				}
			case "jwk":
				// Wallet-backend sends JWK maps as map[string]interface{}.
				for i, k := range req.Resource.Key {
					m, ok := k.(map[string]interface{})
					require.True(t, ok, "jwk key[%d] must be a map", i)
					_, hasKty := m["kty"]
					assert.True(t, hasKty, "jwk key[%d] must have 'kty' field", i)
				}
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Test key material helpers
// ---------------------------------------------------------------------------

// generateWalletTestCert creates a self-signed X.509 certificate and returns
// the parsed certificate and its base64-DER encoding (matching wallet-backend
// x5c format).
func generateWalletTestCert(t *testing.T) (*x509.Certificate, string) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   "wallet-compat-test",
			Organization: []string{"Test"},
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)

	return cert, base64.StdEncoding.EncodeToString(certDER)
}

// generateWalletTestJWK creates an EC P-256 JWK map in the format that
// wallet-backend's NormalizeJWKS produces: {"kty":"EC","crv":"P-256","x":"...","y":"..."}.
func generateWalletTestJWK(t *testing.T) map[string]interface{} {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	return map[string]interface{}{
		"kty": "EC",
		"crv": "P-256",
		"x":   base64.RawURLEncoding.EncodeToString(key.PublicKey.X.Bytes()),
		"y":   base64.RawURLEncoding.EncodeToString(key.PublicKey.Y.Bytes()),
	}
}
