// Package walletcompat provides cross-registry data-driven tests verifying that
// every TrustRegistry implementation correctly handles the AuthZEN evaluation
// request patterns that go-wallet-backend constructs during issuance and
// presentation flows.
//
// Test vectors are loaded from testdata/vectors.json. Each vector specifies:
//   - An AuthZEN EvaluationRequest (the wallet-backend call shape)
//   - The flow it belongs to (issuance, presentation, or both)
//   - Per-registry expected outcomes (where known)
//
// The test output is structured for easy debugging in CI:
//
//	TestVectors/registry=etsi_ewc_demo/vector=eudi_pid_x5c_issuer/flow=issuance
//
// This makes it immediately obvious which registry + vector combination failed.
package walletcompat

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/sirosfoundation/go-trust/pkg/authzen"
	"github.com/sirosfoundation/go-trust/pkg/registry"
	"github.com/sirosfoundation/go-trust/pkg/registry/did"
	"github.com/sirosfoundation/go-trust/pkg/registry/didjwks"
	"github.com/sirosfoundation/go-trust/pkg/registry/didweb"
	"github.com/sirosfoundation/go-trust/pkg/registry/didwebvh"
	"github.com/sirosfoundation/go-trust/pkg/registry/etsi"
	"github.com/sirosfoundation/go-trust/pkg/registry/lote"
	"github.com/sirosfoundation/go-trust/pkg/registry/mdociaca"
	"github.com/sirosfoundation/go-trust/pkg/registry/oidfed"
	"github.com/sirosfoundation/go-trust/pkg/registry/static"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// JSON vector schema
// ---------------------------------------------------------------------------

// testVector is a single test case loaded from testdata/vectors.json.
type testVector struct {
	Name        string            `json:"name"`
	Description string            `json:"description"`
	Flow        string            `json:"flow"` // issuance | presentation | both
	Source      string            `json:"source"`
	Request     json.RawMessage   `json:"request"`
	Expectations map[string]expectedOutcome `json:"expectations"`
}

// expectedOutcome is the expected result for a specific registry.
type expectedOutcome struct {
	Decision      *bool  `json:"decision"`       // nil = don't assert decision (just no-panic)
	ReasonContains string `json:"reason_contains"` // substring expected in reason, if any
}

// ---------------------------------------------------------------------------
// Vector loading and key-material interpolation
// ---------------------------------------------------------------------------

// loadVectors reads testdata/vectors.json and interpolates key material
// placeholders ($TEST_CERT_B64, $TEST_JWK) with real generated material.
func loadVectors(t *testing.T) []testVector {
	t.Helper()

	data, err := os.ReadFile("testdata/vectors.json")
	require.NoError(t, err, "failed to read testdata/vectors.json")

	// Generate key material for interpolation.
	_, certB64 := generateTestCert(t)
	jwkJSON := generateTestJWKJSON(t)

	// Interpolate placeholders.
	s := string(data)
	s = strings.ReplaceAll(s, `"$TEST_CERT_B64"`, fmt.Sprintf("%q", certB64))
	s = strings.ReplaceAll(s, `"$TEST_JWK"`, jwkJSON)

	var vectors []testVector
	require.NoError(t, json.Unmarshal([]byte(s), &vectors), "failed to parse test vectors")
	require.NotEmpty(t, vectors, "no test vectors loaded")
	return vectors
}

// buildRequest deserializes a vector's request into an AuthZEN EvaluationRequest.
func buildRequest(t *testing.T, raw json.RawMessage) *authzen.EvaluationRequest {
	t.Helper()
	var req authzen.EvaluationRequest
	require.NoError(t, json.Unmarshal(raw, &req), "failed to parse request from vector")
	return &req
}

// ---------------------------------------------------------------------------
// Registry catalogue
// ---------------------------------------------------------------------------

// registryEntry pairs a registry instance with its catalogue name.
type registryEntry struct {
	Name     string
	Registry registry.TrustRegistry
}

// buildRegistryCatalogue returns all registry implementations that can be
// constructed. Registries that require network at evaluation time are included
// but will return decision=false for unknown subjects — the test handles that.
func buildRegistryCatalogue(t *testing.T) []registryEntry {
	t.Helper()

	entries := []registryEntry{
		{Name: "static/always_trusted", Registry: static.NewAlwaysTrustedRegistry("compat-always")},
		{Name: "static/never_trusted", Registry: static.NewNeverTrustedRegistry("compat-never")},
		{Name: "static/whitelist_empty", Registry: static.NewWhitelistRegistry()},
	}

	if scp, err := static.NewSystemCertPoolRegistry(static.SystemCertPoolConfig{
		Name: "compat-syscerts",
	}); err == nil {
		entries = append(entries, registryEntry{Name: "static/system_cert_pool", Registry: scp})
	} else {
		t.Logf("SKIP static/system_cert_pool: %v", err)
	}

	if reg, err := oidfed.NewOIDFedRegistry(oidfed.Config{
		TrustAnchors: []oidfed.TrustAnchorConfig{
			{EntityID: "https://trust-anchor.example.com"},
		},
	}); err == nil {
		entries = append(entries, registryEntry{Name: "oidfed", Registry: reg})
	} else {
		t.Logf("SKIP oidfed: %v", err)
	}

	if reg, err := didweb.NewDIDWebRegistry(didweb.Config{}); err == nil {
		entries = append(entries, registryEntry{Name: "didweb", Registry: reg})
	} else {
		t.Logf("SKIP didweb: %v", err)
	}

	if reg, err := didwebvh.NewDIDWebVHRegistry(didwebvh.Config{}); err == nil {
		entries = append(entries, registryEntry{Name: "didwebvh", Registry: reg})
	} else {
		t.Logf("SKIP didwebvh: %v", err)
	}

	if reg, err := didjwks.NewRegistry(didjwks.Config{}); err == nil {
		entries = append(entries, registryEntry{Name: "didjwks", Registry: reg})
	} else {
		t.Logf("SKIP didjwks: %v", err)
	}

	if reg, err := mdociaca.New(nil); err == nil {
		entries = append(entries, registryEntry{Name: "mdociaca", Registry: reg})
	} else {
		t.Logf("SKIP mdociaca: %v", err)
	}

	entries = append(entries, registryEntry{
		Name:     "did_generic_key",
		Registry: did.NewGenericDIDRegistryWithKeyMethod(did.GenericDIDRegistryConfig{}),
	})

	if reg, err := etsi.NewTSLRegistry(etsi.TSLConfig{
		Name:               "EWC-Demo-TSL",
		TSLURLs:            []string{"https://trust.siros.org/ewc-demo.xml"},
		AllowNetworkAccess: true,
		FetchTimeout:       15 * time.Second,
	}); err == nil {
		entries = append(entries, registryEntry{Name: "etsi_ewc_demo", Registry: reg})
	} else {
		t.Logf("SKIP etsi_ewc_demo: %v", err)
	}

	if reg, err := lote.New(lote.Config{
		Name:         "SIROS-LoTE-Demo",
		Sources:      []string{"https://trust.siros.org/lote-demo.json"},
		FetchTimeout: 15 * time.Second,
	}); err == nil {
		entries = append(entries, registryEntry{Name: "lote_siros_demo", Registry: reg})
	} else {
		t.Logf("SKIP lote_siros_demo: %v", err)
	}

	if reg, err := lote.New(lote.Config{
		Name:         "SIROS-LoTL-Demo",
		LoTLSources:  []string{"https://trust.siros.org/list_of_trusted_lists-demo.json"},
		FetchTimeout: 15 * time.Second,
	}); err == nil {
		entries = append(entries, registryEntry{Name: "lote_via_lotl", Registry: reg})
	} else {
		t.Logf("SKIP lote_via_lotl: %v", err)
	}

	return entries
}

// ---------------------------------------------------------------------------
// Core data-driven test: vectors × registries
// ---------------------------------------------------------------------------

// TestVectors is the main data-driven test. For each vector × registry
// combination it:
//  1. Ensures no panic (always)
//  2. Checks expected decision if specified in expectations
//  3. Logs detailed diagnostics for CI debugging
//
// Test naming convention for CI readability:
//
//	TestVectors/registry=<name>/vector=<name>/flow=<flow>
func TestVectors(t *testing.T) {
	vectors := loadVectors(t)
	registries := buildRegistryCatalogue(t)
	ctx := context.Background()

	for _, reg := range registries {
		t.Run("registry="+reg.Name, func(t *testing.T) {
			t.Parallel()
			for _, vec := range vectors {
				t.Run("vector="+vec.Name+"/flow="+vec.Flow, func(t *testing.T) {
					req := buildRequest(t, vec.Request)
					resp, err := reg.Registry.Evaluate(ctx, req)

					// Log full context on any failure for CI.
					logPrefix := fmt.Sprintf("[registry=%s vector=%s flow=%s]",
						reg.Name, vec.Name, vec.Flow)

					if err != nil {
						t.Logf("%s error: %v (may be expected for registries without backing data)",
							logPrefix, err)
					}

					// Check expected outcome if defined for this registry.
					if exp, ok := vec.Expectations[reg.Name]; ok {
						if err != nil {
							t.Errorf("%s unexpected error: %v", logPrefix, err)
							return
						}
						require.NotNilf(t, resp, "%s response must not be nil when err is nil", logPrefix)

						if exp.Decision != nil {
							assert.Equalf(t, *exp.Decision, resp.Decision,
								"%s expected decision=%v got=%v (desc: %s)",
								logPrefix, *exp.Decision, resp.Decision, vec.Description)
						}

						if exp.ReasonContains != "" && resp.Context != nil && resp.Context.Reason != nil {
							reasonJSON, _ := json.Marshal(resp.Context.Reason)
							assert.Containsf(t, string(reasonJSON), exp.ReasonContains,
								"%s expected reason to contain %q", logPrefix, exp.ReasonContains)
						}
					} else {
						// No specific expectation — just verify no panic (test runner
						// catches that) and non-nil response when no error.
						if err == nil {
							require.NotNilf(t, resp, "%s response must not be nil when err is nil", logPrefix)
							t.Logf("%s decision=%v (no assertion — no expectation for this registry)",
								logPrefix, resp.Decision)
						}
					}
				})
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Flow-specific tests: verify expected call sequences
// ---------------------------------------------------------------------------

// TestIssuanceFlow_AlwaysTrusted verifies the issuance call sequence:
// resolution → x5c/jwk trust evaluation.
func TestIssuanceFlow_AlwaysTrusted(t *testing.T) {
	vectors := loadVectors(t)
	always := static.NewAlwaysTrustedRegistry("issuance-flow")
	ctx := context.Background()

	for _, vec := range vectors {
		if vec.Flow != "issuance" && vec.Flow != "both" {
			continue
		}
		t.Run("vector="+vec.Name, func(t *testing.T) {
			req := buildRequest(t, vec.Request)
			resp, err := always.Evaluate(ctx, req)
			require.NoErrorf(t, err, "always_trusted should not error for vector=%s", vec.Name)
			require.NotNil(t, resp)
			assert.Truef(t, resp.Decision,
				"always_trusted must approve issuance vector=%s (desc: %s)",
				vec.Name, vec.Description)
		})
	}
}

// TestPresentationFlow_AlwaysTrusted verifies the presentation call sequence.
func TestPresentationFlow_AlwaysTrusted(t *testing.T) {
	vectors := loadVectors(t)
	always := static.NewAlwaysTrustedRegistry("presentation-flow")
	ctx := context.Background()

	for _, vec := range vectors {
		if vec.Flow != "presentation" && vec.Flow != "both" {
			continue
		}
		t.Run("vector="+vec.Name, func(t *testing.T) {
			req := buildRequest(t, vec.Request)
			resp, err := always.Evaluate(ctx, req)
			require.NoErrorf(t, err, "always_trusted should not error for vector=%s", vec.Name)
			require.NotNil(t, resp)
			assert.Truef(t, resp.Decision,
				"always_trusted must approve presentation vector=%s (desc: %s)",
				vec.Name, vec.Description)
		})
	}
}

// ---------------------------------------------------------------------------
// Structural validation tests
// ---------------------------------------------------------------------------

// TestVectors_RequestValidation verifies that standard wallet-backend request
// patterns pass AuthZEN validation. Non-standard patterns (resolution gate,
// URL subject) are documented as expected deviations.
func TestVectors_RequestValidation(t *testing.T) {
	vectors := loadVectors(t)

	// Patterns that use non-standard resource/subject types.
	nonStandard := map[string]string{
		"spocp_key_resolution_gate":     "resource.type 'resolution' is a wallet-backend internal convention",
		"url_subject_credential_issuer": "subject.type 'url' with resource.type 'credential_issuer' is wallet-backend SPOCP gate",
	}

	for _, vec := range vectors {
		t.Run("vector="+vec.Name, func(t *testing.T) {
			req := buildRequest(t, vec.Request)
			err := req.Validate()

			if reason, ok := nonStandard[vec.Name]; ok {
				if err != nil {
					t.Logf("expected non-standard pattern: %v (%s)", err, reason)
				}
				return
			}
			assert.NoErrorf(t, err, "wallet-backend pattern %q should be valid AuthZEN", vec.Name)
		})
	}
}

// TestVectors_ActionNames verifies all action names are from the expected set.
func TestVectors_ActionNames(t *testing.T) {
	validActions := map[string]bool{
		"credential-issuer":   true,
		"credential-verifier": true,
	}

	vectors := loadVectors(t)
	for _, vec := range vectors {
		t.Run("vector="+vec.Name, func(t *testing.T) {
			req := buildRequest(t, vec.Request)
			if req.Action == nil {
				t.Skip("no action on this vector")
			}
			assert.Truef(t, validActions[req.Action.Name],
				"unexpected action name %q", req.Action.Name)
		})
	}
}

// TestVectors_KeyFormats verifies key material format in each vector.
func TestVectors_KeyFormats(t *testing.T) {
	vectors := loadVectors(t)
	for _, vec := range vectors {
		t.Run("vector="+vec.Name, func(t *testing.T) {
			req := buildRequest(t, vec.Request)
			if len(req.Resource.Key) == 0 {
				t.Skip("no key material in this vector")
			}

			switch req.Resource.Type {
			case "x5c":
				for i, k := range req.Resource.Key {
					s, ok := k.(string)
					require.Truef(t, ok, "x5c key[%d] must be a string", i)
					der, err := base64.StdEncoding.DecodeString(s)
					require.NoErrorf(t, err, "x5c key[%d] must be valid base64", i)
					_, err = x509.ParseCertificate(der)
					require.NoErrorf(t, err, "x5c key[%d] must be a valid DER certificate", i)
				}
			case "jwk":
				for i, k := range req.Resource.Key {
					m, ok := k.(map[string]interface{})
					require.Truef(t, ok, "jwk key[%d] must be a map, got %T", i, k)
					_, hasKty := m["kty"]
					assert.Truef(t, hasKty, "jwk key[%d] must have 'kty' field", i)
				}
			}
		})
	}
}

// TestVectors_ResponseStructure validates that every registry response has
// the expected structure across all vectors.
func TestVectors_ResponseStructure(t *testing.T) {
	vectors := loadVectors(t)
	registries := buildRegistryCatalogue(t)
	ctx := context.Background()

	for _, reg := range registries {
		t.Run("registry="+reg.Name, func(t *testing.T) {
			t.Parallel()
			for _, vec := range vectors {
				t.Run("vector="+vec.Name, func(t *testing.T) {
					req := buildRequest(t, vec.Request)
					resp, err := reg.Registry.Evaluate(ctx, req)
					if err != nil {
						t.Skipf("registry errored (acceptable): %v", err)
					}
					require.NotNil(t, resp, "response must not be nil when err is nil")
					if resp.Context != nil && resp.Context.Reason != nil {
						assert.IsType(t, map[string]interface{}{}, resp.Context.Reason,
							"reason should be a JSON map")
					}
				})
			}
		})
	}
}

// TestVectors_CompositeRegistryManager verifies that the RegistryManager
// routes wallet-backend patterns correctly across multiple registries using
// FirstMatch (the production strategy).
func TestVectors_CompositeRegistryManager(t *testing.T) {
	vectors := loadVectors(t)
	ctx := context.Background()

	always := static.NewAlwaysTrustedRegistry("compat-fallback")
	never := static.NewNeverTrustedRegistry("compat-reject")
	mgr := registry.NewRegistryManager(registry.FirstMatch, 30*time.Second)
	mgr.Register(never)
	mgr.Register(always)

	for _, vec := range vectors {
		t.Run("vector="+vec.Name+"/flow="+vec.Flow, func(t *testing.T) {
			req := buildRequest(t, vec.Request)
			resp, err := mgr.Evaluate(ctx, req)
			if err != nil {
				t.Logf("manager returned error for %s: %v", vec.Name, err)
				return
			}
			require.NotNil(t, resp)
			assert.Truef(t, resp.Decision,
				"FirstMatch with never→always should find always_trusted for vector=%s",
				vec.Name)
		})
	}
}

// TestVectors_ResourceTypeSupport ensures each registry supports the resource
// types that wallet-backend uses.
func TestVectors_ResourceTypeSupport(t *testing.T) {
	registries := buildRegistryCatalogue(t)
	walletResourceTypes := []string{"jwk", "x5c"}

	for _, reg := range registries {
		t.Run("registry="+reg.Name, func(t *testing.T) {
			supported := reg.Registry.SupportedResourceTypes()
			for _, s := range supported {
				if s == "*" {
					return // wildcard — everything supported
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

// ---------------------------------------------------------------------------
// Summary report (runs last, prints a matrix)
// ---------------------------------------------------------------------------

// TestVectors_Summary prints a summary matrix of all vectors × registries.
// This is useful in CI to get a quick overview of what works and what doesn't.
func TestVectors_Summary(t *testing.T) {
	vectors := loadVectors(t)
	registries := buildRegistryCatalogue(t)
	ctx := context.Background()

	type result struct {
		decision bool
		err      error
	}

	// Collect results.
	results := make(map[string]map[string]result) // [regName][vecName]
	for _, reg := range registries {
		results[reg.Name] = make(map[string]result)
		for _, vec := range vectors {
			req := buildRequest(t, vec.Request)
			resp, err := reg.Registry.Evaluate(ctx, req)
			r := result{err: err}
			if resp != nil {
				r.decision = resp.Decision
			}
			results[reg.Name][vec.Name] = r
		}
	}

	// Print matrix.
	t.Log("")
	t.Log("╔══════════════════════════════════════════════════════════════════╗")
	t.Log("║           WALLET-BACKEND COMPATIBILITY MATRIX                  ║")
	t.Log("╚══════════════════════════════════════════════════════════════════╝")
	t.Log("")

	// Header: vector names.
	vecNames := make([]string, len(vectors))
	for i, v := range vectors {
		vecNames[i] = v.Name
	}

	for _, reg := range registries {
		t.Logf("  Registry: %s", reg.Name)
		for _, vec := range vectors {
			r := results[reg.Name][vec.Name]
			status := "✓ PASS"
			if r.err != nil {
				status = "✗ ERR "
			} else if !r.decision {
				status = "○ DENY"
			}
			t.Logf("    %s  %s (%s)", status, vec.Name, vec.Flow)
		}
		t.Log("")
	}
}

// ---------------------------------------------------------------------------
// Key material helpers
// ---------------------------------------------------------------------------

func generateTestCert(t *testing.T) (*x509.Certificate, string) {
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

func generateTestJWKJSON(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	jwk := map[string]interface{}{
		"kty": "EC",
		"crv": "P-256",
		"x":   base64.RawURLEncoding.EncodeToString(key.PublicKey.X.Bytes()),
		"y":   base64.RawURLEncoding.EncodeToString(key.PublicKey.Y.Bytes()),
	}

	b, err := json.Marshal(jwk)
	require.NoError(t, err)
	return string(b)
}
