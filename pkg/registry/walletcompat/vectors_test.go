// Package walletcompat provides cross-registry data-driven tests verifying that
// every TrustRegistry implementation correctly handles the AuthZEN evaluation
// request patterns that go-wallet-backend constructs during issuance and
// presentation flows.
//
// Test vectors are loaded from testdata/vectors/*.json. Each vector specifies:
//   - An AuthZEN EvaluationRequest (the wallet-backend call shape)
//   - The flow it belongs to (issuance, presentation, or both)
//   - Per-registry expected outcomes (where known)
//
// The test output is structured for easy debugging in CI:
//
//	TestVectors/registry=etsi_ewc_demo/vector=eudi_pid_x5c_issuer/flow=issuance
//
// This makes it immediately obvious which registry + vector combination failed.
//
// Fixtures for ETSI TSL, LoTE, and LoTL are fetched via go generate:
//
//	go generate ./pkg/registry/walletcompat/
//
//go:generate go run fetch_fixtures.go
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
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"
	_ "unsafe" // for go:linkname

	"github.com/go-resty/resty/v2"
	"github.com/jarcoal/httpmock"
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

// Access go-oidfed's internal resty client for httpmock patching.
//
//go:linkname oidfedHTTPClient github.com/go-oidfed/lib/internal/http.client
var oidfedHTTPClient *resty.Client

// ---------------------------------------------------------------------------
// JSON vector schema
// ---------------------------------------------------------------------------

// testVector is a single test case loaded from testdata/vectors.json.
type testVector struct {
	Name         string                     `json:"name"`
	Description  string                     `json:"description"`
	Flow         string                     `json:"flow"` // issuance | presentation | both
	Source       string                     `json:"source"`
	Request      json.RawMessage            `json:"request"`
	Expectations map[string]expectedOutcome `json:"expectations"`
}

// expectedOutcome is the expected result for a specific registry.
type expectedOutcome struct {
	Decision       *bool  `json:"decision"`        // nil = don't assert decision (just no-panic)
	ReasonContains string `json:"reason_contains"` // substring expected in reason, if any
}

// ---------------------------------------------------------------------------
// Vector loading and key-material interpolation
// ---------------------------------------------------------------------------

// loadVectors reads all JSON files from testdata/vectors/ (sorted by filename)
// and interpolates key material placeholders ($TEST_CERT_B64, $TEST_JWK) with
// real generated material.
func loadVectors(t *testing.T) []testVector {
	t.Helper()

	files, err := filepath.Glob("testdata/vectors/*.json")
	require.NoError(t, err, "failed to glob testdata/vectors/*.json")
	require.NotEmpty(t, files, "no vector files found in testdata/vectors/")
	sort.Strings(files)

	// Generate key material for interpolation.
	_, certB64 := generateTestCert(t)
	jwkJSON := generateTestJWKJSON(t)

	var vectors []testVector
	for _, f := range files {
		data, err := os.ReadFile(f)
		require.NoErrorf(t, err, "failed to read %s", f)

		// Interpolate placeholders.
		s := string(data)
		s = strings.ReplaceAll(s, `"$TEST_CERT_B64"`, fmt.Sprintf("%q", certB64))
		s = strings.ReplaceAll(s, `"$TEST_JWK"`, jwkJSON)

		var batch []testVector
		require.NoErrorf(t, json.Unmarshal([]byte(s), &batch), "failed to parse %s", f)
		vectors = append(vectors, batch...)
	}
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
// Fixture server: serves LoTE/LoTL/JWKS from testdata/fixtures/
// ---------------------------------------------------------------------------

// fixtureServer returns an httptest.Server that serves trust list fixtures
// from testdata/fixtures/. The LoTL JSON's {{BASE_URL}} placeholders are
// replaced with the server's URL so pointer following works.
// Also serves a JWKS endpoint at /.well-known/jwks.json with the provided key.
func fixtureServer(t *testing.T, pubKey *ecdsa.PublicKey) *httptest.Server {
	t.Helper()

	mux := http.NewServeMux()

	// Serve LoTE JSON
	mux.HandleFunc("/lote-demo.json", func(w http.ResponseWriter, r *http.Request) {
		data, err := os.ReadFile("testdata/fixtures/lote-demo.json")
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write(data)
	})

	// Serve LoTL JSON with URL substitution (deferred until we know the server URL)
	var serverURL string
	mux.HandleFunc("/lotl-demo.json", func(w http.ResponseWriter, r *http.Request) {
		data, err := os.ReadFile("testdata/fixtures/lotl-demo.json")
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		s := strings.ReplaceAll(string(data), "{{BASE_URL}}", serverURL)
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(s))
	})

	// Serve JWKS endpoint for whitelist registry
	if pubKey != nil {
		byteLen := (pubKey.Curve.Params().BitSize + 7) / 8
		xBytes := pubKey.X.Bytes()
		yBytes := pubKey.Y.Bytes()
		if len(xBytes) < byteLen {
			padded := make([]byte, byteLen)
			copy(padded[byteLen-len(xBytes):], xBytes)
			xBytes = padded
		}
		if len(yBytes) < byteLen {
			padded := make([]byte, byteLen)
			copy(padded[byteLen-len(yBytes):], yBytes)
			yBytes = padded
		}
		jwks := map[string]interface{}{
			"keys": []map[string]interface{}{
				{
					"kty": "EC",
					"crv": "P-256",
					"use": "sig",
					"x":   base64.RawURLEncoding.EncodeToString(xBytes),
					"y":   base64.RawURLEncoding.EncodeToString(yBytes),
				},
			},
		}
		jwksJSON, _ := json.Marshal(jwks)
		mux.HandleFunc("/.well-known/jwks.json", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.Write(jwksJSON)
		})
	}

	ts := httptest.NewServer(mux)
	serverURL = ts.URL
	t.Cleanup(ts.Close)
	return ts
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
// constructed. Registries that require network I/O are gated behind the
// SKIP_NETWORK_TESTS environment variable to keep CI fast and deterministic.
func buildRegistryCatalogue(t *testing.T) []registryEntry {
	t.Helper()

	entries := []registryEntry{
		{Name: "static/always_trusted", Registry: static.NewAlwaysTrustedRegistry("compat-always")},
		{Name: "static/never_trusted", Registry: static.NewNeverTrustedRegistry("compat-never")},
		{Name: "static/whitelist_empty", Registry: static.NewWhitelistRegistry()},
		{Name: "static/whitelist_issuers", Registry: static.NewWhitelistRegistry(
			static.WithWhitelistConfig(static.WhitelistConfig{
				Issuers: []string{
					"https://issuer.example.com",
					"https://pid-provider.example.eu",
					"https://mdl-issuer.example.com",
					"https://university.example.edu",
				},
			}),
		)},
		{Name: "static/whitelist_verifiers", Registry: static.NewWhitelistRegistry(
			static.WithWhitelistConfig(static.WhitelistConfig{
				Verifiers: []string{
					"https://verifier.example.com",
				},
			}),
		)},
	}

	if scp, err := static.NewSystemCertPoolRegistry(static.SystemCertPoolConfig{
		Name: "compat-syscerts",
	}); err == nil {
		entries = append(entries, registryEntry{Name: "static/system_cert_pool", Registry: scp})
	} else {
		t.Logf("SKIP static/system_cert_pool: %v", err)
	}

	// Fixture-backed registries (offline, deterministic)
	entries = append(entries, buildFixtureRegistries(t)...)

	skipNetwork := os.Getenv("SKIP_NETWORK_TESTS") == "1"
	if skipNetwork {
		t.Log("SKIP_NETWORK_TESTS=1 — skipping network-backed registries")
		return entries
	}

	if reg, err := oidfed.NewOIDFedRegistry(oidfed.Config{
		TrustAnchors: []oidfed.TrustAnchorConfig{
			{EntityID: "https://realta.labb.sunet.se"},
		},
		CacheTTL: 5 * time.Minute,
	}); err == nil {
		entries = append(entries, registryEntry{Name: "oidfed_realta", Registry: reg})
	} else {
		t.Logf("SKIP oidfed_realta: %v", err)
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

// buildFixtureRegistries creates deterministic, offline registries backed by
// fixtures fetched via go generate. These run even with SKIP_NETWORK_TESTS=1.
func buildFixtureRegistries(t *testing.T) []registryEntry {
	t.Helper()

	fixtureDir, err := filepath.Abs("testdata/fixtures")
	if err != nil {
		t.Logf("SKIP fixture registries: %v", err)
		return nil
	}

	// Check fixtures exist (go generate must have been run)
	if _, err := os.Stat(filepath.Join(fixtureDir, "lote-demo.json")); os.IsNotExist(err) {
		t.Log("SKIP fixture registries: run 'go generate ./pkg/registry/walletcompat/' first")
		return nil
	}

	var entries []registryEntry

	// ETSI LoTE from local fixture XML (ewc-demo.xml is LoTE format, not TSL)
	loteXmlFile := filepath.Join(fixtureDir, "ewc-demo.xml")
	if reg, err := lote.New(lote.Config{
		Name:    "EWC-Demo-Fixture",
		Sources: []string{loteXmlFile},
	}); err == nil {
		entries = append(entries, registryEntry{Name: "fixture/etsi_lote_xml", Registry: reg})
	} else {
		t.Logf("SKIP fixture/etsi_lote_xml: %v", err)
	}

	// LoTE from local fixture JSON
	loteFile := filepath.Join(fixtureDir, "lote-demo.json")
	if reg, err := lote.New(lote.Config{
		Name:    "SIROS-LoTE-Fixture",
		Sources: []string{loteFile},
	}); err == nil {
		entries = append(entries, registryEntry{Name: "fixture/lote", Registry: reg})
	} else {
		t.Logf("SKIP fixture/lote: %v", err)
	}

	// OpenID Federation from httpmock-backed fixtures
	if mockReg := buildOIDFedFixtureRegistry(t, fixtureDir); mockReg != nil {
		entries = append(entries, registryEntry{Name: "fixture/oidfed", Registry: mockReg})
	}

	return entries
}

// oidfedManifest is the JSON structure of testdata/fixtures/oidfed/manifest.json.
type oidfedManifest struct {
	TrustAnchor string `json:"trust_anchor"`
	ListFile    string `json:"list_file"`
	ListURL     string `json:"list_url"`
	Entities    []struct {
		EntityID               string `json:"entity_id"`
		EntityConfigFile       string `json:"entity_config_file"`
		EntityConfigURL        string `json:"entity_config_url"`
		EntityStatementFile    string `json:"entity_statement_file,omitempty"`
		EntityStatementURL     string `json:"entity_statement_url,omitempty"`
		EntityStatementFetchBy string `json:"entity_statement_fetch_by,omitempty"`
	} `json:"entities"`
}

// oidfedMockRegistry wraps an OIDFedRegistry and activates httpmock around
// each Evaluate call so the go-oidfed library's global HTTP client fetches
// from cached fixture JWTs instead of the network.
type oidfedMockRegistry struct {
	inner    registry.TrustRegistry
	setup    func()    // activates httpmock + registers responders
	teardown func()    // deactivates httpmock
}

func (m *oidfedMockRegistry) Evaluate(ctx context.Context, req *authzen.EvaluationRequest) (*authzen.EvaluationResponse, error) {
	m.setup()
	defer m.teardown()
	return m.inner.Evaluate(ctx, req)
}

func (m *oidfedMockRegistry) Healthy() bool                      { return m.inner.Healthy() }
func (m *oidfedMockRegistry) Info() registry.RegistryInfo         { return m.inner.Info() }
func (m *oidfedMockRegistry) SupportedResourceTypes() []string   { return m.inner.SupportedResourceTypes() }
func (m *oidfedMockRegistry) SupportsResolutionOnly() bool        { return m.inner.SupportsResolutionOnly() }
func (m *oidfedMockRegistry) Refresh(ctx context.Context) error   { return m.inner.Refresh(ctx) }

// buildOIDFedFixtureRegistry creates an OIDFed registry backed by httpmock
// responders serving cached JWT fixtures. Returns nil if fixtures are missing.
func buildOIDFedFixtureRegistry(t *testing.T, fixtureDir string) *oidfedMockRegistry {
	t.Helper()

	manifestPath := filepath.Join(fixtureDir, "oidfed", "manifest.json")
	data, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Logf("SKIP fixture/oidfed: %v", err)
		return nil
	}

	var manifest oidfedManifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		t.Logf("SKIP fixture/oidfed: parse manifest: %v", err)
		return nil
	}

	oidfedFixtureDir := filepath.Join(fixtureDir, "oidfed")

	// Pre-load all fixture files into memory.
	// We separate responders into simple (exact URL) and query-param-based
	// (for /fetch?sub=... endpoints where go-oidfed passes sub as a query param).
	type simpleResponder struct {
		url         string
		body        string
		contentType string
	}
	type queryResponder struct {
		baseURL     string
		query       map[string]string
		body        string
		contentType string
	}
	var simple []simpleResponder
	var queryBased []queryResponder

	for _, ent := range manifest.Entities {
		// Entity configuration — simple URL match
		ecData, err := os.ReadFile(filepath.Join(oidfedFixtureDir, ent.EntityConfigFile))
		if err != nil {
			t.Logf("SKIP fixture/oidfed: read %s: %v", ent.EntityConfigFile, err)
			return nil
		}
		simple = append(simple, simpleResponder{
			url:         ent.EntityConfigURL,
			body:        string(ecData),
			contentType: "application/entity-statement+jwt",
		})

		// Entity statement — fetch endpoint uses query params
		if ent.EntityStatementFile != "" {
			esData, err := os.ReadFile(filepath.Join(oidfedFixtureDir, ent.EntityStatementFile))
			if err != nil {
				t.Logf("SKIP fixture/oidfed: read %s: %v", ent.EntityStatementFile, err)
				return nil
			}
			// go-oidfed calls fetchEndpoint with url.Values{"sub": {entityID}}
			// via resty's SetQueryParamsFromValues, so we register with query match.
			queryBased = append(queryBased, queryResponder{
				baseURL:     ent.EntityStatementFetchBy + "/fetch",
				query:       map[string]string{"sub": ent.EntityID},
				body:        string(esData),
				contentType: "application/entity-statement+jwt",
			})
		}
	}

	// List endpoint — simple URL match
	listData, err := os.ReadFile(filepath.Join(oidfedFixtureDir, manifest.ListFile))
	if err != nil {
		t.Logf("SKIP fixture/oidfed: read %s: %v", manifest.ListFile, err)
		return nil
	}
	simple = append(simple, simpleResponder{
		url:         manifest.ListURL,
		body:        string(listData),
		contentType: "application/json",
	})

	// Create the underlying OIDFed registry
	reg, err := oidfed.NewOIDFedRegistry(oidfed.Config{
		TrustAnchors: []oidfed.TrustAnchorConfig{
			{EntityID: manifest.TrustAnchor},
		},
		CacheTTL: 10 * time.Minute,
	})
	if err != nil {
		t.Logf("SKIP fixture/oidfed: create registry: %v", err)
		return nil
	}

	return &oidfedMockRegistry{
		inner: reg,
		setup: func() {
			httpmock.ActivateNonDefault(oidfedHTTPClient.GetClient())
			for _, r := range simple {
				httpmock.RegisterResponder("GET", r.url,
					httpmock.NewStringResponder(200, r.body).HeaderSet(http.Header{
						"Content-Type": {r.contentType},
					}),
				)
			}
			for _, r := range queryBased {
				httpmock.RegisterResponderWithQuery("GET", r.baseURL, r.query,
					httpmock.NewStringResponder(200, r.body).HeaderSet(http.Header{
						"Content-Type": {r.contentType},
					}),
				)
			}
		},
		teardown: func() {
			httpmock.DeactivateAndReset()
		},
	}
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

					if exp.ReasonContains != "" {
						require.NotNilf(t, resp.Context, "%s expected non-nil context for reason assertion", logPrefix)
						require.NotNilf(t, resp.Context.Reason, "%s expected non-nil reason containing %q", logPrefix, exp.ReasonContains)
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

// TestIssuanceFlow_AlwaysTrusted verifies that always_trusted returns
// decision=true for every issuance vector, confirming that the request
// shapes are accepted without error.
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

// TestPresentationFlow_AlwaysTrusted verifies that always_trusted returns
// decision=true for every presentation vector.
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
		"spocp_key_resolution_gate":                "resource.type 'resolution' is a wallet-backend internal convention",
		"spocp_url_subject_gate":                   "subject.type 'url' with resource.type 'credential_issuer' is wallet-backend SPOCP gate",
		"resolution_with_action_credential_issuer": "resource.type 'resolution' with action is a wallet-backend proxy pattern",
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
		"mdl-issuer":          true,
		"issuer":              true,
		"verifier":            true,
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
			require.NoErrorf(t, err, "RegistryManager should not error for vector=%s", vec.Name)
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

	// Left-pad coordinates to fixed 32-byte length per RFC 7518.
	byteLen := (key.PublicKey.Curve.Params().BitSize + 7) / 8
	xBytes := key.PublicKey.X.Bytes()
	yBytes := key.PublicKey.Y.Bytes()
	if len(xBytes) < byteLen {
		padded := make([]byte, byteLen)
		copy(padded[byteLen-len(xBytes):], xBytes)
		xBytes = padded
	}
	if len(yBytes) < byteLen {
		padded := make([]byte, byteLen)
		copy(padded[byteLen-len(yBytes):], yBytes)
		yBytes = padded
	}

	jwk := map[string]interface{}{
		"kty": "EC",
		"crv": "P-256",
		"x":   base64.RawURLEncoding.EncodeToString(xBytes),
		"y":   base64.RawURLEncoding.EncodeToString(yBytes),
	}

	b, err := json.Marshal(jwk)
	require.NoError(t, err)
	return string(b)
}
