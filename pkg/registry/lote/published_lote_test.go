package lote_test

import (
	"context"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/sirosfoundation/g119612/pkg/etsi119602"
	"github.com/sirosfoundation/go-trust/pkg/authzen"
	"github.com/sirosfoundation/go-trust/pkg/authzenclient"
	"github.com/sirosfoundation/go-trust/pkg/registry/lote"
	"github.com/sirosfoundation/go-trust/pkg/testserver"
)

const (
	// Published LoTE URLs from trust.siros.org (GitHub Pages).
	loteURL    = "https://sirosfoundation.github.io/trust-lists/lote-demo.json"
	loteJWSURL = "https://sirosfoundation.github.io/trust-lists/lote-demo.json.jws"
)

func skipIfOffline(t *testing.T) {
	t.Helper()
	if os.Getenv("GO_TRUST_INTEGRATION") == "" {
		t.Skip("set GO_TRUST_INTEGRATION to a non-empty value to run live integration tests")
	}
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Head(loteURL)
	if err != nil {
		t.Skipf("cannot reach %s — skipping", loteURL)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Skipf("cannot reach %s — skipping", loteURL)
	}
}

// TestPublishedLoTE_Load verifies that the live LoTE can be loaded as a
// registry source and that the registry reports healthy.
func TestPublishedLoTE_Load(t *testing.T) {
	skipIfOffline(t)

	reg, err := lote.New(lote.Config{
		Name:         "siros-trust-lists",
		Description:  "SIROS Foundation published LoTE",
		Sources:      []string{loteURL},
		FetchTimeout: 15 * time.Second,
	})
	require.NoError(t, err)
	assert.True(t, reg.Healthy())

	info := reg.Info()
	assert.Equal(t, "siros-trust-lists", info.Name)
	assert.Equal(t, "lote", info.Type)
	assert.True(t, info.Healthy)
	assert.NotNil(t, info.LastUpdated)
}

// TestPublishedLoTE_SchemeInformation verifies the scheme metadata of the
// published LoTE matches the SIROS Foundation trust list definition.
func TestPublishedLoTE_SchemeInformation(t *testing.T) {
	skipIfOffline(t)

	l, err := etsi119602.FetchLoTE(loteURL, &etsi119602.FetchOptions{
		Timeout: 15 * time.Second,
	})
	require.NoError(t, err)

	assert.Equal(t, "SE", l.SchemeInformation.Territory)
	assert.GreaterOrEqual(t, l.SchemeInformation.SequenceNumber, 1)

	// Operator name should reference SIROS Foundation (any language entry)
	require.NotEmpty(t, l.SchemeInformation.SchemeOperator)
	foundOperator := false
	for _, operator := range l.SchemeInformation.SchemeOperator {
		if operator.Value == "SIROS Foundation" {
			foundOperator = true
			break
		}
	}
	assert.True(t, foundOperator, "expected SchemeOperator to include SIROS Foundation")
}

// TestPublishedLoTE_ResolveGrantedEntity verifies that the known granted
// entity can be resolved via the LoTE registry (resolution-only mode,
// no key material required).
func TestPublishedLoTE_ResolveGrantedEntity(t *testing.T) {
	skipIfOffline(t)

	reg, err := lote.New(lote.Config{
		Sources:      []string{loteURL},
		FetchTimeout: 15 * time.Second,
	})
	require.NoError(t, err)

	// Resolution-only evaluation (no resource type/key) — should succeed
	// for any entity in the LoTE with status "granted".
	resp, err := reg.Evaluate(context.Background(), &authzen.EvaluationRequest{
		Subject:  authzen.Subject{Type: "key", ID: "https://issuer.siros.org"},
		Resource: authzen.Resource{ID: "https://issuer.siros.org"},
	})
	require.NoError(t, err)
	assert.True(t, resp.Decision, "granted entity should be resolvable")
	assert.NotNil(t, resp.Context)
	assert.NotNil(t, resp.Context.TrustMetadata, "resolution should include trust metadata")
}

// TestPublishedLoTE_UnknownEntity verifies that entities not in the LoTE
// are correctly rejected.
func TestPublishedLoTE_UnknownEntity(t *testing.T) {
	skipIfOffline(t)

	reg, err := lote.New(lote.Config{
		Sources:      []string{loteURL},
		FetchTimeout: 15 * time.Second,
	})
	require.NoError(t, err)

	resp, err := reg.Evaluate(context.Background(), &authzen.EvaluationRequest{
		Subject:  authzen.Subject{Type: "key", ID: "https://unknown.example.com"},
		Resource: authzen.Resource{ID: "https://unknown.example.com"},
	})
	require.NoError(t, err)
	assert.False(t, resp.Decision, "unknown entity should not be trusted")
}

// TestPublishedLoTE_JWSAvailable verifies that the JWS-signed version of the
// LoTE is reachable and contains a valid compact serialization (three
// dot-separated segments).
func TestPublishedLoTE_JWSAvailable(t *testing.T) {
	skipIfOffline(t)

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Get(loteJWSURL)
	require.NoError(t, err)
	defer resp.Body.Close()

	require.Equal(t, http.StatusOK, resp.StatusCode, "JWS file should be available")

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1*1024*1024))
	require.NoError(t, err)

	compact := strings.TrimSpace(string(body))
	parts := strings.Split(compact, ".")
	assert.Equal(t, 3, len(parts), "JWS compact serialization must have 3 parts (header.payload.signature)")
	for i, p := range parts {
		assert.NotEmpty(t, p, "JWS part %d must not be empty", i)
	}
}

// TestPublishedLoTE_WithTestServer verifies that the live LoTE can back a
// full AuthZEN evaluation through the go-trust test server.
func TestPublishedLoTE_WithTestServer(t *testing.T) {
	skipIfOffline(t)

	reg, err := lote.New(lote.Config{
		Name:         "siros-published",
		Sources:      []string{loteURL},
		FetchTimeout: 15 * time.Second,
	})
	require.NoError(t, err)

	// Use the testserver for a full round-trip through the HTTP API.
	srv := testserver.New(testserver.WithRegistry(reg))
	defer srv.Close()

	client := authzenclient.New(srv.URL())

	ctx := context.Background()

	// Positive: known granted entity
	resp, err := client.Evaluate(ctx, &authzen.EvaluationRequest{
		Subject:  authzen.Subject{Type: "key", ID: "https://issuer.siros.org"},
		Resource: authzen.Resource{ID: "https://issuer.siros.org"},
	})
	require.NoError(t, err)
	assert.True(t, resp.Decision)

	// Negative: unknown entity
	resp, err = client.Evaluate(ctx, &authzen.EvaluationRequest{
		Subject:  authzen.Subject{Type: "key", ID: "https://evil.example.com"},
		Resource: authzen.Resource{ID: "https://evil.example.com"},
	})
	require.NoError(t, err)
	assert.False(t, resp.Decision)
}


