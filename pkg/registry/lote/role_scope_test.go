package lote

import (
	"context"
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/sirosfoundation/g119612/pkg/etsi119602"
	"github.com/sirosfoundation/go-trust/pkg/authzen"
)

// A registry resolving several list types (as the WE BUILD WP4 LoTL does) must
// not let a CA listed for one role vouch for another.
func roleScopedRegistry(t *testing.T, cfg Config) (reg *Registry, leaf string) {
	t.Helper()
	caCert, caKey := generateTestCA(t)
	leafCert := generateLeafCert(t, caCert, caKey)
	leaf = base64.StdEncoding.EncodeToString(leafCert.Raw)

	wallets := minimalLoTE("NL", x509Entity("urn:wallet-provider:nl", caCert))
	wallets.ListAndSchemeInformation.LoTEType = etsi119602.LoTETypeWalletProviders
	pid := minimalLoTE("NO", simpleEntity("urn:pid-provider:no"))
	pid.ListAndSchemeInformation.LoTEType = etsi119602.LoTETypePIDProviders

	dir := t.TempDir()
	cfg.Sources = []string{writeLoTE(t, dir, "wallets.json", wallets), writeLoTE(t, dir, "pid.json", pid)}
	reg, err := New(cfg)
	require.NoError(t, err)
	return reg, leaf
}

func roleRequest(leaf, role string) *authzen.EvaluationRequest {
	req := &authzen.EvaluationRequest{
		Subject:  authzen.Subject{Type: "key", ID: "https://some-issuer.example"},
		Resource: authzen.Resource{Type: "x5c", ID: "https://some-issuer.example", Key: []interface{}{leaf}},
	}
	if role != "" {
		req.Action = &authzen.Action{Name: role}
	}
	return req
}

func TestRoleScope_CAChain(t *testing.T) {
	cfg := Config{RoleSchemeTypes: map[string][]string{
		"http://ec.europa.eu/NS/wallet-provider": {etsi119602.LoTETypeWalletProviders},
		"http://ec.europa.eu/NS/pid-provider":    {etsi119602.LoTETypePIDProviders},
	}}
	reg, leaf := roleScopedRegistry(t, cfg)

	cases := []struct {
		name string
		role string
		want bool
	}{
		{"no role: unscoped, as before", "", true},
		{"mapped role of the listing type", "http://ec.europa.eu/NS/wallet-provider", true},
		{"mapped role of another type", "http://ec.europa.eu/NS/pid-provider", false},
		{"LoTE type URI used as role", etsi119602.LoTETypeWalletProviders, true},
		{"other LoTE type URI as role", etsi119602.LoTETypePIDProviders, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp, err := reg.Evaluate(context.Background(), roleRequest(leaf, tc.role))
			require.NoError(t, err)
			assert.Equal(t, tc.want, resp.Decision, "%v", resp.Context)
		})
	}
}

func TestRoleScope_RequireRole(t *testing.T) {
	reg, leaf := roleScopedRegistry(t, Config{RequireRole: true})

	resp, err := reg.Evaluate(context.Background(), roleRequest(leaf, ""))
	require.NoError(t, err)
	assert.False(t, resp.Decision)

	resp, err = reg.Evaluate(context.Background(), roleRequest(leaf, etsi119602.LoTETypeWalletProviders))
	require.NoError(t, err)
	assert.True(t, resp.Decision)
}

func TestRoleScope_ListedEntityOfWrongType(t *testing.T) {
	reg, _ := roleScopedRegistry(t, Config{})
	resp, err := reg.Evaluate(context.Background(), &authzen.EvaluationRequest{
		Subject:  authzen.Subject{Type: "key", ID: "urn:pid-provider:no"},
		Resource: authzen.Resource{ID: "urn:pid-provider:no"},
		Action:   &authzen.Action{Name: etsi119602.LoTETypeWalletProviders},
	})
	require.NoError(t, err)
	assert.False(t, resp.Decision)
	resp, err = reg.Evaluate(context.Background(), &authzen.EvaluationRequest{
		Subject:  authzen.Subject{Type: "key", ID: "urn:pid-provider:no"},
		Resource: authzen.Resource{ID: "urn:pid-provider:no"},
		Action:   &authzen.Action{Name: etsi119602.LoTETypePIDProviders},
	})
	require.NoError(t, err)
	assert.True(t, resp.Decision)
}
