package lote

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"testing"
	"time"

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

// A role naming a LoTE type that is not loaded matches nothing; it must not
// fall back to unscoped trust.
func TestRoleScope_UnloadedTypeMatchesNothing(t *testing.T) {
	reg, leaf := roleScopedRegistry(t, Config{})
	resp, err := reg.Evaluate(context.Background(), roleRequest(leaf, etsi119602.LoTETypeWRPACProviders))
	require.NoError(t, err)
	assert.False(t, resp.Decision)
}

// The same identifier under two LoTE types keeps separate keys: a key listed
// only for one type does not satisfy the other.
func TestRoleScope_SameIdentifierKeysStaySeparate(t *testing.T) {
	walletCA, _ := generateTestCA(t)
	pidCA, _ := generateTestCA(t)
	wallets := minimalLoTE("NL", x509Entity("urn:provider:nl", walletCA))
	wallets.ListAndSchemeInformation.LoTEType = etsi119602.LoTETypeWalletProviders
	pid := minimalLoTE("NL", x509Entity("urn:provider:nl", pidCA))
	pid.ListAndSchemeInformation.LoTEType = etsi119602.LoTETypePIDProviders
	dir := t.TempDir()
	reg, err := New(Config{Sources: []string{writeLoTE(t, dir, "w.json", wallets), writeLoTE(t, dir, "p.json", pid)}})
	require.NoError(t, err)

	ask := func(ca *x509.Certificate, role string) bool {
		resp, err := reg.Evaluate(context.Background(), &authzen.EvaluationRequest{
			Subject:  authzen.Subject{Type: "key", ID: "urn:provider:nl"},
			Resource: authzen.Resource{Type: "x5c", ID: "urn:provider:nl", Key: []interface{}{base64.StdEncoding.EncodeToString(ca.Raw)}},
			Action:   &authzen.Action{Name: role},
		})
		require.NoError(t, err)
		return resp.Decision
	}
	assert.True(t, ask(walletCA, etsi119602.LoTETypeWalletProviders))
	assert.True(t, ask(pidCA, etsi119602.LoTETypePIDProviders))
	assert.False(t, ask(pidCA, etsi119602.LoTETypeWalletProviders), "a PID key must not pass as a wallet provider")
	assert.False(t, ask(walletCA, etsi119602.LoTETypePIDProviders), "a wallet key must not pass as a PID provider")
}

// A list loaded before its NextUpdate stops being trusted once the deadline
// passes, without waiting for a refresh.
func TestFreshness_ListLapsesAfterLoad(t *testing.T) {
	now := time.Date(2026, 12, 1, 0, 0, 0, 0, time.UTC)
	caCert, _ := generateTestCA(t)
	l := minimalLoTE("SE", x509Entity("urn:e", caCert))
	l.ListAndSchemeInformation.NextUpdate = "2026-12-02T00:00:00Z"
	path := writeLoTE(t, t.TempDir(), "l.json", l)

	reg, err := New(Config{Sources: []string{path}, Now: func() time.Time { return now }})
	require.NoError(t, err)
	req := &authzen.EvaluationRequest{
		Subject:  authzen.Subject{Type: "key", ID: "urn:e"},
		Resource: authzen.Resource{ID: "urn:e"},
	}
	resp, err := reg.Evaluate(context.Background(), req)
	require.NoError(t, err)
	assert.True(t, resp.Decision)

	now = now.Add(48 * time.Hour)
	resp, err = reg.Evaluate(context.Background(), req)
	require.NoError(t, err)
	assert.False(t, resp.Decision, "lapsed list must not keep granting")

	regStale, err := New(Config{Sources: []string{path}, AllowStale: true, Now: func() time.Time { return now }})
	require.NoError(t, err)
	resp, err = regStale.Evaluate(context.Background(), req)
	require.NoError(t, err)
	assert.True(t, resp.Decision)
}

func TestFreshness_LoTLLapseInvalidatesResolvedLists(t *testing.T) {
	now := time.Date(2026, 12, 1, 0, 0, 0, 0, time.UTC)
	dir := t.TempDir()
	l := minimalLoTE("SE", simpleEntity("urn:e"))
	l.ListAndSchemeInformation.LoTEType = etsi119602.LoTETypePIDProviders
	lotePath := writeLoTE(t, dir, "l.json", l)
	lotl := &etsi119602.ListOfTrustedLists{
		ListAndSchemeInformation: etsi119602.ListAndSchemeInformation{
			LoTEVersionIdentifier: 1,
			LoTEType:              etsi119602.LoTLTypeEU,
			SchemeOperatorName:    etsi119602.NameSet{{Lang: "en", Value: "Op"}},
			ListIssueDateTime:     "2026-01-01T00:00:00Z",
			NextUpdate:            "2026-12-02T00:00:00Z",
			PointersToOtherLoTE:   []etsi119602.OtherLoTEPointer{{LoTELocation: lotePath}},
		},
	}
	lotlPath := writeLoTL(t, dir, "lotl.json", lotl)

	reg, err := New(Config{LoTLSources: []string{lotlPath}, Now: func() time.Time { return now }})
	require.NoError(t, err)
	req := &authzen.EvaluationRequest{Subject: authzen.Subject{Type: "key", ID: "urn:e"}, Resource: authzen.Resource{ID: "urn:e"}}
	resp, _ := reg.Evaluate(context.Background(), req)
	require.True(t, resp.Decision)

	now = now.Add(48 * time.Hour)
	resp, _ = reg.Evaluate(context.Background(), req)
	assert.False(t, resp.Decision)
}

// A lapsed LoTL takes only the lists it alone vouches for: a directly
// configured source, and lists reached through another current LoTL, stay.
func TestFreshness_LoTLLapseSparesIndependentTrust(t *testing.T) {
	now := time.Date(2026, 12, 1, 0, 0, 0, 0, time.UTC)
	dir := t.TempDir()
	mk := func(name, id, next string) string {
		l := minimalLoTE("SE", simpleEntity(id))
		l.ListAndSchemeInformation.LoTEType = etsi119602.LoTETypePIDProviders
		l.ListAndSchemeInformation.NextUpdate = next
		return writeLoTE(t, dir, name, l)
	}
	mkLoTL := func(name, next string, pointers ...string) string {
		var ptrs []etsi119602.OtherLoTEPointer
		for _, p := range pointers {
			ptrs = append(ptrs, etsi119602.OtherLoTEPointer{LoTELocation: p})
		}
		return writeLoTL(t, dir, name, &etsi119602.ListOfTrustedLists{
			ListAndSchemeInformation: etsi119602.ListAndSchemeInformation{
				LoTEVersionIdentifier: 1, LoTEType: etsi119602.LoTLTypeEU,
				SchemeOperatorName: etsi119602.NameSet{{Lang: "en", Value: "Op"}},
				ListIssueDateTime:  "2026-01-01T00:00:00Z", NextUpdate: next, PointersToOtherLoTE: ptrs,
			},
		})
	}
	direct := mk("direct.json", "urn:direct", "2099-01-01T00:00:00Z")
	viaShort := mk("short.json", "urn:short-only", "2099-01-01T00:00:00Z")
	viaBoth := mk("both.json", "urn:both", "2099-01-01T00:00:00Z")
	shortLoTL := mkLoTL("short-lotl.json", "2026-12-02T00:00:00Z", viaShort, viaBoth)
	longLoTL := mkLoTL("long-lotl.json", "2099-01-01T00:00:00Z", viaBoth)

	reg, err := New(Config{Sources: []string{direct}, LoTLSources: []string{shortLoTL, longLoTL}, Now: func() time.Time { return now }})
	require.NoError(t, err)
	granted := func(id string) bool {
		resp, err := reg.Evaluate(context.Background(), &authzen.EvaluationRequest{
			Subject: authzen.Subject{Type: "key", ID: id}, Resource: authzen.Resource{ID: id},
		})
		require.NoError(t, err)
		return resp.Decision
	}
	require.True(t, granted("urn:short-only"))

	now = now.Add(48 * time.Hour)
	assert.True(t, granted("urn:direct"), "a directly configured source does not depend on the LoTL")
	assert.False(t, granted("urn:short-only"), "only the lapsed LoTL vouched for it")
	assert.True(t, granted("urn:both"), "still reachable through the current LoTL")
}

// require_role must also cover a subject that is listed directly (#253): a
// missing or unmapped action is denied, not accepted against every list type.
func TestRoleScope_RequireRoleDirectEntity(t *testing.T) {
	cfg := Config{
		RequireRole:     true,
		RoleSchemeTypes: map[string][]string{"credential-issuer": {etsi119602.LoTETypePIDProviders}},
	}
	reg, _ := roleScopedRegistry(t, cfg)
	ask := func(role string) bool {
		req := &authzen.EvaluationRequest{
			Subject:  authzen.Subject{Type: "key", ID: "urn:pid-provider:no"},
			Resource: authzen.Resource{ID: "urn:pid-provider:no"},
		}
		if role != "" {
			req.Action = &authzen.Action{Name: role}
		}
		resp, err := reg.Evaluate(context.Background(), req)
		require.NoError(t, err)
		return resp.Decision
	}
	assert.True(t, ask("credential-issuer"), "mapped role of the listing type")
	assert.True(t, ask(etsi119602.LoTETypePIDProviders), "LoTE type URI as role")
	assert.False(t, ask(""), "no action")
	assert.False(t, ask("something-else"), "unmapped action")

	open, _ := roleScopedRegistry(t, Config{})
	resp, err := open.Evaluate(context.Background(), &authzen.EvaluationRequest{
		Subject:  authzen.Subject{Type: "key", ID: "urn:pid-provider:no"},
		Resource: authzen.Resource{ID: "urn:pid-provider:no"},
	})
	require.NoError(t, err)
	assert.True(t, resp.Decision, "without require_role a role-less request stays unscoped")
}

func TestDisplayName_FromListedEntity(t *testing.T) {
	caCert, caKey := generateTestCA(t)
	leaf := base64.StdEncoding.EncodeToString(generateLeafCert(t, caCert, caKey).Raw)

	named := x509Entity("urn:named", caCert)
	named.TrustedEntityInformation.TEName = etsi119602.NameSet{{Lang: "sv", Value: "Acme Bank AB"}, {Lang: "en", Value: "Acme Bank Ltd"}}
	trade := simpleEntity("urn:trade")
	trade.TrustedEntityInformation.TEName = etsi119602.NameSet{{Lang: "en", Value: "Legal Name"}}
	trade.TrustedEntityInformation.TETradeName = etsi119602.NameSet{{Lang: "sv", Value: "Handelsnamn"}}
	plain := simpleEntity("urn:plain")

	l := minimalLoTE("SE", named, trade, plain)
	l.ListAndSchemeInformation.LoTEType = etsi119602.LoTETypePIDProviders
	reg, err := New(Config{Sources: []string{writeLoTE(t, t.TempDir(), "l.json", l)}})
	require.NoError(t, err)

	ask := func(id string, chain bool) *authzen.EvaluationResponse {
		req := &authzen.EvaluationRequest{Subject: authzen.Subject{Type: "key", ID: id}, Resource: authzen.Resource{ID: id}}
		if chain {
			req.Resource = authzen.Resource{Type: "x5c", ID: id, Key: []interface{}{leaf}}
		}
		resp, err := reg.Evaluate(context.Background(), req)
		require.NoError(t, err)
		return resp
	}

	// direct match by identifier (resolution-only), English preferred
	r := ask("urn:named", false)
	require.True(t, r.Decision)
	assert.Equal(t, "Acme Bank Ltd", r.Context.DisplayName)
	assert.Equal(t, "Handelsnamn", ask("urn:trade", false).Context.DisplayName, "trade name preferred, first entry when no English")
	assert.Empty(t, ask("urn:plain", false).Context.DisplayName, "entity without a name: member absent")

	// CA-anchored chain for an unlisted subject: the CA's name must not label
	// the verifier; the manager falls back to the subject's origin.
	r = ask("https://some-rp.example", true)
	require.True(t, r.Decision, "%v", r.Context)
	assert.Empty(t, r.Context.DisplayName)
}
