package static

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"math/big"
	"net/url"
	"testing"
	"time"

	"github.com/sirosfoundation/go-trust/pkg/authzen"
	"github.com/sirosfoundation/go-trust/pkg/registry"
	"github.com/sirosfoundation/go-trust/pkg/registry/rpcert"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// vidLeaf is a leaf certificate (optionally issued by a test CA) for the
// verifier-identifier tests. orgID + the legal-person policy make it carry an
// ETSI semantic identifier.
type vidLeaf struct {
	leaf   *x509.Certificate
	ca     *x509.Certificate
	b64    string
	caB64  string
	pubKey *ecdsa.PublicKey
}

func newVIDLeaf(t *testing.T, dns []string, uris []string, orgID string) vidLeaf {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	caTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "VID Test CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		KeyUsage: x509.KeyUsageCertSign, BasicConstraintsValid: true, IsCA: true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	require.NoError(t, err)
	ca, err := x509.ParseCertificate(caDER)
	require.NoError(t, err)

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	subject := pkix.Name{CommonName: "rp", Organization: []string{"Test AB"}, Country: []string{"SE"}}
	if orgID != "" {
		subject.ExtraNames = []pkix.AttributeTypeAndValue{{Type: asn1.ObjectIdentifier{2, 5, 4, 97}, Value: orgID}}
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: subject, DNSNames: dns,
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	for _, u := range uris {
		p, err := url.Parse(u)
		require.NoError(t, err)
		tmpl.URIs = append(tmpl.URIs, p)
	}
	if orgID != "" {
		oid, err := x509.ParseOID(rpcert.OIDNCPLegalPerson)
		require.NoError(t, err)
		tmpl.Policies = []x509.OID{oid}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &key.PublicKey, caKey)
	require.NoError(t, err)
	leaf, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return vidLeaf{leaf: leaf, ca: ca, b64: base64.StdEncoding.EncodeToString(leaf.Raw),
		caB64: base64.StdEncoding.EncodeToString(ca.Raw), pubKey: &key.PublicKey}
}

// vidRequest builds a request as RegistryManager.Evaluate would hand it to a
// registry: Subject.ID rewritten to https://host, the client's claim stashed.
func vidRequest(clientID string, action string, types []string, chain ...string) *authzen.EvaluationRequest {
	keys := make([]interface{}, len(chain))
	for i, c := range chain {
		keys[i] = c
	}
	norm := registry.NormalizeSubjectID(clientID)
	req := &authzen.EvaluationRequest{
		Subject:  authzen.Subject{Type: "key", ID: norm},
		Resource: authzen.Resource{Type: "x5c", ID: norm, Key: keys},
		Action:   &authzen.Action{Name: action},
		Context:  map[string]interface{}{},
	}
	registry.StashOriginalSubjectID(req, clientID)
	if types != nil {
		req.Context[authzen.VerifierIDsPolicyContextKey] = types
	}
	return req
}

func idMap(resp *authzen.EvaluationResponse) map[string]authzen.VerifierID {
	m := map[string]authzen.VerifierID{}
	if resp != nil && resp.Context != nil {
		for _, v := range resp.Context.VerifierIDs {
			m[v.Type] = v
		}
	}
	return m
}

// pinnedWhitelist is a whitelist whose entry for host is trusted by key
// fingerprint, the way gdc's verifier is.
func pinnedWhitelist(t *testing.T, host string, key *ecdsa.PublicKey) *WhitelistRegistry {
	t.Helper()
	reg := NewWhitelistRegistry(WithWhitelistConfig(WhitelistConfig{
		Lists:   map[string][]string{"verifiers": {"https://" + host}},
		Actions: map[string]string{"credential-verifier": "verifiers"},
	}))
	fp, err := KeyFingerprint(key)
	require.NoError(t, err)
	reg.keyHashes = map[string]map[string]bool{normalizeEntityID("https://" + host): {fp: true}}
	return reg
}

func TestWhitelist_PinnedKey_VerifierIDs(t *testing.T) {
	both := []string{"x509_san_dns", "x509_san_uri", "semantic"}
	rp := newVIDLeaf(t, []string{"verifier.example.com"}, []string{"https://verifier.example.com/rp"}, "VATSE-556000000101")
	wild := newVIDLeaf(t, []string{"*.example.com"}, nil, "")
	reg := pinnedWhitelist(t, "verifier.example.com", rp.pubKey)
	wildReg := pinnedWhitelist(t, "host.example.com", wild.pubKey)

	run := func(t *testing.T, r *WhitelistRegistry, req *authzen.EvaluationRequest) *authzen.EvaluationResponse {
		t.Helper()
		resp, err := r.Evaluate(context.Background(), req)
		require.NoError(t, err)
		return resp
	}

	t.Run("dns emitted, canonical, client-id-binding; semantic withheld (certificate not authenticated)", func(t *testing.T) {
		resp := run(t, reg, vidRequest("x509_san_dns:verifier.example.com", "credential-verifier", both, rp.b64))
		require.True(t, resp.Decision)
		got := idMap(resp)
		assert.Equal(t, authzen.VerifierID{Type: "x509_san_dns", ID: "verifier.example.com", Basis: "client-id-binding"}, got["x509_san_dns"])
		assert.NotContains(t, got, "semantic", "the pinned-key path does not authenticate certificate content")
		assert.NotContains(t, got, "x509_san_uri")
	})
	t.Run("policy off: nothing", func(t *testing.T) {
		resp := run(t, reg, vidRequest("x509_san_dns:verifier.example.com", "credential-verifier", nil, rp.b64))
		require.True(t, resp.Decision)
		assert.Empty(t, resp.Context.VerifierIDs)
	})
	t.Run("policy enables another type only: nothing", func(t *testing.T) {
		resp := run(t, reg, vidRequest("x509_san_dns:verifier.example.com", "credential-verifier", []string{"x509_san_uri"}, rp.b64))
		require.True(t, resp.Decision)
		assert.Empty(t, resp.Context.VerifierIDs)
	})
	t.Run("hint narrows to the other type: nothing", func(t *testing.T) {
		req := vidRequest("x509_san_dns:verifier.example.com", "credential-verifier", both, rp.b64)
		req.Context[authzen.VerifierIDHintContextKey] = "x509_san_uri"
		resp := run(t, reg, req)
		require.True(t, resp.Decision)
		assert.Empty(t, resp.Context.VerifierIDs)
	})
	t.Run("certificate does not carry the client_id as a SAN: decision true, no id", func(t *testing.T) {
		other := newVIDLeaf(t, []string{"someone-else.example.com"}, nil, "")
		r := pinnedWhitelist(t, "verifier.example.com", other.pubKey)
		resp := run(t, r, vidRequest("x509_san_dns:verifier.example.com", "credential-verifier", both, other.b64))
		require.True(t, resp.Decision)
		assert.Empty(t, resp.Context.VerifierIDs)
	})
	t.Run("wildcard SAN: no id", func(t *testing.T) {
		resp := run(t, wildReg, vidRequest("x509_san_dns:host.example.com", "credential-verifier", both, wild.b64))
		require.True(t, resp.Decision)
		assert.Empty(t, resp.Context.VerifierIDs)
	})
	t.Run("brokered request: no id", func(t *testing.T) {
		req := vidRequest("x509_san_dns:verifier.example.com", "credential-verifier", both, rp.b64)
		req.Context["intermediary_x5c"] = []string{"MIIB"}
		resp := run(t, reg, req)
		require.True(t, resp.Decision)
		assert.Empty(t, resp.Context.VerifierIDs)
	})
	t.Run("https client_id carries no SAN claim: no id", func(t *testing.T) {
		resp := run(t, reg, vidRequest("https://verifier.example.com", "credential-verifier", both, rp.b64))
		require.True(t, resp.Decision)
		assert.Empty(t, resp.Context.VerifierIDs)
	})
	t.Run("key not pinned: deny, no id", func(t *testing.T) {
		other := newVIDLeaf(t, []string{"verifier.example.com"}, nil, "")
		resp := run(t, reg, vidRequest("x509_san_dns:verifier.example.com", "credential-verifier", both, other.b64))
		require.False(t, resp.Decision)
		assert.Empty(t, idMap(resp))
	})
	t.Run("resolution only (no key): decision true, no id", func(t *testing.T) {
		req := vidRequest("x509_san_dns:verifier.example.com", "credential-verifier", both)
		req.Resource = authzen.Resource{}
		resp := run(t, reg, req)
		require.True(t, resp.Decision)
		assert.Empty(t, idMap(resp))
	})
	t.Run("uri scheme: uri id emitted byte-for-byte", func(t *testing.T) {
		r := NewWhitelistRegistry(WithWhitelistConfig(WhitelistConfig{
			Lists:   map[string][]string{"verifiers": {"https://verifier.example.com/rp"}},
			Actions: map[string]string{"credential-verifier": "verifiers"},
		}))
		fp, err := KeyFingerprint(rp.pubKey)
		require.NoError(t, err)
		r.keyHashes = map[string]map[string]bool{normalizeEntityID("https://verifier.example.com/rp"): {fp: true}}
		req := vidRequest("x509_san_uri:https://verifier.example.com/rp", "credential-verifier", both, rp.b64)
		// Subject.ID for a URI client_id is whatever the manager normalised it to;
		// the whitelist entry is matched against that.
		resp := run(t, r, req)
		require.True(t, resp.Decision, "%+v", resp.Context)
		assert.Equal(t, authzen.VerifierID{Type: "x509_san_uri", ID: "https://verifier.example.com/rp", Basis: "client-id-binding"}, idMap(resp)["x509_san_uri"])
	})
}

func TestWhitelist_SystemCA_VerifierIDs(t *testing.T) {
	both := []string{"x509_san_dns", "semantic"}
	rp := newVIDLeaf(t, []string{"verifier.example.com"}, nil, "VATSE-556000000101")

	newReg := func(entry string) *WhitelistRegistry {
		reg := NewWhitelistRegistry(WithWhitelistConfig(WhitelistConfig{
			Lists:                map[string][]string{"verifiers": {entry}},
			Actions:              map[string]string{"credential-verifier": "verifiers"},
			TrustX509ViaSystemCA: true,
		}))
		pool := x509.NewCertPool()
		pool.AddCert(rp.ca)
		reg.systemCertPoolOnce.Do(func() {})
		reg.systemCertPool = pool
		return reg
	}

	t.Run("chain validated: dns and semantic", func(t *testing.T) {
		resp, err := newReg("https://verifier.example.com").Evaluate(context.Background(),
			vidRequest("x509_san_dns:verifier.example.com", "credential-verifier", both, rp.b64))
		require.NoError(t, err)
		require.True(t, resp.Decision, "%+v", resp.Context)
		got := idMap(resp)
		assert.Equal(t, "verifier.example.com", got["x509_san_dns"].ID)
		assert.Equal(t, "client-id-binding", got["x509_san_dns"].Basis)
		assert.Equal(t, "semantic_id:VATSE-556000000101", got["semantic"].ID)
		assert.Equal(t, "x5c-chain", got["semantic"].Basis)
	})
	t.Run("policy off: nothing", func(t *testing.T) {
		resp, err := newReg("https://verifier.example.com").Evaluate(context.Background(),
			vidRequest("x509_san_dns:verifier.example.com", "credential-verifier", nil, rp.b64))
		require.NoError(t, err)
		require.True(t, resp.Decision)
		assert.Empty(t, resp.Context.VerifierIDs)
	})
	t.Run("brokered: semantic kept (end RP's leaf), dns omitted", func(t *testing.T) {
		req := vidRequest("x509_san_dns:verifier.example.com", "credential-verifier", both, rp.b64)
		req.Context["intermediary_x5c"] = []string{"MIIB"}
		resp, err := newReg("https://verifier.example.com").Evaluate(context.Background(), req)
		require.NoError(t, err)
		require.True(t, resp.Decision)
		got := idMap(resp)
		assert.NotContains(t, got, "x509_san_dns")
		assert.Contains(t, got, "semantic")
	})
	t.Run("chain not trusted: deny, no id", func(t *testing.T) {
		reg := newReg("https://verifier.example.com")
		reg.systemCertPool = x509.NewCertPool()
		resp, err := reg.Evaluate(context.Background(),
			vidRequest("x509_san_dns:verifier.example.com", "credential-verifier", both, rp.b64))
		require.NoError(t, err)
		require.False(t, resp.Decision)
		assert.Empty(t, idMap(resp))
	})
	t.Run("binding fails: deny, no id", func(t *testing.T) {
		resp, err := newReg("https://other.example.com").Evaluate(context.Background(),
			vidRequest("x509_san_dns:other.example.com", "credential-verifier", both, rp.b64))
		require.NoError(t, err)
		require.False(t, resp.Decision)
		assert.Empty(t, idMap(resp))
	})
	t.Run("x509_hash pinned: no identifier type exists, none emitted", func(t *testing.T) {
		reg := NewWhitelistRegistry(WithWhitelistConfig(WhitelistConfig{
			Lists:                map[string][]string{"verifiers": {"*"}},
			Actions:              map[string]string{"credential-verifier": "verifiers"},
			TrustX509ViaSystemCA: true,
		}))
		digest := sha256Hex(rp.leaf.Raw)
		resp, err := reg.Evaluate(context.Background(),
			vidRequest("x509_hash:"+digest, "credential-verifier", both, rp.b64))
		require.NoError(t, err)
		require.True(t, resp.Decision, "%+v", resp.Context)
		assert.Empty(t, idMap(resp))
	})
}

func TestSystemCertPool_VerifierIDs(t *testing.T) {
	rp := newVIDLeaf(t, []string{"verifier.example.com"}, nil, "VATSE-556000000101")
	newReg := func(trust bool) *SystemCertPoolRegistry {
		reg, err := NewSystemCertPoolRegistry(SystemCertPoolConfig{})
		require.NoError(t, err)
		pool := x509.NewCertPool()
		if trust {
			pool.AddCert(rp.ca)
		}
		reg.certPool = pool
		return reg
	}
	both := []string{"x509_san_dns", "semantic"}

	t.Run("trusted chain bound to client_id", func(t *testing.T) {
		resp, err := newReg(true).Evaluate(context.Background(),
			vidRequest("x509_san_dns:verifier.example.com", "verifier", both, rp.b64))
		require.NoError(t, err)
		require.True(t, resp.Decision, "%+v", resp.Context)
		got := idMap(resp)
		assert.Equal(t, "verifier.example.com", got["x509_san_dns"].ID)
		assert.Equal(t, "semantic_id:VATSE-556000000101", got["semantic"].ID)
	})
	t.Run("this registry does not bind the client_id itself: a mismatching client_id still allows but gets no dns id", func(t *testing.T) {
		resp, err := newReg(true).Evaluate(context.Background(),
			vidRequest("x509_san_dns:impostor.example.com", "verifier", both, rp.b64))
		require.NoError(t, err)
		require.True(t, resp.Decision)
		got := idMap(resp)
		assert.NotContains(t, got, "x509_san_dns", "an unbound client_id is never echoed")
	})
	t.Run("policy off", func(t *testing.T) {
		resp, err := newReg(true).Evaluate(context.Background(),
			vidRequest("x509_san_dns:verifier.example.com", "verifier", nil, rp.b64))
		require.NoError(t, err)
		require.True(t, resp.Decision)
		assert.Empty(t, idMap(resp))
	})
	t.Run("untrusted chain: deny, no id", func(t *testing.T) {
		resp, err := newReg(false).Evaluate(context.Background(),
			vidRequest("x509_san_dns:verifier.example.com", "verifier", both, rp.b64))
		require.NoError(t, err)
		require.False(t, resp.Decision)
		assert.Empty(t, idMap(resp))
	})
}

func sha256Hex(b []byte) string {
	d := sha256.Sum256(b)
	return hex.EncodeToString(d[:])
}
