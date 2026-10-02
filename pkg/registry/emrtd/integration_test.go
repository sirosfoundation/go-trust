package emrtd

import (
	"context"
	"testing"

	"github.com/sirosfoundation/go-trust/pkg/authzen"
	"github.com/sirosfoundation/go-trust/pkg/authzenclient"
	"github.com/sirosfoundation/go-trust/pkg/testserver"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestHTTPEvaluation drives the registry through the real AuthZEN HTTP
// handler, the way the PEP (facetec-api) does, including JSON (de)coding of
// the request context and the machine-readable response reason.
func TestHTTPEvaluation(t *testing.T) {
	csca := newCSCA(t, kindBrainpool256, "CSCA DE", "DE")
	s := dscSpec("DSC", "DE")
	s.notBefore, s.notAfter = t2010, t2012
	dsc := issue(t, s, newKey(t, kindBrainpool256), csca)
	r := newReg(t, map[string][]*node{"DEU": {csca}})

	srv := testserver.New(testserver.WithRegistry(r))
	defer srv.Close()
	client := authzenclient.New(srv.URL())

	call := func(t *testing.T, country string, ctx map[string]interface{}, chain ...*node) *authzen.EvaluationResponse {
		t.Helper()
		rq := req(country, chain, ctx)
		resp, err := client.Evaluate(context.Background(), rq)
		require.NoError(t, err)
		return resp
	}

	t.Run("allow with signing_time, reason carries the anchor", func(t *testing.T) {
		resp := call(t, "DEU", map[string]interface{}{"signing_time": "2011-06-01T00:00:00Z"}, dsc)
		require.True(t, resp.Decision, "%v", resp.Context)
		admin := resp.Context.Reason["admin"].(map[string]interface{})
		assert.Equal(t, fingerprint(csca.cert), admin["csca_sha256"])
		assert.Equal(t, fingerprint(dsc.cert), admin["dsc_sha256"])
		assert.NotEmpty(t, admin["csca_subject"])
	})
	t.Run("expired when signing_time omitted", func(t *testing.T) {
		resp := call(t, "DEU", nil, dsc)
		require.False(t, resp.Decision)
		assert.Equal(t, CodeExpired, resp.Context.Reason["code"])
	})
	t.Run("malformed signing_time", func(t *testing.T) {
		resp := call(t, "DEU", map[string]interface{}{"signing_time": "soon"}, dsc)
		require.False(t, resp.Decision)
		assert.Equal(t, CodeMalformedRequest, resp.Context.Reason["code"])
	})
	t.Run("unknown country", func(t *testing.T) {
		resp := call(t, "FRA", map[string]interface{}{"signing_time": "2011-06-01T00:00:00Z"}, dsc)
		require.False(t, resp.Decision)
		assert.Equal(t, CodeUnknownCountry, resp.Context.Reason["code"])
	})
}
