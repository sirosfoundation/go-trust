package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/sirosfoundation/go-trust/pkg/authzen"
)

func postBatch(t *testing.T, body string, mutate func(*ServerContext)) (*httptest.ResponseRecorder, authzen.BatchEvaluationResponse) {
	t.Helper()
	r, serverCtx := setupTestServer()
	if mutate != nil {
		mutate(serverCtx)
	}
	req, _ := http.NewRequest("POST", "/evaluations", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	var out authzen.BatchEvaluationResponse
	if w.Code == 200 {
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &out))
	}
	return w, out
}

const batchSubject = `{"type":"key","id":"did:example:alice"}`

func batchResource(cert string) string {
	return `{"type":"x5c","id":"did:example:alice","key":["` + cert + `"]}`
}

func TestBatch_OrderedResultsWithDefaultsAndOverrides(t *testing.T) {
	// The shared subject/resource make items 0 and 2 trusted; item 1 overrides
	// the resource with a certificate that is not valid, so only it is denied.
	body := `{
	  "subject": ` + batchSubject + `,
	  "resource": ` + batchResource(testCertBase64) + `,
	  "action": {"name": "http://ec.europa.eu/NS/wallet-provider"},
	  "evaluations": [
	    {},
	    {"resource": ` + batchResource("AAAA") + `},
	    {"action": {"name": "other-role"}}
	  ]}`
	w, out := postBatch(t, body, nil)
	require.Equal(t, 200, w.Code, w.Body.String())
	require.Len(t, out.Evaluations, 3)
	assert.True(t, out.Evaluations[0].Decision)
	assert.False(t, out.Evaluations[1].Decision)
	assert.True(t, out.Evaluations[2].Decision)

	ids := map[string]bool{}
	for i, e := range out.Evaluations {
		require.NotNil(t, e.Context, "item %d", i)
		assert.NotEmpty(t, e.Context.ID, "item %d carries a decision id", i)
		ids[e.Context.ID] = true
	}
	assert.Len(t, ids, 3, "decision ids are unique per item")
}

func TestBatch_InvalidItemDoesNotFailBatch(t *testing.T) {
	body := `{
	  "evaluations": [
	    {"subject": {"type":"bogus","id":"x"}, "resource": ` + batchResource(testCertBase64) + `},
	    {"subject": ` + batchSubject + `, "resource": ` + batchResource(testCertBase64) + `}
	  ]}`
	w, out := postBatch(t, body, nil)
	require.Equal(t, 200, w.Code, w.Body.String())
	require.Len(t, out.Evaluations, 2)
	assert.False(t, out.Evaluations[0].Decision)
	require.NotNil(t, out.Evaluations[0].Context)
	assert.Contains(t, out.Evaluations[0].Context.Reason["error"], "invalid request")
	assert.True(t, out.Evaluations[1].Decision)
}

func TestBatch_ItemLimit(t *testing.T) {
	item := `{"subject": ` + batchSubject + `, "resource": ` + batchResource(testCertBase64) + `}`
	body := `{"evaluations": [` + item + `,` + item + `,` + item + `]}`

	w, _ := postBatch(t, body, func(s *ServerContext) { s.MaxBatchEvaluations = 2 })
	assert.Equal(t, 400, w.Code)
	assert.Contains(t, w.Body.String(), "too many evaluations")

	w, out := postBatch(t, body, func(s *ServerContext) { s.MaxBatchEvaluations = 3 })
	assert.Equal(t, 200, w.Code)
	assert.Len(t, out.Evaluations, 3)

	// Unset means the default limit.
	items := strings.Repeat(item+",", DefaultMaxBatchEvaluations) + item
	w, _ = postBatch(t, `{"evaluations": [`+items+`]}`, nil)
	assert.Equal(t, 400, w.Code)
}

func TestBatch_BadRequests(t *testing.T) {
	for name, body := range map[string]string{
		"not json":         `{`,
		"no evaluations":   `{"subject": ` + batchSubject + `}`,
		"empty array":      `{"evaluations": []}`,
		"unknown semantic": `{"evaluations": [{}], "options": {"evaluations_semantic": "bogus"}}`,
	} {
		t.Run(name, func(t *testing.T) {
			w, _ := postBatch(t, body, nil)
			assert.Equal(t, 400, w.Code, w.Body.String())
		})
	}
}

func TestBatch_Semantics(t *testing.T) {
	good := `{"subject": ` + batchSubject + `, "resource": ` + batchResource(testCertBase64) + `}`
	bad := `{"subject": ` + batchSubject + `, "resource": ` + batchResource("AAAA") + `}`
	opts := func(s string) string { return `"options": {"evaluations_semantic": "` + s + `"}` }

	_, out := postBatch(t, `{"evaluations": [`+good+`,`+bad+`,`+good+`], `+opts("deny_on_first_deny")+`}`, nil)
	require.Len(t, out.Evaluations, 2, "stops after the first deny")
	assert.True(t, out.Evaluations[0].Decision)
	assert.False(t, out.Evaluations[1].Decision)

	_, out = postBatch(t, `{"evaluations": [`+bad+`,`+good+`,`+bad+`], `+opts("permit_on_first_permit")+`}`, nil)
	require.Len(t, out.Evaluations, 2, "stops after the first permit")
	assert.False(t, out.Evaluations[0].Decision)
	assert.True(t, out.Evaluations[1].Decision)

	_, out = postBatch(t, `{"evaluations": [`+good+`,`+bad+`,`+good+`], `+opts("execute_all")+`}`, nil)
	assert.Len(t, out.Evaluations, 3)
}

func TestBatch_BodyTooLarge(t *testing.T) {
	huge := `{"evaluations": [{"context": {"x": "` + strings.Repeat("a", maxBatchBodyBytes) + `"}}]}`
	w, _ := postBatch(t, huge, nil)
	assert.Equal(t, http.StatusRequestEntityTooLarge, w.Code)
}

func TestBatch_NilRegistryManager(t *testing.T) {
	w, _ := postBatch(t, `{"evaluations": [{}]}`, func(s *ServerContext) { s.RegistryManager = nil })
	assert.Equal(t, 500, w.Code)
}

func TestBatchItem_ContextIsolatedAndOverridden(t *testing.T) {
	req := authzen.BatchEvaluationRequest{
		Context: map[string]interface{}{"a": 1},
		Evaluations: []authzen.BatchEvaluationItem{
			{},
			{Context: map[string]interface{}{"b": 2}},
		},
	}
	first := req.Item(0)
	first.Context["injected"] = true
	assert.NotContains(t, req.Context, "injected", "the shared default is never written through an item")
	assert.NotContains(t, req.Item(0).Context, "injected")
	assert.Equal(t, map[string]interface{}{"b": 2}, req.Item(1).Context, "an item context replaces the default")
}

func TestWellKnown_AdvertisesEvaluationsEndpoint(t *testing.T) {
	r, _ := setupTestServer()
	req, _ := http.NewRequest("GET", "/.well-known/authzen-configuration", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	var md authzen.PDPMetadata
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &md))
	assert.Equal(t, "http://localhost:6001/evaluations", md.AccessEvaluationsEndpoint)
	assert.Equal(t, "http://localhost:6001/evaluation", md.AccessEvaluationEndpoint)
}
