package authzen

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func batchReq(t *testing.T, doc string) *BatchEvaluationRequest {
	t.Helper()
	var r BatchEvaluationRequest
	require.NoError(t, json.Unmarshal([]byte(doc), &r))
	return &r
}

func TestBatchSemantic(t *testing.T) {
	for in, want := range map[string]string{
		"":                       EvaluationsSemanticExecuteAll,
		"execute_all":            EvaluationsSemanticExecuteAll,
		"deny_on_first_deny":     EvaluationsSemanticDenyOnFirstDeny,
		"permit_on_first_permit": EvaluationsSemanticPermitOnFirstPermit,
	} {
		r := &BatchEvaluationRequest{Options: &BatchOptions{EvaluationsSemantic: in}}
		got, err := r.Semantic()
		require.NoError(t, err, in)
		assert.Equal(t, want, got)
	}

	got, err := (&BatchEvaluationRequest{}).Semantic()
	require.NoError(t, err)
	assert.Equal(t, EvaluationsSemanticExecuteAll, got, "no options means the default")

	_, err = (&BatchEvaluationRequest{Options: &BatchOptions{EvaluationsSemantic: "bogus"}}).Semantic()
	assert.Error(t, err)
}

func TestBatchItem_Merge(t *testing.T) {
	r := batchReq(t, `{
	  "subject": {"type":"key","id":"s"},
	  "resource": {"type":"x5c","id":"s","key":["k"]},
	  "action": {"name":"default-role"},
	  "context": {"a": 1},
	  "evaluations": [
	    {},
	    {"subject": {"type":"key","id":"other"}, "action": {"name":"item-role"}, "context": {"b": 2}}
	  ]}`)

	inherit, err := r.Item(0)
	require.NoError(t, err)
	assert.Equal(t, "s", inherit.Subject.ID)
	assert.Equal(t, "default-role", inherit.Action.Name)
	assert.Equal(t, map[string]interface{}{"a": float64(1)}, inherit.Context)

	over, err := r.Item(1)
	require.NoError(t, err)
	assert.Equal(t, "other", over.Subject.ID)
	assert.Equal(t, "s", over.Resource.ID, "members the item omits are inherited")
	assert.Equal(t, "item-role", over.Action.Name)
	assert.Equal(t, map[string]interface{}{"b": float64(2)}, over.Context, "an item context replaces the default")

	// Writes through an item never reach the shared defaults or other items.
	inherit.Context["injected"] = true
	inherit.Action.Name = "changed"
	assert.NotContains(t, r.Context, "injected")
	assert.Equal(t, "default-role", r.Action.Name)
	again, err := r.Item(0)
	require.NoError(t, err)
	assert.NotContains(t, again.Context, "injected")
}

func TestBatchItem_RejectsMalformedEntries(t *testing.T) {
	r := batchReq(t, `{
	  "subject": {"type":"key","id":"s"},
	  "evaluations": [null, 7, "x", [], {"subject":{"id":123}},
	    {"subject":null}, {"resource":null}, {"action":null}, {"context":null}, {"unknown":null}]}`)
	for i := range r.Evaluations {
		_, err := r.Item(i)
		assert.Error(t, err, "entry %d", i)
	}
}
