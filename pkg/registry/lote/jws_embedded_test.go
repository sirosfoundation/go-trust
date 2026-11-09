package lote

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The signed bytes are produced by the publisher's Python tooling
// (json.dumps(doc, sort_keys=True, separators=(",", ":")) with the default
// ensure_ascii), so the canonical form must match it byte for byte. The
// expected string below was produced by that call.
func TestParseEmbeddedJWS_CanonicalForm(t *testing.T) {
	raw := []byte(`{
		"é": {},
		"signature": {"protected": "aGVhZGVy", "signature": "c2ln"},
		"b": [1, -2, true, null],
		"a": "é😀` + "\x7f" + `/ \"\\\n\u0001"
	}`)
	emb, err := parseEmbeddedJWS(raw)
	require.NoError(t, err)
	require.NotNil(t, emb)
	assert.Equal(t, "aGVhZGVy", emb.protected)
	assert.Equal(t, "c2ln", emb.signature)
	assert.Equal(t, `{"a":"\u00e9\ud83d\ude00\u007f/\u2028\"\\\n\u0001","b":[1,-2,true,null],"\u00e9":{}}`, string(emb.payload))
}

func TestParseEmbeddedJWS_NotThisSerialisation(t *testing.T) {
	for name, raw := range map[string]string{
		"no signature member":   `{"LoTE":{}}`,
		"string signature":      `{"LoTE":{},"signature":"abc"}`,
		"not an object":         `[1,2]`,
		"compact-looking token": `aaa.bbb.ccc`,
	} {
		t.Run(name, func(t *testing.T) {
			emb, err := parseEmbeddedJWS([]byte(raw))
			require.NoError(t, err)
			assert.Nil(t, emb)
		})
	}
}

// Documents the canonical form cannot reproduce are refused, never guessed at.
func TestParseEmbeddedJWS_Refuses(t *testing.T) {
	sig := `"signature":{"protected":"aGVhZGVy","signature":"c2ln"}`
	for name, raw := range map[string]string{
		"fraction":              `{"LoTE":{"n":1.5},` + sig + `}`,
		"exponent":              `{"LoTE":{"n":1e3},` + sig + `}`,
		"negative zero":         `{"LoTE":{"n":-0},` + sig + `}`,
		"empty protected":       `{"LoTE":{},"signature":{"protected":"","signature":"c2ln"}}`,
		"flattened plus object": `{"payload":"e30","LoTE":{},` + sig + `}`,
	} {
		t.Run(name, func(t *testing.T) {
			emb, err := parseEmbeddedJWS([]byte(raw))
			require.Error(t, err)
			assert.Nil(t, emb)
		})
	}
}
