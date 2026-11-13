package registry

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/sirosfoundation/go-trust/pkg/authzen"
)

func TestOriginDomain(t *testing.T) {
	cases := map[string]string{
		"https://Verifier.Example.COM/path?q=1":  "verifier.example.com",
		"https://verifier.example.com:8443":      "verifier.example.com",
		"http://user:pw@verifier.example.com./x": "verifier.example.com",
		"x509_san_dns:Verifier.Example.com":      "verifier.example.com",
		"x509_san_uri:https://rp.example.org/cb": "rp.example.org",
		"did:web:example.com":                    "example.com",
		"did:web:example.com:user:alice":         "example.com",
		"did:web:example.com%3A8443":             "example.com",
		"https://xn--bcher-kva.example/":         "xn--bcher-kva.example",
		"x509_hash:abcdef":                       "",
		"urn:pid-provider:no":                    "",
		"did:key:z6Mk":                           "",
		"https://192.0.2.1/x":                    "",
		"https://[2001:db8::1]/x":                "",
		"x509_san_dns:bad_host.example":          "",
		"x509_san_dns:":                          "",
		"https://-bad.example":                   "",
		"ftp://example.com":                      "",
		"":                                       "",
	}
	for in, want := range cases {
		assert.Equal(t, want, OriginDomain(in), in)
	}
}

func TestSanitizeDisplayName(t *testing.T) {
	assert.Equal(t, "Acme Bank AB", SanitizeDisplayName("  Acme \t Bank\nAB "))
	assert.Equal(t, "Acme", SanitizeDisplayName("Ac‮me\x00"), "bidi override and control dropped")
	assert.Equal(t, "", SanitizeDisplayName(" ​ \x07"))
	assert.Equal(t, "Åkerblom Ödla", SanitizeDisplayName("Åkerblom Ödla"))
	long := SanitizeDisplayName(strings.Repeat("ä", 500))
	assert.Equal(t, maxDisplayNameLen, len([]rune(long)))
	assert.True(t, len([]rune(SanitizeDisplayName(strings.Repeat("a ", 500)))) <= maxDisplayNameLen)
}

func TestApplyDisplayName(t *testing.T) {
	req := &authzen.EvaluationRequest{Subject: authzen.Subject{ID: "https://Verifier.example.com"}}

	deny := &authzen.EvaluationResponse{Decision: false}
	applyDisplayName(req, deny)
	assert.Nil(t, deny.Context, "denials get no name")

	fallback := &authzen.EvaluationResponse{Decision: true}
	applyDisplayName(req, fallback)
	assert.Equal(t, "verifier.example.com", fallback.Context.DisplayName)

	named := &authzen.EvaluationResponse{Decision: true, Context: &authzen.EvaluationResponseContext{DisplayName: " Acme‮ Bank "}}
	applyDisplayName(req, named)
	assert.Equal(t, "Acme Bank", named.Context.DisplayName, "registry name wins, sanitized")

	longHost := strings.Repeat("a", 63) + "." + strings.Repeat("b", 63) + "." + strings.Repeat("c", 63) + "." + strings.Repeat("d", 20)
	tooLong := &authzen.EvaluationResponse{Decision: true}
	applyDisplayName(&authzen.EvaluationRequest{Subject: authzen.Subject{ID: "https://" + longHost}}, tooLong)
	assert.Nil(t, tooLong.Context, "overlong origin is omitted, not truncated")

	opaque := &authzen.EvaluationResponse{Decision: true}
	applyDisplayName(&authzen.EvaluationRequest{Subject: authzen.Subject{ID: "x509_hash:ab"}}, opaque)
	assert.Nil(t, opaque.Context, "no name and no origin: member absent")
}

func TestMergeDisplayName(t *testing.T) {
	pos := func(name string) *authzen.EvaluationResponse {
		return &authzen.EvaluationResponse{Decision: true, Context: &authzen.EvaluationResponseContext{DisplayName: name}}
	}
	neg := &authzen.EvaluationResponse{Decision: false, Context: &authzen.EvaluationResponseContext{DisplayName: "Denier"}}

	resp := &authzen.EvaluationResponse{Decision: true}
	mergeDisplayName(resp, []*authzen.EvaluationResponse{pos("Zed"), neg, pos("Alpha"), pos("")})
	assert.Equal(t, "Alpha", resp.Context.DisplayName)

	denied := &authzen.EvaluationResponse{Decision: false}
	mergeDisplayName(denied, []*authzen.EvaluationResponse{pos("Alpha")})
	assert.Nil(t, denied.Context)

	none := &authzen.EvaluationResponse{Decision: true}
	mergeDisplayName(none, []*authzen.EvaluationResponse{neg, pos("")})
	assert.Nil(t, none.Context)
}

// Through the manager, under every strategy: a registry's own name survives
// aggregation, and a positive answer without one gets the origin domain.
func TestManagerDisplayName(t *testing.T) {
	for _, strategy := range []ResolutionStrategy{FirstMatch, AllRegistries, BestMatch, Sequential} {
		t.Run(string(strategy), func(t *testing.T) {
			req := func() *authzen.EvaluationRequest {
				return &authzen.EvaluationRequest{
					Subject:  authzen.Subject{Type: "key", ID: "https://Verifier.example.com/"},
					Resource: authzen.Resource{Type: "jwk", ID: "https://Verifier.example.com/", Key: []interface{}{map[string]interface{}{"kty": "EC"}}},
				}
			}
			mk := func(name, display string) *mockRegistry {
				return &mockRegistry{name: name, healthy: true, resourceTypes: []string{"jwk"},
					evaluateResponse: &authzen.EvaluationResponse{Decision: true, Context: &authzen.EvaluationResponseContext{DisplayName: display}}}
			}

			m := NewRegistryManager(strategy, 5*time.Second)
			m.Register(mk("named", "Acme Bank AB"))
			resp, err := m.Evaluate(context.Background(), req())
			assert.NoError(t, err)
			assert.True(t, resp.Decision, "%+v", resp.Context)
			assert.Equal(t, "Acme Bank AB", resp.Context.DisplayName)

			m = NewRegistryManager(strategy, 5*time.Second)
			m.Register(mk("anon", ""))
			resp, err = m.Evaluate(context.Background(), req())
			assert.NoError(t, err)
			assert.True(t, resp.Decision, "%+v", resp.Context)
			assert.Equal(t, "verifier.example.com", resp.Context.DisplayName)

			m = NewRegistryManager(strategy, 5*time.Second)
			m.Register(&mockRegistry{name: "no", healthy: true, resourceTypes: []string{"jwk"}})
			resp, err = m.Evaluate(context.Background(), req())
			assert.NoError(t, err)
			assert.False(t, resp.Decision)
			if resp.Context != nil {
				assert.Empty(t, resp.Context.DisplayName, "denials carry no name")
			}
		})
	}
}

func TestSanitizeDisplayNameL10n(t *testing.T) {
	assert.Nil(t, SanitizeDisplayNameL10n(nil))
	assert.Nil(t, SanitizeDisplayNameL10n(map[string]string{"": "x", "not a tag": "y", "en": " \u200b "}))
	got := SanitizeDisplayNameL10n(map[string]string{
		"EN":    " Acme\u202e Bank ",
		"sv-SE": "Acme Bank AB",
		"en":    "dup, dropped",
		"@@":    "bad tag",
	})
	assert.Equal(t, map[string]string{"en": "Acme Bank", "sv-se": "Acme Bank AB"}, got)

	many := map[string]string{}
	for i := 0; i < 100; i++ {
		many["a"+string(rune('a'+i%26))+string(rune('a'+i/26))] = "n"
	}
	assert.Len(t, SanitizeDisplayNameL10n(many), maxDisplayNameLangs)
}

func TestDisplayNameL10nTravelsWithTheName(t *testing.T) {
	pos := func(name string, l10n map[string]string) *authzen.EvaluationResponse {
		return &authzen.EvaluationResponse{Decision: true, Context: &authzen.EvaluationResponseContext{DisplayName: name, DisplayNameL10n: l10n}}
	}
	resp := &authzen.EvaluationResponse{Decision: true}
	mergeDisplayName(resp, []*authzen.EvaluationResponse{
		pos("Zed", map[string]string{"en": "Zed"}),
		pos("Alpha", map[string]string{"en": "Alpha", "sv": "Alfa"}),
	})
	assert.Equal(t, "Alpha", resp.Context.DisplayName)
	assert.Equal(t, map[string]string{"en": "Alpha", "sv": "Alfa"}, resp.Context.DisplayNameL10n)

	// An unnamed response falling back to the origin carries no l10n object, and
	// l10n without a usable display_name is dropped.
	fb := &authzen.EvaluationResponse{Decision: true, Context: &authzen.EvaluationResponseContext{DisplayNameL10n: map[string]string{"en": "X"}}}
	applyDisplayName(&authzen.EvaluationRequest{Subject: authzen.Subject{ID: "https://rp.example.com"}}, fb)
	assert.Equal(t, "rp.example.com", fb.Context.DisplayName)
	assert.Nil(t, fb.Context.DisplayNameL10n)
}
