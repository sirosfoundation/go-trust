package did

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"testing"

	"github.com/sirosfoundation/go-trust/pkg/authzen"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// didJwkP256Sig is the exact client_id from a wallet-backend OID4VP failure:
// an ES256 verifier key with use=sig. It is a public P-256 key and nothing
// more, but resolution used to fail because no resolver claimed the method.
const didJwkP256Sig = "did:jwk:eyJrdHkiOiJFQyIsImNydiI6IlAtMjU2IiwidXNlIjoic2lnIiwiYWxnIjoiRVMyNTYiLCJ4IjoiY1QtYzVPSnVvWTUzcXpQbEt1S2RHY1FPUHJSSHJET01LTVVLcWNmZGd1YyIsInkiOiJUSmlCWFUtdUhsaGlfMmlXdnJLaEtiMXppX3ZLUHB1VGVTd1ZDNEhKcmVjIn0"

// didJwkFor builds a did:jwk from a JWK, so tests state the key they mean
// rather than an opaque blob.
func didJwkFor(t *testing.T, jwk map[string]interface{}) string {
	t.Helper()
	raw, err := json.Marshal(jwk)
	require.NoError(t, err)
	return "did:jwk:" + base64.RawURLEncoding.EncodeToString(raw)
}

func TestDIDJwkResolver_Method(t *testing.T) {
	// Distinct from the did:jwks registry, which resolves a JWKS endpoint.
	assert.Equal(t, "jwk", NewDIDJwkResolver().Method())
}

func TestDIDJwkResolver_ResolvesRealVerifierKey(t *testing.T) {
	doc, err := NewDIDJwkResolver().Resolve(context.Background(), didJwkP256Sig)
	require.NoError(t, err)

	assert.Equal(t, didJwkP256Sig, doc.ID)
	require.Len(t, doc.VerificationMethod, 1)

	vm := doc.VerificationMethod[0]
	assert.Equal(t, didJwkP256Sig+"#0", vm.ID)
	assert.Equal(t, "JsonWebKey2020", vm.Type)
	assert.Equal(t, didJwkP256Sig, vm.Controller)

	// The key must survive resolution intact — this is what the caller
	// verifies the request JWT against.
	assert.Equal(t, "EC", vm.PublicKeyJwk["kty"])
	assert.Equal(t, "P-256", vm.PublicKeyJwk["crv"])
	assert.Equal(t, "cT-c5OJuoY53qzPlKuKdGcQOPrRHrDOMKMUKqcfdguc", vm.PublicKeyJwk["x"])
	assert.Equal(t, "TJiBXU-uHlhi_2iWvrKhKb1zi_vKPpuTeSwVC4HJrec", vm.PublicKeyJwk["y"])
}

func TestDIDJwkResolver_VerificationRelationshipsFollowUse(t *testing.T) {
	ec := map[string]interface{}{
		"kty": "EC", "crv": "P-256",
		"x": "cT-c5OJuoY53qzPlKuKdGcQOPrRHrDOMKMUKqcfdguc",
		"y": "TJiBXU-uHlhi_2iWvrKhKb1zi_vKPpuTeSwVC4HJrec",
	}

	t.Run("use=sig is not offered for key agreement", func(t *testing.T) {
		jwk := map[string]interface{}{"use": "sig"}
		for k, v := range ec {
			jwk[k] = v
		}
		doc, err := NewDIDJwkResolver().Resolve(context.Background(), didJwkFor(t, jwk))
		require.NoError(t, err)

		assert.NotNil(t, doc.Authentication)
		assert.NotNil(t, doc.AssertionMethod)
		assert.Nil(t, doc.KeyAgreement, "a signing key must not be usable for key agreement")
	})

	t.Run("use=enc is only offered for key agreement", func(t *testing.T) {
		jwk := map[string]interface{}{"use": "enc"}
		for k, v := range ec {
			jwk[k] = v
		}
		doc, err := NewDIDJwkResolver().Resolve(context.Background(), didJwkFor(t, jwk))
		require.NoError(t, err)

		assert.NotNil(t, doc.KeyAgreement)
		assert.Nil(t, doc.Authentication, "an encryption key must not authenticate")
		assert.Nil(t, doc.AssertionMethod, "an encryption key must not assert")
	})

	t.Run("no use means every relationship", func(t *testing.T) {
		doc, err := NewDIDJwkResolver().Resolve(context.Background(), didJwkFor(t, ec))
		require.NoError(t, err)

		assert.NotNil(t, doc.Authentication)
		assert.NotNil(t, doc.AssertionMethod)
		assert.NotNil(t, doc.KeyAgreement)
		assert.NotNil(t, doc.CapabilityInvocation)
		assert.NotNil(t, doc.CapabilityDelegation)
	})
}

func TestDIDJwkResolver_StripsDIDURLSuffix(t *testing.T) {
	// A caller may pass the verification method's own id back in.
	doc, err := NewDIDJwkResolver().Resolve(context.Background(), didJwkP256Sig+"#0")
	require.NoError(t, err)

	// The document id is the bare DID, not the DID URL.
	assert.Equal(t, didJwkP256Sig, doc.ID)
	assert.Equal(t, didJwkP256Sig+"#0", doc.VerificationMethod[0].ID)
}

func TestDIDJwkResolver_RejectsPrivateKeyMaterial(t *testing.T) {
	// A DID is a public identifier. Publishing a private key in a DID
	// document would hand it to every relying party that resolves it.
	for _, param := range []string{"d", "p", "q", "dp", "dq", "qi", "oth"} {
		t.Run(param, func(t *testing.T) {
			jwk := map[string]interface{}{
				"kty": "EC", "crv": "P-256",
				"x":   "cT-c5OJuoY53qzPlKuKdGcQOPrRHrDOMKMUKqcfdguc",
				"y":   "TJiBXU-uHlhi_2iWvrKhKb1zi_vKPpuTeSwVC4HJrec",
				param: "c2VjcmV0",
			}
			_, err := NewDIDJwkResolver().Resolve(context.Background(), didJwkFor(t, jwk))
			require.Error(t, err)
			assert.Contains(t, err.Error(), "private key parameter")
		})
	}

	t.Run("symmetric oct key", func(t *testing.T) {
		jwk := map[string]interface{}{"kty": "oct", "k": "c2VjcmV0"}
		_, err := NewDIDJwkResolver().Resolve(context.Background(), didJwkFor(t, jwk))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "private key parameter")
	})
}

func TestDIDJwkResolver_RejectsMalformedIdentifiers(t *testing.T) {
	validJSON := base64.RawURLEncoding.EncodeToString([]byte(`{"kty":"EC"}`))

	tests := []struct {
		name string
		did  string
		msg  string
	}{
		{"wrong method", "did:key:z6Mkhaaa", "must start with 'did:jwk:'"},
		{"missing key material", "did:jwk:", "missing key material"},
		{
			// Padded base64 would let two spellings resolve to one key.
			name: "padded base64url",
			did:  "did:jwk:" + base64.URLEncoding.EncodeToString([]byte(`{"kty":"EC","crv":"P-256"}`)),
			msg:  "not unpadded base64url",
		},
		{"not base64url", "did:jwk:!!!not base64!!!", "not unpadded base64url"},
		{
			name: "not JSON",
			did:  "did:jwk:" + base64.RawURLEncoding.EncodeToString([]byte("plain text")),
			msg:  "not a JSON JWK",
		},
		{
			name: "JSON but not an object",
			did:  "did:jwk:" + base64.RawURLEncoding.EncodeToString([]byte(`["EC"]`)),
			msg:  "not a JSON JWK",
		},
		{
			name: "no kty",
			did:  "did:jwk:" + base64.RawURLEncoding.EncodeToString([]byte(`{"crv":"P-256"}`)),
			msg:  "has no 'kty'",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewDIDJwkResolver().Resolve(context.Background(), tt.did)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.msg)
		})
	}

	// Sanity check that the encoder used above produces something resolvable,
	// so the negative cases above fail for the stated reason.
	_, err := NewDIDJwkResolver().Resolve(context.Background(), "did:jwk:"+validJSON)
	require.NoError(t, err)
}

// TestDIDJwkResolver_ThroughRegistry exercises the path the wallet backend
// actually takes: AuthZEN evaluation, then key extraction from trust_metadata.
// Before this resolver existed the registry denied the DID outright.
func TestDIDJwkResolver_ThroughRegistry(t *testing.T) {
	registry := NewGenericDIDRegistryWithLocalMethods(GenericDIDRegistryConfig{})

	resp, err := registry.Evaluate(context.Background(), &authzen.EvaluationRequest{
		Subject: authzen.Subject{ID: didJwkP256Sig},
	})
	require.NoError(t, err)
	require.True(t, resp.Decision, "did:jwk should now resolve")

	require.NotNil(t, resp.Context)
	meta, ok := resp.Context.TrustMetadata.(map[string]interface{})
	require.True(t, ok, "trust metadata should be a DID document")

	// This is the shape the wallet backend reads keys out of; when it is
	// absent the caller reports "resolved but contains no verification
	// method keys".
	vms, ok := meta["verificationMethod"].([]map[string]interface{})
	require.True(t, ok, "DID document must carry verificationMethod")
	require.Len(t, vms, 1)

	jwk, ok := vms[0]["publicKeyJwk"].(map[string]interface{})
	require.True(t, ok, "verification method must carry publicKeyJwk")
	assert.Equal(t, "EC", jwk["kty"])
}

// did:key must keep working alongside the new method.
func TestGenericDIDRegistryWithLocalMethods_KeepsDIDKey(t *testing.T) {
	registry := NewGenericDIDRegistryWithLocalMethods(GenericDIDRegistryConfig{})
	methods := registry.getSupportedMethods()
	assert.Contains(t, methods, "did:key")
	assert.Contains(t, methods, "did:jwk")
}

func TestNewGenericDIDRegistryForMethods(t *testing.T) {
	t.Run("empty list enables every local method", func(t *testing.T) {
		r, err := NewGenericDIDRegistryForMethods(GenericDIDRegistryConfig{}, nil)
		require.NoError(t, err)
		assert.ElementsMatch(t, []string{"did:key", "did:jwk"}, r.getSupportedMethods())
	})

	t.Run("an explicit list enables only what it names", func(t *testing.T) {
		r, err := NewGenericDIDRegistryForMethods(GenericDIDRegistryConfig{}, []string{"jwk"})
		require.NoError(t, err)
		assert.Equal(t, []string{"did:jwk"}, r.getSupportedMethods())
	})

	t.Run("the did: prefix is accepted", func(t *testing.T) {
		r, err := NewGenericDIDRegistryForMethods(GenericDIDRegistryConfig{}, []string{"did:jwk", "did:key"})
		require.NoError(t, err)
		assert.ElementsMatch(t, []string{"did:key", "did:jwk"}, r.getSupportedMethods())
	})

	t.Run("an unknown method fails rather than being skipped", func(t *testing.T) {
		// Skipping it would start the service resolving less than was asked
		// for, which only shows up later as an unresolvable DID.
		_, err := NewGenericDIDRegistryForMethods(GenericDIDRegistryConfig{}, []string{"jwk", "web"})
		require.Error(t, err)
		assert.Contains(t, err.Error(), `unknown DID method "web"`)
	})
}

// TestVerifyKeyBinding_KidKeyMaterial covers the AuthZEN request wallet-common
// sends when a verifier's request JWT header carries a `kid` rather than an
// inline `jwk` — the normal shape for a DID-based client_id.
//
// This used to fail with "resource.key[0] must be a JWK object", so the PDP
// reported an otherwise valid verifier as untrusted even though the wallet had
// already verified the request signature against the resolved key.
func TestVerifyKeyBinding_KidKeyMaterial(t *testing.T) {
	registry := NewGenericDIDRegistryWithLocalMethods(GenericDIDRegistryConfig{})

	evaluate := func(t *testing.T, kid string) *authzen.EvaluationResponse {
		t.Helper()
		resp, err := registry.Evaluate(context.Background(), &authzen.EvaluationRequest{
			Subject:  authzen.Subject{ID: didJwkP256Sig},
			Resource: authzen.Resource{Type: "kid", Key: []interface{}{kid}},
		})
		require.NoError(t, err)
		return resp
	}

	t.Run("absolute DID URL", func(t *testing.T) {
		resp := evaluate(t, didJwkP256Sig+"#0")
		require.True(t, resp.Decision, "kid naming the verification method should bind")
		assert.Equal(t, didJwkP256Sig+"#0", resp.Context.Reason["verification_method"])
	})

	t.Run("relative fragment", func(t *testing.T) {
		assert.True(t, evaluate(t, "#0").Decision)
	})

	t.Run("the bare DID, when the document declares one method", func(t *testing.T) {
		assert.True(t, evaluate(t, didJwkP256Sig).Decision)
	})

	t.Run("a kid naming no method does not bind", func(t *testing.T) {
		resp := evaluate(t, didJwkP256Sig+"#nope")
		require.False(t, resp.Decision, "a kid the document does not declare must not bind")
		assert.Contains(t, resp.Context.Reason["error"], "no matching verification method")
	})

	t.Run("a fragment naming no method does not bind", func(t *testing.T) {
		assert.False(t, evaluate(t, "#nope").Decision)
	})

	t.Run("a different DID does not bind", func(t *testing.T) {
		// The bare-DID shorthand must not turn into "any single-method document".
		other := didJwkFor(t, map[string]interface{}{
			"kty": "EC", "crv": "P-256",
			"x": "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
			"y": "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0",
		})
		assert.False(t, evaluate(t, other).Decision)
	})
}

// The JWK branch must keep working unchanged.
func TestVerifyKeyBinding_JWKKeyMaterialStillWorks(t *testing.T) {
	registry := NewGenericDIDRegistryWithLocalMethods(GenericDIDRegistryConfig{})

	resp, err := registry.Evaluate(context.Background(), &authzen.EvaluationRequest{
		Subject: authzen.Subject{ID: didJwkP256Sig},
		Resource: authzen.Resource{Type: "jwk", Key: []interface{}{
			map[string]interface{}{
				"kty": "EC", "crv": "P-256",
				"x": "cT-c5OJuoY53qzPlKuKdGcQOPrRHrDOMKMUKqcfdguc",
				"y": "TJiBXU-uHlhi_2iWvrKhKb1zi_vKPpuTeSwVC4HJrec",
			},
		}},
	})
	require.NoError(t, err)
	assert.True(t, resp.Decision)
}

func TestVerifyKeyBinding_RejectsUnusableKeyMaterial(t *testing.T) {
	registry := NewGenericDIDRegistryWithLocalMethods(GenericDIDRegistryConfig{})

	resp, err := registry.Evaluate(context.Background(), &authzen.EvaluationRequest{
		Subject:  authzen.Subject{ID: didJwkP256Sig},
		Resource: authzen.Resource{Type: "jwk", Key: []interface{}{42}},
	})
	require.NoError(t, err)
	require.False(t, resp.Decision)
	assert.Contains(t, resp.Context.Reason["error"], "must be a JWK object or a key identifier")
}

// A DID document may embed a verification method belonging to another
// controller. A relative reference such as "#0" resolves against the
// document's own DID, so it must not bind a foreign method that merely
// happens to share the fragment.
func TestFindVerificationMethodByKid_FragmentIsScopedToTheDocument(t *testing.T) {
	doc := &DIDDocument{
		ID: "did:example:subject",
		VerificationMethod: []VerificationMethod{
			{ID: "did:other:controller#0", Type: "JsonWebKey2020", Controller: "did:other:controller"},
			{ID: "did:example:subject#keys-1", Type: "JsonWebKey2020", Controller: "did:example:subject"},
		},
	}

	assert.Nil(t, findVerificationMethodByKid(doc, "#0"),
		"#0 must resolve against did:example:subject, not bind did:other:controller#0")

	vm := findVerificationMethodByKid(doc, "#keys-1")
	require.NotNil(t, vm, "a fragment naming this document's own method should bind")
	assert.Equal(t, "did:example:subject#keys-1", vm.ID)

	// An absolute identifier still binds whatever the document declares,
	// including a foreign one: the signer named it in full rather than
	// relying on resolution against the subject.
	vm = findVerificationMethodByKid(doc, "did:other:controller#0")
	require.NotNil(t, vm)
	assert.Equal(t, "did:other:controller#0", vm.ID)

	// The bare-DID shorthand needs an unambiguous document, and this one
	// declares two methods.
	assert.Nil(t, findVerificationMethodByKid(doc, "did:example:subject"))
}
