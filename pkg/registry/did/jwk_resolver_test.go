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
