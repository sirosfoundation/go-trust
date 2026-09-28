package coseutil

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"math/big"
	"testing"

	"github.com/fxamacker/cbor/v2"
)

// signUntagged builds a genuinely signed untagged COSE_Sign1, the way a
// conformant VICAL/RICAL signer does: Sig_structure over an empty
// external_aad, ES256, raw r||s signature (RFC 9053 §2.1), no tag(18).
func signUntagged(t *testing.T, key *ecdsa.PrivateKey, protected map[int64]any, payload []byte) []byte {
	t.Helper()
	protBytes, err := cbor.Marshal(protected)
	if err != nil {
		t.Fatalf("marshal protected: %v", err)
	}
	toBeSigned, err := cbor.Marshal([]any{"Signature1", protBytes, []byte{}, payload})
	if err != nil {
		t.Fatalf("marshal Sig_structure: %v", err)
	}
	digest := sha256.Sum256(toBeSigned)
	r, s, err := ecdsa.Sign(rand.Reader, key, digest[:])
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])
	out, err := cbor.Marshal([]any{protBytes, map[any]any{}, payload, sig})
	if err != nil {
		t.Fatalf("marshal COSE_Sign1: %v", err)
	}
	return out
}

func TestVerifySign1_RoundTrip(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	// 1 = alg, -7 = ES256
	doc := signUntagged(t, key, map[int64]any{1: -7}, []byte("payload"))

	msg, err := ParseUntaggedSign1(doc)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if err := VerifySign1(msg, key.Public()); err != nil {
		t.Errorf("verify a correctly signed document: %v", err)
	}
}

func TestVerifySign1_RejectsWrongKey(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	doc := signUntagged(t, key, map[int64]any{1: -7}, []byte("payload"))

	msg, err := ParseUntaggedSign1(doc)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if err := VerifySign1(msg, other.Public()); err == nil {
		t.Error("verification must fail against a key that did not sign the document")
	}
}

func TestVerifySign1_RejectsTamperedPayload(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	doc := signUntagged(t, key, map[int64]any{1: -7}, []byte("payload"))

	msg, err := ParseUntaggedSign1(doc)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	msg.Payload = []byte("tampered")
	if err := VerifySign1(msg, key.Public()); err == nil {
		t.Error("verification must fail once the payload no longer matches the signature")
	}
}

func TestVerifySign1_Errors(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	t.Run("nil message", func(t *testing.T) {
		if err := VerifySign1(nil, key.Public()); err == nil {
			t.Error("want error for a nil message")
		}
	})

	t.Run("no alg in protected header", func(t *testing.T) {
		doc := signUntagged(t, key, map[int64]any{}, []byte("payload"))
		msg, err := ParseUntaggedSign1(doc)
		if err != nil {
			t.Fatalf("parse: %v", err)
		}
		if err := VerifySign1(msg, key.Public()); err == nil {
			t.Error("want error when the protected header carries no alg")
		}
	})

	t.Run("key type does not match alg", func(t *testing.T) {
		doc := signUntagged(t, key, map[int64]any{1: -8}, []byte("payload")) // -8 = EdDSA
		msg, err := ParseUntaggedSign1(doc)
		if err != nil {
			t.Fatalf("parse: %v", err)
		}
		if err := VerifySign1(msg, key.Public()); err == nil {
			t.Error("want error when an EdDSA alg is paired with an ECDSA key")
		}
	})
}

func TestParseUntaggedSign1_Rejects(t *testing.T) {
	for name, data := range map[string][]byte{
		"not cbor":                   []byte{0xff, 0xff, 0xff},
		"empty":                      {},
		"cbor but not a sign1 array": mustCBOR(t, map[string]string{"a": "b"}),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseUntaggedSign1(data); err == nil {
				t.Errorf("want error for %s", name)
			}
		})
	}
}

func TestNormalizeHeaderLabels(t *testing.T) {
	in := map[any]any{
		int64(1):     "int64",
		int(2):       "int",
		uint64(3):    "uint64",
		uint(4):      "uint",
		"text-label": "dropped",
	}
	got := NormalizeHeaderLabels(in)

	for _, want := range []int64{1, 2, 3, 4} {
		if _, ok := got[want]; !ok {
			t.Errorf("label %d should survive normalization, whatever integer type it decoded as", want)
		}
	}
	if len(got) != 4 {
		t.Errorf("a text label should be dropped, not coerced: got %d entries, want 4", len(got))
	}
}

func TestX5ChainDER(t *testing.T) {
	t.Run("single bstr", func(t *testing.T) {
		got, err := X5ChainDER(map[int64]interface{}{HeaderLabelX5Chain: []byte{0x01}})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(got) != 1 {
			t.Errorf("a lone certificate must still yield a one-element chain, got %d", len(got))
		}
	})

	t.Run("array of bstr", func(t *testing.T) {
		got, err := X5ChainDER(map[int64]interface{}{
			HeaderLabelX5Chain: []interface{}{[]byte{0x01}, []byte{0x02}},
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(got) != 2 {
			t.Errorf("want 2 certificates, got %d", len(got))
		}
	})

	t.Run("absent", func(t *testing.T) {
		if _, err := X5ChainDER(map[int64]interface{}{}); err == nil {
			t.Error("want error when the header carries no x5chain")
		}
	})

	t.Run("wrong element type", func(t *testing.T) {
		if _, err := X5ChainDER(map[int64]interface{}{
			HeaderLabelX5Chain: []interface{}{"not-a-bstr"},
		}); err == nil {
			t.Error("want error when a chain element is not a byte string")
		}
	})

	t.Run("wrong container type", func(t *testing.T) {
		if _, err := X5ChainDER(map[int64]interface{}{
			HeaderLabelX5Chain: big.NewInt(1),
		}); err == nil {
			t.Error("want error for an x5chain that is neither bstr nor array")
		}
	})
}

func mustCBOR(t *testing.T, v any) []byte {
	t.Helper()
	b, err := cbor.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return b
}
