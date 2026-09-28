// Package coseutil provides the COSE_Sign1 handling shared by the registries
// that consume ISO/IEC 18013-5 trust lists.
//
// VICAL (Annex C) and RICAL (Annex F) are both distributed as a COSE_Sign1
// in its *untagged* four-element form — "the untagged COSE_Sign1 structure",
// per C.1.7.1 and F.3.2 — so the tag(18) variant that cose.Sign1Message
// expects does not apply to either.
package coseutil

import (
	"crypto"
	"fmt"
	"math"

	cose "github.com/veraison/go-cose"
)

// HeaderLabelX5Chain is the COSE header label carrying a certificate chain
// (RFC 9360 §2). VICAL puts it in the unprotected header, RICAL in the
// protected one, so callers read whichever applies and pass the map here.
const HeaderLabelX5Chain int64 = 33

// ParseUntaggedSign1 decodes an untagged COSE_Sign1 four-element CBOR array.
func ParseUntaggedSign1(data []byte) (*cose.UntaggedSign1Message, error) {
	var msg cose.UntaggedSign1Message
	if err := msg.UnmarshalCBOR(data); err != nil {
		return nil, fmt.Errorf("decode COSE_Sign1: %w", err)
	}
	return &msg, nil
}

// VerifySign1 checks the signature against pubKey with a zero-length
// external_aad, which both C.1.7.1 and F.3.2 require. The algorithm is read
// from the protected header, where COSE requires it to be when there is no
// externally supplied data.
//
// go-cose normalizes a nil external_aad to an empty bstr internally, so this
// cannot reproduce the trap a hand-rolled encoder is prone to: a nil []byte
// boxed in an `any` encodes as CBOR null (0xf6) rather than an empty byte
// string (0x40), which hashes a different Sig_structure than the signer used
// and makes verification fail for every conformant document.
func VerifySign1(msg *cose.UntaggedSign1Message, pubKey crypto.PublicKey) error {
	if msg == nil {
		return fmt.Errorf("nil COSE_Sign1")
	}
	alg, err := msg.Headers.Protected.Algorithm()
	if err != nil {
		return fmt.Errorf("read alg from protected header: %w", err)
	}
	verifier, err := cose.NewVerifier(alg, pubKey)
	if err != nil {
		return fmt.Errorf("build %v verifier: %w", alg, err)
	}
	return msg.Verify([]byte{}, verifier)
}

// NormalizeHeaderLabels narrows a COSE header map to its integer labels.
// Labels may decode as any integer width, and private-use labels may be text
// strings, so each key is coerced rather than type-asserted; non-integer
// labels are dropped rather than treated as an error, since a header carrying
// one is still valid and may still hold the label we want.
func NormalizeHeaderLabels(hdr map[any]any) map[int64]interface{} {
	out := make(map[int64]interface{}, len(hdr))
	for k, v := range hdr {
		switch key := k.(type) {
		case int64:
			out[key] = v
		case int:
			out[int64(key)] = v
		case uint64:
			if key <= math.MaxInt64 {
				out[int64(key)] = v
			}
		case uint:
			if uint64(key) <= math.MaxInt64 {
				out[int64(key)] = v
			}
		}
	}
	return out
}

// X5ChainDER pulls the raw DER certificates out of a decoded COSE header.
// RFC 9360 allows either a single bstr (one certificate) or an array of
// bstr (a chain, leaf first).
func X5ChainDER(hdr map[int64]interface{}) ([][]byte, error) {
	raw, ok := hdr[HeaderLabelX5Chain]
	if !ok {
		return nil, fmt.Errorf("no x5chain (label %d) in header", HeaderLabelX5Chain)
	}
	switch v := raw.(type) {
	case []byte:
		return [][]byte{v}, nil
	case []interface{}:
		out := make([][]byte, 0, len(v))
		for i, item := range v {
			b, ok := item.([]byte)
			if !ok {
				return nil, fmt.Errorf("x5chain element %d is not a byte string", i)
			}
			out = append(out, b)
		}
		return out, nil
	default:
		return nil, fmt.Errorf("unsupported x5chain encoding: %T", raw)
	}
}
