// Package static provides simple static trust registries.
package static

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"sort"

	"github.com/sirosfoundation/g119612/pkg/utils/x509util"
)

// KeyFingerprint computes a SHA-256 fingerprint of a public key.
// The fingerprint is computed from a canonical JWK representation.
// Returns the base64url-encoded hash.
func KeyFingerprint(pubKey crypto.PublicKey) (string, error) {
	canonicalJWK, err := PublicKeyToCanonicalJWK(pubKey)
	if err != nil {
		return "", fmt.Errorf("converting key to canonical JWK: %w", err)
	}

	// Sort keys for deterministic JSON encoding
	sorted := sortedJWK(canonicalJWK)
	jsonBytes, err := json.Marshal(sorted)
	if err != nil {
		return "", fmt.Errorf("encoding canonical JWK: %w", err)
	}

	hash := sha256.Sum256(jsonBytes)
	return base64.RawURLEncoding.EncodeToString(hash[:]), nil
}

// sortedJWK sorts JWK keys alphabetically for deterministic JSON encoding.
func sortedJWK(jwk map[string]string) map[string]string {
	// Already uses string values, just need deterministic order
	return jwk
}

// PublicKeyToCanonicalJWK converts a crypto.PublicKey to a canonical JWK representation.
// Only includes the required public key parameters (kty, crv, x, y, n, e) for fingerprinting.
func PublicKeyToCanonicalJWK(pubKey crypto.PublicKey) (map[string]string, error) {
	switch key := pubKey.(type) {
	case *ecdsa.PublicKey:
		curveName := key.Curve.Params().Name
		// Convert curve names to JWK format
		var crv string
		switch curveName {
		case "P-256":
			crv = "P-256"
		case "P-384":
			crv = "P-384"
		case "P-521":
			crv = "P-521"
		default:
			return nil, fmt.Errorf("unsupported EC curve: %s", curveName)
		}

		byteLen := (key.Curve.Params().BitSize + 7) / 8

		// Use ECDH().Bytes() to get the uncompressed point (Go 1.20+).
		// This avoids deprecated direct access to key.X and key.Y fields.
		// The returned bytes are in uncompressed format: 0x04 || X || Y
		ecdhKey, err := key.ECDH()
		if err != nil {
			return nil, fmt.Errorf("failed to convert ECDSA key to ECDH: %w", err)
		}
		marshaled := ecdhKey.Bytes()
		if len(marshaled) != 1+2*byteLen {
			return nil, fmt.Errorf("unexpected marshaled key length: got %d, want %d", len(marshaled), 1+2*byteLen)
		}
		// Skip the 0x04 prefix and split into X and Y
		xPadded := marshaled[1 : 1+byteLen]
		yPadded := marshaled[1+byteLen:]

		return map[string]string{
			"kty": "EC",
			"crv": crv,
			"x":   base64.RawURLEncoding.EncodeToString(xPadded),
			"y":   base64.RawURLEncoding.EncodeToString(yPadded),
		}, nil

	case *rsa.PublicKey:
		// RSA public key: n (modulus) and e (exponent)
		nBytes := key.N.Bytes()
		eBytes := big.NewInt(int64(key.E)).Bytes()

		return map[string]string{
			"kty": "RSA",
			"n":   base64.RawURLEncoding.EncodeToString(nBytes),
			"e":   base64.RawURLEncoding.EncodeToString(eBytes),
		}, nil

	case ed25519.PublicKey:
		return map[string]string{
			"kty": "OKP",
			"crv": "Ed25519",
			"x":   base64.RawURLEncoding.EncodeToString(key),
		}, nil

	default:
		return nil, fmt.Errorf("unsupported key type: %T", pubKey)
	}
}

// ExtractPublicKeyFromRequest extracts the public key from an AuthZEN evaluation request.
// Supports both x5c (X.509 certificate chain) and jwk resource types.
func ExtractPublicKeyFromRequest(resourceType string, resourceKey []interface{}) (crypto.PublicKey, error) {
	switch resourceType {
	case "x5c", "x509_san_dns":
		certs, err := x509util.ParseX5CFromArray(resourceKey)
		if err != nil {
			return nil, fmt.Errorf("parsing x5c: %w", err)
		}
		if len(certs) == 0 {
			return nil, fmt.Errorf("no certificates in x5c array")
		}
		// Return the public key from the leaf certificate
		return certs[0].PublicKey, nil

	case "jwk":
		if len(resourceKey) == 0 {
			return nil, fmt.Errorf("empty jwk array")
		}
		jwk, ok := resourceKey[0].(map[string]interface{})
		if !ok {
			return nil, fmt.Errorf("jwk is not a map")
		}
		return ParseJWKPublicKey(jwk)

	default:
		return nil, fmt.Errorf("unsupported resource type: %s", resourceType)
	}
}

// ParseJWKPublicKey parses a public key from a JWK map.
func ParseJWKPublicKey(jwk map[string]interface{}) (crypto.PublicKey, error) {
	kty, ok := jwk["kty"].(string)
	if !ok {
		return nil, fmt.Errorf("missing or invalid kty in JWK")
	}

	switch kty {
	case "EC":
		return parseECPublicKey(jwk)
	case "RSA":
		return parseRSAPublicKey(jwk)
	case "OKP":
		return parseOKPPublicKey(jwk)
	default:
		return nil, fmt.Errorf("unsupported key type: %s", kty)
	}
}

func parseECPublicKey(jwk map[string]interface{}) (*ecdsa.PublicKey, error) {
	crv, ok := jwk["crv"].(string)
	if !ok {
		return nil, fmt.Errorf("missing or invalid crv in EC JWK")
	}

	xStr, ok := jwk["x"].(string)
	if !ok {
		return nil, fmt.Errorf("missing or invalid x in EC JWK")
	}

	yStr, ok := jwk["y"].(string)
	if !ok {
		return nil, fmt.Errorf("missing or invalid y in EC JWK")
	}

	xBytes, err := base64.RawURLEncoding.DecodeString(xStr)
	if err != nil {
		// Try standard base64
		xBytes, err = base64.StdEncoding.DecodeString(xStr)
		if err != nil {
			return nil, fmt.Errorf("decoding x: %w", err)
		}
	}

	yBytes, err := base64.RawURLEncoding.DecodeString(yStr)
	if err != nil {
		yBytes, err = base64.StdEncoding.DecodeString(yStr)
		if err != nil {
			return nil, fmt.Errorf("decoding y: %w", err)
		}
	}

	var curve elliptic.Curve
	switch crv {
	case "P-256":
		curve = elliptic.P256()
	case "P-384":
		curve = elliptic.P384()
	case "P-521":
		curve = elliptic.P521()
	default:
		return nil, fmt.Errorf("unsupported curve: %s", crv)
	}

	return &ecdsa.PublicKey{
		Curve: curve,
		X:     new(big.Int).SetBytes(xBytes),
		Y:     new(big.Int).SetBytes(yBytes),
	}, nil
}

func parseRSAPublicKey(jwk map[string]interface{}) (*rsa.PublicKey, error) {
	nStr, ok := jwk["n"].(string)
	if !ok {
		return nil, fmt.Errorf("missing or invalid n in RSA JWK")
	}

	eStr, ok := jwk["e"].(string)
	if !ok {
		return nil, fmt.Errorf("missing or invalid e in RSA JWK")
	}

	nBytes, err := base64.RawURLEncoding.DecodeString(nStr)
	if err != nil {
		nBytes, err = base64.StdEncoding.DecodeString(nStr)
		if err != nil {
			return nil, fmt.Errorf("decoding n: %w", err)
		}
	}

	eBytes, err := base64.RawURLEncoding.DecodeString(eStr)
	if err != nil {
		eBytes, err = base64.StdEncoding.DecodeString(eStr)
		if err != nil {
			return nil, fmt.Errorf("decoding e: %w", err)
		}
	}

	// Convert exponent bytes to int
	e := 0
	for _, b := range eBytes {
		e = e<<8 + int(b)
	}

	return &rsa.PublicKey{
		N: new(big.Int).SetBytes(nBytes),
		E: e,
	}, nil
}

func parseOKPPublicKey(jwk map[string]interface{}) (ed25519.PublicKey, error) {
	crv, ok := jwk["crv"].(string)
	if !ok {
		return nil, fmt.Errorf("missing or invalid crv in OKP JWK")
	}

	if crv != "Ed25519" {
		return nil, fmt.Errorf("unsupported OKP curve: %s", crv)
	}

	xStr, ok := jwk["x"].(string)
	if !ok {
		return nil, fmt.Errorf("missing or invalid x in OKP JWK")
	}

	xBytes, err := base64.RawURLEncoding.DecodeString(xStr)
	if err != nil {
		xBytes, err = base64.StdEncoding.DecodeString(xStr)
		if err != nil {
			return nil, fmt.Errorf("decoding x: %w", err)
		}
	}

	if len(xBytes) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("invalid Ed25519 public key size: %d", len(xBytes))
	}

	return ed25519.PublicKey(xBytes), nil
}

// ExtractPublicKeysFromJWKS extracts all public keys from a JWKS response.
func ExtractPublicKeysFromJWKS(jwksData map[string]interface{}) ([]crypto.PublicKey, error) {
	keysVal, ok := jwksData["keys"]
	if !ok {
		return nil, fmt.Errorf("missing 'keys' in JWKS")
	}

	keys, ok := keysVal.([]interface{})
	if !ok {
		return nil, fmt.Errorf("'keys' is not an array")
	}

	var pubKeys []crypto.PublicKey
	for i, keyVal := range keys {
		jwk, ok := keyVal.(map[string]interface{})
		if !ok {
			continue // Skip invalid entries
		}

		pubKey, err := ParseJWKPublicKey(jwk)
		if err != nil {
			// Log and continue - some keys may be for other purposes
			continue
		}

		pubKeys = append(pubKeys, pubKey)
		_ = i // Suppress unused variable warning
	}

	return pubKeys, nil
}

// extractPublicKeyFromCert extracts the public key from an X.509 certificate.
func extractPublicKeyFromCert(cert *x509.Certificate) crypto.PublicKey {
	return cert.PublicKey
}

// canonicalJWKJSON produces deterministic JSON encoding of a JWK for fingerprinting.
func canonicalJWKJSON(jwk map[string]string) ([]byte, error) {
	// Get sorted keys
	keys := make([]string, 0, len(jwk))
	for k := range jwk {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	// Build JSON manually for deterministic ordering
	buf := []byte("{")
	for i, k := range keys {
		if i > 0 {
			buf = append(buf, ',')
		}
		keyJSON, _ := json.Marshal(k)
		valJSON, _ := json.Marshal(jwk[k])
		buf = append(buf, keyJSON...)
		buf = append(buf, ':')
		buf = append(buf, valJSON...)
	}
	buf = append(buf, '}')
	return buf, nil
}
