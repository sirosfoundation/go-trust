package lote

import (
	"context"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/sirosfoundation/g119612/pkg/etsi119602"
)

func TestVerifyJWS_LoTL_SharedVisitedDoesNotBypassTopLevel(t *testing.T) {
	// B is reached first as a nested pointer of A and fails verification. When
	// B is then configured as its own top-level LoTL source it must be verified
	// again and fail the load, not be skipped as "already visited".
	f := newJWSFixture(t)
	b := f.lotl("b.jws")
	tamperFile(t, b)
	a := f.lotl("a.jws", lotlPointer(b, etsi119602.LoTLTypeEU, "EU"))

	_, err := New(Config{LoTLSources: []string{a, b}, VerifyJWS: true, TrustAnchorProvider: f.provider()})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "signature verification failed")
}

func TestVerifyJWS_LoTL_CycleStillCut(t *testing.T) {
	// A and B point at each other; with verification on, resolution must
	// terminate.
	f := newJWSFixture(t)
	pathA := filepath.Join(f.dir, "a.jws")
	pathB := filepath.Join(f.dir, "b.jws")
	mk := func(target string) []byte {
		l := &etsi119602.ListOfTrustedLists{
			ListAndSchemeInformation: etsi119602.ListAndSchemeInformation{
				LoTEVersionIdentifier: 1,
				LoTEType:              etsi119602.LoTLTypeEU,
				SchemeOperatorName:    etsi119602.NameSet{{Lang: "en", Value: "EU"}},
				PointersToOtherLoTE:   []etsi119602.OtherLoTEPointer{lotlPointer(target, etsi119602.LoTLTypeEU, "EU")},
			},
		}
		data, err := l.MarshalLoTL()
		require.NoError(t, err)
		return data
	}
	f.signedFile("a.jws", mk(pathB))
	f.signedFile("b.jws", mk(pathA))

	reg, err := New(Config{LoTLSources: []string{pathA}, VerifyJWS: true, TrustAnchorProvider: f.provider()})
	require.NoError(t, err)
	assert.True(t, reg.Healthy())
}

func TestVerifyJWS_FetchFailureAndGarbagePayload(t *testing.T) {
	f := newJWSFixture(t)

	t.Run("missing source", func(t *testing.T) {
		_, err := New(Config{Sources: []string{filepath.Join(f.dir, "missing.jws")}, VerifyJWS: true, TrustAnchorProvider: f.provider()})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to fetch raw LoTE")
	})
	t.Run("validly signed non-LoTE payload", func(t *testing.T) {
		src := f.signedFile("garbage.jws", []byte(`not json`))
		_, err := New(Config{Sources: []string{src}, VerifyJWS: true, TrustAnchorProvider: f.provider()})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to parse verified LoTE")
	})
}

func TestVerifyLoTEJWS_Branches(t *testing.T) {
	f := newJWSFixture(t)
	good := f.lote("g.jws", "https://g.example.com")
	raw, err := os.ReadFile(good)
	require.NoError(t, err)
	parts := splitDots(string(raw))

	t.Run("nil roots refused", func(t *testing.T) {
		_, _, err := verifyLoTEJWS(context.Background(), raw, nil, time.Now())
		require.Error(t, err)
	})
	t.Run("flattened JSON serialization", func(t *testing.T) {
		flat := `{"protected":"` + parts[0] + `","payload":"` + parts[1] + `","signature":"` + parts[2] + `"}`
		leaf, payload, err := verifyLoTEJWS(context.Background(), []byte(flat), f.roots, time.Now())
		require.NoError(t, err)
		assert.NotNil(t, leaf)
		assert.Contains(t, string(payload), "g.example.com")
	})
	t.Run("not JWS at all", func(t *testing.T) {
		_, _, err := verifyLoTEJWS(context.Background(), []byte("{{{"), f.roots, time.Now())
		require.Error(t, err)
	})
	t.Run("tampered payload encoding", func(t *testing.T) {
		bad := parts[0] + ".%%%." + parts[2]
		_, _, err := verifyLoTEJWS(context.Background(), []byte(bad), f.roots, time.Now())
		require.Error(t, err)
	})
}

func TestLoadTrustAnchorBundle_ValidThenMalformed(t *testing.T) {
	ca, _ := generateTestCA(t)
	good := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.Raw})
	bad := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("garbage")})
	// A truncated block that pem.Decode cannot parse at all.
	truncated := []byte("-----BEGIN CERTIFICATE-----\nAAAA\n")

	for name, tail := range map[string][]byte{"corrupt cert": bad, "truncated block": truncated} {
		t.Run(name, func(t *testing.T) {
			p := filepath.Join(t.TempDir(), "b.pem")
			require.NoError(t, os.WriteFile(p, append(append([]byte{}, good...), tail...), 0o600))
			_, err := LoadTrustAnchorBundle(p)
			require.Error(t, err, "a valid anchor must not mask a corrupt one after it")
		})
	}
	// Sanity: the valid one alone is accepted.
	p := filepath.Join(t.TempDir(), "ok.pem")
	require.NoError(t, os.WriteFile(p, good, 0o600))
	_, err := LoadTrustAnchorBundle(p)
	require.NoError(t, err)
}
