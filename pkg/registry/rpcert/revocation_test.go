package rpcert

import (
	"crypto/x509"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestRevocationMode_Evaluate is the table that matters most here: the
// difference between "revoked" and "could not determine", and the fact that
// warn allows both while still reporting them.
func TestRevocationMode_Evaluate(t *testing.T) {
	tests := []struct {
		name        string
		mode        RevocationMode
		state       RevocationState
		wantAllowed bool
		wantReason  bool
	}{
		{"off ignores revoked", RevocationOff, RevocationRevoked, true, false},
		{"off ignores undetermined", RevocationOff, RevocationUndetermined, true, false},
		{"off allows good", RevocationOff, RevocationGood, true, false},

		{"warn allows good silently", RevocationWarn, RevocationGood, true, false},
		{"warn allows revoked but reports", RevocationWarn, RevocationRevoked, true, true},
		{"warn allows undetermined but reports", RevocationWarn, RevocationUndetermined, true, true},

		{"fail allows good", RevocationFail, RevocationGood, true, false},
		{"fail rejects revoked", RevocationFail, RevocationRevoked, false, true},
		{"fail rejects undetermined", RevocationFail, RevocationUndetermined, false, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := tt.mode.Evaluate(tt.state, "the access certificate")
			assert.Equal(t, tt.wantAllowed, d.Allowed)
			assert.Equal(t, tt.wantReason, d.Reason != "", "reason presence")
			if tt.mode != RevocationOff {
				assert.Equal(t, tt.state, d.State)
			}
		})
	}
}

// TestRevocationMode_UndeterminedIsNotAPass pins the distinction the whole
// type exists for: an unreachable list must never read as valid.
func TestRevocationMode_UndeterminedIsNotAPass(t *testing.T) {
	d := RevocationWarn.Evaluate(RevocationUndetermined, "the registration certificate")
	assert.True(t, d.Allowed, "warn mode proceeds")
	assert.Contains(t, d.Reason, "not evidence that it is valid")
	assert.NotEqual(t, RevocationGood, d.State)
}

// TestRevocationMode_UnknownModeIsNotOff covers a configuration typo: it
// must not silently disable the check.
func TestRevocationMode_UnknownModeIsNotOff(t *testing.T) {
	d := RevocationMode("warnn").Evaluate(RevocationRevoked, "cert")
	assert.NotEmpty(t, d.Reason, "an unrecognised mode must still report")
	assert.False(t, RevocationMode("warnn").Valid())

	for _, m := range []RevocationMode{RevocationOff, RevocationWarn, RevocationFail} {
		assert.True(t, m.Valid(), string(m))
	}
}

func TestRevocationMode_EvaluateDefaultSubject(t *testing.T) {
	d := RevocationFail.Evaluate(RevocationRevoked, "")
	assert.Contains(t, d.Reason, "certificate has been revoked")
}

// ---------------------------------------------------------------------------
// Status references
// ---------------------------------------------------------------------------

func TestRPEntitlements_StatusReference(t *testing.T) {
	t.Run("present", func(t *testing.T) {
		ent := &RPEntitlements{StatusListURI: "https://registrar.example/status", StatusListIndex: 42}
		ref, ok := ent.StatusReference()
		require.True(t, ok)
		assert.Equal(t, "https://registrar.example/status", ref.URI)
		assert.Equal(t, 42, ref.Index)
	})

	t.Run("absent", func(t *testing.T) {
		_, ok := (&RPEntitlements{}).StatusReference()
		assert.False(t, ok)
	})

	t.Run("index zero is a real index", func(t *testing.T) {
		ent := &RPEntitlements{StatusListURI: "https://registrar.example/status", StatusListIndex: 0}
		ref, ok := ent.StatusReference()
		require.True(t, ok, "index 0 is the first slot, not a missing reference")
		assert.Equal(t, 0, ref.Index)
	})

	t.Run("nil receiver", func(t *testing.T) {
		var ent *RPEntitlements
		_, ok := ent.StatusReference()
		assert.False(t, ok)
	})
}

// TestStatusReference_FromSandboxCertificate wires the parser to the
// revocation reference, against the real Registrar-issued fixture.
func TestStatusReference_FromSandboxCertificate(t *testing.T) {
	token, err := os.ReadFile("testdata/german-sandbox-wrprc.jwt")
	require.NoError(t, err)
	payload, err := ParseWRPRCJWTPayload(string(token))
	require.NoError(t, err)
	ent, err := ParseWRPRCClaims(payload)
	require.NoError(t, err)

	ref, ok := ent.StatusReference()
	require.True(t, ok)
	assert.Equal(t, "https://sandbox.eudi-wallet.org/api/status-management/status-list", ref.URI)
	assert.Equal(t, 9940, ref.Index)
}

// ---------------------------------------------------------------------------
// Certificate revocation endpoints
// ---------------------------------------------------------------------------

func TestCRLDistributionPoints(t *testing.T) {
	tests := []struct {
		name string
		in   []string
		want []string
	}{
		{
			name: "https and http are returned in order",
			in:   []string{"https://ca.example/crl", "http://ca.example/other.crl"},
			want: []string{"https://ca.example/crl", "http://ca.example/other.crl"},
		},
		{
			name: "duplicates collapse",
			in:   []string{"https://ca.example/crl", "https://ca.example/crl"},
			want: []string{"https://ca.example/crl"},
		},
		{
			name: "ldap is dropped as unfetchable",
			in:   []string{"ldap://ca.example/cn=crl", "https://ca.example/crl"},
			want: []string{"https://ca.example/crl"},
		},
		{
			name: "only unfetchable schemes yields nothing",
			in:   []string{"ldap://ca.example/cn=crl"},
			want: nil,
		},
		{
			name: "no distribution points",
			in:   nil,
			want: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cert := &x509.Certificate{CRLDistributionPoints: tt.in}
			assert.Equal(t, tt.want, CRLDistributionPoints(cert))
		})
	}

	t.Run("nil certificate", func(t *testing.T) {
		assert.Nil(t, CRLDistributionPoints(nil))
	})
}

func TestOCSPResponders(t *testing.T) {
	cert := &x509.Certificate{OCSPServer: []string{
		"http://ocsp.example", "http://ocsp.example", "ldap://ocsp.example",
	}}
	assert.Equal(t, []string{"http://ocsp.example"}, OCSPResponders(cert))
	assert.Nil(t, OCSPResponders(nil))
	assert.Nil(t, OCSPResponders(&x509.Certificate{}))
}

// TestNoRevocationEndpointsIsUndetermined records the intended reading of an
// empty result, which is the whole reason these helpers return a list rather
// than a bool.
func TestNoRevocationEndpointsIsUndetermined(t *testing.T) {
	cert := &x509.Certificate{}
	require.Empty(t, CRLDistributionPoints(cert))
	require.Empty(t, OCSPResponders(cert))

	// A certificate that cannot be checked is undetermined, not good - and
	// under fail mode that is a rejection.
	assert.False(t, RevocationFail.Evaluate(RevocationUndetermined, "the access certificate").Allowed)
	assert.True(t, RevocationWarn.Evaluate(RevocationUndetermined, "the access certificate").Allowed)
}
