package rpcert

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ─── CheckWRPACWRPRCBinding ──────────────────────────────────────────────────

func TestCheckWRPACWRPRCBinding_Match(t *testing.T) {
	ent := &RPEntitlements{Subject: WRPRCSubject{ID: "LEIXG-123"}}
	err := CheckWRPACWRPRCBinding("LEIXG-123", ent)
	assert.NoError(t, err)
}

func TestCheckWRPACWRPRCBinding_Mismatch(t *testing.T) {
	ent := &RPEntitlements{Subject: WRPRCSubject{ID: "LEIXG-999"}}
	err := CheckWRPACWRPRCBinding("LEIXG-123", ent)
	require.Error(t, err)

	var bindErr *BindingError
	require.True(t, errors.As(err, &bindErr))
	assert.Equal(t, "LEIXG-123", bindErr.WRPACOrgID)
	assert.Equal(t, "LEIXG-999", bindErr.WRPRCSubID)
	assert.Contains(t, err.Error(), "LEIXG-123")
	assert.Contains(t, err.Error(), "LEIXG-999")
}

func TestCheckWRPACWRPRCBinding_EmptyWRPACOrgID(t *testing.T) {
	ent := &RPEntitlements{Subject: WRPRCSubject{ID: "LEIXG-999"}}
	// wrpac org absent — cannot enforce; expect no error
	assert.NoError(t, CheckWRPACWRPRCBinding("", ent))
}

func TestCheckWRPACWRPRCBinding_EmptyWRPRCSubID(t *testing.T) {
	ent := &RPEntitlements{Subject: WRPRCSubject{ID: ""}}
	assert.NoError(t, CheckWRPACWRPRCBinding("LEIXG-123", ent))
}

func TestCheckWRPACWRPRCBinding_NilWRPRC(t *testing.T) {
	assert.NoError(t, CheckWRPACWRPRCBinding("LEIXG-123", nil))
}

// ─── DCQLPolicyEvaluator ──────────────────────────────────────────────────────

func TestStrictDCQLPolicyEvaluator_AllowsMatchingTypes(t *testing.T) {
	ev := StrictDCQLPolicyEvaluator{}
	ent := &RPEntitlements{
		RPIdentifier:      "rp1",
		AllowedAttributes: []string{"eu.europa.ec.eudi.pid.1", "org.iso.18013.5.1.mDL"},
	}
	result := ev.Evaluate(context.Background(), ent, []string{"eu.europa.ec.eudi.pid.1"})
	assert.True(t, result.Allowed)
	assert.Empty(t, result.OverRequestedTypes)
}

func TestStrictDCQLPolicyEvaluator_BlocksOverRequest(t *testing.T) {
	ev := StrictDCQLPolicyEvaluator{}
	ent := &RPEntitlements{
		RPIdentifier:      "rp1",
		AllowedAttributes: []string{"eu.europa.ec.eudi.pid.1"},
	}
	result := ev.Evaluate(context.Background(), ent, []string{"eu.europa.ec.eudi.pid.1", "org.iso.18013.5.1.mDL"})
	assert.False(t, result.Allowed)
	assert.Contains(t, result.OverRequestedTypes, "org.iso.18013.5.1.mDL")
	assert.Contains(t, result.Message, "AUTHZ-ATT-01-FAIL")
}

func TestStrictDCQLPolicyEvaluator_CaseInsensitive(t *testing.T) {
	ev := StrictDCQLPolicyEvaluator{}
	ent := &RPEntitlements{
		RPIdentifier:      "rp1",
		AllowedAttributes: []string{"Eu.Europa.Ec.Eudi.Pid.1"},
	}
	result := ev.Evaluate(context.Background(), ent, []string{"eu.europa.ec.eudi.pid.1"})
	assert.True(t, result.Allowed)
}

func TestStrictDCQLPolicyEvaluator_EmptyAllowedSkipsEnforcement(t *testing.T) {
	ev := StrictDCQLPolicyEvaluator{}
	ent := &RPEntitlements{RPIdentifier: "rp1"} // no allowed attrs
	result := ev.Evaluate(context.Background(), ent, []string{"anything"})
	assert.True(t, result.Allowed, "no registered types means cannot enforce; should permit")
}

func TestStrictDCQLPolicyEvaluator_NoRequestedTypes(t *testing.T) {
	ev := StrictDCQLPolicyEvaluator{}
	ent := &RPEntitlements{AllowedAttributes: []string{"pid"}}
	result := ev.Evaluate(context.Background(), ent, nil)
	assert.True(t, result.Allowed)
}

func TestPermissiveDCQLPolicyEvaluator_AlwaysAllows(t *testing.T) {
	ev := PermissiveDCQLPolicyEvaluator{}
	ent := &RPEntitlements{
		RPIdentifier:      "rp1",
		AllowedAttributes: []string{"eu.europa.ec.eudi.pid.1"},
	}
	result := ev.Evaluate(context.Background(), ent, []string{"eu.europa.ec.eudi.pid.1", "org.iso.18013.5.1.mDL"})
	assert.True(t, result.Allowed, "permissive evaluator must always allow")
	assert.NotEmpty(t, result.OverRequestedTypes, "but still reports over-requested types")
	assert.Contains(t, result.Message, "WARN")
}

// ─── TrustEvaluationError ────────────────────────────────────────────────────

func TestTrustEvaluationError_ErrorString(t *testing.T) {
	e := NewTrustEvaluationError(ErrCodeTrustAnchorInvalid, "signer not in LoTE", nil)
	assert.Contains(t, e.Error(), "TRUST_ANCHOR_INVALID")
	assert.Contains(t, e.Error(), "signer not in LoTE")
}

func TestTrustEvaluationError_WithCause(t *testing.T) {
	cause := errors.New("x509: certificate expired")
	e := NewTrustEvaluationError(ErrCodeCertificateInvalid, "validation failed", cause)
	assert.Contains(t, e.Error(), "CERTIFICATE_INVALID")
	assert.Contains(t, e.Error(), "x509: certificate expired")
	assert.ErrorIs(t, e, cause)
}

func TestTrustEvaluationError_Codes(t *testing.T) {
	codes := []TrustEvaluationErrorCode{
		ErrCodeTrustAnchorInvalid,
		ErrCodeCertificateInvalid,
		ErrCodeBindingFailed,
		ErrCodeWrongEntitlement,
		ErrCodeRegistrationInvalid,
		ErrCodeAttestationTypeNotRegistered,
		ErrCodeIntermediaryNotAuthorized,
	}
	for _, code := range codes {
		e := NewTrustEvaluationError(code, "test", nil)
		assert.Equal(t, code, e.Code)
	}
}

func TestBindingError_ErrorString(t *testing.T) {
	e := &BindingError{WRPACOrgID: "A", WRPRCSubID: "B"}
	assert.Contains(t, e.Error(), "A")
	assert.Contains(t, e.Error(), "B")
	assert.Contains(t, e.Error(), "ARF RPRC_16")
}
