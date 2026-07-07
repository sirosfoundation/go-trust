// Package rpcert — DCQL policy evaluator interface and built-in implementations.
//
// DCQLPolicyEvaluator checks whether a credential request (DCQL query) is within
// the scope authorised by the RP's WRPRC entitlements. The evaluation is invoked
// after WRPRC signature verification, before the wallet discloses attributes.
//
// The interface is designed for injection: callers that need EDP (Electronic Data
// Policy) enforcement inject their own implementation; those that only need
// entitlement-level enforcement use StrictDCQLPolicyEvaluator; those that want
// audit-only warnings use PermissiveDCQLPolicyEvaluator.
//
// User-override prompts (RFC003 AUTHZ-EDPV-01-OVERRIDE, AUTHZ-EDPV-02-OVERRIDE)
// are NOT in this package — they are a UI/UX concern that belongs in the wallet
// frontend. This package returns typed errors; the caller decides what to present.
//
// References:
//   - ETSI TS 119 475 v1.1.1 Tables 8–9 — WRPRC credential queries
//   - RFC003 §10.2.3 AUTHZ-ENT-*, AUTHZ-EDPV-*
package rpcert

import (
	"context"
	"fmt"
	"strings"
)

// DCQLPolicyResult is returned by DCQLPolicyEvaluator.Evaluate.
type DCQLPolicyResult struct {
	// Allowed indicates whether the request may proceed.
	Allowed bool

	// OverRequestedTypes lists credential types/formats present in the request
	// but absent from the RP's registered credentials array. Empty when Allowed=true.
	OverRequestedTypes []string

	// Message is a human-readable description of the outcome, suitable for
	// inclusion in audit logs or deny-reason fields.
	Message string
}

// DCQLPolicyEvaluator checks whether a DCQL credential request is authorised
// by the RP's WRPRC entitlements.
type DCQLPolicyEvaluator interface {
	// Evaluate checks the request against the entitlements. requestedTypes is
	// the list of credential types (vct values or ISO mdoc doctypes) being
	// requested. Returns a DCQLPolicyResult; never returns a Go error — policy
	// outcomes are communicated through the result struct.
	Evaluate(ctx context.Context, ent *RPEntitlements, requestedTypes []string) DCQLPolicyResult
}

// StrictDCQLPolicyEvaluator denies requests containing credential types not
// listed in the RP's registered credentials array. Use this for production
// deployments where over-requesting must be blocked at the trust layer.
type StrictDCQLPolicyEvaluator struct{}

// Evaluate returns Allowed=false when any requested type is absent from the
// RP's entitlements.ProvidedAttestations (for providers) or RP credential list.
func (StrictDCQLPolicyEvaluator) Evaluate(_ context.Context, ent *RPEntitlements, requestedTypes []string) DCQLPolicyResult {
	if ent == nil || len(requestedTypes) == 0 {
		return DCQLPolicyResult{Allowed: true, Message: "no credential types to check"}
	}

	// Build allowed set from AllowedAttributes (top-level claim names) plus
	// any credential format/meta keys from ProvidedAttestations.
	allowed := make(map[string]bool, len(ent.AllowedAttributes))
	for _, a := range ent.AllowedAttributes {
		allowed[strings.ToLower(a)] = true
	}
	for _, c := range ent.ProvidedAttestations {
		if c.Format != "" {
			allowed[strings.ToLower(c.Format)] = true
		}
	}

	if len(allowed) == 0 {
		// No registered credential data — cannot enforce; permit.
		return DCQLPolicyResult{Allowed: true, Message: "no registered credential types; cannot enforce DCQL policy"}
	}

	var over []string
	for _, t := range requestedTypes {
		if !allowed[strings.ToLower(t)] {
			over = append(over, t)
		}
	}
	if len(over) == 0 {
		return DCQLPolicyResult{Allowed: true, Message: "all requested types are within entitlements"}
	}
	return DCQLPolicyResult{
		Allowed:            false,
		OverRequestedTypes: over,
		Message: fmt.Sprintf("RP %q is requesting credential types not in entitlements: %s (AUTHZ-ATT-01-FAIL)",
			ent.RPIdentifier, strings.Join(over, ", ")),
	}
}

// PermissiveDCQLPolicyEvaluator always permits the request but populates
// OverRequestedTypes for audit. Use this in warn-only deployments where the
// wallet wants to log over-requests without blocking the flow.
type PermissiveDCQLPolicyEvaluator struct{}

// Evaluate always returns Allowed=true but notes any over-requested types.
func (PermissiveDCQLPolicyEvaluator) Evaluate(ctx context.Context, ent *RPEntitlements, requestedTypes []string) DCQLPolicyResult {
	strict := StrictDCQLPolicyEvaluator{}
	r := strict.Evaluate(ctx, ent, requestedTypes)
	r.Allowed = true // override — permissive mode never blocks
	if len(r.OverRequestedTypes) > 0 {
		r.Message = fmt.Sprintf("WARN: over-requested types (not blocking): %s", strings.Join(r.OverRequestedTypes, ", "))
	}
	return r
}
