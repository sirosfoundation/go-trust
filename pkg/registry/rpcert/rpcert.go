// Package rpcert provides an abstraction layer for Relying Party registration
// certificate (WRPRC) validation and entitlement extraction.
//
// The WRPRC format is not yet finalized in the EUDI Wallet specifications —
// it could be X.509, SD-JWT, or CBOR. This package defines format-agnostic
// interfaces so the validation pipeline works regardless of the final format.
//
// References:
//   - ETSI TS 119 475 v1.1.1 — RP attributes supporting Wallet user's authorisation decisions
//   - ETSI TS 119 411-8 v1.1.1 — Access Certificate Policy for EUDI Wallet Relying Parties
//   - ARF RPRC_16 to RPRC_21 — Registration certificate validation requirements
package rpcert

import (
	"context"
	"fmt"
	"time"
)

// RPEntitlements represents the entitlements and registration data extracted
// from a Relying Party Registration Certificate or National Register lookup.
type RPEntitlements struct {
	// RPIdentifier is the unique identifier of the Relying Party
	// (e.g., from the WRPAC Subject or registration entry).
	RPIdentifier string `json:"rp_identifier"`

	// AllowedAttributes lists the attribute names the RP is entitled to request.
	// Used for over-request detection per TS 119 475.
	AllowedAttributes []string `json:"allowed_attributes,omitempty"`

	// Purpose describes the registered purpose for which the RP requests attributes.
	Purpose string `json:"purpose,omitempty"`

	// RegistrationStatus indicates the RP's current registration status.
	// Values: "registered", "suspended", "revoked", "not_found".
	RegistrationStatus RegistrationStatus `json:"registration_status"`

	// ValidFrom is when the registration/entitlements become valid.
	ValidFrom *time.Time `json:"valid_from,omitempty"`

	// ValidUntil is when the registration/entitlements expire.
	ValidUntil *time.Time `json:"valid_until,omitempty"`

	// Intermediary indicates whether the RP is registered as an intermediary/broker.
	Intermediary bool `json:"intermediary,omitempty"`

	// IntermediaryFor lists RP identifiers this intermediary may act on behalf of.
	IntermediaryFor []string `json:"intermediary_for,omitempty"`

	// Raw contains the raw registration certificate data for downstream consumers.
	Raw interface{} `json:"raw,omitempty"`
}

// RegistrationStatus represents the registration state of an RP.
type RegistrationStatus string

const (
	StatusRegistered RegistrationStatus = "registered"
	StatusSuspended  RegistrationStatus = "suspended"
	StatusRevoked    RegistrationStatus = "revoked"
	StatusNotFound   RegistrationStatus = "not_found"
	StatusUnknown    RegistrationStatus = "unknown"
)

// IsValid returns true if the RP's registration status allows presentations.
func (e *RPEntitlements) IsValid() bool {
	if e.RegistrationStatus != StatusRegistered {
		return false
	}
	now := time.Now()
	if e.ValidFrom != nil && now.Before(*e.ValidFrom) {
		return false
	}
	if e.ValidUntil != nil && now.After(*e.ValidUntil) {
		return false
	}
	return true
}

// RegistrationCertValidator validates a Relying Party Registration Certificate
// and extracts entitlements from it. Implementations handle specific WRPRC formats
// (X.509, SD-JWT, CBOR, etc.).
type RegistrationCertValidator interface {
	// Validate parses and validates the registration certificate data,
	// returning the extracted entitlements. The certData format depends
	// on the implementation (PEM-encoded X.509, SD-JWT string, CBOR bytes, etc.).
	Validate(ctx context.Context, certData []byte) (*RPEntitlements, error)

	// Format returns the certificate format this validator handles
	// (e.g., "x509", "sd-jwt", "cbor").
	Format() string
}

// NationalRegisterClient queries the National Register API (TS5/TS6) to look up
// RP registration data when no WRPRC is provided by the RP.
type NationalRegisterClient interface {
	// LookupRP queries the register for an RP's registration status and entitlements.
	LookupRP(ctx context.Context, rpIdentifier string) (*RPEntitlements, error)

	// Healthy returns true if the register API is reachable.
	Healthy() bool
}

// OverRequestResult contains the result of comparing requested attributes
// against RP entitlements.
type OverRequestResult struct {
	// Allowed lists attributes the RP is entitled to request.
	Allowed []string `json:"allowed"`

	// Requested lists all attributes the RP is requesting.
	Requested []string `json:"requested"`

	// OverRequested lists attributes requested but not in the RP's entitlements.
	OverRequested []string `json:"over_requested,omitempty"`

	// IsOverRequest is true if the RP is requesting attributes beyond their entitlements.
	IsOverRequest bool `json:"is_over_request"`
}

// DetectOverRequest compares the requested attributes against the RP's
// entitled attributes and returns details about any over-request.
func DetectOverRequest(entitlements *RPEntitlements, requestedAttributes []string) *OverRequestResult {
	if entitlements == nil || len(entitlements.AllowedAttributes) == 0 {
		// No entitlement data available — cannot determine over-request
		return &OverRequestResult{
			Requested:     requestedAttributes,
			IsOverRequest: false,
		}
	}

	allowed := make(map[string]bool, len(entitlements.AllowedAttributes))
	for _, attr := range entitlements.AllowedAttributes {
		allowed[attr] = true
	}

	var overRequested []string
	for _, attr := range requestedAttributes {
		if !allowed[attr] {
			overRequested = append(overRequested, attr)
		}
	}

	return &OverRequestResult{
		Allowed:       entitlements.AllowedAttributes,
		Requested:     requestedAttributes,
		OverRequested: overRequested,
		IsOverRequest: len(overRequested) > 0,
	}
}

// Config configures the RP certificate validation pipeline.
type Config struct {
	// CertFormat specifies the expected WRPRC format ("x509", "sd-jwt", "cbor").
	// Determines which RegistrationCertValidator implementation is used.
	CertFormat string `json:"cert_format,omitempty" yaml:"cert_format,omitempty"`

	// RegisterURL is the base URL for the National Register API (TS5/TS6).
	// Used as fallback when no WRPRC is provided by the RP.
	RegisterURL string `json:"register_url,omitempty" yaml:"register_url,omitempty"`

	// StrictEntitlementCheck controls whether over-request results in rejection (true)
	// or just a warning in the response (false). Defaults to false (warn-only).
	StrictEntitlementCheck bool `json:"strict_entitlement_check,omitempty" yaml:"strict_entitlement_check,omitempty"`

	// AllowWithoutWRPRC controls whether presentations are allowed when no WRPRC
	// is available and the National Register lookup fails. Defaults to true.
	AllowWithoutWRPRC bool `json:"allow_without_wrprc,omitempty" yaml:"allow_without_wrprc,omitempty"`

	// Timeout for National Register API calls.
	Timeout time.Duration `json:"timeout,omitempty" yaml:"timeout,omitempty"`
}

// DefaultConfig returns a Config with sensible defaults.
func DefaultConfig() Config {
	return Config{
		CertFormat:             "x509",
		StrictEntitlementCheck: false,
		AllowWithoutWRPRC:      true,
		Timeout:                10 * time.Second,
	}
}

// ValidatorRegistry maps certificate formats to their validators.
// This allows runtime selection of the appropriate validator based on config.
type ValidatorRegistry struct {
	validators map[string]RegistrationCertValidator
}

// NewValidatorRegistry creates a new ValidatorRegistry.
func NewValidatorRegistry() *ValidatorRegistry {
	return &ValidatorRegistry{
		validators: make(map[string]RegistrationCertValidator),
	}
}

// Register adds a validator for the given format.
func (r *ValidatorRegistry) Register(format string, v RegistrationCertValidator) {
	r.validators[format] = v
}

// Get returns the validator for the given format, or an error if not registered.
func (r *ValidatorRegistry) Get(format string) (RegistrationCertValidator, error) {
	v, ok := r.validators[format]
	if !ok {
		return nil, fmt.Errorf("no registration certificate validator registered for format %q", format)
	}
	return v, nil
}

// Formats returns the list of registered validator formats.
func (r *ValidatorRegistry) Formats() []string {
	formats := make([]string, 0, len(r.validators))
	for f := range r.validators {
		formats = append(formats, f)
	}
	return formats
}
