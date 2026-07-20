// WRPRC entitlement URI constants per ETSI TS 119 475 v1.1.1 Annex A.
//
// These URIs are used in the `entitlements` claim of a WRPRC JWT payload
// (Table 7, GEN-5.2.4-03) to identify the role(s) assigned to the WRP.
// At least one entitlement URI must be present. The corresponding OIDs
// are id-etsi-wrpa-entitlement 1..10.
//
// Sub-entitlement URIs for Payment Service Providers are defined in Annex A.3.1
// and are in the /SubEntitlement/ path.
package rpcert

import "fmt"

// Entitlement role URIs (Annex A.2, id-etsi-wrpa-entitlement 1–10).
const (
	// EntitlementServiceProvider is the general service provider role.
	// OID: id-etsi-wrpa-entitlement 1 (A.2.1)
	EntitlementServiceProvider = "https://uri.etsi.org/19475/Entitlement/Service_Provider"

	// EntitlementQEAAProvider is for QTSPs issuing qualified electronic
	// attestations of attributes.
	// OID: id-etsi-wrpa-entitlement 2 (A.2.2)
	EntitlementQEAAProvider = "https://uri.etsi.org/19475/Entitlement/QEAA_Provider"

	// EntitlementNonQEAAProvider is for non-qualified EAA providers.
	// OID: id-etsi-wrpa-entitlement 3 (A.2.3)
	EntitlementNonQEAAProvider = "https://uri.etsi.org/19475/Entitlement/Non_Q_EAA_Provider"

	// EntitlementPUBEAAProvider is for public sector bodies or their agents
	// issuing attestations from authentic sources.
	// OID: id-etsi-wrpa-entitlement 4 (A.2.4)
	EntitlementPUBEAAProvider = "https://uri.etsi.org/19475/Entitlement/PUB_EAA_Provider"

	// EntitlementPIDProvider is the provider of person identification data.
	// OID: id-etsi-wrpa-entitlement 5 (A.2.5)
	EntitlementPIDProvider = "https://uri.etsi.org/19475/Entitlement/PID_Provider"

	// EntitlementQCertForESealProvider is for QTSPs issuing qualified
	// certificates for electronic seals.
	// OID: id-etsi-wrpa-entitlement 6 (A.2.6)
	EntitlementQCertForESealProvider = "https://uri.etsi.org/19475/Entitlement/QCert_for_ESeal_Provider"

	// EntitlementQCertForESigProvider is for QTSPs issuing qualified
	// certificates for electronic signatures.
	// OID: id-etsi-wrpa-entitlement 7 (A.2.7)
	EntitlementQCertForESigProvider = "https://uri.etsi.org/19475/Entitlement/QCert_for_ESig_Provider"

	// EntitlementRQSealCDsProvider is for QTSPs managing remote qualified
	// electronic seal creation devices.
	// OID: id-etsi-wrpa-entitlement 8 (A.2.8)
	EntitlementRQSealCDsProvider = "https://uri.etsi.org/19475/Entitlement/rQSealCDs_Provider"

	// EntitlementRQSigCDsProvider is for QTSPs managing remote qualified
	// electronic signature creation devices.
	// OID: id-etsi-wrpa-entitlement 9 (A.2.9)
	EntitlementRQSigCDsProvider = "https://uri.etsi.org/19475/Entitlement/rQSigCDs_Provider"

	// EntitlementESigESealCreationProvider is for non-qualified providers
	// of remote signature/seal creation.
	// OID: id-etsi-wrpa-entitlement 10 (A.2.10)
	EntitlementESigESealCreationProvider = "https://uri.etsi.org/19475/Entitlement/ESig_ESeal_Creation_Provider"
)

// AllEntitlementURIs is the complete set of Annex A.2 entitlement URIs.
var AllEntitlementURIs = []string{
	EntitlementServiceProvider,
	EntitlementQEAAProvider,
	EntitlementNonQEAAProvider,
	EntitlementPUBEAAProvider,
	EntitlementPIDProvider,
	EntitlementQCertForESealProvider,
	EntitlementQCertForESigProvider,
	EntitlementRQSealCDsProvider,
	EntitlementRQSigCDsProvider,
	EntitlementESigESealCreationProvider,
}

// Payment Service Provider sub-entitlement URIs (Annex A.3.1).
const (
	// SubEntitlementPSPAS is the Account Servicing Payment Service Provider.
	SubEntitlementPSPAS = "https://uri.etsi.org/19475/SubEntitlement/psp/psp-as"

	// SubEntitlementPSPPI is the Payment Initiation Service Provider.
	SubEntitlementPSPPI = "https://uri.etsi.org/19475/SubEntitlement/psp/psp-pi"

	// SubEntitlementPSPAI is the Account Information Service Provider.
	SubEntitlementPSPAI = "https://uri.etsi.org/19475/SubEntitlement/psp/psp-ai"

	// SubEntitlementPSPIC is the Payment Service Provider issuing
	// card-based payment instruments.
	SubEntitlementPSPIC = "https://uri.etsi.org/19475/SubEntitlement/psp/psp-ic"

	// SubEntitlementPSPUnspecified is the unspecified PSP role.
	SubEntitlementPSPUnspecified = "https://uri.etsi.org/19475/SubEntitlement/psp/unspecified"
)

// HasEntitlement returns true if the given entitlement URI is present in the
// RPEntitlements.EntitlementURIs slice.
func (e *RPEntitlements) HasEntitlement(uri string) bool {
	for _, u := range e.EntitlementURIs {
		if u == uri {
			return true
		}
	}
	return false
}

// IsEAAProvider returns true when the RP holds at least one EAA-issuing
// entitlement (QEAA, Non-Q-EAA, or PUB-EAA).
func (e *RPEntitlements) IsEAAProvider() bool {
	return e.HasEntitlement(EntitlementQEAAProvider) ||
		e.HasEntitlement(EntitlementNonQEAAProvider) ||
		e.HasEntitlement(EntitlementPUBEAAProvider)
}

// BindingError is returned when WRPAC and WRPRC subject identifiers do not match.
type BindingError struct {
	WRPACOrgID string
	WRPRCSubID string
}

func (e *BindingError) Error() string {
	return fmt.Sprintf("WRPAC organization_identifier %q does not match WRPRC sub.id %q (ARF RPRC_16, TS 119 475 §5.1)", e.WRPACOrgID, e.WRPRCSubID)
}

// CheckWRPACWRPRCBinding verifies that the organization_identifier from the WRPAC
// matches the sub.id of the WRPRC per ARF RPRC_16 and ETSI TS 119 475 §5.1.
//
// Either argument being empty means "not present" — the check is only enforced
// when both values are non-empty, so callers in WRPRC-only flows pass "" for
// wrpacOrgID without triggering a spurious error.
func CheckWRPACWRPRCBinding(wrpacOrgID string, wrprc *RPEntitlements) error {
	if wrpacOrgID == "" || wrprc == nil || wrprc.Subject.ID == "" {
		return nil
	}
	if wrpacOrgID != wrprc.Subject.ID {
		return &BindingError{WRPACOrgID: wrpacOrgID, WRPRCSubID: wrprc.Subject.ID}
	}
	return nil
}

// ServiceBindingError is returned when WRPAC and WRPRC service identifiers do
// not match. A nil WRPACServiceID or a WRPRC without service_identifier are
// both treated as "absent" and cause no error — see CheckWRPACWRPRCServiceBinding.
type ServiceBindingError struct {
	WRPACServiceID string
	WRPRCServiceID string
}

func (e *ServiceBindingError) Error() string {
	return fmt.Sprintf(
		"WRPAC service_identifier %q does not match WRPRC service_identifier %q"+
			" — service-level binding check failed (Stefan Santesson convention,"+
			" OID 0.4.0.19475.99.1 pending ETSI standardisation)",
		e.WRPACServiceID, e.WRPRCServiceID,
	)
}

// CheckWRPACWRPRCServiceBinding verifies that the service_identifier from the
// WRPAC Subject DN (OIDWRPACServiceIdentifier = 0.4.0.19475.99.1) matches the
// "service_identifier" claim in the WRPRC JWT.
//
// This is a service-level binding check that complements the organisation-level
// binding performed by CheckWRPACWRPRCBinding. It allows distinguishing between
// multiple WRPAC/WRPRC pairs issued to the same organisation for different
// services (e.g. a sign-in service and a payment service).
//
// The check is OPTIONAL and only enforced when BOTH sides carry the value:
//   - wrpacServiceID is the value from X5CEnrichmentResult.WRPACServiceID.
//     If empty (strict ETSI cert without the attribute), the check is skipped.
//   - wrprc.ServiceIdentifier is the WRPRC JWT "service_identifier" claim.
//     If empty (WRPRC issued before this convention), the check is skipped.
//
// Callers MUST still call CheckWRPACWRPRCBinding for organisation-level binding
// before calling this function — the two checks are complementary, not alternatives.
//
// Background: Stefan Santesson (PTS Sweden) proposed this convention as a
// de-facto interoperability mechanism pending ETSI standardisation. It is NOT
// part of ETSI TS 119 411-8 v1.1.1 or TS 119 475 v1.1.1.
//
// TODO(etsi): Once ETSI formally assigns the OID and standardises the WRPRC
// claim name, update OIDWRPACServiceIdentifier (wrpac.go) and the JSON tag
// on RPEntitlements.ServiceIdentifier to match.
func CheckWRPACWRPRCServiceBinding(wrpacServiceID string, wrprc *RPEntitlements) error {
	if wrpacServiceID == "" || wrprc == nil || wrprc.ServiceIdentifier == "" {
		// One or both sides absent — check is not applicable.
		return nil
	}
	if wrpacServiceID != wrprc.ServiceIdentifier {
		return &ServiceBindingError{
			WRPACServiceID: wrpacServiceID,
			WRPRCServiceID: wrprc.ServiceIdentifier,
		}
	}
	return nil
}
