package mdocrical

import (
	"context"
	"encoding/base64"
	"fmt"
	"time"

	"github.com/sirosfoundation/go-trust/pkg/authzen"
	"github.com/sirosfoundation/go-trust/pkg/registry"
)

// evaluateTrustAnchorPreload answers a resolution-only request: it delivers
// the RICAL's anchors (policy return_trust_anchors: [rical]) so a client can
// warm its offline cache. subject.id names this registry.
func (r *Registry) evaluateTrustAnchorPreload(ctx context.Context, req *authzen.EvaluationRequest) (*authzen.EvaluationResponse, error) {
	if !r.SupportsResolutionOnlyFor(req) {
		return r.denyWithReason("resolution-only requests are not supported for this registry"), nil
	}
	rical, err := r.getRical(ctx)
	if err != nil {
		return r.denyWithReason(fmt.Sprintf("failed to get RICAL: %v", err)), nil
	}
	set, ok := r.trustAnchorSet(rical)
	if !ok {
		return r.denyWithReason("the RICAL has no valid trust anchors to offer"), nil
	}
	resp := &authzen.EvaluationResponse{
		Decision: true,
		Context: &authzen.EvaluationResponseContext{
			Reason: map[string]interface{}{"trust_anchor": "mdoc_rical", "rical_provider": rical.Provider},
		},
	}
	registry.AddTrustAnchorSet(resp, req, set)
	return resp, nil
}

// SupportsResolutionOnlyFor is true only for a preload of this registry's list:
// the policy enabled "rical" and subject.id names the registry.
func (r *Registry) SupportsResolutionOnlyFor(req *authzen.EvaluationRequest) bool {
	return registry.TrustAnchorResolutionTarget(req, r.config.Name, authzen.TrustAnchorTypeRICAL)
}

// trustAnchorSet is the response member for a verified RICAL: every entry (the
// non-CA entries carry constraints too) with the fields a client needs to find
// the first matching entry bottom-up (F.3.2.6) and apply its constraints. A
// constraint the PDP cannot evaluate is flagged, so the client treats it as
// not satisfied. ok is false when the list must not be offered.
func (r *Registry) trustAnchorSet(l *RICAL) (authzen.TrustAnchorSet, bool) {
	anchors := make([]authzen.TrustAnchor, 0, len(l.CertificateInfos))
	for i := range l.CertificateInfos {
		info := &l.CertificateInfos[i]
		if _, err := registry.ParseCertificate(info.Certificate, r.config.CryptoExt); err != nil {
			continue
		}
		a := authzen.TrustAnchor{
			X5C:            base64.StdEncoding.EncodeToString(info.Certificate),
			Type:           info.Type,
			Name:           info.Name,
			IssuingCountry: info.IssuingCountry,
		}
		if len(info.SKI) > 0 {
			a.SKI = base64.StdEncoding.EncodeToString(info.SKI)
		}
		if len(info.AKI) > 0 {
			a.AKI = base64.StdEncoding.EncodeToString(info.AKI)
		}
		if info.IsTrustAnchor {
			t := true
			a.IsTrustAnchor = &t
		}
		for _, c := range info.constraints() {
			a.TrustConstraints = append(a.TrustConstraints, authzen.TrustAnchorConstraint{
				Policies:            c.Policies,
				EKU:                 c.EKU,
				PathLen:             c.PathLen,
				CertificateProfiles: c.CertificateProfiles,
				// A present-but-empty eku or certificateProfiles member is
				// unsatisfiable here, and omitempty would export it as no
				// restriction at all.
				UnsupportedExtensions: len(c.Extensions) > 0 || (c.EKU != nil && len(c.EKU) == 0) || (c.CertificateProfiles != nil && len(c.CertificateProfiles) == 0),
			})
		}
		anchors = append(anchors, a)
	}
	return registry.BuildTrustAnchorSet(time.Now(), r.config.Name, authzen.TrustAnchorTypeRICAL,
		l.Date, l.NextUpdate, l.NotAfter, anchors)
}
