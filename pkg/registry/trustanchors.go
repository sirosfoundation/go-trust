package registry

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
	"strings"
	"time"

	"github.com/sirosfoundation/go-trust/pkg/authzen"
)

const (
	// DefaultTrustAnchorTTL applies when a list declares no nextUpdate.
	DefaultTrustAnchorTTL = 24 * time.Hour
	// OverdueTrustAnchorTTL applies when a list's nextUpdate has passed but the
	// list is still valid (the provider is late): a short retry, not zero.
	OverdueTrustAnchorTTL = 15 * time.Minute
	// MaxTrustAnchors bounds the anchors of one list in a response.
	MaxTrustAnchors = 1000
)

// TrustAnchorTypesEnabled returns the trust anchor list types the policy
// enabled for this request (context key return_trust_anchors, written only by
// applyPolicyToRequest). A nil result means the member is off.
func TrustAnchorTypesEnabled(req *authzen.EvaluationRequest) []string {
	if req == nil || req.Context == nil {
		return nil
	}
	return extractStringSliceFromContext(req.Context, authzen.TrustAnchorsPolicyContextKey)
}

// TrustAnchorEnabled reports whether list type t may be returned for req.
func TrustAnchorEnabled(req *authzen.EvaluationRequest, t string) bool {
	for _, e := range TrustAnchorTypesEnabled(req) {
		if e == t {
			return true
		}
	}
	return false
}

// TrustAnchorTTL is how long a client may use a list's anchors, from now.
// nextUpdate and notAfter are the list's own RFC 3339 values (empty when the
// list has none). ok is false when the list must contribute nothing: it is
// past notAfter, or carries a nextUpdate or notAfter that cannot be parsed (a
// list that cannot be dated is not offered).
func TrustAnchorTTL(now time.Time, nextUpdate, notAfter string) (ttl time.Duration, ok bool) {
	var limit time.Time
	if notAfter != "" {
		limit = ParseSourceTime(notAfter)
		if limit.IsZero() || !now.Before(limit) {
			return 0, false
		}
	}
	if nextUpdate == "" {
		ttl = DefaultTrustAnchorTTL
	} else {
		next := ParseSourceTime(nextUpdate)
		if next.IsZero() {
			return 0, false
		}
		if next.After(now) {
			ttl = next.Sub(now)
		} else {
			ttl = OverdueTrustAnchorTTL
		}
	}
	if !limit.IsZero() && now.Add(ttl).After(limit) {
		ttl = limit.Sub(now)
	}
	ttl = ttl.Truncate(time.Second)
	if ttl < time.Second {
		return 0, false
	}
	return ttl, true
}

// BuildTrustAnchorSet assembles a response entry from a verified list: it
// bounds the anchor count, sets the TTL and derives the version from the
// content. ok is false when the list must not be offered (see TrustAnchorTTL).
func BuildTrustAnchorSet(now time.Time, registryName, listType, issuedAt, nextUpdate, notAfter string, anchors []authzen.TrustAnchor) (authzen.TrustAnchorSet, bool) {
	ttl, ok := TrustAnchorTTL(now, nextUpdate, notAfter)
	if !ok || len(anchors) == 0 {
		return authzen.TrustAnchorSet{}, false
	}
	excluded := 0
	if len(anchors) > MaxTrustAnchors {
		excluded = len(anchors) - MaxTrustAnchors
		anchors = anchors[:MaxTrustAnchors]
	}
	// Hashed from the anchors alone: the version changes when the trust
	// content does, not when the provider merely reissues the list.
	sum := sha256.New()
	_ = json.NewEncoder(sum).Encode(anchors)
	return authzen.TrustAnchorSet{
		Registry:   registryName,
		Type:       listType,
		Version:    "sha256:" + hex.EncodeToString(sum.Sum(nil)),
		IssuedAt:   issuedAt,
		NextUpdate: nextUpdate,
		TTLSeconds: int64(ttl / time.Second),
		Anchors:    anchors,
		Excluded:   excluded,
	}, true
}

// AddTrustAnchorSet appends set to resp.Context.TrustAnchors. It fails closed:
// nothing is added unless the decision is true and the policy enabled the
// set's type. A set for the same registry is not added twice.
func AddTrustAnchorSet(resp *authzen.EvaluationResponse, req *authzen.EvaluationRequest, set authzen.TrustAnchorSet) {
	if resp == nil || !resp.Decision || len(set.Anchors) == 0 || !TrustAnchorEnabled(req, set.Type) {
		return
	}
	if resp.Context == nil {
		resp.Context = &authzen.EvaluationResponseContext{}
	}
	for _, e := range resp.Context.TrustAnchors {
		if e.Registry == set.Registry && e.Type == set.Type {
			return
		}
	}
	resp.Context.TrustAnchors = append(resp.Context.TrustAnchors, set)
}

// mergeTrustAnchors copies the trust anchor lists of the positive child
// responses into resp (the aggregate of a multi-registry strategy or
// composite), in a stable order. resp itself must already be positive.
func mergeTrustAnchors(resp *authzen.EvaluationResponse, children []*authzen.EvaluationResponse) {
	if resp == nil || !resp.Decision {
		return
	}
	for _, c := range children {
		if c == nil || !c.Decision || c.Context == nil {
			continue
		}
		for _, set := range c.Context.TrustAnchors {
			dup := false
			if resp.Context != nil {
				for _, e := range resp.Context.TrustAnchors {
					if e.Registry == set.Registry && e.Type == set.Type {
						dup = true
						break
					}
				}
			}
			if dup {
				continue
			}
			if resp.Context == nil {
				resp.Context = &authzen.EvaluationResponseContext{}
			}
			resp.Context.TrustAnchors = append(resp.Context.TrustAnchors, set)
		}
	}
	if resp.Context != nil {
		sort.SliceStable(resp.Context.TrustAnchors, func(i, j int) bool {
			a, b := resp.Context.TrustAnchors[i], resp.Context.TrustAnchors[j]
			if a.Type != b.Type {
				return a.Type < b.Type
			}
			return a.Registry < b.Registry
		})
	}
}

// ResolutionOnlyAware is implemented by registries whose resolution-only
// support depends on the request: the VICAL and RICAL registries answer a
// resolution-only request only to deliver trust anchors, and only when the
// policy enabled them and the request names the registry.
type ResolutionOnlyAware interface {
	SupportsResolutionOnlyFor(req *authzen.EvaluationRequest) bool
}

// supportsResolutionOnly reports whether reg takes part in a resolution-only
// request.
func supportsResolutionOnly(reg TrustRegistry, req *authzen.EvaluationRequest) bool {
	if a, ok := reg.(ResolutionOnlyAware); ok && a.SupportsResolutionOnlyFor(req) {
		return true
	}
	return reg.SupportsResolutionOnly()
}

// TrustAnchorResolutionTarget reports whether a resolution-only request is a
// preload of the named registry's list of the given type: the policy enabled
// the type and subject.id names the registry.
func TrustAnchorResolutionTarget(req *authzen.EvaluationRequest, registryName, listType string) bool {
	return req != nil && req.IsResolutionOnlyRequest() &&
		TrustAnchorEnabled(req, listType) &&
		strings.EqualFold(req.Subject.ID, registryName)
}
