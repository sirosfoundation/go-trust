package registry

import (
	"net"
	"net/url"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/sirosfoundation/go-trust/pkg/authzen"
)

// maxDisplayNameLen bounds a display name in runes.
const maxDisplayNameLen = 200

// SanitizeDisplayName makes a registry-supplied name safe to show in a consent
// UI: whitespace is collapsed and trimmed, control, format (which includes the
// bidirectional overrides) and other non-printing characters are dropped, and
// the result is capped at maxDisplayNameLen runes. It returns "" when nothing
// printable remains.
func SanitizeDisplayName(name string) string {
	if !utf8.ValidString(name) {
		name = strings.ToValidUTF8(name, "")
	}
	var b strings.Builder
	space := false
	n := 0
	for _, r := range name {
		switch {
		case unicode.IsSpace(r):
			space = b.Len() > 0
			continue
		case unicode.IsControl(r), unicode.Is(unicode.Cf, r), !unicode.IsPrint(r):
			continue
		}
		if n >= maxDisplayNameLen {
			break
		}
		if space {
			b.WriteByte(' ')
			n++
			space = false
			if n >= maxDisplayNameLen {
				break
			}
		}
		b.WriteRune(r)
		n++
	}
	return strings.TrimSpace(b.String())
}

// OriginDomain derives the normalized domain name of the site a subject
// identifier names: the lower-case host of an http(s) URL, of a did:web
// identifier, or of an x509_san_dns/x509_san_uri client_id, without port,
// userinfo or a trailing dot. Internationalized names stay in their ASCII
// (punycode) form. It returns "" for identifiers that do not name a site (hash
// identifiers, URNs, IP addresses).
func OriginDomain(id string) string {
	id = strings.TrimSpace(id)
	var host string
	switch {
	case strings.HasPrefix(id, "x509_san_dns:"):
		host = strings.TrimPrefix(id, "x509_san_dns:")
	case strings.HasPrefix(id, "x509_san_uri:"):
		host = hostOfURL(strings.TrimPrefix(id, "x509_san_uri:"))
	case strings.HasPrefix(id, "did:web:"):
		host = strings.SplitN(strings.TrimPrefix(id, "did:web:"), ":", 2)[0]
		if u, err := url.PathUnescape(host); err == nil {
			host = u
		}
		host = stripPort(host)
	case strings.HasPrefix(id, "https://"), strings.HasPrefix(id, "http://"):
		host = hostOfURL(id)
	default:
		return ""
	}
	return normalizeHost(host)
}

func hostOfURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") {
		return ""
	}
	return u.Hostname()
}

func stripPort(h string) string {
	if host, _, err := net.SplitHostPort(h); err == nil {
		return host
	}
	return h
}

func normalizeHost(h string) string {
	h = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(h), "."))
	if h == "" || len(h) > 253 || net.ParseIP(h) != nil {
		return ""
	}
	for _, label := range strings.Split(h, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return ""
		}
		for _, c := range label {
			if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' {
				return ""
			}
		}
	}
	return h
}

// applyDisplayName ensures a positive response carries a display_name: the
// registry-supplied one (already merged by the strategy) or, failing that, the
// origin domain of the subject. Denials are left untouched.
func applyDisplayName(req *authzen.EvaluationRequest, resp *authzen.EvaluationResponse) {
	if resp == nil || !resp.Decision {
		return
	}
	if resp.Context != nil {
		if name := SanitizeDisplayName(resp.Context.DisplayName); name != "" {
			resp.Context.DisplayName = name
			return
		}
		resp.Context.DisplayName = ""
	}
	if req == nil {
		return
	}
	// An overlong domain is omitted rather than truncated into a misleading host.
	if origin := OriginDomain(req.Subject.ID); origin != "" && len(origin) <= maxDisplayNameLen {
	if origin := OriginDomain(req.Subject.ID); origin != "" && len(origin) <= maxDisplayNameLen {
		if resp.Context == nil {
			resp.Context = &authzen.EvaluationResponseContext{}
		}
		resp.Context.DisplayName = origin
	}
}

// mergeDisplayName carries a registry-supplied display name from the positive
// children into the aggregate of a multi-registry strategy or composite. Children
// finish in no particular order, so the lexically smallest name wins to keep
// responses reproducible. A name only ever comes from a decision that said true.
func mergeDisplayName(resp *authzen.EvaluationResponse, children []*authzen.EvaluationResponse) {
	if resp == nil || !resp.Decision {
		return
	}
	var names []string
	for _, c := range children {
		if c != nil && c.Decision && c.Context != nil && c.Context.DisplayName != "" {
			names = append(names, c.Context.DisplayName)
		}
	}
	if len(names) == 0 {
		return
	}
	sort.Strings(names)
	if resp.Context == nil {
		resp.Context = &authzen.EvaluationResponseContext{}
	}
	resp.Context.DisplayName = names[0]
}
