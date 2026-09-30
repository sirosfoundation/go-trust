// Package emrtd provides a trust registry for ICAO 9303 eMRTD Document Signer
// Certificates (DSCs).
//
// The registry answers one question on behalf of a policy enforcement point
// that has already verified an electronic passport's SOD: does this DSC chain,
// for the claimed issuing state, to a Country Signing CA (CSCA) in our
// reviewed anchor list? It never sees the SOD itself.
//
// # Anchor layout
//
// Anchors are read from AnchorsDir/<ALPHA3>/*.pem (ISO 3166-1 alpha-3
// directory names, e.g. SWE, DEU). The directory name is the country. Each
// certificate's subject C (alpha-2) must correspond to the directory through
// an embedded ISO 3166 table, otherwise the file is skipped and logged.
// Only the anchors tree is ever read: candidate, revoked and provenance
// trees of the anchor repository are not loaded. CRLs are optional and are
// read from CRLsDir/<ALPHA3>/*.crl (DER or PEM).
//
// # Request
//
//	subject:  {type: key, id: "SWE"}               alpha-3 issuing state
//	resource: {type: x5c, key: [DSC, extra...]}    extras are UNTRUSTED
//	action:   {name: "emrtd-document-signer"}
//	context:  {signing_time: RFC 3339}             optional, default now
//
// # Trust model
//
// Certificates in resource.key other than the first are only ever used as
// candidate intermediates (link certificates). They are never anchors, never
// consulted for trust, and are required to carry CA basic constraints. The
// system certificate pool is never used. Chain validation is done here, on
// top of go-cryptoutil signature checking, rather than through crypto/x509's
// Verify, because Verify has no extension point for brainpool curves and
// applies web-PKI rules (extended key usage, critical extension handling)
// that real eMRTD PKI does not follow. See chain.go for each leniency.
package emrtd

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/sirosfoundation/go-cryptoutil"
	"github.com/sirosfoundation/go-cryptoutil/brainpool"
	"github.com/sirosfoundation/go-cryptoutil/ecparams"
	"github.com/sirosfoundation/go-trust/pkg/authzen"
	"github.com/sirosfoundation/go-trust/pkg/registry"
)

// ActionName is the AuthZEN action.name this registry serves.
const ActionName = "emrtd-document-signer"

// Machine-readable deny codes returned in context.reason.code and
// context.reason.admin.code.
const (
	CodeUnknownCountry   = "unknown_country"
	CodeNoAnchor         = "no_anchor"
	CodeChainInvalid     = "chain_invalid"
	CodeCountryMismatch  = "country_mismatch"
	CodeExpired          = "expired"
	CodeNotYetValid      = "not_yet_valid"
	CodeBadKeyUsage      = "bad_key_usage"
	CodeRevoked          = "revoked"
	CodeMalformedRequest = "malformed_request"
)

// maxRequestCerts bounds the number of certificates accepted in resource.key.
const maxRequestCerts = 16

// maxCertB64Len bounds one base64-encoded certificate (~24 KiB of DER),
// checked before decoding so an oversized entry cannot force a large allocation.
const maxCertB64Len = 32 * 1024

// defaultReloadDebounce coalesces bursts of file events (an anchors repo sync
// touches many files) into a single reload.
const defaultReloadDebounce = 250 * time.Millisecond

// defaultRootCheckInterval is how often resolved root locations are compared.
const defaultRootCheckInterval = 30 * time.Second

// Config configures an eMRTD registry.
type Config struct {
	// Name is the registry name (default "emrtd-csca").
	Name string
	// Description is a human-readable description.
	Description string
	// AnchorsDir holds <ALPHA3>/*.pem CSCA (and link) certificates. Required.
	AnchorsDir string
	// CRLsDir optionally holds <ALPHA3>/*.crl files.
	CRLsDir string
	// Watch reloads anchors and CRLs when files change.
	Watch bool
	// CryptoExt extends certificate parsing and signature verification. If
	// nil, a default instance with brainpool support is used.
	CryptoExt *cryptoutil.Extensions
	// Logger receives load and decision logs (default slog.Default()).
	Logger *slog.Logger
	// RootCheckInterval is how often the resolved (symlink-free) location of
	// anchors_dir and crls_dir is re-checked when Watch is on; a change, for
	// example an ancestor directory that is a symlink being swapped, triggers
	// a reload (default 30s). File watches cannot see such a swap.
	RootCheckInterval time.Duration

	// ReloadDebounce is the quiet period after a file event before reloading
	// (default 250ms). A sustained stream of events cannot postpone the reload
	// beyond maxReloadDelayFactor times this value after the first event.
	ReloadDebounce time.Duration

	afterArm func() // test hook: runs after watches are armed, before the reconciling reload
	// Now overrides the clock (tests).
	Now func() time.Time
}

type anchor struct {
	cert   *x509.Certificate
	sha256 string
}

// snapshot is an immutable view of loaded trust data, swapped atomically.
type snapshot struct {
	anchors      map[string][]*anchor  // alpha-3 -> anchors
	crls         map[string][]*crlData // alpha-3 -> CRLs
	fingerprints []string              // sorted anchor SHA-256s, for Info
}

// Registry implements registry.TrustRegistry for eMRTD DSC validation.
type Registry struct {
	cfg  Config
	ext  *cryptoutil.Extensions
	log  *slog.Logger
	snap atomic.Pointer[snapshot]

	reloadMu sync.Mutex
	watcher  *fsnotify.Watcher
	stopCh   chan struct{}
	stopOnce sync.Once
}

var _ registry.TrustRegistry = (*Registry)(nil)

// New loads the anchors and returns a registry. It fails if AnchorsDir is not
// readable or a CRL file in CRLsDir cannot be parsed (an unparseable CRL means
// revocation cannot be checked, which must not silently pass).
func New(cfg Config) (*Registry, error) {
	if cfg.AnchorsDir == "" {
		return nil, errors.New("emrtd: anchors_dir is required")
	}
	if cfg.Name == "" {
		cfg.Name = "emrtd-csca"
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.RootCheckInterval <= 0 {
		cfg.RootCheckInterval = defaultRootCheckInterval
	}
	if cfg.ReloadDebounce <= 0 {
		cfg.ReloadDebounce = defaultReloadDebounce
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	ext := cfg.CryptoExt
	if ext == nil {
		ext = cryptoutil.New()
		brainpool.Register(ext)
		ecparams.Register(ext)
	}
	r := &Registry{cfg: cfg, ext: ext, log: cfg.Logger}
	if err := r.reload(); err != nil {
		return nil, err
	}
	if cfg.Watch {
		if err := r.startWatching(); err != nil {
			return nil, err
		}
		// Changes between the initial load and the watches being armed
		// generate no event; reconcile once now.
		if cfg.afterArm != nil {
			cfg.afterArm()
		}
		if err := r.reload(); err != nil {
			_ = r.Close()
			return nil, err
		}
	}
	return r, nil
}

// Close stops the file watcher.
func (r *Registry) Close() error {
	r.stopOnce.Do(func() {
		if r.stopCh != nil {
			close(r.stopCh)
		}
	})
	r.reloadMu.Lock()
	defer r.reloadMu.Unlock()
	if r.watcher != nil {
		err := r.watcher.Close()
		r.watcher = nil
		return err
	}
	return nil
}

// SupportedResourceTypes implements registry.TrustRegistry.
func (r *Registry) SupportedResourceTypes() []string { return []string{"x5c"} }

// SupportsResolutionOnly implements registry.TrustRegistry.
func (r *Registry) SupportsResolutionOnly() bool { return false }

// Healthy is true once anchors have been loaded.
func (r *Registry) Healthy() bool { return r.snap.Load() != nil }

// Refresh reloads anchors and CRLs from disk. On error the previous data stays
// in effect.
func (r *Registry) Refresh(context.Context) error { return r.reload() }

// Info implements registry.TrustRegistry.
func (r *Registry) Info() registry.RegistryInfo {
	// The fingerprint list is precomputed per snapshot (Info is called on
	// every routed request) and copied out, so a caller that edits the
	// returned slice cannot change later responses or race with readers.
	var anchors []string
	if s := r.snap.Load(); s != nil {
		anchors = append([]string(nil), s.fingerprints...)
	}
	return registry.RegistryInfo{
		Name:         r.cfg.Name,
		Type:         "emrtd",
		Description:  r.cfg.Description,
		Version:      "1.0.0",
		TrustAnchors: anchors,
	}
}

// Countries returns the alpha-3 codes that currently have at least one anchor.
func (r *Registry) Countries() []string {
	s := r.snap.Load()
	if s == nil {
		return nil
	}
	out := make([]string, 0, len(s.anchors))
	for c := range s.anchors {
		out = append(out, c)
	}
	return out
}

// Evaluate implements registry.TrustRegistry.
func (r *Registry) Evaluate(ctx context.Context, req *authzen.EvaluationRequest) (*authzen.EvaluationResponse, error) {
	resp := r.evaluate(ctx, req)
	if !resp.Decision {
		r.log.Info("emrtd denied", "registry", r.cfg.Name, "subject", req.Subject.ID,
			"code", resp.Context.Reason["code"], "detail", resp.Context.Reason["error"])
	}
	return resp, nil
}

func (r *Registry) evaluate(ctx context.Context, req *authzen.EvaluationRequest) *authzen.EvaluationResponse {
	if req.Action == nil || req.Action.Name != ActionName {
		return r.deny(CodeMalformedRequest, "action.name must be "+ActionName)
	}
	if req.Resource.Type != "x5c" {
		return r.deny(CodeMalformedRequest, "resource.type must be x5c")
	}

	if req.Subject.Type != "key" {
		return r.deny(CodeMalformedRequest, "subject.type must be key")
	}

	country := strings.ToUpper(strings.TrimSpace(req.Subject.ID))
	if _, ok := alpha3ToAlpha2[country]; !ok {
		return r.deny(CodeUnknownCountry, fmt.Sprintf("subject.id %q is not an ISO 3166-1 alpha-3 code", req.Subject.ID))
	}

	// Same contract as authzen.EvaluationRequest.Validate: resource.id must be
	// present and equal subject.id. The manager enforces it before dispatch;
	// a direct caller must not be able to bypass it.
	if req.Resource.ID == "" || req.Resource.ID != req.Subject.ID {
		return r.deny(CodeMalformedRequest, "resource.id must be present and match subject.id")
	}

	at, err := r.signingTime(req)
	if err != nil {
		return r.deny(CodeMalformedRequest, err.Error())
	}

	certs, err := r.parseChain(req.Resource.Key)
	if err != nil {
		return r.deny(CodeMalformedRequest, err.Error())
	}
	dsc, extras := certs[0], certs[1:]

	snap := r.snap.Load()
	if snap == nil || len(snap.anchors[country]) == 0 {
		return r.deny(CodeUnknownCountry, "no trust anchors loaded for "+country)
	}

	// The DSC subject C, when present, must agree with the claimed state.
	// A DSC without a C attribute is tolerated (see chain.go leniencies);
	// the anchor, which is directory-scoped, carries the real binding.
	for _, c := range dsc.Subject.Country {
		if !countryMatches(country, c) {
			return r.deny(CodeCountryMismatch,
				fmt.Sprintf("DSC subject C=%q does not match issuing state %s", c, country))
		}
	}

	pl, err := pathLenFromContext(req.Context)
	if err != nil {
		return r.deny(CodeMalformedRequest, err.Error())
	}

	s := newSearch(ctx)
	vc := crlVerdicts{}
	var first *authzen.EvaluationResponse
	var accepted []*x509.Certificate
	found, nameMatched := r.buildPaths(s, dsc, extras, snap.anchors[country], func(p []*x509.Certificate) bool {
		if d := r.checkPath(p, at, snap.crls[country], pl, vc); d != nil {
			if first == nil {
				first = d
			}
			return false
		}
		accepted = p
		return true
	})
	if accepted != nil {
		return r.allow(country, accepted, at)
	}
	if d := r.searchStopped(s); d != nil {
		return d
	}
	if found {
		return first
	}

	// Would it chain for a different state? Then the claim is wrong.
	for other, list := range snap.anchors {
		if other == country {
			continue
		}
		anyPath, _ := r.buildPaths(s, dsc, extras, list, func([]*x509.Certificate) bool { return true })
		if d := r.searchStopped(s); d != nil {
			return d
		}
		if anyPath {
			return r.deny(CodeCountryMismatch,
				fmt.Sprintf("DSC chains to a %s anchor, not %s", other, country))
		}
	}
	if nameMatched {
		return r.deny(CodeChainInvalid, "an anchor with the issuer name exists but no valid signature path was found")
	}
	return r.deny(CodeNoAnchor, "no anchor for "+country+" issued this DSC")
}

// searchStopped returns an explicit denial when the path search was cut short
// by cancellation or by its work budget, so a truncated search is never
// mistaken for an exhaustive one.
func (r *Registry) searchStopped(s *search) *authzen.EvaluationResponse {
	switch {
	case s.canceled:
		return r.deny(CodeChainInvalid, "certificate path search canceled: "+s.ctx.Err().Error())
	case s.exhausted:
		return r.deny(CodeChainInvalid, "certificate path search exceeded its work limit; too many candidate link certificates")
	}
	return nil
}

func (r *Registry) signingTime(req *authzen.EvaluationRequest) (time.Time, error) {
	raw, ok := req.Context["signing_time"]
	if !ok || raw == nil {
		return r.cfg.Now(), nil
	}
	s, ok := raw.(string)
	if !ok {
		return time.Time{}, errors.New("context.signing_time must be an RFC 3339 string")
	}
	// RFC 3339 fractional seconds use a period; Go's parser also accepts a
	// comma, which the documented contract must reject.
	if strings.Contains(s, ",") {
		return time.Time{}, errors.New("context.signing_time is not RFC 3339: fractional seconds must use a period")
	}
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return time.Time{}, fmt.Errorf("context.signing_time is not RFC 3339: %v", err)
	}
	return t, nil
}

func (r *Registry) parseChain(key interface{}) ([]*x509.Certificate, error) {
	var b64 []string
	switch v := key.(type) {
	case []string:
		b64 = v
	case []interface{}:
		if len(v) > maxRequestCerts {
			return nil, fmt.Errorf("resource.key has %d certificates, maximum is %d", len(v), maxRequestCerts)
		}
		for _, item := range v {
			s, ok := item.(string)
			if !ok {
				return nil, errors.New("resource.key entries must be base64 strings")
			}
			b64 = append(b64, s)
		}
	default:
		return nil, errors.New("resource.key must be an array of base64 DER certificates")
	}
	if len(b64) == 0 {
		return nil, errors.New("resource.key is empty; the DSC is required")
	}
	if len(b64) > maxRequestCerts {
		return nil, fmt.Errorf("resource.key has %d certificates, maximum is %d", len(b64), maxRequestCerts)
	}
	certs := make([]*x509.Certificate, 0, len(b64))
	for i, s := range b64 {
		if len(s) > maxCertB64Len {
			return nil, fmt.Errorf("certificate %d: encoded size %d exceeds maximum %d", i, len(s), maxCertB64Len)
		}
		der, err := base64.StdEncoding.DecodeString(s)
		if err != nil {
			return nil, fmt.Errorf("certificate %d: invalid base64: %v", i, err)
		}
		c, err := registry.ParseCertificate(der, r.ext)
		if err != nil {
			return nil, fmt.Errorf("certificate %d: invalid X.509: %v", i, err)
		}
		// go-cryptoutil's brainpool fallback returns a skeleton certificate
		// (Raw + PublicKey only) when neither parser copes with the whole
		// certificate, e.g. a brainpool subject key under an RSA-PSS
		// signature. Without the TBS bytes nothing can be verified, so refuse
		// explicitly instead of reporting a misleading chain error.
		if c.PublicKey == nil || len(c.RawTBSCertificate) == 0 {
			return nil, fmt.Errorf("certificate %d: unsupported public key / signature algorithm combination", i)
		}
		certs = append(certs, c)
	}
	return certs, nil
}

func fingerprint(c *x509.Certificate) string {
	sum := sha256.Sum256(c.Raw)
	return hex.EncodeToString(sum[:])
}

func (r *Registry) deny(code, detail string) *authzen.EvaluationResponse {
	return &authzen.EvaluationResponse{
		Decision: false,
		Context: &authzen.EvaluationResponseContext{
			Reason: map[string]interface{}{
				"code":     code,
				"error":    detail,
				"user":     "eMRTD document signer is not trusted",
				"admin":    map[string]interface{}{"code": code, "detail": detail},
				"registry": r.cfg.Name,
				"type":     "emrtd",
			},
		},
	}
}

func (r *Registry) allow(country string, path []*x509.Certificate, at time.Time) *authzen.EvaluationResponse {
	dsc, csca := path[0], path[len(path)-1]
	var links []string
	for _, c := range path[1 : len(path)-1] {
		links = append(links, fingerprint(c))
	}
	admin := map[string]interface{}{
		"csca_sha256":  fingerprint(csca),
		"csca_subject": csca.Subject.String(),
		"dsc_sha256":   fingerprint(dsc),
		"country":      country,
		"signing_time": at.UTC().Format(time.RFC3339Nano),
	}
	if len(links) > 0 {
		admin["link_sha256"] = links
	}
	return &authzen.EvaluationResponse{
		Decision: true,
		Context: &authzen.EvaluationResponseContext{
			Reason: map[string]interface{}{
				"user":     "eMRTD document signer chains to a trusted CSCA for " + country,
				"admin":    admin,
				"registry": r.cfg.Name,
				"type":     "emrtd",
			},
		},
	}
}

// --- loading and watching -------------------------------------------------

// reload rebuilds the snapshot from disk and swaps it in atomically.
func (r *Registry) reload() error {
	r.reloadMu.Lock()
	defer r.reloadMu.Unlock()

	anchors, err := r.loadAnchors()
	if err != nil {
		return err
	}
	crls := map[string][]*crlData{}
	if r.cfg.CRLsDir != "" {
		if crls, err = r.loadCRLs(); err != nil {
			return err
		}
	}
	n := 0
	var fps []string
	for _, l := range anchors {
		n += len(l)
		for _, a := range l {
			fps = append(fps, a.sha256)
		}
	}
	sort.Strings(fps)
	r.snap.Store(&snapshot{anchors: anchors, crls: crls, fingerprints: fps})
	r.log.Info("emrtd anchors loaded", "registry", r.cfg.Name, "countries", len(anchors), "anchors", n)
	if n == 0 {
		r.log.Warn("emrtd registry has no anchors; every request will be denied", "dir", r.cfg.AnchorsDir)
	}
	return nil
}

// requireRegularFile rejects anything but a regular anchor or CRL file.
// A symlink is refused because the watcher only sees events inside the
// watched tree: replacing the target of a link that points elsewhere would
// change trust data with no event and leave a removed anchor trusted or a new
// CRL unseen. Symlinks are supported at the root (swapped atomically, and the
// parent is watched), not below it. Other special files (a FIFO named .pem
// would block the read forever, and with it startup or a reload) are refused
// for the same fail-closed reason.
func requireRegularFile(path string) error {
	st, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !st.Mode().IsRegular() {
		return fmt.Errorf("emrtd: %s is not a regular file (%s); anchor and CRL files must be regular files (only the configured root may be a symlink)", path, st.Mode().Type())
	}
	return nil
}

// crlData is a parsed CRL plus an index of its revoked serial numbers, built
// once at load time so each evaluation does a map lookup instead of scanning
// a possibly large national list.
type crlData struct {
	*x509.RevocationList
	revoked map[string]struct{}
}

func newCRLData(l *x509.RevocationList) *crlData {
	idx := make(map[string]struct{}, len(l.RevokedCertificateEntries))
	for _, e := range l.RevokedCertificateEntries {
		idx[e.SerialNumber.String()] = struct{}{}
	}
	return &crlData{RevocationList: l, revoked: idx}
}

func (c *crlData) isRevoked(serial *big.Int) bool {
	_, ok := c.revoked[serial.String()]
	return ok
}

var (
	oidDeltaCRLIndicator = asn1.ObjectIdentifier{2, 5, 29, 27}
	oidIssuingDistPoint  = asn1.ObjectIdentifier{2, 5, 29, 28}
)

// isIndirectCRL reports whether the CRL's issuingDistributionPoint extension
// (RFC 5280 5.2.5) sets indirectCRL [4] BOOLEAN to true. The whole extension
// is scanned: a duplicate extension, or a duplicate [4] element (a FALSE
// followed by a TRUE), is malformed and rejected rather than resolved by
// taking the first one, because Go's parser accepts such encodings. A
// malformed extension is an error, so the caller fails closed.
func isIndirectCRL(crl *x509.RevocationList) (bool, error) {
	found := false
	indirect := false
	for _, ext := range crl.Extensions {
		if !ext.Id.Equal(oidIssuingDistPoint) {
			continue
		}
		if found {
			return false, errors.New("duplicate issuingDistributionPoint extension")
		}
		found = true
		var seq asn1.RawValue
		if rest, err := asn1.Unmarshal(ext.Value, &seq); err != nil || len(rest) != 0 ||
			seq.Class != asn1.ClassUniversal || seq.Tag != asn1.TagSequence || !seq.IsCompound {
			return false, errors.New("not a SEQUENCE")
		}
		seen := false
		body := seq.Bytes
		for len(body) > 0 {
			var el asn1.RawValue
			rest, err := asn1.Unmarshal(body, &el)
			if err != nil {
				return false, err
			}
			body = rest
			if el.Class != asn1.ClassContextSpecific || el.Tag != 4 {
				continue
			}
			if seen {
				return false, errors.New("duplicate indirectCRL element")
			}
			seen = true
			if len(el.Bytes) != 1 {
				return false, errors.New("indirectCRL is not a BOOLEAN")
			}
			indirect = el.Bytes[0] != 0
		}
	}
	return indirect, nil
}

// countryDirs lists the per-country subdirectories of an anchors or CRLs root.
// A symlink to a directory is REJECTED rather than ignored: DirEntry.IsDir is
// false for it, so skipping would silently drop that country's anchors or,
// worse, its CRLs (revocation data) while loading still succeeds. Symlinks
// are supported at the root (atomic tree swaps) and for individual files, not
// for country directories.
func countryDirs(root string) ([]string, error) {
	entries, err := os.ReadDir(root)
	if err != nil {
		return nil, err
	}
	var dirs []string
	for _, e := range entries {
		// Inspect every entry with Lstat rather than trusting DirEntry.Type():
		// some filesystems report no type (0), which would hide both a
		// symlink and a real country directory, and loading would succeed
		// without that country's data. An entry that cannot be inspected
		// fails the load.
		p := filepath.Join(root, e.Name())
		lst, err := os.Lstat(p)
		if err != nil {
			return nil, fmt.Errorf("emrtd: inspecting %s: %w", p, err)
		}
		if lst.Mode()&os.ModeSymlink != 0 {
			// A link named like a country stands for that country's data
			// whatever it resolves to (directory, file, nothing): refuse. Any
			// link that does resolve to a directory is refused too. Only an
			// unrelated non-directory link is ignored.
			st, err := os.Stat(p)
			_, isCountry := alpha3ToAlpha2[e.Name()]
			if isCountry || (err == nil && st.IsDir()) {
				return nil, fmt.Errorf("emrtd: %s is a symlink; country directories must be real directories (a symlinked root is fine)", p)
			}
			continue
		}
		if lst.IsDir() {
			dirs = append(dirs, e.Name())
			continue
		}
		// A regular file, FIFO etc. named like a country is a country
		// directory that was replaced by something else: loading without it
		// would publish a snapshot missing that state's anchors or CRLs.
		if _, isCountry := alpha3ToAlpha2[e.Name()]; isCountry {
			return nil, fmt.Errorf("emrtd: %s is not a directory (%s); a country entry must be a real directory", p, lst.Mode().Type())
		}
	}
	return dirs, nil
}

func (r *Registry) loadAnchors() (map[string][]*anchor, error) {
	dirs, err := countryDirs(r.cfg.AnchorsDir)
	if err != nil {
		return nil, fmt.Errorf("emrtd: reading anchors_dir: %w", err)
	}
	out := map[string][]*anchor{}
	for _, country := range dirs {
		if _, ok := alpha3ToAlpha2[country]; !ok {
			r.log.Error("emrtd: skipping directory that is not an ISO 3166-1 alpha-3 code", "dir", country)
			continue
		}
		// List the country directory literally. filepath.Glob would treat
		// metacharacters in anchors_dir (e.g. /data/anchors[1]) as a pattern
		// and could read a different, sibling directory's files as anchors.
		entries, err := os.ReadDir(filepath.Join(r.cfg.AnchorsDir, country))
		if err != nil {
			return nil, fmt.Errorf("emrtd: reading %s: %w", filepath.Join(r.cfg.AnchorsDir, country), err)
		}
		var files []string
		for _, e := range entries {
			if strings.HasSuffix(e.Name(), ".pem") {
				files = append(files, filepath.Join(r.cfg.AnchorsDir, country, e.Name()))
			}
		}
		seen := map[string]bool{}
		for _, f := range files {
			if err := requireRegularFile(f); err != nil {
				return nil, err
			}
			data, err := os.ReadFile(f)
			if err != nil {
				r.log.Error("emrtd: cannot read anchor file, skipping", "file", f, "error", err)
				continue
			}
			certs, err := registry.ParseCertificatesPEM(data, r.ext)
			if err != nil || len(certs) == 0 {
				r.log.Error("emrtd: no valid certificate in anchor file, skipping", "file", f, "error", err)
				continue
			}
			for _, c := range certs {
				if c.PublicKey == nil || len(c.RawTBSCertificate) == 0 {
					r.log.Error("emrtd: anchor has unsupported key/signature algorithm combination, skipping", "file", f)
					continue
				}
				if len(c.Subject.Country) != 1 || !countryMatches(country, c.Subject.Country[0]) {
					r.log.Error("emrtd: anchor subject C does not match its country directory, skipping",
						"file", f, "dir", country, "subject", c.Subject.String())
					continue
				}
				fp := fingerprint(c)
				if seen[fp] {
					continue
				}
				seen[fp] = true
				out[country] = append(out[country], &anchor{cert: c, sha256: fp})
			}
		}
	}
	return out, nil
}

func (r *Registry) loadCRLs() (map[string][]*crlData, error) {
	dirs, err := countryDirs(r.cfg.CRLsDir)
	if err != nil {
		return nil, fmt.Errorf("emrtd: reading crls_dir: %w", err)
	}
	out := map[string][]*crlData{}
	for _, country := range dirs {
		entries, err := os.ReadDir(filepath.Join(r.cfg.CRLsDir, country))
		if err != nil {
			return nil, err
		}
		if _, ok := alpha3ToAlpha2[country]; !ok {
			// A directory that is not a country but holds CRLs (crls_dir/swe
			// instead of crls_dir/SWE) would silently drop those revocations
			// from the published snapshot: fail the load. Empty or unrelated
			// directories are still only logged.
			for _, e := range entries {
				if strings.EqualFold(filepath.Ext(e.Name()), ".crl") {
					return nil, fmt.Errorf("emrtd: %s/%s contains CRL files but %q is not an ISO 3166-1 alpha-3 code (upper case, e.g. SWE)", r.cfg.CRLsDir, country, country)
				}
			}
			r.log.Error("emrtd: skipping CRL directory that is not an alpha-3 code", "dir", country)
			continue
		}
		for _, e := range entries {
			// Filter on the suffix only: a directory named x.crl (a CRL file
			// replaced by a directory) must reach requireRegularFile and fail
			// the load, not be skipped into a snapshot missing that CRL.
			if !strings.EqualFold(filepath.Ext(e.Name()), ".crl") {
				continue
			}
			f := filepath.Join(r.cfg.CRLsDir, country, e.Name())
			if err := requireRegularFile(f); err != nil {
				return nil, err
			}
			data, err := os.ReadFile(f)
			if err != nil {
				return nil, fmt.Errorf("emrtd: reading CRL %s: %w", f, err)
			}
			ders, err := crlDERs(data)
			if err != nil {
				return nil, fmt.Errorf("emrtd: CRL file %s: %w", f, err)
			}
			for _, der := range ders {
				crl, err := x509.ParseRevocationList(der)
				if err != nil {
					return nil, fmt.Errorf("emrtd: parsing CRL %s: %w", f, err)
				}
				if err := checkCRLSupported(crl, country, f); err != nil {
					return nil, err
				}
				out[country] = append(out[country], newCRLData(crl))
			}
		}
	}
	return out, nil
}

// crlDERs returns the DER of every CRL in a file: either one raw DER CRL, or
// one or more PEM blocks (each of which is used, so an appended list cannot be
// silently dropped). The file must contain nothing but whitespace-separated,
// well-formed PEM blocks: pem.Decode skips junk and malformed blocks while
// looking for the next valid header, which would publish a snapshot silently
// missing the skipped list's revocations, so each block must start right
// after the previous one and skipping anything is an error.
func crlDERs(data []byte) ([][]byte, error) {
	const begin = "-----BEGIN "
	if !bytes.Contains(data, []byte(begin)) {
		return [][]byte{data}, nil // raw DER (or garbage, which the parser rejects)
	}
	var out [][]byte
	rest := bytes.TrimSpace(data)
	for len(rest) > 0 {
		blk, after := pem.Decode(rest)
		if blk == nil {
			return nil, errors.New("malformed PEM data")
		}
		consumed := rest[:len(rest)-len(after)]
		if !bytes.HasPrefix(consumed, []byte(begin)) || bytes.Count(consumed, []byte(begin)) != 1 {
			return nil, errors.New("malformed or unexpected data between PEM blocks")
		}
		out = append(out, blk.Bytes)
		rest = bytes.TrimSpace(after)
	}
	return out, nil
}

// checkCRLSupported refuses CRLs whose semantics the lookup cannot honour, so
// they are never silently treated as complete direct lists.
func checkCRLSupported(crl *x509.RevocationList, country, file string) error {
	// A CRL filed under the wrong country would never be consulted for the
	// state it belongs to, silently disabling revocation for it. Its issuer's
	// C, when present, must match the directory.
	for _, c := range crl.Issuer.Country {
		if !countryMatches(country, c) {
			return fmt.Errorf("emrtd: CRL %s is issued by C=%q but filed under %s; move it to the right country directory", file, c, country)
		}
	}
	// An indirect CRL may be signed by a delegated issuer and name a different
	// issuer per entry. Neither is supported: it would be silently ignored by
	// the issuer-scoped lookup, so refuse it.
	if indirect, err := isIndirectCRL(crl); err != nil {
		return fmt.Errorf("emrtd: CRL %s has an unparsable issuingDistributionPoint extension: %w", file, err)
	} else if indirect {
		return fmt.Errorf("emrtd: CRL %s is an indirect CRL (issuingDistributionPoint indirectCRL=true); indirect CRLs are not supported", file)
	}
	// A delta CRL lists only changes since a base CRL. Checked on its own it
	// would look like a complete list and let a certificate revoked in the
	// base through, and combining deltas with bases is not supported.
	for _, ext := range crl.Extensions {
		if ext.Id.Equal(oidDeltaCRLIndicator) {
			return fmt.Errorf("emrtd: CRL %s is a delta CRL (deltaCRLIndicator); delta CRLs are not supported, provide complete CRLs", file)
		}
	}
	return nil
}

func (r *Registry) startWatching() error {
	w, err := fsnotify.NewWatcher()
	if err != nil {
		return fmt.Errorf("emrtd: creating watcher: %w", err)
	}
	r.watcher = w
	r.stopCh = make(chan struct{})
	// Captured here, synchronously, NOT inside the goroutine: a swap that
	// happens before the goroutine first runs must still register as a change
	// against the location the first load used. A swap between that load and
	// this capture is covered by the reconciling reload New runs after arming.
	resolved := r.resolvedRoots()
	if err := r.armWatches(w); err != nil {
		_ = w.Close()
		r.watcher = nil
		return err
	}
	go r.watchLoop(w, r.stopCh, resolved)
	return nil
}

// armWatches watches the roots' parents, the roots and every country
// subdirectory, and reconciles the watcher to exactly that set. Directory
// watches (not file watches) survive atomic rename-over updates.
//
// Every wanted path is removed and re-added, because when a symlinked root is
// swapped the same path string now resolves to a different inode, and a plain
// Add would leave the watch on the old (possibly retained) target behind.
// Paths that are no longer wanted are dropped, so repeated swaps cannot
// accumulate watches towards the kernel limit.
func (r *Registry) armWatches(w *fsnotify.Watcher) error {
	wanted := map[string]bool{}
	rearm := func(p string) error {
		_ = w.Remove(p) // ignore "not watched": the point is to drop a stale inode
		wanted[p] = true
		if err := w.Add(p); err != nil {
			return fmt.Errorf("emrtd: watching %s: %w", p, err)
		}
		return nil
	}
	var roots []string
	for _, root := range []string{r.cfg.AnchorsDir, r.cfg.CRLsDir} {
		if root != "" {
			roots = append(roots, root)
		}
	}
	// Roots first, country directories second: the root watch must be in
	// place BEFORE the directory set is enumerated, so a country created in
	// between raises an event (and a re-arm) instead of slipping through
	// with neither a watch nor an event. The parent directory is watched too:
	// a root that is a symlink is swapped (or the tree replaced) by changing
	// its directory entry, which only the parent sees.
	for _, root := range roots {
		if err := rearm(filepath.Dir(filepath.Clean(root))); err != nil {
			return err
		}
		if err := rearm(root); err != nil {
			return err
		}
	}
	for _, root := range roots {
		dirs, err := countryDirs(root)
		if err != nil {
			return err
		}
		for _, d := range dirs {
			if err := rearm(filepath.Join(root, d)); err != nil {
				return err
			}
		}
	}
	for _, p := range w.WatchList() {
		if !wanted[p] {
			_ = w.Remove(p)
		}
	}
	return nil
}

// relevantEvent filters events from the parent-directory watches: only the
// roots themselves, their country directories and files in those count.
func (r *Registry) relevantEvent(name string) bool {
	name = filepath.Clean(name)
	for _, root := range []string{r.cfg.AnchorsDir, r.cfg.CRLsDir} {
		if root == "" {
			continue
		}
		root = filepath.Clean(root)
		if name == root || filepath.Dir(name) == root || filepath.Dir(filepath.Dir(name)) == root {
			return true
		}
	}
	return false
}

// maxReloadDelayFactor bounds how long a stream of file events may keep
// resetting the debounce timer: the reload runs at most this many debounce
// periods after the first event of a burst, so a removed CSCA or a new CRL
// takes effect even while files are written continuously.
const maxReloadDelayFactor = 20

// retryInterval is the delay before retrying a failed reload or re-arm.
func (r *Registry) retryInterval() time.Duration {
	if r.cfg.ReloadDebounce > 0 && r.cfg.ReloadDebounce < time.Second {
		return 10 * r.cfg.ReloadDebounce
	}
	return 10 * time.Second
}

// resolvedRoots returns the symlink-free locations of the configured roots,
// joined, with a marker for one that cannot be resolved (so its disappearance
// and reappearance both register as changes).
func (r *Registry) resolvedRoots() string {
	var parts []string
	for _, root := range []string{r.cfg.AnchorsDir, r.cfg.CRLsDir} {
		if root == "" {
			continue
		}
		p, err := filepath.EvalSymlinks(root)
		if err != nil {
			p = "!unresolved:" + root
		}
		parts = append(parts, p)
	}
	return strings.Join(parts, "\x00")
}

func (r *Registry) watchLoop(w *fsnotify.Watcher, stop <-chan struct{}, lastResolved string) {
	// Directory watches follow the inodes they were armed on, so a symlink in
	// an ANCESTOR of a root that is swapped (old target left intact) raises no
	// event on any watched directory. Poll the resolved locations and treat a
	// change like a file event.
	poll := time.NewTicker(r.cfg.RootCheckInterval)
	defer poll.Stop()
	var timer *time.Timer
	var fire <-chan time.Time
	var burstStart time.Time // first event of the pending burst; zero when none
	armDebounce := func() {
		now := time.Now()
		if burstStart.IsZero() {
			burstStart = now
		}
		// Quiet-period debounce, but never later than the burst's hard deadline.
		delay := r.cfg.ReloadDebounce
		if left := burstStart.Add(maxReloadDelayFactor * r.cfg.ReloadDebounce).Sub(now); left < delay {
			delay = max(left, 0)
		}
		if timer == nil {
			timer = time.NewTimer(delay)
		} else {
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			timer.Reset(delay)
		}
		fire = timer.C
	}
	for {
		select {
		case <-stop:
			if timer != nil {
				timer.Stop()
			}
			return
		case <-poll.C:
			if cur := r.resolvedRoots(); cur != lastResolved {
				lastResolved = cur
				r.log.Info("emrtd: anchors/CRL location changed, scheduling reload")
				armDebounce()
			}
		case ev, ok := <-w.Events:
			if !ok {
				return
			}
			if !r.relevantEvent(ev.Name) {
				continue
			}
			armDebounce()
		case err, ok := <-w.Errors:
			if !ok {
				return
			}
			// Events may have been lost (e.g. queue overflow): reconcile.
			r.log.Error("emrtd: file watcher error, scheduling reload", "error", err)
			armDebounce()
		case <-fire:
			fire = nil
			burstStart = time.Time{}
			failed := false
			// Arm the watches first, then reload: a file added between the
			// scan and the arming would otherwise generate no event and be
			// missed until the next unrelated change.
			r.reloadMu.Lock()
			if r.watcher == w {
				if err := r.armWatches(w); err != nil {
					failed = true
					r.log.Error("emrtd: re-arming watches failed", "error", err)
				}
			}
			r.reloadMu.Unlock()
			if err := r.reload(); err != nil {
				failed = true
				r.log.Error("emrtd: reload failed, keeping previous trust data", "error", err)
			}
			if failed {
				// The root may have been replaced (its watch is gone) or be
				// briefly absent; keep retrying so removed anchors do not
				// stay trusted indefinitely.
				timer.Reset(r.retryInterval())
				fire = timer.C
			}
		}
	}
}
