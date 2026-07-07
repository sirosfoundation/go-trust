// Package lote — LoTE signer trust anchor interface.
//
// LoTETrustAnchorProvider is the extension point for LoTE JWS signature
// verification per ETSI TS 119 615. Callers inject their own implementation;
// the core library ships a no-op that skips verification for environments
// where the LoTE source is already considered trustworthy (e.g. in tests or
// deployments that verify authenticity through other means such as HTTPS
// pinning or a controlled internal distribution).
//
// An OJEU-anchored implementation (for APTITUDE/EUDI production use) belongs
// outside this package because the OJEU endpoint address is
// deployment-specific.
package lote

import (
	"context"
	"crypto/x509"
)

// LoTETrustAnchorProvider supplies the root certificates used to anchor the
// LoTE signer certificate chain during JWS signature verification. Implementations
// decide how and where to obtain the roots (e.g. from OJEU, from a local file,
// or from a pinned certificate bundle).
//
// TrustAnchors is called once per LoTE load. It may return a cached set.
// Returning a nil pool with a nil error disables signature verification for
// that call (equivalent to NilTrustAnchorProvider).
type LoTETrustAnchorProvider interface {
	TrustAnchors(ctx context.Context) (*x509.CertPool, error)
}

// NilTrustAnchorProvider is the no-op implementation of LoTETrustAnchorProvider.
// It returns a nil pool, causing JWS signature verification to be skipped.
// Use this when the LoTE source is trusted through other means (HTTPS,
// controlled distribution) or in test environments.
type NilTrustAnchorProvider struct{}

// TrustAnchors returns nil, nil — signature verification is skipped.
func (NilTrustAnchorProvider) TrustAnchors(_ context.Context) (*x509.CertPool, error) {
	return nil, nil
}

// StaticTrustAnchorProvider holds a fixed CertPool. Useful for testing and
// for deployments where the root certificates are managed out-of-band.
type StaticTrustAnchorProvider struct {
	pool *x509.CertPool
}

// NewStaticTrustAnchorProvider creates a provider with the given root certificates.
// If pool is nil the behaviour is the same as NilTrustAnchorProvider.
func NewStaticTrustAnchorProvider(pool *x509.CertPool) *StaticTrustAnchorProvider {
	return &StaticTrustAnchorProvider{pool: pool}
}

// TrustAnchors returns the configured pool.
func (p *StaticTrustAnchorProvider) TrustAnchors(_ context.Context) (*x509.CertPool, error) {
	return p.pool, nil
}
