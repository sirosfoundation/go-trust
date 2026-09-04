package main

import (
	"testing"
	"time"

	"github.com/sirosfoundation/go-trust/pkg/config"
)

// TestETSITSLConfigCarriesEveryConfiguredField is the test whose absence let
// six fields be dropped silently.
//
// The failure mode is what makes it worth pinning: a dropped field does not
// produce a wrong value, it produces the zero value, and the registry then
// fails with "no trust data loaded - configure CertBundle, TSLFiles, or
// TSLURLs" while the operator is looking at a config file that plainly
// configures TSLURLs.
func TestETSITSLConfigCarriesEveryConfiguredField(t *testing.T) {
	cfg := &config.ETSIRegistryConfig{
		Enabled:            true,
		Name:               "wrpac-tsl",
		Description:        "test anchors",
		CertBundle:         "/etc/trust/bundle.pem",
		TSLFiles:           []string{"/etc/trust/local.xml"},
		TSLURLs:            []string{"https://registrar.example.org/tsl.xml"},
		FollowRefs:         true,
		MaxRefDepth:        4,
		AllowNetworkAccess: true,
		FetchTimeout:       "17s",
		UserAgent:          "test-agent/1.0",
		LOTLSignerBundle:   "/etc/trust/lotl-signers.pem",
		RequireSignature:   true,
		FollowPivots:       true,
	}

	got := etsiTSLConfig(cfg, nil, nil)

	if len(got.TSLURLs) != 1 || got.TSLURLs[0] != cfg.TSLURLs[0] {
		t.Errorf("TSLURLs = %v, want %v", got.TSLURLs, cfg.TSLURLs)
	}
	if len(got.TSLFiles) != 1 || got.TSLFiles[0] != cfg.TSLFiles[0] {
		t.Errorf("TSLFiles = %v, want %v", got.TSLFiles, cfg.TSLFiles)
	}
	if got.CertBundle != cfg.CertBundle {
		t.Errorf("CertBundle = %q, want %q", got.CertBundle, cfg.CertBundle)
	}
	if !got.FollowRefs {
		t.Error("FollowRefs was not carried across")
	}
	if got.MaxRefDepth != cfg.MaxRefDepth {
		t.Errorf("MaxRefDepth = %d, want %d", got.MaxRefDepth, cfg.MaxRefDepth)
	}
	if !got.AllowNetworkAccess {
		// Without this a URL source is refused even when one is configured.
		t.Error("AllowNetworkAccess was not carried across")
	}
	if got.FetchTimeout != 17*time.Second {
		t.Errorf("FetchTimeout = %v, want 17s", got.FetchTimeout)
	}
	if got.UserAgent != cfg.UserAgent {
		t.Errorf("UserAgent = %q, want %q", got.UserAgent, cfg.UserAgent)
	}
	if got.LOTLSignerBundle != cfg.LOTLSignerBundle {
		t.Errorf("LOTLSignerBundle = %q, want %q", got.LOTLSignerBundle, cfg.LOTLSignerBundle)
	}
	if !got.RequireSignature {
		t.Error("RequireSignature was not carried across")
	}
	if !got.FollowPivots {
		t.Error("FollowPivots was not carried across")
	}
	if got.Name != cfg.Name || got.Description != cfg.Description {
		t.Errorf("Name/Description = %q/%q, want %q/%q", got.Name, got.Description, cfg.Name, cfg.Description)
	}
}

func TestETSITSLConfigDefaultsNameAndDescription(t *testing.T) {
	got := etsiTSLConfig(&config.ETSIRegistryConfig{Enabled: true}, nil, nil)
	if got.Name != "ETSI-TSL" {
		t.Errorf("Name = %q, want the ETSI-TSL default", got.Name)
	}
	if got.Description == "" {
		t.Error("Description was left empty")
	}
}

func TestETSITSLConfigIgnoresAnUnparseableFetchTimeout(t *testing.T) {
	// A bad duration must leave the default in place rather than propagate a
	// zero timeout, which would be "no timeout" rather than "the default".
	got := etsiTSLConfig(&config.ETSIRegistryConfig{Enabled: true, FetchTimeout: "soon"}, nil, nil)
	if got.FetchTimeout != 0 {
		t.Errorf("FetchTimeout = %v, want the zero value so the registry applies its own default", got.FetchTimeout)
	}
}
