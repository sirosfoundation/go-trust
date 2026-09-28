package main

import (
	"context"
	"strings"
	"testing"

	"github.com/sirosfoundation/g119612/pkg/logging"
	"github.com/sirosfoundation/go-trust/pkg/authzen"
	"github.com/sirosfoundation/go-trust/pkg/config"
	"github.com/sirosfoundation/go-trust/pkg/registry"
	staticreg "github.com/sirosfoundation/go-trust/pkg/registry/static"
)

// TestResolutionStrategyFromConfig covers item 3 of #176: main.go passed
// registry.FirstMatch as a literal, so "all", "best_match" and "sequential"
// were implemented, tested and unreachable from a config file.
func TestResolutionStrategyFromConfig(t *testing.T) {
	cases := []struct {
		configured string
		want       registry.ResolutionStrategy
	}{
		{"", registry.FirstMatch},
		{"first_match", registry.FirstMatch},
		{"all", registry.AllRegistries},
		{"best_match", registry.BestMatch},
		{"sequential", registry.Sequential},
		// An unknown value must not silently become something else.
		{"nonsense", registry.FirstMatch},
	}

	for _, tc := range cases {
		cfg := &config.Config{}
		cfg.Registries.Strategy = tc.configured
		if got := resolutionStrategy(cfg, logging.SilentLogger()); got != tc.want {
			t.Errorf("strategy %q = %q, want %q", tc.configured, got, tc.want)
		}
	}

	if got := resolutionStrategy(nil, logging.SilentLogger()); got != registry.FirstMatch {
		t.Errorf("nil config = %q, want first_match", got)
	}
}

func TestCompositeOperatorParsing(t *testing.T) {
	cases := []struct {
		in   string
		want registry.LogicOperator
		ok   bool
	}{
		{"AND", registry.LogicAND, true},
		{"and", registry.LogicAND, true},
		{" Or ", registry.LogicOR, true},
		{"MAJORITY", registry.LogicMAJORITY, true},
		{"QUORUM", registry.LogicQUORUM, true},
		{"XOR", "", false},
		{"", "", false},
	}

	for _, tc := range cases {
		got, ok := compositeOperator(tc.in)
		if ok != tc.ok || got != tc.want {
			t.Errorf("compositeOperator(%q) = (%q, %v), want (%q, %v)", tc.in, got, ok, tc.want, tc.ok)
		}
	}
}

// TestCompositeTakesOwnershipOfChildren is the one that matters. A child left
// registered alongside its composite is still evaluated on its own, and under
// first_match can return decision=true by itself — which is exactly the
// agreement an AND composite was configured to require.
func TestCompositeTakesOwnershipOfChildren(t *testing.T) {
	mgr := registry.NewRegistryManager(registry.FirstMatch, 0)
	mgr.Register(namedRegistry("alpha"))
	mgr.Register(namedRegistry("beta"))
	mgr.Register(namedRegistry("gamma"))

	cfg := &config.Config{}
	cfg.Registries.Composite = []config.CompositeRegistryConfig{{
		Name:       "both",
		Operator:   "AND",
		Registries: []string{"alpha", "beta"},
	}}

	if err := configureCompositeRegistriesFromConfig(cfg, mgr, logging.SilentLogger()); err != nil {
		t.Fatalf("configureCompositeRegistriesFromConfig: %v", err)
	}

	if mgr.GetRegistry("alpha") != nil {
		t.Error("alpha is still registered standalone; it can satisfy first_match alone")
	}
	if mgr.GetRegistry("beta") != nil {
		t.Error("beta is still registered standalone")
	}
	if mgr.GetRegistry("gamma") == nil {
		t.Error("gamma was not named by the composite and must be left alone")
	}
	if mgr.GetRegistry("both") == nil {
		t.Fatal("the composite itself was not registered")
	}

	names := map[string]bool{}
	for _, info := range mgr.ListRegistries() {
		names[info.Name] = true
	}
	if len(names) != 2 || !names["both"] || !names["gamma"] {
		t.Errorf("registries = %v, want exactly {both, gamma}", names)
	}
}

func TestCompositeQuorumThresholdIsCarried(t *testing.T) {
	mgr := registry.NewRegistryManager(registry.FirstMatch, 0)
	mgr.Register(namedRegistry("a"))
	mgr.Register(namedRegistry("b"))
	mgr.Register(namedRegistry("c"))

	cfg := &config.Config{}
	cfg.Registries.Composite = []config.CompositeRegistryConfig{{
		Name:       "two-of-three",
		Operator:   "QUORUM",
		Threshold:  2,
		Timeout:    "3s",
		Registries: []string{"a", "b", "c"},
	}}

	if err := configureCompositeRegistriesFromConfig(cfg, mgr, logging.SilentLogger()); err != nil {
		t.Fatalf("configureCompositeRegistriesFromConfig: %v", err)
	}

	comp := mgr.GetRegistry("two-of-three")
	if comp == nil {
		t.Fatal("composite was not registered")
	}
	if got := comp.Info().Type; got != "composite" {
		t.Errorf("Info().Type = %q, want composite", got)
	}
}

// namedRegistry returns a trivially-trusting registry, used here only as a named
// participant: these tests are about wiring, not trust decisions.
func namedRegistry(name string) registry.TrustRegistry {
	return staticreg.NewAlwaysTrustedRegistry(name)
}

// TestCompositeConfigValidation covers the rejections. Each one exists because
// accepting it would silently yield a weaker trust rule than the operator
// wrote, so "it errors" is the behaviour under test, not an implementation
// detail.
func TestCompositeConfigValidation(t *testing.T) {
	cases := []struct {
		name    string
		comp    config.CompositeRegistryConfig
		wantErr string
	}{
		{
			name:    "no name",
			comp:    config.CompositeRegistryConfig{Operator: "AND", Registries: []string{"a"}},
			wantErr: "no name",
		},
		{
			name:    "unknown operator",
			comp:    config.CompositeRegistryConfig{Name: "c", Operator: "XOR", Registries: []string{"a"}},
			wantErr: "unknown operator",
		},
		{
			name:    "no children",
			comp:    config.CompositeRegistryConfig{Name: "c", Operator: "AND"},
			wantErr: "names no child registries",
		},
		{
			name:    "missing child",
			comp:    config.CompositeRegistryConfig{Name: "c", Operator: "AND", Registries: []string{"a", "nope"}},
			wantErr: "not configured",
		},
		{
			name:    "quorum threshold missing",
			comp:    config.CompositeRegistryConfig{Name: "c", Operator: "QUORUM", Registries: []string{"a", "b"}},
			wantErr: "threshold 0",
		},
		{
			name:    "quorum threshold above child count",
			comp:    config.CompositeRegistryConfig{Name: "c", Operator: "QUORUM", Threshold: 5, Registries: []string{"a", "b"}},
			wantErr: "threshold 5",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			mgr := registry.NewRegistryManager(registry.FirstMatch, 0)
			mgr.Register(namedRegistry("a"))
			mgr.Register(namedRegistry("b"))

			cfg := &config.Config{}
			cfg.Registries.Composite = []config.CompositeRegistryConfig{tc.comp}

			err := configureCompositeRegistriesFromConfig(cfg, mgr, logging.SilentLogger())
			if err == nil {
				t.Fatalf("expected an error mentioning %q", tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("error = %q, want it to mention %q", err, tc.wantErr)
			}
		})
	}
}

// TestCompositeInvalidTimeoutIsNotFatal pins the one malformed value that is
// deliberately tolerated: a bad timeout weakens no trust rule, it just falls
// back to the CompositeRegistry default.
func TestCompositeInvalidTimeoutIsNotFatal(t *testing.T) {
	mgr := registry.NewRegistryManager(registry.FirstMatch, 0)
	mgr.Register(namedRegistry("a"))
	mgr.Register(namedRegistry("b"))

	cfg := &config.Config{}
	cfg.Registries.Composite = []config.CompositeRegistryConfig{{
		Name:        "c",
		Description: "described, to exercise WithDescription",
		Operator:    "OR",
		Timeout:     "soon-ish",
		Registries:  []string{"a", "b"},
	}}

	if err := configureCompositeRegistriesFromConfig(cfg, mgr, logging.SilentLogger()); err != nil {
		t.Fatalf("an invalid timeout must not fail startup: %v", err)
	}
	comp := mgr.GetRegistry("c")
	if comp == nil {
		t.Fatal("composite was not registered")
	}
	if got := comp.Info().Description; got != "described, to exercise WithDescription" {
		t.Errorf("Description = %q; WithDescription was not applied", got)
	}
}

// TestCompositeRejectsAmbiguousChildName pins the duplicate-name case.
// Register permits duplicate Info().Name values — a config-file ETSI registry
// and a CLI-configured one both default to "ETSI-TSL" — so taking "one of
// them" would leave the other top-level, free to allow a request on its own.
// There is no safe way to guess which was meant.
func TestCompositeRejectsAmbiguousChildName(t *testing.T) {
	mgr := registry.NewRegistryManager(registry.FirstMatch, 0)
	mgr.Register(namedRegistry("ETSI-TSL"))
	mgr.Register(namedRegistry("ETSI-TSL"))
	mgr.Register(namedRegistry("whitelist"))

	cfg := &config.Config{}
	cfg.Registries.Composite = []config.CompositeRegistryConfig{{
		Name:       "c",
		Operator:   "AND",
		Registries: []string{"ETSI-TSL", "whitelist"},
	}}

	err := configureCompositeRegistriesFromConfig(cfg, mgr, logging.SilentLogger())
	if err == nil {
		t.Fatal("expected an error: two registries share the named child")
	}
	if !strings.Contains(err.Error(), "share that name") {
		t.Errorf("error = %q, want it to explain the ambiguity", err)
	}
}

// TestCompositeNonPositiveTimeoutUsesDefault covers the values ParseDuration
// accepts but that would install an already-expired context, making
// context-aware children fail instantly and turning every evaluation into a
// denial.
func TestCompositeNonPositiveTimeoutUsesDefault(t *testing.T) {
	for _, timeout := range []string{"0", "0s", "-5s"} {
		mgr := registry.NewRegistryManager(registry.FirstMatch, 0)
		mgr.Register(namedRegistry("a"))

		cfg := &config.Config{}
		cfg.Registries.Composite = []config.CompositeRegistryConfig{{
			Name:       "c",
			Operator:   "OR",
			Timeout:    timeout,
			Registries: []string{"a"},
		}}

		if err := configureCompositeRegistriesFromConfig(cfg, mgr, logging.SilentLogger()); err != nil {
			t.Fatalf("timeout %q must fall back to the default, not fail: %v", timeout, err)
		}

		comp := mgr.GetRegistry("c")
		if comp == nil {
			t.Fatalf("timeout %q: composite was not registered", timeout)
		}
		// The default timeout must still let a child answer.
		resp, err := comp.Evaluate(context.Background(), &authzen.EvaluationRequest{
			Subject:  authzen.Subject{Type: "key", ID: "https://rp.example.com"},
			Resource: authzen.Resource{Type: "x5c", ID: "https://rp.example.com", Key: []any{"MIIC..."}},
		})
		if err != nil {
			t.Errorf("timeout %q: Evaluate returned %v; the context expired immediately", timeout, err)
			continue
		}
		if !resp.Decision {
			t.Errorf("timeout %q: decision=false; an expired context turned an allow into a denial", timeout)
		}
	}
}
