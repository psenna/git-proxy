package config_test

import (
	"testing"

	"github.com/psenna/git-proxy/internal/config"
)

// TestUpstreamConfig_KindParsed verifies the upstream.kind field is parsed
// from YAML (v1.md M10). config is a pure YAML leaf — it does NOT import the
// upstream registry (no cycle), so this test only asserts the field round-trips
// through YAML; the registry resolution + fail-closed-on-unknown-kind behavior
// is exercised in internal/upstream (registry + github) tests.
func TestUpstreamConfig_KindParsed(t *testing.T) {
	cfg, err := config.Parse([]byte(`
listen: "127.0.0.1:8080"
upstream:
  kind: github
  url: "https://github.example.com"
`))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if cfg.Upstream.Kind != "github" {
		t.Fatalf("kind: want github, got %q", cfg.Upstream.Kind)
	}
	if cfg.Upstream.URL != "https://github.example.com" {
		t.Fatalf("url: want https://github.example.com, got %q", cfg.Upstream.URL)
	}
}

// TestUpstreamConfig_KindDefaultEmpty verifies an absent upstream.kind defaults
// to empty (which main.go maps to upstream.Build's "plain" default — backward
// compatible with the pre-M10 hardcoded plain.New).
func TestUpstreamConfig_KindDefaultEmpty(t *testing.T) {
	cfg, err := config.Parse([]byte(`
listen: "127.0.0.1:8080"
upstream:
  url: "http://git.example.com"
`))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if cfg.Upstream.Kind != "" {
		t.Fatalf("kind: want empty (defaults to plain), got %q", cfg.Upstream.Kind)
	}
}