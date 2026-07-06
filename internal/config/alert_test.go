package config_test

import (
	"testing"

	"github.com/psenna/git-proxy/internal/config"
)

// TestPolicyConfig_DryRun verifies the DryRun field is parsed from YAML
// (dry_run: true) and defaults false when absent (preserves existing behavior:
// enforce-on-deny). ToPolicy carries the mode through; the engine stays pure
// (dry-run is a proxy-level concern, wired via SetDryRun in main.go — NOT in
// the engine).
func TestPolicyConfig_DryRun(t *testing.T) {
	cfg, err := config.Parse([]byte(`
listen: "127.0.0.1:8080"
upstream:
  url: "http://git.example.com"
policy:
  dry_run: true
  mode: collect_all
`))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if !cfg.Policy.DryRun {
		t.Fatalf("dry_run: want true, got false")
	}
	if cfg.Policy.Mode != "collect_all" {
		t.Fatalf("mode: %q want collect_all", cfg.Policy.Mode)
	}
}

// TestPolicyConfig_DryRunDefaultFalse verifies an absent dry_run defaults to
// false (enforce-on-deny — today's behavior).
func TestPolicyConfig_DryRunDefaultFalse(t *testing.T) {
	cfg, err := config.Parse([]byte(`
listen: "127.0.0.1:8080"
upstream:
  url: "http://git.example.com"
`))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if cfg.Policy.DryRun {
		t.Fatalf("dry_run must default false, got true")
	}
}

// TestAlertConfig_EmptyDisabled verifies an empty/absent alerts.webhook means
// alerts are disabled (no startup error — empty → disabled, NOT fail-fast).
func TestAlertConfig_EmptyDisabled(t *testing.T) {
	cfg, err := config.Parse([]byte(`
listen: "127.0.0.1:8080"
upstream:
  url: "http://git.example.com"
`))
	if err != nil {
		t.Fatalf("Parse (no alerts): %v", err)
	}
	if cfg.Alerts.Webhook != "" {
		t.Fatalf("absent alerts.webhook must be empty, got %q", cfg.Alerts.Webhook)
	}
}

// TestAlertConfig_MalformedWebhookFailsFast verifies a malformed webhook URL
// is rejected at config load (startup fail-fast on a config error), NOT at
// alert time. An empty webhook is allowed (disabled); a malformed one is not.
func TestAlertConfig_MalformedWebhookFailsFast(t *testing.T) {
	_, err := config.Parse([]byte(`
listen: "127.0.0.1:8080"
upstream:
  url: "http://git.example.com"
alerts:
  webhook: "://not-a-url"
`))
	if err == nil {
		t.Fatalf("malformed webhook URL must fail at config load (startup fail-fast)")
	}
}

// TestAlertConfig_NonHTTPSchemeRejected verifies a webhook URL with a non-http(s)
// scheme (e.g. "file://...") is rejected at config load, BEFORE the sink is
// built. This is the single source of truth for the scheme allowlist: config
// fails first with a config-namespaced error so a typo doesn't surface later as
// a sink-construction error. http and https are accepted (see
// TestAlertConfig_ValidWebhookAccepted for https; http is accepted by the same
// path).
func TestAlertConfig_NonHTTPSchemeRejected(t *testing.T) {
	_, err := config.Parse([]byte(`
listen: "127.0.0.1:8080"
upstream:
  url: "http://git.example.com"
alerts:
  webhook: "file:///etc/shadow"
`))
	if err == nil {
		t.Fatalf("non-http(s) webhook URL must fail at config load (scheme allowlist)")
	}
}

// TestAlertConfig_ValidWebhookAccepted verifies a well-formed webhook URL is
// accepted at config load.
func TestAlertConfig_ValidWebhookAccepted(t *testing.T) {
	cfg, err := config.Parse([]byte(`
listen: "127.0.0.1:8080"
upstream:
  url: "http://git.example.com"
alerts:
  webhook: "https://hooks.example.com/git-proxy"
`))
	if err != nil {
		t.Fatalf("Parse (valid webhook): %v", err)
	}
	if cfg.Alerts.Webhook != "https://hooks.example.com/git-proxy" {
		t.Fatalf("webhook: %q", cfg.Alerts.Webhook)
	}
}