// Package config loads the git-proxy YAML configuration.
//
// The configuration carries the proxy listen address, the upstream git server
// URL, and a repo map that translates a repository path as seen by the agent
// into the repository path served by the upstream.
//
// Example:
//
//	listen: "127.0.0.1:8080"
//	upstream:
//	  url: "http://git.example.com"
//	repos:
//	  "team/repo.git": "team/repo.git"
package config

import (
	"fmt"
	"net"
	"net/url"
	"os"

	"gopkg.in/yaml.v3"
)

// Config is the parsed proxy configuration.
type Config struct {
	Listen   string            `yaml:"listen"`
	Upstream UpstreamConfig    `yaml:"upstream"`
	// IssueUpstream is an OPTIONAL, separately-configured upstream that sources
	// the issue tracker (the broker's issue routes), distinct from Upstream
	// (the SCM that backs git protocol + PRSupport). Empty Kind (absent) means
	// issues are disabled — issue routes return 501 per-op; the broker's
	// PRSupport startup fail-closed is unchanged. Decoupling the issue provider
	// from the SCM lets a deployment run, e.g., GitHub as the SCM and Jira as
	// the issue source with no core change. v1 sets both to kind: github
	// (reusing the github adapter, which implements IssueSupport). See
	// internal/port/issues.go.
	IssueUpstream UpstreamConfig `yaml:"issue_upstream"`
	Repos    map[string]string `yaml:"repos"`
	// PublicRepos is the optional allowlist of upstream repository patterns
	// the proxy serves to anonymous (uncredentialed) agents for read-only
	// access. Patterns match the UPSTREAM (mapped) repo path. Wildcards like
	// "public/*" are allowed; bare "*" and "**" are not. Empty/absent → no
	// allowlist (deny-by-default for uncredentialed repos). Patterns are
	// validated at startup by repomatch.NewBoolMatcher in main.go (NOT in
	// Validate) so a malformed pattern fails fast at proxy start, not at
	// config parse time.
	PublicRepos []string `yaml:"public_repos"`
	Auth     AuthConfig        `yaml:"auth"`
	Policy   PolicyConfig      `yaml:"policy"`
	SSH      SSHConfig         `yaml:"ssh"`
	Audit    AuditConfig       `yaml:"audit"`
	Alerts   AlertConfig       `yaml:"alerts"`
	Broker   BrokerConfig      `yaml:"broker"`
}

// BrokerConfig configures the optional agent-facing PR/CI broker HTTP server.
// When Listen is empty/absent the broker is disabled (git-protocol-only
// operation — today's behavior). When enabled, the broker exposes a small REST
// surface to already-authenticated agents and forwards each op to the upstream
// SCM REST API using the proxy's held GitHub token (the agent never receives the
// token). It runs as a separate mux on a separate port from the git-protocol
// frontend; it is NOT a sub-path of the git frontend. config is a pure YAML
// leaf: the broker package defines its own config type and main.go maps this
// into it (mirroring UpstreamConfig), so this struct carries only YAML-facing
// fields and no behavior.
type BrokerConfig struct {
	// Listen is the broker HTTP listen address (e.g. "127.0.0.1:8090").
	// Empty/absent → broker disabled. MUST parse as host:port and MUST differ
	// from the git-protocol Listen address (a separate mux on a separate port).
	Listen string `yaml:"listen"`
	// AllowedAgents is the allowlist of agent names permitted to use broker
	// ops. Empty/absent means "all authenticated agents" (auth still gates;
	// production should set this explicitly).
	AllowedAgents []string `yaml:"allowed_agents"`
	// AllowedOps optionally restricts which op kinds are permitted.
	// Empty/absent means all ops are allowed. Values: "pr.create", "pr.get",
	// "pr.list", "pr.merge", "pr.comment", "pr.review", "ci.status".
	AllowedOps []string `yaml:"allowed_ops"`
	// MergeMethod is the default GitHub merge method when a merge request does
	// not specify one. One of "merge", "squash", "rebase". Empty defaults to
	// "merge".
	MergeMethod string `yaml:"merge_method"`
}

// AuditConfig configures the optional append-only JSONL audit log. When File
// is empty/absent audit is disabled (the pre-audit behavior — no sink wired,
// the proxy skips recording). When set, main.go opens the file at startup
// (fail-fast if it cannot be opened) and wires the sink into both frontends;
// the sink is closed on shutdown. The file is append-only and 0o600.
type AuditConfig struct {
	// File is the filesystem path to the JSONL audit log. Empty → disabled.
	File string `yaml:"file"`
}

// AlertConfig configures the optional violation-alert sink. When Webhook is
// empty/absent alerts are disabled (the pre-alert behavior — no sink wired, the
// proxy never fires an Alert). When set, main.go builds a webhook alert sink
// (HTTP POST) at startup, wraps it in a MultiAlertSink with a log sink, and
// wires it into both frontends; the sink is closed on shutdown. A malformed
// webhook URL fails fast at startup (a config error), NOT at alert time — an
// unreachable webhook at runtime is best-effort (logged, never blocks the op).
// The webhook POST body leaves the proxy, so the Alert payload is treated as a
// leak surface (no blob content, raw secrets, upstream URLs/creds — see
// port.Alert no-leak contract).
type AlertConfig struct {
	// Webhook is the HTTP(S) URL to POST violation Alerts to. Empty → disabled.
	Webhook string `yaml:"webhook"`
}

// UpstreamConfig describes the upstream git server the proxy forwards to.
type UpstreamConfig struct {
	// Kind selects the upstream/SCM adapter by registry name (v1.md M10). Empty
	// means "plain" (the default, backward compatible — plain smart-HTTP git).
	// "github" selects the GitHub adapter skeleton (internal/upstream/github).
	// An unknown Kind fails at startup via upstream.Build (fail-closed — no
	// silent fallback). config is a pure YAML leaf: it does NOT import the
	// upstream registry (no cycle); main.go maps this into upstream.UpstreamConfig.
	Kind            string `yaml:"kind"`
	URL             string `yaml:"url"`
	CredentialsFile string `yaml:"credentials_file"`
}

// SSHConfig configures the optional SSH transport frontend. When Listen is
// empty/absent the SSH frontend is disabled (HTTP-only operation — today's
// behavior). When Listen is set, the SSH frontend is enabled and
// AuthorizedKeys MUST be non-empty (an enabled SSH frontend with no authorized
// keys would deny everyone, which is a likely misconfiguration — require the
// map explicitly). HostKey is the SSH host private-key file path; if empty,
// the frontend generates an ephemeral ed25519 key at startup (dev/test only,
// logged as a warning — not for production).
type SSHConfig struct {
	// Listen is the SSH server listen address (e.g. "127.0.0.1:2222").
	// Empty/absent → SSH frontend disabled.
	Listen string `yaml:"listen"`
	// HostKey is the filesystem path to an SSH host private key (PEM). Empty
	// → ephemeral ed25519 (dev/test only).
	HostKey string `yaml:"host_key"`
	// AuthorizedKeys maps agent-name → authorized public key string (in
	// authorized_keys form, e.g. "ssh-ed25519 AAAA... comment"). The SSH
	// frontend maps a presented client key (by fingerprint) to the agent
	// identity. Required when Listen is set.
	AuthorizedKeys map[string]string `yaml:"authorized_keys"`
}
type AuthConfig struct {
	// Tokens maps a bearer token to the agent name it authenticates. A request
	// is authorized if it presents any token in this map. Empty (the default)
	// means no tokens are valid; in that case the proxy runs without auth only
	// if no Authenticator is wired (see cmd/git-proxy). Production deployments
	// must configure at least one token.
	Tokens map[string]string `yaml:"tokens"`
}

// Parse decodes configuration from raw YAML bytes.
func Parse(b []byte) (*Config, error) {
	var c Config
	if err := yaml.Unmarshal(b, &c); err != nil {
		return nil, fmt.Errorf("config: parse yaml: %w", err)
	}
	if err := c.validate(); err != nil {
		return nil, err
	}
	return &c, nil
}

// Load reads and parses the configuration file at path.
func Load(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("config: read %s: %w", path, err)
	}
	return Parse(b)
}

// validate enforces required fields. Security-relevant config defaults to deny:
// a missing listen address or upstream URL is a configuration error, not a
// silent default.
func (c *Config) validate() error {
	if c.Listen == "" {
		return fmt.Errorf("config: listen is required")
	}
	if c.Upstream.URL == "" {
		return fmt.Errorf("config: upstream.url is required")
	}
	// Issue upstream: optional. When Kind is set (issues opted-in), the URL is
	// required — a missing URL on an enabled issue upstream is a config error
	// (fail closed at startup, NOT a silent fallback to the SCM upstream). An
	// absent IssueUpstream (empty Kind) means issues disabled, which is allowed.
	if c.IssueUpstream.Kind != "" && c.IssueUpstream.URL == "" {
		return fmt.Errorf("config: issue_upstream.url is required when issue_upstream.kind is set")
	}
	// SSH frontend: disabled when Listen is empty (HTTP-only operation). When
	// enabled, AuthorizedKeys MUST be non-empty (fail closed: an enabled SSH
	// frontend with no authorized keys is a misconfiguration — require the map
	// explicitly rather than silently denying everyone). HostKey is optional
	// (ephemeral fallback for dev/test, warned at startup).
	if c.SSH.Listen != "" && len(c.SSH.AuthorizedKeys) == 0 {
		return fmt.Errorf("config: ssh.authorized_keys is required when ssh.listen is set (an enabled SSH frontend with no authorized keys denies everyone)")
	}
	// Alerts: an empty webhook means alerts are disabled (allowed — no
	// fail-fast). A non-empty but malformed webhook URL is a config error:
	// fail fast at startup (NOT at alert time) so a typo is caught immediately
	// rather than silently dropping every alert. An unreachable webhook at
	// runtime is best-effort (the sink returns a delivery error the proxy logs;
	// the op proceeds), which is distinct from a malformed URL.
	if c.Alerts.Webhook != "" {
		if err := validateWebhookURL(c.Alerts.Webhook); err != nil {
			return fmt.Errorf("config: alerts.webhook: %w", err)
		}
	}
	// Broker: disabled when Listen is empty (git-protocol-only operation). When
	// enabled, Listen MUST parse as host:port and MUST differ from the git
	// frontend Listen address — the broker is a separate mux on a separate port,
	// never a sub-path of the git frontend. A collision would silently shadow one
	// server with the other, so fail closed at startup.
	if c.Broker.Listen != "" {
		if err := validateHostPort(c.Broker.Listen); err != nil {
			return fmt.Errorf("config: broker.listen: %w", err)
		}
		if c.Broker.Listen == c.Listen {
			return fmt.Errorf("config: broker.listen must differ from listen (broker runs on a separate port)")
		}
	}
	return nil
}

// validateHostPort parses a as host:port (net.SplitHostPort) and requires a
// non-empty host and port, so a malformed listen address (e.g. "not-a-url",
// "8090", or ":8090" with no host) fails at startup rather than binding
// unexpectedly. A bare ":8090" (all-interfaces, no host) is accepted for dev
// convenience — it is a valid host:port with an empty host — but a value with no
// port separator is rejected.
func validateHostPort(a string) error {
	host, port, err := net.SplitHostPort(a)
	if err != nil {
		return fmt.Errorf("invalid host:port %q: %w", a, err)
	}
	if port == "" {
		return fmt.Errorf("invalid host:port %q: missing port", a)
	}
	_ = host // host may be empty ("":8090 binds all interfaces); port is required
	return nil
}

// validateWebhookURL parses u and requires an http(s) scheme and a host so a
// malformed webhook URL (e.g. "://not-a-url", "not a url", or a "file://..."
// typo) fails at startup, not at alert time. The scheme allowlist is the single
// source of truth: the config layer fails before the sink is even built, with a
// config-namespaced error. The webhook sink (internal/alert/webhook) applies
// the same allowlist independently as defense-in-depth (a sink constructed
// directly, e.g. in a test, is still rejected), but config is what operators
// see first.
func validateWebhookURL(u string) error {
	parsed, err := url.Parse(u)
	if err != nil {
		return err
	}
	if parsed.Scheme == "" || parsed.Host == "" {
		return fmt.Errorf("missing scheme or host")
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return fmt.Errorf("unsupported scheme %q (http/https only)", parsed.Scheme)
	}
	return nil
}

// RepoPath maps an agent-facing repository path to the upstream repository
// path. If the repo is not in the map, the agent-facing path is used verbatim
// (passthrough). Later milestones may fail closed on unknown repos; passthrough
// does not.
func (c *Config) RepoPath(repo string) string {
	if p, ok := c.Repos[repo]; ok && p != "" {
		return p
	}
	return repo
}
