package config

import (
	"strings"
	"testing"
)

const validYAML = `
listen: "127.0.0.1:8080"
upstream:
  url: "http://git.example.com"
repos:
  "team/repo.git": "internal/repo.git"
`

func TestParseValid(t *testing.T) {
	c, err := Parse([]byte(validYAML))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if c.Listen != "127.0.0.1:8080" {
		t.Errorf("Listen = %q, want 127.0.0.1:8080", c.Listen)
	}
	if c.Upstream.URL != "http://git.example.com" {
		t.Errorf("Upstream.URL = %q", c.Upstream.URL)
	}
	if got := c.Repos["team/repo.git"]; got != "internal/repo.git" {
		t.Errorf("repo map = %q", got)
	}
}

func TestParseMissingListen(t *testing.T) {
	_, err := Parse([]byte(`
upstream:
  url: "http://git.example.com"
`))
	if err == nil || !strings.Contains(err.Error(), "listen is required") {
		t.Fatalf("expected listen required error, got %v", err)
	}
}

func TestParseMissingUpstreamURL(t *testing.T) {
	_, err := Parse([]byte(`
listen: "127.0.0.1:8080"
`))
	if err == nil || !strings.Contains(err.Error(), "upstream.url is required") {
		t.Fatalf("expected upstream.url required error, got %v", err)
	}
}

func TestParseInvalidYAML(t *testing.T) {
	_, err := Parse([]byte("listen: [unterminated"))
	if err == nil {
		t.Fatal("expected yaml parse error, got nil")
	}
}

func TestRepoPath(t *testing.T) {
	c, err := Parse([]byte(validYAML))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if got := c.RepoPath("team/repo.git"); got != "internal/repo.git" {
		t.Errorf("mapped repo = %q, want internal/repo.git", got)
	}
	// Unknown repos pass through unchanged.
	if got := c.RepoPath("other.git"); got != "other.git" {
		t.Errorf("unknown repo = %q, want other.git", got)
	}
}

func TestParseAuthAndVault(t *testing.T) {
	c, err := Parse([]byte(`
listen: "127.0.0.1:8080"
upstream:
  url: "http://git.example.com"
  credentials_file: "/etc/git-proxy/vault.yaml"
auth:
  tokens:
    "agent-token-1": "agent-1"
    "agent-token-2": "agent-2"
`))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if c.Upstream.CredentialsFile != "/etc/git-proxy/vault.yaml" {
		t.Errorf("CredentialsFile = %q", c.Upstream.CredentialsFile)
	}
	if got := c.Auth.Tokens["agent-token-1"]; got != "agent-1" {
		t.Errorf("token agent-token-1 = %q, want agent-1", got)
	}
	if got := c.Auth.Tokens["agent-token-2"]; got != "agent-2" {
		t.Errorf("token agent-token-2 = %q, want agent-2", got)
	}
}

func TestParseBrokerConfigDisabledByDefault(t *testing.T) {
	c, err := Parse([]byte(validYAML))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if c.Broker.Listen != "" {
		t.Errorf("Broker.Listen = %q, want empty (broker disabled by default)", c.Broker.Listen)
	}
}

func TestParseBrokerConfigEnabled(t *testing.T) {
	c, err := Parse([]byte(`
listen: "127.0.0.1:8080"
upstream:
  url: "http://git.example.com"
broker:
  listen: "127.0.0.1:8090"
  allowed_agents: ["agent-1", "agent-2"]
  allowed_ops: ["pr.create", "ci.status"]
  merge_method: "squash"
`))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if c.Broker.Listen != "127.0.0.1:8090" {
		t.Errorf("Broker.Listen = %q", c.Broker.Listen)
	}
	if len(c.Broker.AllowedAgents) != 2 || c.Broker.AllowedAgents[0] != "agent-1" {
		t.Errorf("Broker.AllowedAgents = %v", c.Broker.AllowedAgents)
	}
	if len(c.Broker.AllowedOps) != 2 {
		t.Errorf("Broker.AllowedOps = %v", c.Broker.AllowedOps)
	}
	if c.Broker.MergeMethod != "squash" {
		t.Errorf("Broker.MergeMethod = %q", c.Broker.MergeMethod)
	}
}

func TestParseBrokerListenCollisionRejected(t *testing.T) {
	_, err := Parse([]byte(`
listen: "127.0.0.1:8080"
upstream:
  url: "http://git.example.com"
broker:
  listen: "127.0.0.1:8080"
`))
	if err == nil || !strings.Contains(err.Error(), "broker.listen") {
		t.Fatalf("expected broker.listen collision error, got %v", err)
	}
}

func TestParseBrokerListenMalformedRejected(t *testing.T) {
	_, err := Parse([]byte(`
listen: "127.0.0.1:8080"
upstream:
  url: "http://git.example.com"
broker:
  listen: "not-a-host-port"
`))
	if err == nil || !strings.Contains(err.Error(), "broker.listen") {
		t.Fatalf("expected broker.listen malformed error, got %v", err)
	}
}

func TestParseAuditConfig(t *testing.T) {
	// Set: audit enabled with a file path.
	c, err := Parse([]byte(`
listen: "127.0.0.1:8080"
upstream:
  url: "http://git.example.com"
audit:
  file: "/var/log/git-proxy/audit.jsonl"
`))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if c.Audit.File != "/var/log/git-proxy/audit.jsonl" {
		t.Errorf("Audit.File = %q, want /var/log/git-proxy/audit.jsonl", c.Audit.File)
	}
	// Empty/absent: audit disabled (valid — no validation error).
	c2, err := Parse([]byte(`
listen: "127.0.0.1:8080"
upstream:
  url: "http://git.example.com"
`))
	if err != nil {
		t.Fatalf("Parse (no audit): %v", err)
	}
	if c2.Audit.File != "" {
		t.Errorf("Audit.File = %q, want empty (disabled)", c2.Audit.File)
	}
}

func TestParseIssueUpstreamDisabledByDefault(t *testing.T) {
	c, err := Parse([]byte(validYAML))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if c.IssueUpstream.Kind != "" || c.IssueUpstream.URL != "" {
		t.Errorf("IssueUpstream = %+v, want empty (issues disabled by default)", c.IssueUpstream)
	}
}

func TestParseIssueUpstreamEnabled(t *testing.T) {
	c, err := Parse([]byte(`
listen: "127.0.0.1:8080"
upstream:
  kind: github
  url: "https://github.com"
issue_upstream:
  kind: github
  url: "https://github.com"
  credentials_file: /creds/issues.yaml
`))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if c.IssueUpstream.Kind != "github" {
		t.Errorf("IssueUpstream.Kind = %q, want github", c.IssueUpstream.Kind)
	}
	if c.IssueUpstream.URL != "https://github.com" {
		t.Errorf("IssueUpstream.URL = %q", c.IssueUpstream.URL)
	}
	if c.IssueUpstream.CredentialsFile != "/creds/issues.yaml" {
		t.Errorf("IssueUpstream.CredentialsFile = %q", c.IssueUpstream.CredentialsFile)
	}
}

func TestParseIssueUpstreamKindWithoutURLRejected(t *testing.T) {
	_, err := Parse([]byte(`
listen: "127.0.0.1:8080"
upstream:
  url: "https://github.com"
issue_upstream:
  kind: github
`))
	if err == nil || !strings.Contains(err.Error(), "issue_upstream.url is required") {
		t.Fatalf("expected issue_upstream.url required error, got %v", err)
	}
}

func TestParsePublicRepos(t *testing.T) {
	c, err := Parse([]byte(`
listen: "127.0.0.1:8080"
upstream:
  url: "http://git.example.com"
public_repos: ["public/*", "org/r.git"]
`))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(c.PublicRepos) != 2 {
		t.Fatalf("PublicRepos = %v (len %d), want 2 entries", c.PublicRepos, len(c.PublicRepos))
	}
	if c.PublicRepos[0] != "public/*" || c.PublicRepos[1] != "org/r.git" {
		t.Errorf("PublicRepos = %v, want [public/* org/r.git]", c.PublicRepos)
	}

	// Absent public_repos → nil (no allowlist; deny-by-default).
	c2, err := Parse([]byte(validYAML))
	if err != nil {
		t.Fatalf("Parse (no public_repos): %v", err)
	}
	if c2.PublicRepos != nil {
		t.Errorf("PublicRepos = %v, want nil when absent", c2.PublicRepos)
	}
}

func TestParseIssueUpstreamAbsentIsValid(t *testing.T) {
	// No issue_upstream at all: issues disabled, valid (no validation error).
	c, err := Parse([]byte(`
listen: "127.0.0.1:8080"
upstream:
  url: "https://github.com"
broker:
  listen: "127.0.0.1:8090"
`))
	if err != nil {
		t.Fatalf("Parse (no issue_upstream): %v", err)
	}
	if c.IssueUpstream.Kind != "" {
		t.Errorf("IssueUpstream.Kind = %q, want empty", c.IssueUpstream.Kind)
	}
}
