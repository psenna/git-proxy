package config

import (
	"strings"
	"testing"
)

func TestParseSSHConfig(t *testing.T) {
	c, err := Parse([]byte(`
listen: "127.0.0.1:8080"
upstream:
  url: "http://git.example.com"
ssh:
  listen: "127.0.0.1:2222"
  host_key: "/etc/git-proxy/ssh_host_ed25519"
  authorized_keys:
    "agent-1": "ssh-ed25519 AAAAC3Nz... comment"
`))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if c.SSH.Listen != "127.0.0.1:2222" {
		t.Errorf("SSH.Listen = %q", c.SSH.Listen)
	}
	if c.SSH.HostKey != "/etc/git-proxy/ssh_host_ed25519" {
		t.Errorf("SSH.HostKey = %q", c.SSH.HostKey)
	}
	if got := c.SSH.AuthorizedKeys["agent-1"]; got != "ssh-ed25519 AAAAC3Nz... comment" {
		t.Errorf("SSH.AuthorizedKeys[agent-1] = %q", got)
	}
}

// TestParseSSH_DisabledWhenListenEmpty asserts that an empty/absent
// ssh.listen leaves the SSH frontend disabled (no validation error, no
// required authorized_keys). HTTP frontend config still required.
func TestParseSSH_DisabledWhenListenEmpty(t *testing.T) {
	c, err := Parse([]byte(`
listen: "127.0.0.1:8080"
upstream:
  url: "http://git.example.com"
ssh:
  host_key: "/etc/git-proxy/ssh_host_ed25519"
`))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if c.SSH.Listen != "" {
		t.Errorf("SSH.Listen = %q, want empty (disabled)", c.SSH.Listen)
	}
}

// TestParseSSH_RequiresAuthorizedKeysWhenListenSet asserts fail-closed: an
// SSH frontend with a listen address but no authorized keys is a config error
// (it would deny everyone — that's fine, but a missing map is a likely
// misconfiguration; require it explicitly).
func TestParseSSH_RequiresAuthorizedKeysWhenListenSet(t *testing.T) {
	_, err := Parse([]byte(`
listen: "127.0.0.1:8080"
upstream:
  url: "http://git.example.com"
ssh:
  listen: "127.0.0.1:2222"
`))
	if err == nil || !strings.Contains(err.Error(), "authorized_keys") {
		t.Fatalf("expected authorized_keys required error, got %v", err)
	}
}

// TestParseSSH_HTTPStillRequired asserts the existing HTTP frontend validation
// (listen + upstream.url) is unchanged when SSH is configured.
func TestParseSSH_HTTPStillRequired(t *testing.T) {
	_, err := Parse([]byte(`
ssh:
  listen: "127.0.0.1:2222"
  authorized_keys:
    "agent-1": "ssh-ed25519 AAAA key"
`))
	if err == nil || !strings.Contains(err.Error(), "listen is required") {
		t.Fatalf("expected HTTP listen required error, got %v", err)
	}
}