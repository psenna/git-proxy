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