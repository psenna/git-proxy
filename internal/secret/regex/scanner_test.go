package regex_test

import (
	"strings"
	"testing"

	"github.com/psenna/git-proxy/internal/secret/regex"
)

func TestScanner_Defaults(t *testing.T) {
	sc, err := regex.New(nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	cases := []struct {
		name    string
		path    string
		content string
		wantRule string // expect a finding with this rule name
	}{
		{name: "aws access key id", path: "config.yml", content: "aws_access_key_id: AKIAIOSFODNN7EXAMPLE\n", wantRule: "aws-access-key-id"},
		{name: "github pat", path: "tools.sh", content: "export GH_TOKEN=ghp_abcdefghijklmnopqrstuvwxyz0123456789\n", wantRule: "github-pat"},
		{name: "gitlab pat", path: "ci.yml", content: "token: glpat-abcdefghijklmnopqrstuvwxyz0123\n", wantRule: "gitlab-pat"},
		{name: "private key header", path: "id_rsa", content: "-----BEGIN RSA PRIVATE KEY-----\nbody\n", wantRule: "private-key"},
		{name: "private key openSSH", path: "id_ed25519", content: "-----BEGIN OPENSSH PRIVATE KEY-----\n", wantRule: "private-key"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			findings := sc.Scan(c.path, []byte(c.content))
			found := false
			for _, f := range findings {
				if f.Rule == c.wantRule {
					found = true
					// Line is 1-based and points at the matching line.
					if f.Line < 1 {
						t.Errorf("rule %q: Line=%d, want >=1", c.wantRule, f.Line)
					}
					if f.Path != c.path {
						t.Errorf("rule %q: Path=%q, want %q", c.wantRule, f.Path, c.path)
					}
				}
			}
			if !found {
				t.Fatalf("no finding with rule %q; got %+v", c.wantRule, findings)
			}
		})
	}
}

func TestScanner_CleanFileNoFindings(t *testing.T) {
	sc, _ := regex.New(nil)
	content := []byte("# README\n\nThis is a normal project.\nNo secrets here.\n")
	if findings := sc.Scan("README.md", content); len(findings) != 0 {
		t.Fatalf("clean file got findings: %+v", findings)
	}
}

func TestScanner_Redaction(t *testing.T) {
	sc, _ := regex.New(nil)
	secret := "AKIAIOSFODNN7EXAMPLE"
	content := []byte("key: " + secret + "\n")
	findings := sc.Scan("config.yml", content)
	if len(findings) == 0 {
		t.Fatal("expected a finding")
	}
	for _, f := range findings {
		if strings.Contains(f.Snippet, secret) {
			t.Errorf("snippet leaks secret value %q: %q", secret, f.Snippet)
		}
		if !strings.Contains(f.Snippet, "REDACTED") {
			t.Errorf("snippet does not mark redaction: %q", f.Snippet)
		}
	}
}

func TestScanner_ExtraPattern(t *testing.T) {
	sc, err := regex.New([]regex.Pattern{{Regex: `company-token-[A-Z0-9]{12}`, Name: "company-token"}})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	findings := sc.Scan("app.cfg", []byte("token: company-token-AB12CD34EF56\n"))
	found := false
	for _, f := range findings {
		if f.Rule == "company-token" {
			found = true
			if strings.Contains(f.Snippet, "company-token-AB12CD34EF56") {
				t.Errorf("extra pattern secret not redacted: %q", f.Snippet)
			}
		}
	}
	if !found {
		t.Fatalf("extra pattern not detected; got %+v", findings)
	}
}

func TestScanner_BadExtraPatternReturnsError(t *testing.T) {
	if _, err := regex.New([]regex.Pattern{{Regex: `[`, Name: "bad"}}); err == nil {
		t.Fatal("expected error for malformed extra pattern regex")
	}
}

func TestScanner_PureDeterministic(t *testing.T) {
	sc, _ := regex.New(nil)
	content := []byte("token: ghp_abcdefghijklmnopqrstuvwxyz0123456789\n")
	first := sc.Scan("a", content)
	second := sc.Scan("a", content)
	if len(first) != len(second) {
		t.Fatalf("non-deterministic: %d vs %d", len(first), len(second))
	}
	for i := range first {
		if first[i] != second[i] {
			t.Fatalf("non-deterministic finding %d: %+v vs %+v", i, first[i], second[i])
		}
	}
}