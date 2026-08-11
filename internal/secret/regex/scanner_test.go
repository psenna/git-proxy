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
		name     string
		path     string
		content  string
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
			findings := sc.Scan(c.path, []byte(c.content), nil)
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
	if findings := sc.Scan("README.md", content, nil); len(findings) != 0 {
		t.Fatalf("clean file got findings: %+v", findings)
	}
}

func TestScanner_Redaction(t *testing.T) {
	sc, _ := regex.New(nil)
	secret := "AKIAIOSFODNN7EXAMPLE"
	content := []byte("key: " + secret + "\n")
	findings := sc.Scan("config.yml", content, nil)
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
	findings := sc.Scan("app.cfg", []byte("token: company-token-AB12CD34EF56\n"), nil)
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
	first := sc.Scan("a", content, nil)
	second := sc.Scan("a", content, nil)
	if len(first) != len(second) {
		t.Fatalf("non-deterministic: %d vs %d", len(first), len(second))
	}
	for i := range first {
		if first[i] != second[i] {
			t.Fatalf("non-deterministic finding %d: %+v vs %+v", i, first[i], second[i])
		}
	}
}

// TestScanner_AllowlistSuppressesExactMatch: an AWS access key id whose raw
// matched value exactly equals an allowlist entry is suppressed (Suppressed=true)
// and its snippet stays redacted (the raw value must not appear). Path/Line/Rule
// are still correct.
func TestScanner_AllowlistSuppressesExactMatch(t *testing.T) {
	sc, err := regex.New(nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	const secret = "AKIAIOSFODNN7EXAMPLE"
	findings := sc.Scan("config.yml", []byte("aws_access_key_id: "+secret+"\n"), []string{secret})
	if len(findings) == 0 {
		t.Fatal("expected a finding")
	}
	for _, f := range findings {
		if f.Rule != "aws-access-key-id" {
			continue
		}
		if !f.Suppressed {
			t.Errorf("finding for %q not suppressed; got Suppressed=%v", secret, f.Suppressed)
		}
		if f.Path != "config.yml" {
			t.Errorf("Path = %q, want config.yml", f.Path)
		}
		if f.Line != 1 {
			t.Errorf("Line = %d, want 1", f.Line)
		}
		if strings.Contains(f.Snippet, secret) {
			t.Errorf("snippet leaks raw value %q: %q", secret, f.Snippet)
		}
		if !strings.Contains(f.Snippet, "REDACTED") {
			t.Errorf("snippet does not mark redaction: %q", f.Snippet)
		}
	}
}

// TestScanner_AllowlistSuppressesHighEntropy: a high-entropy run whose raw value
// exactly matches an allowlist entry is suppressed.
func TestScanner_AllowlistSuppressesHighEntropy(t *testing.T) {
	sc, err := regex.New(nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	// 60-char base64-ish run: above the {40,} entropy-run threshold and high
	// enough entropy to trip the heuristic.
	const run = "Z9hJ4kL2mN7pQ1rS3tU5vW0xY6aB8cD4eF7gH2iJ3kL6mN9oP0qR"
	findings := sc.Scan("config.txt", []byte("token: "+run+"\n"), []string{run})
	var sawEntropy bool
	for _, f := range findings {
		if f.Rule != "high-entropy" {
			continue
		}
		sawEntropy = true
		if !f.Suppressed {
			t.Errorf("high-entropy finding not suppressed; got %+v", f)
		}
		if strings.Contains(f.Snippet, run) {
			t.Errorf("snippet leaks raw run %q: %q", run, f.Snippet)
		}
	}
	if !sawEntropy {
		t.Fatalf("no high-entropy finding; got %+v", findings)
	}
}

// TestScanner_EmptyAllowlistIsTodayBehavior: nil and empty allowlists produce no
// Suppressed findings — every match is live (today's behavior).
func TestScanner_EmptyAllowlistIsTodayBehavior(t *testing.T) {
	sc, _ := regex.New(nil)
	const secret = "AKIAIOSFODNN7EXAMPLE"
	content := []byte("key: " + secret + "\n")
	for _, allow := range [][]string{nil, {}, []string{"", "  "}} {
		findings := sc.Scan("config.yml", content, allow)
		if len(findings) == 0 {
			t.Fatalf("allowlist %v: expected a finding", allow)
		}
		for _, f := range findings {
			if f.Suppressed {
				t.Errorf("allowlist %v: finding unexpectedly suppressed: %+v", allow, f)
			}
		}
	}
}

// TestScanner_AllowlistDoesNotPartialMatch: a prefix entry ("AKIA") must not
// suppress the full key — the comparison is exact-match on the raw value.
func TestScanner_AllowlistDoesNotPartialMatch(t *testing.T) {
	sc, _ := regex.New(nil)
	const secret = "AKIAIOSFODNN7EXAMPLE"
	findings := sc.Scan("config.yml", []byte("key: "+secret+"\n"), []string{"AKIA"})
	for _, f := range findings {
		if f.Suppressed {
			t.Errorf("prefix allowlist entry suppressed a non-equal value: %+v", f)
		}
	}
}

// TestScanner_AllowlistMixed: an allowlisted secret on one line is suppressed
// while a different secret on another line stays live.
func TestScanner_AllowlistMixed(t *testing.T) {
	sc, _ := regex.New(nil)
	const aws = "AKIAIOSFODNN7EXAMPLE"
	content := "aws: " + aws + "\n" + "gl: glpat-abcdefghijklmnopqrstuvwxyz0123\n"
	findings := sc.Scan("config.yml", []byte(content), []string{aws})
	var sawSuppressed, sawLive bool
	for _, f := range findings {
		if f.Suppressed {
			sawSuppressed = true
			if f.Rule != "aws-access-key-id" {
				t.Errorf("suppressed finding rule = %q, want aws-access-key-id", f.Rule)
			}
		} else {
			sawLive = true
		}
	}
	if !sawSuppressed {
		t.Errorf("expected a suppressed aws finding; got %+v", findings)
	}
	if !sawLive {
		t.Errorf("expected a live (non-suppressed) gitlab finding; got %+v", findings)
	}
}

// TestScanner_AllowlistWhitespaceEntriesDropped: whitespace-only allowlist
// entries are dropped (they must not match anything), while a real entry still
// suppresses its exact match.
func TestScanner_AllowlistWhitespaceEntriesDropped(t *testing.T) {
	sc, _ := regex.New(nil)
	const secret = "AKIAIOSFODNN7EXAMPLE"
	findings := sc.Scan("config.yml", []byte("key: "+secret+"\n"), []string{"", "   ", secret})
	found := false
	for _, f := range findings {
		if f.Rule != "aws-access-key-id" {
			continue
		}
		found = true
		if !f.Suppressed {
			t.Errorf("finding not suppressed despite exact allowlist match: %+v", f)
		}
	}
	if !found {
		t.Fatalf("no aws-access-key-id finding; got %+v", findings)
	}
}

func TestScanner_SkipsBinaryBlobs(t *testing.T) {
	// A binary blob (NUL byte present) containing a long high-entropy run must
	// yield NO finding; the same run in a text file must still be flagged so
	// the entropy heuristic stays effective for text.
	sc, _ := regex.New(nil)
	// 60-char base64-ish run: well above the 40-char entropy-run threshold and
	// high-entropy enough to trip the heuristic.
	run := "Z9hJ4kL2mN7pQ1rS3tU5vW0xY6aB8cD4eF7gH2iJ3kL6mN9oP0qR"
	binary := append([]byte("header\n"), []byte(run)...)
	binary = append(binary, 0, '\n') // NUL byte => binary
	binary = append(binary, []byte(run)...)

	if got := sc.Scan("artifact.bin", binary, nil); len(got) != 0 {
		t.Fatalf("binary blob got findings: %+v", got)
	}

	text := []byte("header\n" + run + "\n")
	got := sc.Scan("config.txt", text, nil)
	if len(got) == 0 {
		t.Fatalf("text with same high-entropy run got no finding; want at least one")
	}
	var sawEntropy bool
	for _, f := range got {
		if f.Rule == "high-entropy" {
			sawEntropy = true
		}
	}
	if !sawEntropy {
		t.Fatalf("text run did not trip high-entropy; got %+v", got)
	}
}
