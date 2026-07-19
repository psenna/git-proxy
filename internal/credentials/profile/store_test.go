package profile

import (
	"bytes"
	"log"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeVault writes the YAML body to a temp file and returns its path. The
// caller does NOT need to clean up: t.TempDir() handles it.
func writeVault(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "credentials.yaml")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatalf("write vault: %v", err)
	}
	return p
}

// --- Field resolution ---

func TestFieldResolution_EnvWinsOverFile(t *testing.T) {
	body := `
credentials:
  - name: company_abc
    username: file-user
    password: lit-pass
    token: lit-tok
    repos: ["mycompany/repo1.git"]
`
	p := writeVault(t, body)
	t.Setenv("COMPANY_ABC_TOKEN", "set-tok")
	// PASSWORD unset → file value used
	s, err := New(p)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	c, ok := s.CredentialsFor("mycompany/repo1.git")
	if !ok {
		t.Fatalf("expected creds for mycompany/repo1.git")
	}
	if c.Token != "set-tok" {
		t.Errorf("token: got %q, want %q (env should win)", c.Token, "set-tok")
	}
	if c.Password != "lit-pass" {
		t.Errorf("password: got %q, want %q (env unset → file)", c.Password, "lit-pass")
	}
}

func TestFieldResolution_PasswordEnv(t *testing.T) {
	body := `
credentials:
  - name: company_abc
    password: lit-pass
    repos: ["mycompany/repo1.git"]
`
	p := writeVault(t, body)
	t.Setenv("COMPANY_ABC_PASSWORD", "p")
	s, err := New(p)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	c, ok := s.CredentialsFor("mycompany/repo1.git")
	if !ok {
		t.Fatalf("expected creds")
	}
	if c.Password != "p" {
		t.Errorf("password: got %q, want %q", c.Password, "p")
	}
}

func TestFieldResolution_EmptyEnvFallsBackToFile(t *testing.T) {
	body := `
credentials:
  - name: company_abc
    token: lit-tok
    repos: ["mycompany/repo1.git"]
`
	p := writeVault(t, body)
	// Setting to empty string models "env unset/empty" — envOr treats empty as
	// fall-back.
	t.Setenv("COMPANY_ABC_TOKEN", "")
	s, err := New(p)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	c, ok := s.CredentialsFor("mycompany/repo1.git")
	if !ok {
		t.Fatalf("expected creds")
	}
	if c.Token != "lit-tok" {
		t.Errorf("token: got %q, want %q (empty env → file fallback)", c.Token, "lit-tok")
	}
}

func TestFieldResolution_BothUnsetReturnsEmpty(t *testing.T) {
	body := `
credentials:
  - name: company_abc
    username: file-user
    repos: ["mycompany/repo1.git"]
`
	p := writeVault(t, body)
	// No env set; file has no password/token. Profile is secretless → store
	// returns (zero, false).
	s, err := New(p)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	c, ok := s.CredentialsFor("mycompany/repo1.git")
	if ok {
		t.Errorf("expected no creds for secretless profile, got %+v", c)
	}
}

// --- Uppercasing ---

func TestUppercasing_LowercaseEnvNotRead(t *testing.T) {
	body := `
credentials:
  - name: company_abc
    token: lit-tok
    repos: ["mycompany/repo1.git"]
`
	p := writeVault(t, body)
	// A lowercase-prefixed var should NOT be read — only the uppercased name is.
	t.Setenv("company_abc_TOKEN", "wrong-tok")
	s, err := New(p)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	c, ok := s.CredentialsFor("mycompany/repo1.git")
	if !ok {
		t.Fatalf("expected creds")
	}
	if c.Token != "lit-tok" {
		t.Errorf("token: got %q, want %q (lowercase env must not be read)", c.Token, "lit-tok")
	}
}

func TestUppercasing_UppercaseEnvRead(t *testing.T) {
	body := `
credentials:
  - name: company_abc
    token: lit-tok
    repos: ["mycompany/repo1.git"]
`
	p := writeVault(t, body)
	t.Setenv("COMPANY_ABC_TOKEN", "env-tok")
	s, err := New(p)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	c, ok := s.CredentialsFor("mycompany/repo1.git")
	if !ok {
		t.Fatalf("expected creds")
	}
	if c.Token != "env-tok" {
		t.Errorf("token: got %q, want %q", c.Token, "env-tok")
	}
}

// --- Matching ---

func TestMatching_ExactWinsOverWildcard(t *testing.T) {
	body := `
credentials:
  - name: A
    password: pass-A
    token: tok-A
    repos: ["mycompany/repo1.git"]
  - name: B
    password: pass-B
    token: tok-B
    repos: ["mycompany/*"]
`
	p := writeVault(t, body)
	s, err := New(p)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	c, ok := s.CredentialsFor("mycompany/repo1.git")
	if !ok {
		t.Fatalf("expected creds")
	}
	if c.Password != "pass-A" {
		t.Errorf("exact match: got %q, want pass-A", c.Password)
	}
}

func TestMatching_WildcardMatch(t *testing.T) {
	body := `
credentials:
  - name: A
    password: pass-A
    token: tok-A
    repos: ["mycompany/repo1.git"]
  - name: B
    password: pass-B
    token: tok-B
    repos: ["mycompany/*"]
`
	p := writeVault(t, body)
	s, err := New(p)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	c, ok := s.CredentialsFor("mycompany/repo2.git")
	if !ok {
		t.Fatalf("expected creds for wildcard match")
	}
	if c.Password != "pass-B" {
		t.Errorf("wildcard match: got %q, want pass-B", c.Password)
	}
}

func TestMatching_NoMatch(t *testing.T) {
	body := `
credentials:
  - name: A
    password: pass-A
    token: tok-A
    repos: ["mycompany/repo1.git"]
  - name: B
    password: pass-B
    token: tok-B
    repos: ["mycompany/*"]
`
	p := writeVault(t, body)
	s, err := New(p)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, ok := s.CredentialsFor("other/x.git"); ok {
		t.Errorf("expected no creds for other/x.git")
	}
}

// --- Tri-state out of the store ---

func TestTriState_ProfiledWithSecret(t *testing.T) {
	body := `
credentials:
  - name: company_abc
    password: lit-pass
    token: lit-tok
    repos: ["mycompany/repo1.git"]
`
	p := writeVault(t, body)
	s, err := New(p)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	c, ok := s.CredentialsFor("mycompany/repo1.git")
	if !ok {
		t.Fatalf("expected (creds, true) for profiled-with-secret")
	}
	if c.Password != "lit-pass" || c.Token != "lit-tok" {
		t.Errorf("got password=%q token=%q", c.Password, c.Token)
	}
}

func TestTriState_SecretlessProfile(t *testing.T) {
	body := `
credentials:
  - name: company_abc
    username: file-user
    repos: ["mycompany/repo1.git"]
`
	p := writeVault(t, body)
	s, err := New(p)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	c, ok := s.CredentialsFor("mycompany/repo1.git")
	if ok {
		t.Errorf("expected (zero, false) for secretless profile, got %+v", c)
	}
}

func TestTriState_NoProfile(t *testing.T) {
	body := `
credentials:
  - name: company_abc
    password: lit-pass
    token: lit-tok
    repos: ["mycompany/repo1.git"]
`
	p := writeVault(t, body)
	s, err := New(p)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, ok := s.CredentialsFor("nowhere/match.git"); ok {
		t.Errorf("expected (zero, false) for no profile match")
	}
}

// --- Startup fatal ---

func TestStartupFatal_Table(t *testing.T) {
	cases := []struct {
		name string
		body string
	}{
		{
			name: "empty name",
			body: `
credentials:
  - name: ""
    password: p
    token: t
    repos: ["r/x.git"]
`,
		},
		{
			name: "invalid chars",
			body: `
credentials:
  - name: "bad-name"
    password: p
    token: t
    repos: ["r/x.git"]
`,
		},
		{
			name: "dup name case-insensitive",
			body: `
credentials:
  - name: company_abc
    password: p
    token: t
    repos: ["a/x.git"]
  - name: COMPANY_ABC
    password: p
    token: t
    repos: ["b/x.git"]
`,
		},
		{
			name: "empty repos",
			body: `
credentials:
  - name: company_abc
    password: p
    token: t
    repos: []
`,
		},
		{
			name: "malformed pattern",
			body: `
credentials:
  - name: company_abc
    password: p
    token: t
    repos: ["["]
`,
		},
		{
			name: "bare star",
			body: `
credentials:
  - name: company_abc
    password: p
    token: t
    repos: ["*"]
`,
		},
		{
			name: "double star",
			body: `
credentials:
  - name: company_abc
    password: p
    token: t
    repos: ["a/**"]
`,
		},
		{
			name: "dup exact repo across profiles",
			body: `
credentials:
  - name: A
    password: p
    token: t
    repos: ["mycompany/repo1.git"]
  - name: B
    password: p
    token: t
    repos: ["mycompany/repo1.git"]
`,
		},
		{
			name: "dup wildcard across profiles",
			body: `
credentials:
  - name: A
    password: p
    token: t
    repos: ["mycompany/*"]
  - name: B
    password: p
    token: t
    repos: ["mycompany/*"]
`,
		},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			p := writeVault(t, tc.body)
			s, err := New(p)
			if err == nil {
				t.Fatalf("expected error from New, got nil; store=%+v", s)
			}
		})
	}
}

func TestStartupFatal_BadPath(t *testing.T) {
	// A path that cannot be read is a fatal startup error.
	s, err := New("/no/such/file/here.yaml")
	if err == nil {
		t.Fatalf("expected error for missing file, got nil; store=%+v", s)
	}
}

func TestNew_EmptyPathReturnsEmptyStore(t *testing.T) {
	s, err := New("")
	if err != nil {
		t.Fatalf("New(empty): %v", err)
	}
	if s == nil {
		t.Fatal("New(empty) returned nil store")
	}
	if _, ok := s.CredentialsFor("anything/x.git"); ok {
		t.Errorf("empty store should match nothing")
	}
}

// --- Startup non-fatal (warnings) ---

func TestStartupNonFatal_SecretlessProfileWarning(t *testing.T) {
	body := `
credentials:
  - name: company_abc
    description: "Main org token"
    username: file-user
    repos: ["mycompany/repo1.git"]
`
	p := writeVault(t, body)
	orig := log.Default().Writer()
	defer log.SetOutput(orig)
	var buf bytes.Buffer
	log.SetOutput(&buf)
	s, err := New(p)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if s == nil {
		t.Fatal("nil store")
	}
	out := buf.String()
	// Warning must reference the uppercased env-var NAMES and description.
	for _, want := range []string{"COMPANY_ABC_PASSWORD", "COMPANY_ABC_TOKEN", "Main org token"} {
		if !strings.Contains(out, want) {
			t.Errorf("warning missing %q; got:\n%s", want, out)
		}
	}
}

func TestStartupNonFatal_OneLeggedTokenOnly(t *testing.T) {
	body := `
credentials:
  - name: company_abc
    description: "broker-only profile"
    token: lit-tok
    repos: ["mycompany/repo1.git"]
`
	p := writeVault(t, body)
	orig := log.Default().Writer()
	defer log.SetOutput(orig)
	var buf bytes.Buffer
	log.SetOutput(&buf)
	if _, err := New(p); err != nil {
		t.Fatalf("New: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "broker-only") {
		t.Errorf("expected broker-only info line; got:\n%s", out)
	}
}

func TestStartupNonFatal_OneLeggedPasswordOnly(t *testing.T) {
	body := `
credentials:
  - name: company_abc
    description: "git-only profile"
    password: lit-pass
    repos: ["mycompany/repo1.git"]
`
	p := writeVault(t, body)
	orig := log.Default().Writer()
	defer log.SetOutput(orig)
	var buf bytes.Buffer
	log.SetOutput(&buf)
	if _, err := New(p); err != nil {
		t.Fatalf("New: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "git-only") {
		t.Errorf("expected git-only info line; got:\n%s", out)
	}
}

// --- No-leak binding (security invariant) ---
//
// A startup warning fires when a profile is one-legged (password set, token
// empty, or vice versa) or fully secretless. That warning must name the
// env-var NAMES (uppercased) and the profile description — NEVER the resolved
// secret values. This is a hard security invariant: the warnings are
// operator-facing log output; a leaked secret in a log is a compromise.

func TestNoLeak_WarningNeverIncludesSecretValue(t *testing.T) {
	// Profile has a real file password but no token (env or file) → the
	// "password but no token" warning fires. The env var COMPANY_ABC_TOKEN is
	// unset (empty) so it models "no usable env"; the warning must name the
	// env-var NAME and description but must not echo the file password value.
	body := `
credentials:
  - name: company_abc
    description: "secret profile"
    password: hunter2
    repos: ["mycompany/repo1.git"]
`
	p := writeVault(t, body)
	t.Setenv("COMPANY_ABC_TOKEN", "")
	orig := log.Default().Writer()
	defer log.SetOutput(orig)
	var buf bytes.Buffer
	log.SetOutput(&buf)
	if _, err := New(p); err != nil {
		t.Fatalf("New: %v", err)
	}
	out := buf.String()
	if strings.Contains(out, "hunter2") {
		t.Errorf("LEAK: warning includes file password value; got:\n%s", out)
	}
	// The env-var NAME and description SHOULD appear.
	if !strings.Contains(out, "COMPANY_ABC_TOKEN") {
		t.Errorf("warning should name COMPANY_ABC_TOKEN; got:\n%s", out)
	}
	if !strings.Contains(out, "secret profile") {
		t.Errorf("warning should include description; got:\n%s", out)
	}
}

func TestNoLeak_EnvSecretNotInWarning(t *testing.T) {
	// A secretless profile (no file password/token) with a real-looking env
	// token set must NOT echo that env value in the "no usable credential"
	// warning — only the env-var NAME.
	body := `
credentials:
  - name: company_abc
    description: "secret profile"
    username: file-user
    repos: ["mycompany/repo1.git"]
`
	p := writeVault(t, body)
	// Token env is empty → profile is secretless → "no usable credential"
	// warning fires.
	t.Setenv("COMPANY_ABC_TOKEN", "")
	t.Setenv("COMPANY_ABC_PASSWORD", "")
	orig := log.Default().Writer()
	defer log.SetOutput(orig)
	var buf bytes.Buffer
	log.SetOutput(&buf)
	if _, err := New(p); err != nil {
		t.Fatalf("New: %v", err)
	}
	out := buf.String()
	// A real-looking secret set via env would leak if the warning ever
	// printed resolved values. Here env is empty, so there is no value to
	// leak — but assert the warning text only contains NAMES, not any value
	// placeholder.
	if strings.Contains(out, "ghp_") || strings.Contains(out, "hunter") {
		t.Errorf("LEAK: warning includes a secret-like value; got:\n%s", out)
	}

	// Now: one-legged profile where the token comes from env (real secret) and
	// password is empty → "token but no password" warning fires. Assert the
	// env secret value is NOT in the warning, but the env-var NAME is.
	body2 := `
credentials:
  - name: company_abc
    description: "broker profile"
    repos: ["mycompany/repo1.git"]
`
	p2 := writeVault(t, body2)
	t.Setenv("COMPANY_ABC_TOKEN", "ghp_supersecret")
	t.Setenv("COMPANY_ABC_PASSWORD", "")
	var buf2 bytes.Buffer
	log.SetOutput(&buf2)
	if _, err := New(p2); err != nil {
		t.Fatalf("New p2: %v", err)
	}
	out2 := buf2.String()
	if strings.Contains(out2, "ghp_supersecret") {
		t.Errorf("LEAK: warning includes env token value; got:\n%s", out2)
	}
	if !strings.Contains(out2, "COMPANY_ABC_PASSWORD") {
		t.Errorf("warning should name COMPANY_ABC_PASSWORD; got:\n%s", out2)
	}
}

// --- WildcardPatterns ---

func TestWildcardPatterns(t *testing.T) {
	body := `
credentials:
  - name: A
    description: "team A repos"
    password: p
    token: t
    repos: ["mycompany/repo1.git", "mycompany/*"]
  - name: B
    description: "team B repos"
    password: p
    token: t
    repos: ["otherteam/*", "sibling/exact.git"]
`
	p := writeVault(t, body)
	s, err := New(p)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ws := s.WildcardPatterns()
	if len(ws) != 2 {
		t.Fatalf("expected 2 wildcards, got %d: %+v", len(ws), ws)
	}
	byPattern := map[string]profileWildcard{}
	for _, w := range ws {
		byPattern[w.Pattern] = w
	}
	if w, ok := byPattern["mycompany/*"]; !ok {
		t.Errorf("missing mycompany/*; got %+v", ws)
	} else {
		if w.Name != "A" {
			t.Errorf("mycompany/* Name: got %q, want A", w.Name)
		}
		if w.Description != "team A repos" {
			t.Errorf("mycompany/* Description: got %q, want 'team A repos'", w.Description)
		}
	}
	if w, ok := byPattern["otherteam/*"]; !ok {
		t.Errorf("missing otherteam/*; got %+v", ws)
	} else {
		if w.Name != "B" {
			t.Errorf("otherteam/* Name: got %q, want B", w.Name)
		}
		if w.Description != "team B repos" {
			t.Errorf("otherteam/* Description: got %q, want 'team B repos'", w.Description)
		}
	}
}
