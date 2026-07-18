package file

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/psenna/git-proxy/internal/port"
)

const vaultYAML = `credentials:
  "test.git":
    username: ci-bot
    password: upstream-secret
  "team/repo.git":
    username: team-bot
    password: team-secret
`

func writeVault(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "vault.yaml")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatalf("write vault: %v", err)
	}
	return p
}

func TestStore_LoadsPerRepoCreds(t *testing.T) {
	s, err := New(writeVault(t, vaultYAML))
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	c, ok := s.CredentialsFor("test.git")
	if !ok {
		t.Fatal("expected creds for test.git")
	}
	if c.Username != "ci-bot" || c.Password != "upstream-secret" {
		t.Errorf("creds = %+v, want {ci-bot, upstream-secret}", c)
	}

	c2, ok := s.CredentialsFor("team/repo.git")
	if !ok || c2.Username != "team-bot" || c2.Password != "team-secret" {
		t.Errorf("creds for team/repo.git = %+v, ok=%v", c2, ok)
	}
}

func TestStore_UnknownRepoFailClosed(t *testing.T) {
	s, err := New(writeVault(t, vaultYAML))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, ok := s.CredentialsFor("unknown.git"); ok {
		t.Error("expected no creds for unknown repo; CredentialStore must fail closed")
	}
}

func TestStore_EmptyPathReturnsEmptyStore(t *testing.T) {
	s, err := New("")
	if err != nil {
		t.Fatalf("New(\"\"): %v", err)
	}
	if _, ok := s.CredentialsFor("test.git"); ok {
		t.Error("empty vault path must not resolve any creds")
	}
}

func TestStore_MalformedVaultFails(t *testing.T) {
	if _, err := New(writeVault(t, "credentials: [unterminated")); err == nil {
		t.Fatal("expected parse error for malformed vault, got nil")
	}
}

func TestStore_MissingFileFails(t *testing.T) {
	if _, err := New(filepath.Join(t.TempDir(), "nope.yaml")); err == nil {
		t.Fatal("expected error for missing vault file, got nil")
	}
}

const vaultWithTokenYAML = `credentials:
  "gh/owner/repo.git":
    username: ci-bot
    password: upstream-secret
    token: ghp_broker_token
  "team/repo.git":
    username: team-bot
    password: team-secret
`

func TestStore_LoadsTokenField(t *testing.T) {
	s, err := New(writeVault(t, vaultWithTokenYAML))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	c, ok := s.CredentialsFor("gh/owner/repo.git")
	if !ok {
		t.Fatal("expected creds for gh/owner/repo.git")
	}
	if c.Token != "ghp_broker_token" {
		t.Errorf("Token = %q, want ghp_broker_token", c.Token)
	}
	// The Basic-auth fields are unchanged alongside the new token field.
	if c.Username != "ci-bot" || c.Password != "upstream-secret" {
		t.Errorf("basic creds = {%s, %s}, want {ci-bot, upstream-secret}", c.Username, c.Password)
	}
}

func TestStore_RepoWithoutTokenHasEmptyToken(t *testing.T) {
	s, err := New(writeVault(t, vaultWithTokenYAML))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	c, ok := s.CredentialsFor("team/repo.git")
	if !ok {
		t.Fatal("expected creds for team/repo.git")
	}
	if c.Token != "" {
		t.Errorf("Token = %q, want empty (no token configured for this repo)", c.Token)
	}
}

func TestStore_ImplementsCredentialStore(t *testing.T) {
	var _ port.CredentialStore = (*Store)(nil)
}
