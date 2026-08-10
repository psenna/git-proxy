package gitx

import (
	"strings"
	"testing"

	"github.com/psenna/git-proxy/internal/port"
)

// staticStore is a port.CredentialStore that returns a fixed credential and
// ok flag for every repo (used to exercise upstreamRepoURL's credential
// branches without the profile store).
type staticStore struct {
	c  port.Credentials
	ok bool
}

func (s staticStore) CredentialsFor(string) (port.Credentials, bool) {
	return s.c, s.ok
}

// TestUpstreamRepoURL covers the git-protocol leg's upstream-URL credential
// embedding, in particular the token-only synthesis (GitHub PAT Basic form
// x-access-token:<token>) that lets a token-only profile authenticate the
// mirror's clone/fetch. It also guards against the pre-fix regression where a
// token-only profile embedded a malformed ":@" empty userinfo.
func TestUpstreamRepoURL(t *testing.T) {
	const base = "https://github.com/owner"
	const repo = "repo.git"
	const bare = "https://github.com/owner/repo.git"

	cases := []struct {
		name  string
		creds port.CredentialStore
		want  string
	}{
		{
			name:  "nil creds yields bare URL",
			creds: nil,
			want:  bare,
		},
		{
			name:  "no matching profile yields bare URL",
			creds: staticStore{ok: false},
			want:  bare,
		},
		{
			name:  "secretless profile (ok but all fields empty) yields bare URL, not malformed :@",
			creds: staticStore{c: port.Credentials{}, ok: true},
			want:  bare,
		},
		{
			name:  "token-only synthesizes x-access-token Basic userinfo",
			creds: staticStore{c: port.Credentials{Token: "ghp_x"}, ok: true},
			want:  "https://x-access-token:ghp_x@github.com/owner/repo.git",
		},
		{
			name:  "full profile embeds username:password userinfo",
			creds: staticStore{c: port.Credentials{Username: "u", Password: "p", Token: "ghp_x"}, ok: true},
			want:  "https://u:p@github.com/owner/repo.git",
		},
		{
			name:  "password-only profile embeds :password userinfo",
			creds: staticStore{c: port.Credentials{Password: "p"}, ok: true},
			want:  "https://:p@github.com/owner/repo.git",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := upstreamRepoURL(base, repo, tc.creds)
			if got != tc.want {
				t.Fatalf("upstreamRepoURL(...) = %q, want %q", got, tc.want)
			}
			// Defense-in-depth: the token-only URL must never be the malformed
			// ":@" empty-userinfo form that caused issue #71's 401/502.
			if strings.Contains(tc.name, "token-only") && !strings.Contains(got, "x-access-token:ghp_x@") {
				t.Errorf("token-only URL missing synthesized userinfo: %q", got)
			}
		})
	}
}

// TestRedactCreds_SynthesizedUserinfo confirms the synthesized x-access-token
// userinfo is stripped from git stderr before an error reaches the agent, so
// the embedded PAT never leaks through a wrapped gitx error.
func TestRedactCreds_SynthesizedUserinfo(t *testing.T) {
	in := "fatal: could not read Username for 'https://x-access-token:ghp_supersecret@github.com/owner/repo.git'"
	got := redactCreds(in)
	want := "fatal: could not read Username for 'https://***@github.com/owner/repo.git'"
	if got != want {
		t.Fatalf("redactCreds(...) = %q, want %q", got, want)
	}
	if strings.Contains(got, "ghp_supersecret") {
		t.Errorf("redactCreds leaked the token: %q", got)
	}
}
