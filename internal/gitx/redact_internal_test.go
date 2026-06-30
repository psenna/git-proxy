package gitx

import "testing"

// TestRedactCreds verifies URL-embedded credentials are stripped from arbitrary
// strings (git stderr) before they can leak via a wrapped error. This is the
// defense-in-depth counterpart to the generic agent-facing deny reasons: even a
// future caller that %v's a gitx error must not surface upstream creds.
func TestRedactCreds(t *testing.T) {
	cases := []struct {
		name, in, want string
	}{
		{
			name: "user:pass stripped",
			in:   "fatal: unable to access 'https://ci-bot:upstream-do-not-leak-PW@example.com/repo.git/': failed",
			want: "fatal: unable to access 'https://***@example.com/repo.git/': failed",
		},
		{
			name: "user-only stripped (git redacts password but not username)",
			in:   "fatal: unable to access 'http://ci-bot@example.com/repo.git/': failed",
			want: "fatal: unable to access 'http://***@example.com/repo.git/': failed",
		},
		{
			name: "no userinfo unchanged",
			in:   "fatal: unable to access 'http://example.com/repo.git/': failed",
			want: "fatal: unable to access 'http://example.com/repo.git/': failed",
		},
		{
			name: "file url unchanged",
			in:   "fatal: repository 'file:///tmp/repo.git' not found",
			want: "fatal: repository 'file:///tmp/repo.git' not found",
		},
		{
			name: "no url unchanged",
			in:   "error: cannot lock ref 'refs/heads/main'",
			want: "error: cannot lock ref 'refs/heads/main'",
		},
		{
			name: "multiple urls in one string",
			in:   "fetch http://u:p@h/a and http://u2:p2@h2/b done",
			want: "fetch http://***@h/a and http://***@h2/b done",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := redactCreds(c.in); got != c.want {
				t.Errorf("redactCreds(%q)\n  got  = %q\n  want = %q", c.in, got, c.want)
			}
		})
	}
}