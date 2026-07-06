package httpfront

import "testing"

// TestParsePath verifies smart-HTTP path splitting. The endpoint is always a
// SUFFIX of the path; matching on a substring (the original strings.Index
// implementation) mis-routed a repo whose path contained an endpoint token
// (e.g. "/git-upload-pack.git/git-upload-pack" → empty repo), so this test
// locks in the HasSuffix behavior and guards that regression.
func TestParsePath(t *testing.T) {
	cases := []struct {
		name         string
		path         string
		wantRepo     string
		wantEndpoint string
		wantOK       bool
	}{
		{"simple upload-pack", "/team/repo.git/git-upload-pack", "team/repo.git", "/git-upload-pack", true},
		{"simple receive-pack", "/team/repo.git/git-receive-pack", "team/repo.git", "/git-receive-pack", true},
		{"info/refs", "/team/repo.git/info/refs", "team/repo.git", "/info/refs", true},
		{"root repo upload-pack", "/repo.git/git-upload-pack", "repo.git", "/git-upload-pack", true},
		{"deep repo", "/org/team/repo.git/git-upload-pack", "org/team/repo.git", "/git-upload-pack", true},
		// Regression cases: a repo name containing an endpoint token. The old
		// substring match (strings.Index) found the token inside the repo name
		// and returned an empty repo (mis-routing the agent to the upstream
		// root). HasSuffix matches only the real suffix.
		{"repo named like endpoint", "/git-upload-pack.git/git-upload-pack", "git-upload-pack.git", "/git-upload-pack", true},
		{"repo named info/refs", "/info/refs.git/info/refs", "info/refs.git", "/info/refs", true},
		{"repo named receive-pack", "/git-receive-pack.git/git-receive-pack", "git-receive-pack.git", "/git-receive-pack", true},
		{"non-git path", "/some/other/path", "", "", false},
		{"bare endpoint no repo", "/git-upload-pack", "", "/git-upload-pack", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			repo, ep, ok := parsePath(c.path)
			if ok != c.wantOK {
				t.Fatalf("ok: got %v want %v (repo=%q ep=%q)", ok, c.wantOK, repo, ep)
			}
			if ok {
				if repo != c.wantRepo {
					t.Fatalf("repo: got %q want %q", repo, c.wantRepo)
				}
				if ep != c.wantEndpoint {
					t.Fatalf("endpoint: got %q want %q", ep, c.wantEndpoint)
				}
			}
		})
	}
}