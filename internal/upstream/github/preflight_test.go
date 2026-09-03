package github

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/psenna/git-proxy/internal/port"
	"github.com/psenna/git-proxy/internal/preflight"
	"github.com/psenna/git-proxy/internal/upstream/github/rest"
)

func mustBase(t *testing.T, url string) string {
	t.Helper()
	b, err := rest.BaseURL(url)
	if err != nil {
		t.Fatalf("BaseURL: %v", err)
	}
	return b
}

func TestProber_ProbeMatrix(t *testing.T) {
	perms := []preflight.Permission{
		preflight.PermMetadata, preflight.PermContents, preflight.PermChecks,
		preflight.PermActions, preflight.PermPullRequests, preflight.PermIssues,
	}
	statusCases := []struct {
		name   string
		status int
		rl0    bool
		want   error
	}{
		{"ok", http.StatusOK, false, nil},
		{"unauthorized", http.StatusUnauthorized, false, port.ErrUnauthorized},
		{"forbidden", http.StatusForbidden, false, port.ErrForbidden},
		{"ratelimited", http.StatusForbidden, true, port.ErrRateLimited},
		{"notfound", http.StatusNotFound, false, port.ErrNotFound},
		{"server", http.StatusInternalServerError, false, port.ErrUpstream},
	}
	for _, sc := range statusCases {
		for _, perm := range perms {
			t.Run(sc.name+"/"+string(perm), func(t *testing.T) {
				var sawAuth, sawPath string
				srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					sawAuth = r.Header.Get("Authorization")
					sawPath = r.URL.Path
					if sc.rl0 {
						w.Header().Set("X-RateLimit-Remaining", "0")
					}
					w.WriteHeader(sc.status)
					_, _ = w.Write([]byte(`{}`))
				}))
				defer srv.Close()
				p := &Prober{base: mustBase(t, srv.URL)}
				err := p.Probe(context.Background(), "ptok", "o/r.git", perm)
				if sc.want == nil {
					if err != nil {
						t.Fatalf("Probe(%s) = %v, want nil", perm, err)
					}
				} else if !errors.Is(err, sc.want) {
					t.Fatalf("Probe(%s) = %v, want %v", perm, err, sc.want)
				}
				if !strings.HasPrefix(sawPath, "/api/v3/repos/o/r") {
					t.Errorf("path = %q, want /api/v3/repos/o/r...", sawPath)
				}
				if sawAuth != "Bearer ptok" {
					t.Errorf("auth = %q, want Bearer ptok", sawAuth)
				}
			})
		}
	}
}

func TestProber_ContentsEmptyRepo409IsOK(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/commits") {
			w.WriteHeader(http.StatusConflict) // empty repo
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()
	p := &Prober{base: mustBase(t, srv.URL)}
	if err := p.Probe(context.Background(), "tok", "o/r.git", preflight.PermContents); err != nil {
		t.Errorf("Probe(contents) on empty repo = %v, want nil (409 is OK)", err)
	}
}

func TestProber_ChecksHeadNotFoundRetriesDefaultBranch(t *testing.T) {
	t.Run("retry succeeds", func(t *testing.T) {
		var hitDefault bool
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch {
			case strings.Contains(r.URL.Path, "/commits/HEAD/check-runs"):
				w.WriteHeader(http.StatusNotFound)
			case r.URL.Path == "/api/v3/repos/o/r":
				_, _ = w.Write([]byte(`{"default_branch":"trunk"}`))
			case strings.Contains(r.URL.Path, "/commits/trunk/check-runs"):
				hitDefault = true
				_, _ = w.Write([]byte(`{"check_runs":[]}`))
			default:
				w.WriteHeader(http.StatusNotFound)
			}
		}))
		defer srv.Close()
		p := &Prober{base: mustBase(t, srv.URL)}
		if err := p.Probe(context.Background(), "tok", "o/r.git", preflight.PermChecks); err != nil {
			t.Errorf("Probe(checks) = %v, want nil after default-branch retry", err)
		}
		if !hitDefault {
			t.Error("default-branch check-runs was not retried")
		}
	})
	t.Run("retry forbidden surfaces forbidden", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch {
			case strings.Contains(r.URL.Path, "/commits/HEAD/check-runs"):
				w.WriteHeader(http.StatusNotFound)
			case r.URL.Path == "/api/v3/repos/o/r":
				_, _ = w.Write([]byte(`{"default_branch":"trunk"}`))
			case strings.Contains(r.URL.Path, "/commits/trunk/check-runs"):
				w.WriteHeader(http.StatusForbidden)
			default:
				w.WriteHeader(http.StatusNotFound)
			}
		}))
		defer srv.Close()
		p := &Prober{base: mustBase(t, srv.URL)}
		if err := p.Probe(context.Background(), "tok", "o/r.git", preflight.PermChecks); !errors.Is(err, port.ErrForbidden) {
			t.Errorf("Probe(checks) = %v, want ErrForbidden", err)
		}
	})
	t.Run("still 404 stays inconclusive not missing", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/api/v3/repos/o/r" {
				_, _ = w.Write([]byte(`{"default_branch":"trunk"}`))
				return
			}
			w.WriteHeader(http.StatusNotFound)
		}))
		defer srv.Close()
		p := &Prober{base: mustBase(t, srv.URL)}
		err := p.Probe(context.Background(), "tok", "o/r.git", preflight.PermChecks)
		if errors.Is(err, port.ErrForbidden) {
			t.Errorf("Probe(checks) = %v, must not be ErrForbidden (a 404 is not a permission verdict)", err)
		}
		if !errors.Is(err, port.ErrNotFound) {
			t.Errorf("Probe(checks) = %v, want ErrNotFound (inconclusive)", err)
		}
	})
}

func TestProber_SampleRepo_Org(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v3/orgs/example-org/repos" {
			_, _ = w.Write([]byte(`[{"full_name":"example-org/svc"}]`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()
	p := &Prober{base: mustBase(t, srv.URL)}
	got, err := p.SampleRepo(context.Background(), "tok", "example-org/*")
	if err != nil {
		t.Fatalf("SampleRepo: %v", err)
	}
	if got != "example-org/svc.git" {
		t.Errorf("SampleRepo = %q, want example-org/svc.git", got)
	}
}

func TestProber_SampleRepo_UserFallback(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v3/orgs/profile-a/repos":
			w.WriteHeader(http.StatusNotFound)
		case "/api/v3/users/profile-a/repos":
			_, _ = w.Write([]byte(`[{"full_name":"profile-a/dots"}]`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()
	p := &Prober{base: mustBase(t, srv.URL)}
	got, err := p.SampleRepo(context.Background(), "tok", "profile-a/*")
	if err != nil {
		t.Fatalf("SampleRepo: %v", err)
	}
	if got != "profile-a/dots.git" {
		t.Errorf("SampleRepo = %q", got)
	}
}

func TestProber_SampleRepo_ForbiddenIsNoSample(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()
	p := &Prober{base: mustBase(t, srv.URL)}
	if _, err := p.SampleRepo(context.Background(), "tok", "example-org/*"); !errors.Is(err, preflight.ErrNoSample) {
		t.Errorf("SampleRepo = %v, want ErrNoSample", err)
	}
}

func TestProber_SampleRepo_UnsupportedPatternIsNoSample(t *testing.T) {
	p := &Prober{base: "https://api.github.com"}
	for _, pat := range []string{"example-org/sub/*", "example-org/*/x", "example-org/svc-*"} {
		if _, err := p.SampleRepo(context.Background(), "tok", pat); !errors.Is(err, preflight.ErrNoSample) {
			t.Errorf("SampleRepo(%q) = %v, want ErrNoSample (no HTTP call)", pat, err)
		}
	}
}

func TestProber_ErrorsCarryNoToken(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"message":"Bearer sekrettok echoed back"}`))
	}))
	defer srv.Close()
	p := &Prober{base: mustBase(t, srv.URL)}
	err := p.Probe(context.Background(), "sekrettok", "o/r.git", preflight.PermMetadata)
	if err == nil {
		t.Fatal("want error")
	}
	if strings.Contains(err.Error(), "sekrettok") {
		t.Errorf("error leaks token: %v", err)
	}
}

func TestSelfRegister_GitHubProber(t *testing.T) {
	p, ok, err := preflight.ProberFor("github", "https://github.com")
	if err != nil {
		t.Fatalf("ProberFor: %v", err)
	}
	if !ok {
		t.Fatal("github prober not registered")
	}
	if _, isProber := p.(*Prober); !isProber {
		t.Fatalf("ProberFor returned %T, want *github.Prober", p)
	}
}
