package httpfront

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/psenna/git-proxy/internal/auth"
	"github.com/psenna/git-proxy/internal/credentials/repomatch"
	"github.com/psenna/git-proxy/internal/port"
)

// stubAuth is a port.Authenticator that accepts exactly one token.
type stubAuth struct {
	valid    string
	identity auth.AgentIdentity
}

func (a *stubAuth) Authenticate(_ context.Context, token string) (auth.AgentIdentity, error) {
	if token == a.valid {
		return a.identity, nil
	}
	return auth.AgentIdentity{}, errors.New("invalid token")
}

func newTestAuth() *stubAuth {
	return &stubAuth{valid: "good-token", identity: auth.AgentIdentity{Name: "agent-1"}}
}

// A nil Authenticator means no auth: requests pass through (passthrough mode).
func TestFrontend_NilAuthPassthrough(t *testing.T) {
	f := newTestFrontend(t, nil)
	req := httptest.NewRequest(http.MethodGet, "/test.git/info/refs?service=git-upload-pack", nil)
	rr := httptest.NewRecorder()
	f.handle(rr, req)
	// info/refs reverse-proxies to the upstream; status is the upstream's
	// (200 on success). No 401.
	if rr.Code == http.StatusUnauthorized {
		t.Fatalf("nil auth must not 401; got %d", rr.Code)
	}
}

func TestFrontend_MissingToken_Unauthorized(t *testing.T) {
	f := newTestFrontend(t, newTestAuth())
	req := httptest.NewRequest(http.MethodGet, "/test.git/info/refs?service=git-upload-pack", nil)
	rr := httptest.NewRecorder()
	f.handle(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("code = %d, want 401 for missing token", rr.Code)
	}
	if got := rr.Header().Get("WWW-Authenticate"); got != "Bearer" {
		t.Errorf("WWW-Authenticate = %q, want Bearer", got)
	}
}

func TestFrontend_WrongScheme_Unauthorized(t *testing.T) {
	f := newTestFrontend(t, newTestAuth())
	req := httptest.NewRequest(http.MethodGet, "/test.git/info/refs?service=git-upload-pack", nil)
	req.Header.Set("Authorization", "Basic good-token")
	rr := httptest.NewRecorder()
	f.handle(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("code = %d, want 401 for non-Bearer scheme", rr.Code)
	}
}

func TestFrontend_InvalidToken_Unauthorized(t *testing.T) {
	f := newTestFrontend(t, newTestAuth())
	req := httptest.NewRequest(http.MethodGet, "/test.git/info/refs?service=git-upload-pack", nil)
	req.Header.Set("Authorization", "Bearer not-valid")
	rr := httptest.NewRecorder()
	f.handle(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("code = %d, want 401 for invalid token", rr.Code)
	}
}

// TestFrontend_AuthGatesAllEndpoints asserts that the shared auth check (which
// runs in handle BEFORE the endpoint switch) gates all three smart-HTTP
// endpoints, not just /info/refs. A refactor that moved auth into per-endpoint
// handlers would otherwise drop coverage on the POST endpoints. Auth fails
// before the endpoint switch is reached, so proxy: nil is safe (the proxy is
// never invoked).
func TestFrontend_AuthGatesAllEndpoints(t *testing.T) {
	endpoints := []string{
		"/test.git/info/refs?service=git-upload-pack",
		"/test.git/git-upload-pack",
		"/test.git/git-receive-pack",
	}
	cases := []struct {
		name string
		auth string // Authorization header value; "" means none
	}{
		{name: "no_token", auth: ""},
		{name: "invalid_token", auth: "Bearer not-valid"},
	}
	for _, ep := range endpoints {
		for _, c := range cases {
			t.Run(ep+"_"+c.name, func(t *testing.T) {
				f := newTestFrontend(t, newTestAuth())
				method := http.MethodGet
				if ep != "/test.git/info/refs?service=git-upload-pack" {
					method = http.MethodPost
				}
				req := httptest.NewRequest(method, ep, nil)
				if c.auth != "" {
					req.Header.Set("Authorization", c.auth)
				}
				rr := httptest.NewRecorder()
				f.handle(rr, req)
				if rr.Code != http.StatusUnauthorized {
					t.Fatalf("code = %d, want 401 for %s (%s)", rr.Code, ep, c.name)
				}
				if got := rr.Header().Get("WWW-Authenticate"); got != "Bearer" {
					t.Errorf("WWW-Authenticate = %q, want Bearer", got)
				}
			})
		}
	}
}

func TestFrontend_ValidToken_PassesAuth(t *testing.T) {
	f := newTestFrontend(t, newTestAuth())
	req := httptest.NewRequest(http.MethodGet, "/test.git/info/refs?service=git-upload-pack", nil)
	req.Header.Set("Authorization", "Bearer good-token")
	rr := httptest.NewRecorder()
	f.handle(rr, req)
	if rr.Code == http.StatusUnauthorized {
		t.Fatalf("valid token must not 401; got %d", rr.Code)
	}
}

// newTestFrontend builds a Frontend pointed at a trivial upstream that returns
// 200 OK for any path, so auth wiring can be exercised in isolation.
func newTestFrontend(t *testing.T, a port.Authenticator) *Frontend {
	t.Helper()
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(up.Close)
	f := &Frontend{
		upstreamURL: up.URL,
		proxy:       nil, // not exercised by info/refs tests
		repos:       map[string]string{},
		client:      up.Client(),
		auth:        a,
	}
	return f
}

// recordingUpstream is an httptest upstream that records whether it was hit and
// the Authorization header it received. The handler fails the test if hit is
// unexpected (fail-on-hit). Used by the deny-by-default test to prove an denied
// request never reaches the upstream.
type recordingUpstream struct {
	srv       *httptest.Server
	mu        sync.Mutex
	hits      int
	authHdr   string
	failOnHit bool
}

func newRecordingUpstream(t *testing.T, failOnHit bool) *recordingUpstream {
	t.Helper()
	up := &recordingUpstream{failOnHit: failOnHit}
	up.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		up.mu.Lock()
		up.hits++
		up.authHdr = r.Header.Get("Authorization")
		shouldFail := up.failOnHit
		up.mu.Unlock()
		if shouldFail {
			t.Errorf("upstream should not be hit (path %s)", r.URL.Path)
		}
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(up.srv.Close)
	return up
}

func (u *recordingUpstream) snapshot() (int, string) {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.hits, u.authHdr
}

// newDenyFrontend builds a Frontend over up with the given cred store and
// publicRepos allowlist. proxy is nil: the deny-check runs before any proxy
// call, so a denied request never reaches a nil proxy (panics only if the deny
// logic regresses — which the test would catch as a failure, not a false pass).
func newDenyFrontend(t *testing.T, up *recordingUpstream, a port.Authenticator, creds port.CredentialStore, public port.RepoMatcher) *Frontend {
	t.Helper()
	return &Frontend{
		upstreamURL: up.srv.URL,
		proxy:       nil,
		repos:       map[string]string{},
		client:      up.srv.Client(),
		auth:        a,
		creds:       creds,
		publicRepos: public,
	}
}

// TestFrontend_DenyByDefault asserts the HTTP git leg is deny-by-default: a repo
// with no credential profile and no public_repos entry is 403'd without reaching
// the upstream (fail-closed, no-leak). A public_repos entry allows anonymous
// read (no Authorization header to upstream) but still denies push. Auth gates
// before the deny-check, so an unauthenticated request gets 401, not 403.
func TestFrontend_DenyByDefault(t *testing.T) {
	authn := newTestAuth()

	// Case 1: no creds, no public_repos → 403 on an authenticated read, upstream
	// never hit (fail-closed). repo "other/x.git" is not in any cred store.
	t.Run("deny_unconfigured_read", func(t *testing.T) {
		up := newRecordingUpstream(t, true) // fail if hit
		f := newDenyFrontend(t, up, authn, nil, nil)
		req := httptest.NewRequest(http.MethodGet, "/other/x.git/info/refs?service=git-upload-pack", nil)
		req.Header.Set("Authorization", "Bearer good-token")
		rr := httptest.NewRecorder()
		f.handle(rr, req)
		if rr.Code != http.StatusForbidden {
			t.Fatalf("code = %d, want 403 for unconfigured repo", rr.Code)
		}
		if !strings.Contains(rr.Body.String(), "repository not served by this proxy") {
			t.Errorf("body = %q, want it to contain the generic deny reason", rr.Body.String())
		}
		if hits, _ := up.snapshot(); hits != 0 {
			t.Errorf("upstream hit %d times; deny must not reach upstream", hits)
		}
	})

	// Case 2: public_repos matches "other/*" → read allowed, upstream IS hit,
	// and the upstream request has NO Authorization header (anonymous read).
	t.Run("allow_public_read_anonymous", func(t *testing.T) {
		public, err := repomatch.NewBoolMatcher([]string{"other/*"})
		if err != nil {
			t.Fatalf("NewBoolMatcher: %v", err)
		}
		up := newRecordingUpstream(t, false) // hit expected
		f := newDenyFrontend(t, up, authn, nil, public)
		req := httptest.NewRequest(http.MethodGet, "/other/x.git/info/refs?service=git-upload-pack", nil)
		req.Header.Set("Authorization", "Bearer good-token")
		rr := httptest.NewRecorder()
		f.handle(rr, req)
		if rr.Code == http.StatusForbidden {
			t.Fatalf("public_repos read should be allowed; got 403 body=%q", rr.Body.String())
		}
		hits, authHdr := up.snapshot()
		if hits == 0 {
			t.Fatalf("upstream not hit; public_repos read should reach upstream")
		}
		if authHdr != "" {
			t.Errorf("upstream Authorization header = %q; anonymous read must attach none", authHdr)
		}
	})

	// Case 3: public_repos matches but the request is a push (git-receive-pack
	// POST) → 403, upstream not hit. public_repos is read-only.
	t.Run("deny_public_push", func(t *testing.T) {
		public, err := repomatch.NewBoolMatcher([]string{"other/*"})
		if err != nil {
			t.Fatalf("NewBoolMatcher: %v", err)
		}
		up := newRecordingUpstream(t, true) // fail if hit
		f := newDenyFrontend(t, up, authn, nil, public)
		req := httptest.NewRequest(http.MethodPost, "/other/x.git/git-receive-pack", bytes.NewReader([]byte("0000")))
		req.Header.Set("Authorization", "Bearer good-token")
		rr := httptest.NewRecorder()
		f.handle(rr, req)
		if rr.Code != http.StatusForbidden {
			t.Fatalf("code = %d, want 403 for push to public_repos (read-only)", rr.Code)
		}
		if hits, _ := up.snapshot(); hits != 0 {
			t.Errorf("upstream hit %d times; denied push must not reach upstream", hits)
		}
	})

	// Case 4: unauthenticated (no Bearer) → 401, not 403. Confirms auth gates
	// before the deny-check (no leak to unauthenticated callers).
	t.Run("unauth_is_401_not_403", func(t *testing.T) {
		up := newRecordingUpstream(t, true) // fail if hit
		f := newDenyFrontend(t, up, authn, nil, nil)
		req := httptest.NewRequest(http.MethodGet, "/other/x.git/info/refs?service=git-upload-pack", nil)
		rr := httptest.NewRecorder()
		f.handle(rr, req)
		if rr.Code != http.StatusUnauthorized {
			t.Fatalf("code = %d, want 401 for unauthenticated request (auth before deny)", rr.Code)
		}
		if got := rr.Header().Get("WWW-Authenticate"); got != "Bearer" {
			t.Errorf("WWW-Authenticate = %q, want Bearer", got)
		}
		if hits, _ := up.snapshot(); hits != 0 {
			t.Errorf("upstream hit %d times; unauth must not reach upstream", hits)
		}
	})
}
