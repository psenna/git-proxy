package httpfront

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/psenna/git-proxy/internal/auth"
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
