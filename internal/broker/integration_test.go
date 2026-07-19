package broker

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/psenna/git-proxy/internal/auth/token"
	"github.com/psenna/git-proxy/internal/port"
	"github.com/psenna/git-proxy/internal/upstream"
	"github.com/psenna/git-proxy/internal/upstream/github"
)

// fakeGHVault is a CredentialStore holding one repo's GitHub token. The adapter
// reads CredentialsFor(repo).Token for the Bearer leg; the agent never sees it.
type fakeGHVault struct{ token string }

func (f fakeGHVault) CredentialsFor(_ string) (port.Credentials, bool) {
	return port.Credentials{Token: f.token}, true
}

// fakeGitHub is a recording GitHub REST server mounted under /api/v3 (the
// GHES REST root the adapter derives from a non-github.com upstream URL). It
// captures the Authorization header of every request so the test can prove the
// proxy token (ghp_test) reached GitHub and the agent token (agent-token-1)
// never did.
type fakeGitHub struct {
	mu       sync.Mutex
	auths    []string
	mergeErr int // HTTP status to return on PUT .../merge (0 = 200 OK)
}

func (f *fakeGitHub) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v3/repos/owner/repo/pulls", func(w http.ResponseWriter, r *http.Request) {
		f.record(r)
		if r.Method == http.MethodPost {
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"number":7,"title":"t","state":"open","head":{"ref":"feat"},"base":{"ref":"main"},"html_url":"https://gh/pull/7"}`))
			return
		}
		_, _ = w.Write([]byte(`[{"number":7,"state":"open","head":{"ref":"feat"},"base":{"ref":"main"},"html_url":"u"}]`))
	})
	mux.HandleFunc("/api/v3/repos/owner/repo/pulls/7", func(w http.ResponseWriter, r *http.Request) {
		f.record(r)
		_, _ = w.Write([]byte(`{"number":7,"title":"t","state":"open","mergeable":true,"head":{"ref":"feat"},"base":{"ref":"main"},"html_url":"u"}`))
	})
	mux.HandleFunc("/api/v3/repos/owner/repo/pulls/7/merge", func(w http.ResponseWriter, r *http.Request) {
		f.record(r)
		if f.mergeErr != 0 {
			w.WriteHeader(f.mergeErr)
			return
		}
		w.WriteHeader(http.StatusOK)
	})
	return mux
}

func (f *fakeGitHub) record(r *http.Request) {
	f.mu.Lock()
	f.auths = append(f.auths, r.Header.Get("Authorization"))
	f.mu.Unlock()
}

func (f *fakeGitHub) authsSeen() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	cp := make([]string, len(f.auths))
	copy(cp, f.auths)
	return cp
}

// bootIntegration stands up a fake GitHub + real github adapter + real broker
// and returns the broker's base URL plus the fake GitHub for assertions. The
// broker's audit sink is shared so the test can inspect broker events.
func bootIntegration(t *testing.T, cfg Config) (brokerURL string, gh *fakeGitHub, sink *recordingSink, cancel context.CancelFunc) {
	t.Helper()
	gh = &fakeGitHub{}
	srv := httptest.NewServer(gh.handler())
	t.Cleanup(srv.Close)

	adapter := github.New(upstream.UpstreamConfig{
		Kind:            "github",
		URL:             srv.URL, // non-github.com host → rest.BaseURL derives <srv.URL>/api/v3 (GHES path)
		CredentialsStore: fakeGHVault{token: "ghp_test"},
	})

	authn := token.New(map[string]string{
		"agent-token-1": "alice",
		"bob-token-2":   "bob",
	})
	sink = &recordingSink{}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	b, err := New(ln, adapter, nil, map[string]string{"owner/repo.git": "owner/repo.git"}, authn, sink, cfg)
	if err != nil {
		t.Fatalf("broker.New: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() { errCh <- b.Serve(ctx) }()
	t.Cleanup(func() {
		cancel()
		<-errCh
		_ = ln.Close()
	})
	return "http://" + ln.Addr().String(), gh, sink, cancel
}

func req(t *testing.T, method, url, bearer string, body []byte) *http.Response {
	t.Helper()
	var br io.Reader
	if body != nil {
		br = bytes.NewReader(body)
	}
	req, _ := http.NewRequest(method, url, br)
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := (&http.Client{Timeout: 2 * time.Second}).Do(req)
	if err != nil {
		t.Fatalf("Do %s %s: %v", method, url, err)
	}
	return resp
}

func TestIntegration_BrokerEndToEnd(t *testing.T) {
	brokerURL, gh, sink, _ := bootIntegration(t, Config{MergeMethod: "merge"})

	// 1. Create PR → 201.
	resp := req(t, http.MethodPost, brokerURL+"/owner%2Frepo.git/prs", "agent-token-1", []byte(`{"head":"feat","base":"main","title":"t"}`))
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create status = %d, want 201: %s", resp.StatusCode, body)
	}
	if !strings.Contains(string(body), `"number":7`) {
		t.Errorf("create body = %s, want number 7", body)
	}

	// 2. Get PR → 200.
	resp = req(t, http.MethodGet, brokerURL+"/owner%2Frepo.git/prs/7", "agent-token-1", nil)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("get status = %d, want 200", resp.StatusCode)
	}

	// 3. Merge PR → 204 (broker returns No Content on a successful merge).
	resp = req(t, http.MethodPost, brokerURL+"/owner%2Frepo.git/prs/7/merge", "agent-token-1", nil)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("merge status = %d, want 204", resp.StatusCode)
	}

	// No-leak: the proxy token (ghp_test) reached GitHub on every request; the
	// agent token (agent-token-1) never did.
	auths := gh.authsSeen()
	if len(auths) < 3 {
		t.Fatalf("fake GitHub saw %d requests, want >=3", len(auths))
	}
	for _, a := range auths {
		if a != "Bearer ghp_test" {
			t.Errorf("fake GitHub Authorization = %q, want Bearer ghp_test", a)
		}
		if strings.Contains(a, "agent-token-1") {
			t.Errorf("agent token leaked to GitHub: %q", a)
		}
	}

	// Audit: broker recorded an allow per op, Transport "broker", no token leak.
	if len(sink.events) < 3 {
		t.Fatalf("audit recorded %d events, want >=3", len(sink.events))
	}
	for i, e := range sink.events {
		if e.Transport != "broker" {
			t.Errorf("event %d Transport = %q, want broker", i, e.Transport)
		}
		if strings.Contains(e.Agent, "ghp_test") || strings.Contains(e.Repo, "ghp_test") {
			t.Errorf("audit event %d leaks proxy token: %+v", i, e)
		}
		for _, r := range e.Reasons {
			if strings.Contains(r, "ghp_test") || strings.Contains(r, "agent-token-1") {
				t.Errorf("audit event %d reason leaks a token: %q", i, r)
			}
		}
	}
}

func TestIntegration_Negatives(t *testing.T) {
	brokerURL, _, _, _ := bootIntegration(t, Config{})

	// No Bearer → 401.
	resp := req(t, http.MethodGet, brokerURL+"/owner%2Frepo.git/prs/7", "", nil)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("no-bearer status = %d, want 401", resp.StatusCode)
	}

	// Bad Bearer → 401.
	resp = req(t, http.MethodGet, brokerURL+"/owner%2Frepo.git/prs/7", "wrong", nil)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("bad-bearer status = %d, want 401", resp.StatusCode)
	}

	// Unallowlisted agent → 403 (bob-token-2 authenticates as "bob"; only alice
	// is permitted).
	brokerURL2, _, _, _ := bootIntegration(t, Config{AllowedAgents: []string{"alice"}})
	resp = req(t, http.MethodGet, brokerURL2+"/owner%2Frepo.git/prs/7", "bob-token-2", nil)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("unallowlisted status = %d, want 403", resp.StatusCode)
	}
}

func TestIntegration_GitHubConflictMapsToBroker409(t *testing.T) {
	brokerURL, gh, _, _ := bootIntegration(t, Config{})
	gh.mergeErr = http.StatusConflict // GitHub says not-mergeable (409)

	resp := req(t, http.MethodPost, brokerURL+"/owner%2Frepo.git/prs/7/merge", "agent-token-1", nil)
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("status = %d, want 409 (GitHub 409 → broker 409): %s", resp.StatusCode, body)
	}
	if !strings.Contains(string(body), `"not mergeable"`) {
		t.Errorf("body = %s, want generic 'not mergeable' reason", body)
	}
}