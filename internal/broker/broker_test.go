package broker

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/psenna/git-proxy/internal/auth"
	"github.com/psenna/git-proxy/internal/port"
)

// stubUpstream implements port.Upstream ONLY (not PRSupport), for the New
// type-assert fail-closed test. The git-protocol methods are unused here.
type stubUpstream struct{}

func (stubUpstream) ListRefs(context.Context, string) (port.Refs, error)         { return port.Refs{}, nil }
func (stubUpstream) ListRefsService(context.Context, string, string) (port.Refs, error) { return port.Refs{}, nil }
func (stubUpstream) UploadPack(context.Context, string, io.Reader) (io.ReadCloser, error) { return nil, nil }
func (stubUpstream) ReceivePack(context.Context, string, io.Reader) (io.ReadCloser, error) { return nil, nil }

// stubPRSupport implements both port.Upstream and port.PRSupport, for the New
// success path and handler tests (PR9). Its methods return canned values/errs.
type stubPRSupport struct {
	stubUpstream
	prNumber int
	prErr    error
	mergeErr error
	summary  port.CheckSummary
}

func (s stubPRSupport) BranchProtection(context.Context, string, string) (port.BranchProtection, error) {
	return port.BranchProtection{}, port.ErrNotImplemented
}
func (s stubPRSupport) EnsurePR(context.Context, string, string, string, string) (port.PR, error) {
	return port.PR{Number: s.prNumber, URL: "https://gh/pull/" + itoa(s.prNumber)}, s.prErr
}
func (s stubPRSupport) GetPR(context.Context, string, int) (port.PRState, error) {
	return port.PRState{Number: s.prNumber}, s.prErr
}
func (s stubPRSupport) ListPRs(context.Context, string, string) ([]port.PRState, error) {
	return []port.PRState{{Number: s.prNumber}}, s.prErr
}
func (s stubPRSupport) MergePR(context.Context, string, int, string) error { return s.mergeErr }
func (s stubPRSupport) CommentPR(context.Context, string, int, string) error { return s.prErr }
func (s stubPRSupport) ReviewPR(context.Context, string, int, string, string) error { return s.prErr }
func (s stubPRSupport) Checks(context.Context, string, string) (port.CheckSummary, error) {
	return s.summary, s.prErr
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}

// fakeAuthenticator implements port.Authenticator with a fixed token→name map.
type fakeAuthenticator struct {
	tokens map[string]string
}

func (f fakeAuthenticator) Authenticate(_ context.Context, token string) (auth.AgentIdentity, error) {
	if name, ok := f.tokens[token]; ok {
		return auth.AgentIdentity{Name: name}, nil
	}
	return auth.AgentIdentity{}, errors.New("invalid token")
}

// recordingSink captures audit events for assertions.
type recordingSink struct{ events []port.AuditEvent }

func (r *recordingSink) Record(_ context.Context, e port.AuditEvent) error {
	r.events = append(r.events, e)
	return nil
}

func mustNew(t *testing.T, up port.Upstream, authn port.Authenticator, audit port.AuditSink, cfg Config) *Broker {
	t.Helper()
	b, err := New(nil, up, nil, authn, audit, cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return b
}

func TestNew_FailsClosedWhenUpstreamLacksPRSupport(t *testing.T) {
	_, err := New(nil, stubUpstream{}, nil, fakeAuthenticator{}, nil, Config{})
	if err == nil {
		t.Fatal("New: want error when upstream does not implement PRSupport (fail closed)")
	}
}

func TestNew_TypeAssertsPRSupport(t *testing.T) {
	b := mustNew(t, stubPRSupport{prNumber: 7}, fakeAuthenticator{}, nil, Config{})
	if b.prs == nil {
		t.Fatal("New: prs is nil after successful type-assert")
	}
	if b.mergeMethod != "merge" {
		t.Errorf("mergeMethod = %q, want merge (default)", b.mergeMethod)
	}
}

func TestNew_MergeMethodDefaultAndOverride(t *testing.T) {
	if b := mustNew(t, stubPRSupport{}, fakeAuthenticator{}, nil, Config{}); b.mergeMethod != "merge" {
		t.Errorf("default mergeMethod = %q, want merge", b.mergeMethod)
	}
	if b := mustNew(t, stubPRSupport{}, fakeAuthenticator{}, nil, Config{MergeMethod: "squash"}); b.mergeMethod != "squash" {
		t.Errorf("mergeMethod = %q, want squash", b.mergeMethod)
	}
}

func TestAuthenticate(t *testing.T) {
	b := mustNew(t, stubPRSupport{}, fakeAuthenticator{tokens: map[string]string{"good": "alice"}}, nil, Config{})

	cases := []struct {
		name string
		auth string
		want string // expected agent name; empty means expect error
	}{
		{"valid bearer", "Bearer good", "alice"},
		{"missing header", "", ""},
		{"wrong scheme", "Token good", ""},
		{"unknown token", "Bearer bad", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
			if tc.auth != "" {
				req.Header.Set("Authorization", tc.auth)
			}
			id, err := b.authenticate(req)
			if tc.want == "" {
				if err == nil {
					t.Fatalf("authenticate(%q): want error, got %v", tc.auth, id)
				}
				return
			}
			if err != nil {
				t.Fatalf("authenticate(%q): %v", tc.auth, err)
			}
			if id.Name != tc.want {
				t.Errorf("agent = %q, want %q", id.Name, tc.want)
			}
		})
	}
}

func TestAuthenticate_NilAuthenticatorFailsClosed(t *testing.T) {
	b := mustNew(t, stubPRSupport{}, nil, nil, Config{})
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	req.Header.Set("Authorization", "Bearer anything")
	if _, err := b.authenticate(req); err == nil {
		t.Fatal("authenticate with nil authenticator: want error (broker never runs unauthenticated)")
	}
}

func TestAuthorize(t *testing.T) {
	cases := []struct {
		name          string
		allowedAgents []string
		allowedOps    []string
		agent         string
		op            string
		want          bool
	}{
		{"empty sets allow all", nil, nil, "alice", "pr.merge", true},
		{"agent allowlist match", []string{"alice"}, nil, "alice", "pr.merge", true},
		{"agent allowlist miss", []string{"bob"}, nil, "alice", "pr.merge", false},
		{"op allowlist match", nil, []string{"pr.get"}, "alice", "pr.get", true},
		{"op allowlist miss", nil, []string{"pr.get"}, "alice", "pr.merge", false},
		{"both allowlists match", []string{"alice"}, []string{"pr.merge"}, "alice", "pr.merge", true},
		{"agent ok op miss", []string{"alice"}, []string{"pr.get"}, "alice", "pr.merge", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b := mustNew(t, stubPRSupport{}, fakeAuthenticator{}, nil, Config{AllowedAgents: tc.allowedAgents, AllowedOps: tc.allowedOps})
			if got := b.authorize(auth.AgentIdentity{Name: tc.agent}, tc.op); got != tc.want {
				t.Errorf("authorize(%q,%q) = %v, want %v", tc.agent, tc.op, got, tc.want)
			}
		})
	}
}

func TestResolveRepo(t *testing.T) {
	b := mustNew(t, stubPRSupport{}, fakeAuthenticator{}, nil, Config{})
	b.repos = map[string]string{"alias": "owner/repo.git"}
	if got := b.resolveRepo("alias"); got != "owner/repo.git" {
		t.Errorf("resolveRepo(alias) = %q, want owner/repo.git", got)
	}
	if got := b.resolveRepo("owner/repo.git"); got != "owner/repo.git" {
		t.Errorf("resolveRepo(unknown) = %q, want passthrough", got)
	}
}

func TestAudit_RecordsBrokerEventNoLeak(t *testing.T) {
	sink := &recordingSink{}
	b := mustNew(t, stubPRSupport{}, fakeAuthenticator{}, sink, Config{})
	b.audit(context.Background(), "alice", "owner/repo.git", "pr.merge", "deny", []string{"not permitted"})

	if len(sink.events) != 1 {
		t.Fatalf("recorded %d events, want 1", len(sink.events))
	}
	e := sink.events[0]
	if e.Transport != "broker" {
		t.Errorf("Transport = %q, want broker", e.Transport)
	}
	if e.Agent != "alice" || e.Repo != "owner/repo.git" || e.Service != "pr.merge" || e.Verdict != "deny" {
		t.Errorf("event = %+v", e)
	}
	if len(e.Reasons) != 1 || e.Reasons[0] != "not permitted" {
		t.Errorf("Reasons = %v", e.Reasons)
	}
	if e.Time.IsZero() {
		t.Error("Time is zero; want a stamped time")
	}
}

func TestAudit_NilSinkIsNoop(t *testing.T) {
	b := mustNew(t, stubPRSupport{}, fakeAuthenticator{}, nil, Config{})
	// Must not panic with a nil sink.
	b.audit(context.Background(), "alice", "owner/repo.git", "pr.merge", "allow", nil)
}

func TestServe_Healthz(t *testing.T) {
	b := mustNew(t, stubPRSupport{}, fakeAuthenticator{}, nil, Config{})
	srv := httptest.NewServer(b.server.Handler)
	defer srv.Close()
	resp, err := http.Get(srv.URL + "/healthz")
	if err != nil {
		t.Fatalf("GET /healthz: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}
}