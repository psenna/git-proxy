package plain

import (
	"context"
	"encoding/base64"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/psenna/git-proxy/internal/port"
	"github.com/psenna/git-proxy/internal/upstream"
)

// TestSelfRegister asserts the plain adapter self-registers as "plain" on the
// upstream default registry via init(). The default (empty Kind) resolves to
// "plain", so Build with an empty Kind must succeed and return a non-nil
// Upstream — proving backward compatibility (the default path is unchanged).
func TestSelfRegister_PlainOnDefaultRegistry(t *testing.T) {
	f, ok := upstream.Lookup("plain")
	if !ok {
		t.Fatal(`upstream.Lookup("plain"): want found (self-registered via init)`)
	}
	up, err := f(upstream.UpstreamConfig{URL: "http://example.git"})
	if err != nil {
		t.Fatalf("factory: %v", err)
	}
	if up == nil {
		t.Fatal("factory returned nil Upstream")
	}
}

func TestBuild_EmptyKindBuildsPlain(t *testing.T) {
	// The empty Kind defaults to "plain" (backward compatible). Build on the
	// default registry must succeed and return a working Upstream.
	up, err := upstream.Build(upstream.UpstreamConfig{URL: "http://example.git"})
	if err != nil {
		t.Fatalf("Build empty kind: %v", err)
	}
	if up == nil {
		t.Fatal("Build empty kind: returned nil Upstream")
	}
}

func TestBuild_PlainKindBuildsPlain(t *testing.T) {
	// Explicit "plain" Kind builds a plain upstream via the default registry.
	up, err := upstream.Build(upstream.UpstreamConfig{Kind: "plain", URL: "http://example.git"})
	if err != nil {
		t.Fatalf("Build plain: %v", err)
	}
	if up == nil {
		t.Fatal("Build plain: returned nil Upstream")
	}
}

// TestUpstream_AttachesVaultCreds asserts the proxy attaches upstream Basic
// auth credentials from the vault to its outgoing request, proving the
// vault→upstream wiring. The agent never sees this request.
func TestUpstream_AttachesVaultCreds(t *testing.T) {
	var gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/x-git-upload-pack-advertisement")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "0000")
	}))
	defer srv.Close()

	store := memStore{creds: map[string]port.Credentials{
		"test.git": {Username: "ci-bot", Password: "upstream-secret"},
	}}
	up := New(srv.URL, store)

	if _, err := up.ListRefs(context.Background(), "test.git"); err != nil {
		t.Fatalf("ListRefs: %v", err)
	}
	if gotAuth == "" {
		t.Fatal("upstream request had no Authorization header; vault creds not attached")
	}
	want := "Basic " + base64.StdEncoding.EncodeToString([]byte("ci-bot:upstream-secret"))
	if gotAuth != want {
		t.Errorf("Authorization = %q, want %q", gotAuth, want)
	}
}

// TestUpstream_NoCredsWhenVaultEmpty asserts that repos without vault entries
// get no Authorization header (fail closed: no fallback creds).
func TestUpstream_NoCredsWhenVaultEmpty(t *testing.T) {
	var gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/x-git-upload-pack-advertisement")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "0000")
	}))
	defer srv.Close()

	up := New(srv.URL, memStore{creds: map[string]port.Credentials{
		"other.git": {Username: "x", Password: "y"},
	}})
	if _, err := up.ListRefs(context.Background(), "test.git"); err != nil {
		t.Fatalf("ListRefs: %v", err)
	}
	if gotAuth != "" {
		t.Errorf("upstream request got Authorization %q for repo with no vault entry", gotAuth)
	}
}

// TestUpstream_TokenOnlyNoBasicHeader asserts that a token-only credential
// profile (Token set, Username and Password both empty) does NOT attach an
// Authorization header on the git leg. A token-only profile is broker-only
// (the Token is consumed by the SCM adapter, not by Basic auth); attaching
// SetBasicAuth("", "") would emit a meaningless "Basic Og==" header. The git
// leg must skip Basic auth entirely when both Basic fields are empty, leaving
// the request anonymous (subject to deny-by-default / public_repos upstream).
func TestUpstream_TokenOnlyNoBasicHeader(t *testing.T) {
	var gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/x-git-upload-pack-advertisement")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "0000")
	}))
	defer srv.Close()

	store := memStore{creds: map[string]port.Credentials{
		"test.git": {Username: "", Password: "", Token: "ghp_broker_only"},
	}}
	up := New(srv.URL, store)

	if _, err := up.ListRefs(context.Background(), "test.git"); err != nil {
		t.Fatalf("ListRefs: %v", err)
	}
	if gotAuth != "" {
		t.Errorf("token-only profile attached Authorization %q; git leg must skip Basic auth when Username and Password are both empty", gotAuth)
	}
}

// TestUpstream_NilVaultNoCreds asserts a nil vault never attaches creds.
func TestUpstream_NilVaultNoCreds(t *testing.T) {
	var gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/x-git-upload-pack-advertisement")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "0000")
	}))
	defer srv.Close()

	up := New(srv.URL, nil)
	if _, err := up.ListRefs(context.Background(), "test.git"); err != nil {
		t.Fatalf("ListRefs: %v", err)
	}
	if gotAuth != "" {
		t.Errorf("nil vault attached Authorization %q", gotAuth)
	}
}

type memStore struct {
	creds map[string]port.Credentials
}

func (m memStore) CredentialsFor(repo string) (port.Credentials, bool) {
	c, ok := m.creds[repo]
	return c, ok
}
