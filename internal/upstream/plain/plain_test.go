package plain

import (
	"context"
	"encoding/base64"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/psenna/git-proxy/internal/port"
)

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
