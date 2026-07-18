package rest

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/psenna/git-proxy/internal/port"
)

// fakeGitHub returns canned responses keyed by method+path, recording every
// request's Authorization header and path so tests can assert the proxy's token
// is sent (and never the agent's).
type fakeGitHub struct {
	mux      *http.ServeMux
	bearer   []string
	paths    []string
	lastResp int
	body     string
	headers  http.Header
}

func newFakeGitHub(t *testing.T, status int, body string) *fakeGitHub {
	t.Helper()
	f := &fakeGitHub{lastResp: status, body: body, headers: http.Header{}}
	f.mux = http.NewServeMux()
	f.mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		f.bearer = append(f.bearer, r.Header.Get("Authorization"))
		f.paths = append(f.paths, r.Method+" "+r.URL.Path)
		if h := r.Header.Get("X-RitHub-Leak"); h != "" { // exercise no-leak through headers
			w.Header().Set("X-RitHub-Leak", h)
		}
		if r.Header.Get("Link-Drip") == "drip" {
			w.Header().Set("Link", `<`+r.URL.String()+`?page=2>; rel="next"`)
		}
		w.WriteHeader(f.lastResp)
		_, _ = w.Write([]byte(f.body))
	})
	return f
}

func (f *fakeGitHub) server(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(f.mux)
}

func TestClient_SetsBearerAndApiHeaders(t *testing.T) {
	f := newFakeGitHub(t, http.StatusOK, `{}`)
	s := f.server(t)
	defer s.Close()

	c := New(s.URL, "ghp_proxy_token")
	var out map[string]any
	if _, err := c.do(context.Background(), http.MethodGet, "repos/owner/repo/pulls", nil, &out); err != nil {
		t.Fatalf("do: %v", err)
	}
	if len(f.bearer) != 1 || f.bearer[0] != "Bearer ghp_proxy_token" {
		t.Errorf("Authorization = %v, want Bearer ghp_proxy_token", f.bearer)
	}
	if len(f.paths) != 1 || f.paths[0] != "GET /repos/owner/repo/pulls" {
		t.Errorf("path = %v", f.paths)
	}
}

func TestClient_MapErrors(t *testing.T) {
	cases := []struct {
		status int
		want   error
	}{
		{http.StatusUnauthorized, port.ErrUnauthorized},
		{http.StatusForbidden, port.ErrForbidden},
		{http.StatusNotFound, port.ErrNotFound},
		{http.StatusUnprocessableEntity, port.ErrUnprocessable},
		{http.StatusConflict, port.ErrNotMergeable},
		{http.StatusTooManyRequests, port.ErrRateLimited},
		{http.StatusInternalServerError, port.ErrUpstream},
		{http.StatusBadGateway, port.ErrUpstream},
	}
	for _, tc := range cases {
		t.Run(http.StatusText(tc.status), func(t *testing.T) {
			f := newFakeGitHub(t, tc.status, `{"message":"a body that must NOT appear in the error"}`)
			s := f.server(t)
			defer s.Close()
			c := New(s.URL, "ghp_proxy_token")
			_, err := c.do(context.Background(), http.MethodGet, "repos/o/r/pulls/1", nil, nil)
			if !errors.Is(err, tc.want) {
				t.Errorf("status %d: err = %v, want %v", tc.status, err, tc.want)
			}
			if err != nil && strings.Contains(err.Error(), "a body that must NOT appear") {
				t.Errorf("status %d: error leaks upstream body: %v", tc.status, err)
			}
		})
	}
}

func TestClient_NoLeakTokenInError(t *testing.T) {
	// A GHES-style deployment might echo request headers in a 5xx body; the
	// client must never surface that body, or the token would leak to the agent.
	f := newFakeGitHub(t, http.StatusInternalServerError, `{"message":"Bearer ghp_proxy_token leaked"}`)
	s := f.server(t)
	defer s.Close()
	c := New(s.URL, "ghp_proxy_token")
	_, err := c.do(context.Background(), http.MethodGet, "repos/o/r/pulls/1", nil, nil)
	if err == nil {
		t.Fatal("expected error")
	}
	if strings.Contains(err.Error(), "ghp_proxy_token") {
		t.Errorf("error leaks token: %v", err)
	}
}

func TestClient_NormalizeRepo(t *testing.T) {
	cases := []struct {
		in            string
		wantOwner     string
		wantRepo      string
		wantErr       bool
	}{
		{"owner/repo.git", "owner", "repo", false},
		{"owner/repo", "owner", "repo", false},
		{"team/sub/repo.git", "team", "sub/repo", false}, // split on FIRST slash
		{"repo", "", "", true},
		{"", "", "", true},
	}
	for _, tc := range cases {
		o, r, err := normalizeRepo(tc.in)
		if tc.wantErr {
			if err == nil {
				t.Errorf("%q: expected error, got (%q,%q,nil)", tc.in, o, r)
			}
			continue
		}
		if err != nil || o != tc.wantOwner || r != tc.wantRepo {
			t.Errorf("%q: got (%q,%q,%v), want (%q,%q,nil)", tc.in, o, r, err, tc.wantOwner, tc.wantRepo)
		}
	}
}

func TestClient_ListAllFollowsPagination(t *testing.T) {
	got := 0
	mux := http.NewServeMux()
	mux.HandleFunc("/repos/o/r/pulls", func(w http.ResponseWriter, r *http.Request) {
		got++
		if page := r.URL.Query().Get("page"); page == "" || page == "1" {
			q := r.URL.Query()
			q.Set("page", "2")
			w.Header().Set("Link", `<`+r.URL.Path+`?`+q.Encode()+`>; rel="next"`)
			_, _ = w.Write([]byte(`[{"number":1}]`))
			return
		}
		_, _ = w.Write([]byte(`[{"number":2}]`))
	})
	s := httptest.NewServer(mux)
	defer s.Close()

	c := New(s.URL, "ghp_proxy_token")
	var all []struct {
		Number int `json:"number"`
	}
	if err := c.listAll(context.Background(), "repos/o/r/pulls", &all); err != nil {
		t.Fatalf("listAll: %v", err)
	}
	if got != 2 {
		t.Errorf("requests = %d, want 2 (followed one Link)", got)
	}
	if len(all) != 2 || all[0].Number != 1 || all[1].Number != 2 {
		t.Errorf("results = %+v, want [{1},{2}]", all)
	}
}

func TestClient_DecodesJSONOnSuccess(t *testing.T) {
	f := newFakeGitHub(t, http.StatusOK, `{"number":42,"html_url":"https://x/pull/42"}`)
	s := f.server(t)
	defer s.Close()
	c := New(s.URL, "tok")
	var out struct {
		Number  int    `json:"number"`
		HTMLURL string `json:"html_url"`
	}
	if _, err := c.do(context.Background(), http.MethodGet, "repos/o/r/pulls/42", nil, &out); err != nil {
		t.Fatalf("do: %v", err)
	}
	if out.Number != 42 || out.HTMLURL != "https://x/pull/42" {
		t.Errorf("decoded = %+v", out)
	}
}

func TestClient_OmitsBodyWhenOutNil(t *testing.T) {
	f := newFakeGitHub(t, http.StatusOK, `{"irrelevant":"body"}`)
	s := f.server(t)
	defer s.Close()
	c := New(s.URL, "tok")
	resp, err := c.do(context.Background(), http.MethodGet, "repos/o/r/pulls/1", nil, nil)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	if resp != nil {
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}
	// No assertion on decode (out was nil); just ensure no panic / no error.
}

func TestClient_DoRejectsNonJSONDecode(t *testing.T) {
	f := newFakeGitHub(t, http.StatusOK, `not-json`)
	s := f.server(t)
	defer s.Close()
	c := New(s.URL, "tok")
	var out map[string]any
	_, err := c.do(context.Background(), http.MethodGet, "repos/o/r/pulls/1", nil, &out)
	if err == nil {
		t.Fatal("expected decode error for non-JSON 200 body")
	}
	// ensure decode error doesn't leak the token accidentally
	if strings.Contains(err.Error(), "tok") {
		t.Errorf("decode error leaks token: %v", err)
	}
}