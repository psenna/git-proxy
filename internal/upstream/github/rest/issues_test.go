package rest

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/psenna/git-proxy/internal/port"
)

func TestCreateIssue(t *testing.T) {
	rs, s := newRecordingServer(t, okJSON(`{"number":42,"title":"t","state":"open","body":"b","html_url":"https://gh/issues/42","labels":[{"name":"bug"}]}`))
	defer s.Close()
	c := New(s.URL, "ghp_proxy")

	issue, err := c.CreateIssue(context.Background(), "owner/repo.git", "t", "b")
	if err != nil {
		t.Fatalf("CreateIssue: %v", err)
	}
	if issue.Number != 42 || issue.URL != "https://gh/issues/42" {
		t.Errorf("Issue = %+v", issue)
	}
	if len(rs.paths) != 1 || rs.paths[0] != "/repos/owner/repo/issues" {
		t.Errorf("path = %v, want /repos/owner/repo/issues (no .git)", rs.paths)
	}
	if rs.methods[0] != http.MethodPost {
		t.Errorf("method = %v", rs.methods)
	}
	if rs.bodies[0]["title"] != "t" || rs.bodies[0]["body"] != "b" {
		t.Errorf("body = %v", rs.bodies[0])
	}
}

func TestCreateIssue_OmitsEmptyBody(t *testing.T) {
	rs, s := newRecordingServer(t, okJSON(`{"number":1,"html_url":"u"}`))
	defer s.Close()
	c := New(s.URL, "tok")
	if _, err := c.CreateIssue(context.Background(), "o/r.git", "t", ""); err != nil {
		t.Fatalf("CreateIssue: %v", err)
	}
	if _, ok := rs.bodies[0]["body"]; ok {
		t.Errorf("empty body should be omitted, body = %v", rs.bodies[0])
	}
}

func TestGetIssue(t *testing.T) {
	rs, s := newRecordingServer(t, okJSON(`{"number":3,"title":"x","state":"closed","body":"bd","html_url":"u","labels":[{"name":"a"},{"name":"b"}]}`))
	defer s.Close()
	c := New(s.URL, "tok")
	st, err := c.GetIssue(context.Background(), "owner/repo.git", 3)
	if err != nil {
		t.Fatalf("GetIssue: %v", err)
	}
	if st.Number != 3 || st.Title != "x" || st.State != "closed" || st.Body != "bd" || st.URL != "u" {
		t.Errorf("IssueState = %+v", st)
	}
	if len(st.Labels) != 2 || st.Labels[0] != "a" || st.Labels[1] != "b" {
		t.Errorf("Labels = %v, want [a b]", st.Labels)
	}
	if rs.paths[0] != "/repos/owner/repo/issues/3" {
		t.Errorf("path = %v", rs.paths)
	}
}

func TestGetIssue_EmptyLabelsIsNotNil(t *testing.T) {
	_, s := newRecordingServer(t, okJSON(`{"number":1,"state":"open","html_url":"u"}`))
	defer s.Close()
	c := New(s.URL, "tok")
	st, err := c.GetIssue(context.Background(), "o/r.git", 1)
	if err != nil {
		t.Fatalf("GetIssue: %v", err)
	}
	if st.Labels == nil {
		t.Errorf("Labels = nil, want non-nil empty slice")
	}
	if len(st.Labels) != 0 {
		t.Errorf("Labels = %v, want empty", st.Labels)
	}
}

func TestListIssues_FiltersPullRequestsAndPaginates(t *testing.T) {
	page := 0
	mux := http.NewServeMux()
	mux.HandleFunc("/repos/o/r/issues", func(w http.ResponseWriter, r *http.Request) {
		page++
		if state := r.URL.Query().Get("state"); state != "closed" {
			t.Errorf("state query = %q, want closed", state)
		}
		if page == 1 {
			q := r.URL.Query()
			q.Set("page", "2")
			w.Header().Set("Link", `<`+r.URL.Path+`?`+q.Encode()+`>; rel="next"`)
			// page 1: an issue + a PR (PR carries a non-null pull_request object)
			_, _ = w.Write([]byte(`[{"number":1,"state":"closed","html_url":"i1"},{"number":2,"state":"closed","html_url":"pr2","pull_request":{"url":"x"}}]`))
			return
		}
		// page 2: an issue only (null pull_request, the normal issue shape)
		_, _ = w.Write([]byte(`[{"number":3,"state":"closed","html_url":"i3","pull_request":null}]`))
	})
	s := httptest.NewServer(mux)
	defer s.Close()
	c := New(s.URL, "tok")
	issues, err := c.ListIssues(context.Background(), "o/r.git", "closed")
	if err != nil {
		t.Fatalf("ListIssues: %v", err)
	}
	// PR #2 must be filtered out; issues #1 and #3 remain, in order.
	if len(issues) != 2 || issues[0].Number != 1 || issues[1].Number != 3 {
		t.Errorf("issues = %+v, want [#1 #3] (PR filtered)", issues)
	}
}

func TestListIssues_EmptyStateDefaultsOpen(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/repos/o/r/issues", func(w http.ResponseWriter, r *http.Request) {
		if state := r.URL.Query().Get("state"); state != "open" {
			t.Errorf("state = %q, want open default", state)
		}
		_, _ = w.Write([]byte(`[]`))
	})
	s := httptest.NewServer(mux)
	defer s.Close()
	c := New(s.URL, "tok")
	if _, err := c.ListIssues(context.Background(), "o/r.git", ""); err != nil {
		t.Fatalf("ListIssues: %v", err)
	}
}

func TestCommentIssue(t *testing.T) {
	rs, s := newRecordingServer(t, func(w http.ResponseWriter) { w.WriteHeader(http.StatusCreated) })
	defer s.Close()
	c := New(s.URL, "tok")
	if err := c.CommentIssue(context.Background(), "owner/repo.git", 5, "note"); err != nil {
		t.Fatalf("CommentIssue: %v", err)
	}
	if rs.paths[0] != "/repos/owner/repo/issues/5/comments" {
		t.Errorf("path = %v", rs.paths)
	}
	if rs.bodies[0]["body"] != "note" {
		t.Errorf("body = %v", rs.bodies[0])
	}
}

func TestCloseIssue(t *testing.T) {
	rs, s := newRecordingServer(t, func(w http.ResponseWriter) { w.WriteHeader(http.StatusOK) })
	defer s.Close()
	c := New(s.URL, "tok")
	if err := c.CloseIssue(context.Background(), "owner/repo.git", 9); err != nil {
		t.Fatalf("CloseIssue: %v", err)
	}
	if rs.methods[0] != http.MethodPatch || rs.paths[0] != "/repos/owner/repo/issues/9" {
		t.Errorf("req = %v %v, want PATCH /repos/owner/repo/issues/9", rs.methods, rs.paths)
	}
	if rs.bodies[0]["state"] != "closed" {
		t.Errorf("body = %v, want state=closed", rs.bodies[0])
	}
}

func TestReopenIssue(t *testing.T) {
	rs, s := newRecordingServer(t, func(w http.ResponseWriter) { w.WriteHeader(http.StatusOK) })
	defer s.Close()
	c := New(s.URL, "tok")
	if err := c.ReopenIssue(context.Background(), "owner/repo.git", 9); err != nil {
		t.Fatalf("ReopenIssue: %v", err)
	}
	if rs.methods[0] != http.MethodPatch {
		t.Errorf("method = %v, want PATCH", rs.methods)
	}
	if rs.bodies[0]["state"] != "open" {
		t.Errorf("body = %v, want state=open", rs.bodies[0])
	}
}

func TestEditIssue_OnlyChangedFields(t *testing.T) {
	rs, s := newRecordingServer(t, okJSON(`{"number":7,"title":"new","state":"open","body":"kept","html_url":"u","labels":[]}`))
	defer s.Close()
	c := New(s.URL, "tok")
	st, err := c.EditIssue(context.Background(), "owner/repo.git", 7, "new", "")
	if err != nil {
		t.Fatalf("EditIssue: %v", err)
	}
	if st.Title != "new" || st.Body != "kept" {
		t.Errorf("IssueState = %+v", st)
	}
	if rs.methods[0] != http.MethodPatch || rs.paths[0] != "/repos/owner/repo/issues/7" {
		t.Errorf("req = %v %v", rs.methods, rs.paths)
	}
	// Empty body must be OMITTED (a nil pointer), not sent as null/"" — otherwise
	// GitHub would blank the body. Only title is present.
	if _, ok := rs.bodies[0]["body"]; ok {
		t.Errorf("empty body field must be omitted, body = %v", rs.bodies[0])
	}
	if rs.bodies[0]["title"] != "new" {
		t.Errorf("title = %v, want new", rs.bodies[0])
	}
}

func TestEditIssue_NoChange(t *testing.T) {
	rs, s := newRecordingServer(t, okJSON(`{"number":7,"title":"old","state":"open","html_url":"u"}`))
	defer s.Close()
	c := New(s.URL, "tok")
	if _, err := c.EditIssue(context.Background(), "o/r.git", 7, "", ""); err != nil {
		t.Fatalf("EditIssue: %v", err)
	}
	// Both fields omitted → empty JSON object (a no-op PATCH).
	if len(rs.bodies[0]) != 0 {
		t.Errorf("no-change PATCH should be {}, got %v", rs.bodies[0])
	}
}

func TestAddLabels(t *testing.T) {
	rs, s := newRecordingServer(t, okJSON(`[{"name":"bug"},{"name":"p1"}]`))
	defer s.Close()
	c := New(s.URL, "tok")
	names, err := c.AddLabels(context.Background(), "owner/repo.git", 5, []string{"bug", "p1"})
	if err != nil {
		t.Fatalf("AddLabels: %v", err)
	}
	if len(names) != 2 || names[0] != "bug" || names[1] != "p1" {
		t.Errorf("names = %v, want [bug p1]", names)
	}
	if rs.paths[0] != "/repos/owner/repo/issues/5/labels" {
		t.Errorf("path = %v", rs.paths)
	}
	if rs.bodies[0]["labels"] == nil {
		t.Errorf("body = %v, want labels array", rs.bodies[0])
	}
}

func TestRemoveLabel_EscapesLabel(t *testing.T) {
	var gotMethod, gotEscaped string
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		// r.URL.Path is the DECODED path (space), so assert on the encoded form
		// to confirm the label was percent-escaped on the wire.
		gotEscaped = r.URL.EscapedPath()
		w.WriteHeader(http.StatusOK)
	})
	s := httptest.NewServer(mux)
	defer s.Close()
	c := New(s.URL, "tok")
	if err := c.RemoveLabel(context.Background(), "owner/repo.git", 5, "needs review"); err != nil {
		t.Fatalf("RemoveLabel: %v", err)
	}
	if gotMethod != http.MethodDelete {
		t.Errorf("method = %v, want DELETE", gotMethod)
	}
	// A label with a space must be percent-encoded in the path.
	if gotEscaped != "/repos/owner/repo/issues/5/labels/needs%20review" {
		t.Errorf("escaped path = %q, want label url-encoded", gotEscaped)
	}
}

func TestIssues_StatusToSentinel(t *testing.T) {
	cases := []struct {
		name   string
		status int
		want   error
		op      func(c *Client) error
	}{
		{"GetIssue_NotFound", http.StatusNotFound, port.ErrNotFound, func(c *Client) error {
			_, err := c.GetIssue(context.Background(), "o/r.git", 9)
			return err
		}},
		{"AddLabels_Unprocessable", http.StatusUnprocessableEntity, port.ErrUnprocessable, func(c *Client) error {
			_, err := c.AddLabels(context.Background(), "o/r.git", 1, []string{"x"})
			return err
		}},
		{"CreateIssue_Unauthorized", http.StatusUnauthorized, port.ErrUnauthorized, func(c *Client) error {
			_, err := c.CreateIssue(context.Background(), "o/r.git", "t", "")
			return err
		}},
		{"CloseIssue_Forbidden", http.StatusForbidden, port.ErrForbidden, func(c *Client) error {
			return c.CloseIssue(context.Background(), "o/r.git", 1)
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFakeGitHub(t, tc.status, `{"message":"a body that must NOT appear in the error"}`)
			srv := f.server(t)
			defer srv.Close()
			c := New(srv.URL, "ghp_proxy")
			if err := tc.op(c); !errors.Is(err, tc.want) {
				t.Errorf("err = %v, want %v", err, tc.want)
			}
		})
	}
}

func TestIssues_BearerIsProxyToken(t *testing.T) {
	// Every issue op must send the proxy's token as Bearer and never leak it in
	// an error (the agent never sees the proxy token).
	f := newFakeGitHub(t, http.StatusInternalServerError, `{"message":"Bearer ghp_proxy leaked"}`)
	srv := f.server(t)
	defer srv.Close()
	c := New(srv.URL, "ghp_proxy")
	err := c.CloseIssue(context.Background(), "o/r.git", 1)
	if err == nil {
		t.Fatal("expected error")
	}
	if len(f.bearer) != 1 || f.bearer[0] != "Bearer ghp_proxy" {
		t.Errorf("Authorization = %v, want Bearer ghp_proxy", f.bearer)
	}
	if strings.Contains(err.Error(), "ghp_proxy") {
		t.Errorf("error leaks token: %v", err)
	}
}

func TestIssues_RejectMalformedRepo(t *testing.T) {
	c := New("https://api.github.com", "tok")
	if _, err := c.GetIssue(context.Background(), "no-slash", 1); err == nil {
		t.Error("expected error for repo with no owner/name slash")
	}
	if _, err := c.CreateIssue(context.Background(), "no-slash", "t", ""); err == nil {
		t.Error("expected error for CreateIssue with malformed repo")
	}
}