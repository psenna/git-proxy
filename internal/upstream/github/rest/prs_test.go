package rest

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/psenna/git-proxy/internal/port"
)

// recordingServer captures method+path and the decoded JSON body of each
// request, then returns a canned response.
type recordingServer struct {
	methods []string
	paths   []string
	bodies  []map[string]any
	resp    func(w http.ResponseWriter)
}

func newRecordingServer(t *testing.T, respFn func(w http.ResponseWriter)) (*recordingServer, *httptest.Server) {
	t.Helper()
	rs := &recordingServer{resp: respFn}
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		rs.methods = append(rs.methods, r.Method)
		rs.paths = append(rs.paths, r.URL.Path)
		if r.Body != nil {
			b, _ := io.ReadAll(r.Body)
			var m map[string]any
			_ = json.Unmarshal(b, &m)
			rs.bodies = append(rs.bodies, m)
		}
		rs.resp(w)
	})
	return rs, httptest.NewServer(mux)
}

func okJSON(body string) func(http.ResponseWriter) {
	return func(w http.ResponseWriter) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	}
}

func TestCreatePR(t *testing.T) {
	rs, s := newRecordingServer(t, okJSON(`{"number":7,"title":"fix","state":"open","mergeable":true,"head":{"ref":"feat"},"base":{"ref":"main"},"html_url":"https://gh/pull/7"}`))
	defer s.Close()
	c := New(s.URL, "tok")

	pr, err := c.CreatePR(context.Background(), "owner/repo.git", "feat", "main", "fix")
	if err != nil {
		t.Fatalf("CreatePR: %v", err)
	}
	if pr.Number != 7 || pr.Title != "fix" || pr.State != "open" || pr.Head != "feat" || pr.Base != "main" || pr.URL != "https://gh/pull/7" {
		t.Errorf("PR = %+v", pr)
	}
	if len(rs.paths) != 1 || rs.paths[0] != "/repos/owner/repo/pulls" {
		t.Errorf("path = %v, want /repos/owner/repo/pulls (no .git)", rs.paths)
	}
	if rs.methods[0] != http.MethodPost {
		t.Errorf("method = %v", rs.methods)
	}
	if rs.bodies[0]["head"] != "feat" || rs.bodies[0]["base"] != "main" || rs.bodies[0]["title"] != "fix" {
		t.Errorf("body = %v", rs.bodies[0])
	}
}

func TestGetPR(t *testing.T) {
	_, s := newRecordingServer(t, okJSON(`{"number":3,"title":"x","state":"closed","mergeable":false,"head":{"ref":"b"},"base":{"ref":"main"},"html_url":"u"}`))
	defer s.Close()
	c := New(s.URL, "tok")
	pr, err := c.GetPR(context.Background(), "owner/repo.git", 3)
	if err != nil {
		t.Fatalf("GetPR: %v", err)
	}
	if pr.Number != 3 || pr.State != "closed" {
		t.Errorf("PR = %+v", pr)
	}
}

func TestGetPR_NotFound(t *testing.T) {
	rs := &recordingServer{}
	rs.resp = func(w http.ResponseWriter) { w.WriteHeader(http.StatusNotFound) }
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) { rs.resp(w) })
	s := httptest.NewServer(mux)
	defer s.Close()
	c := New(s.URL, "tok")
	_, err := c.GetPR(context.Background(), "owner/repo.git", 99)
	if !errors.Is(err, port.ErrNotFound) {
		t.Errorf("err = %v, want ErrNotFound", err)
	}
}

func TestListPRs(t *testing.T) {
	page := 0
	mux := http.NewServeMux()
	mux.HandleFunc("/repos/o/r/pulls", func(w http.ResponseWriter, r *http.Request) {
		page++
		if state := r.URL.Query().Get("state"); state != "open" {
			t.Errorf("state query = %q, want open", state)
		}
		if page == 1 {
			q := r.URL.Query()
			q.Set("page", "2")
			w.Header().Set("Link", `<`+r.URL.Path+`?`+q.Encode()+`>; rel="next"`)
			_, _ = w.Write([]byte(`[{"number":1,"state":"open","head":{"ref":"a"},"base":{"ref":"main"}}]`))
			return
		}
		_, _ = w.Write([]byte(`[{"number":2,"state":"open","head":{"ref":"b"},"base":{"ref":"main"}}]`))
	})
	s := httptest.NewServer(mux)
	defer s.Close()
	c := New(s.URL, "tok")
	prs, err := c.ListPRs(context.Background(), "o/r.git", "open")
	if err != nil {
		t.Fatalf("ListPRs: %v", err)
	}
	if len(prs) != 2 || prs[0].Number != 1 || prs[1].Number != 2 {
		t.Errorf("prs = %+v", prs)
	}
}

func TestMergePR(t *testing.T) {
	rs, s := newRecordingServer(t, func(w http.ResponseWriter) { w.WriteHeader(http.StatusOK) })
	defer s.Close()
	c := New(s.URL, "tok")
	if err := c.MergePR(context.Background(), "owner/repo.git", 7, "squash"); err != nil {
		t.Fatalf("MergePR: %v", err)
	}
	if rs.methods[0] != http.MethodPut || rs.paths[0] != "/repos/owner/repo/pulls/7/merge" {
		t.Errorf("req = %v %v", rs.methods, rs.paths)
	}
	if rs.bodies[0]["merge_method"] != "squash" {
		t.Errorf("body = %v", rs.bodies[0])
	}
}

func TestMergePR_NotMergeable(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusConflict) })
	s := httptest.NewServer(mux)
	defer s.Close()
	c := New(s.URL, "tok")
	if err := c.MergePR(context.Background(), "owner/repo.git", 7, "merge"); !errors.Is(err, port.ErrNotMergeable) {
		t.Errorf("err = %v, want ErrNotMergeable", err)
	}
}

func TestCommentPR(t *testing.T) {
	rs, s := newRecordingServer(t, func(w http.ResponseWriter) { w.WriteHeader(http.StatusCreated) })
	defer s.Close()
	c := New(s.URL, "tok")
	if err := c.CommentPR(context.Background(), "owner/repo.git", 5, "lgtm"); err != nil {
		t.Fatalf("CommentPR: %v", err)
	}
	if rs.paths[0] != "/repos/owner/repo/issues/5/comments" {
		t.Errorf("path = %v, want the issues-comments endpoint", rs.paths)
	}
	if rs.bodies[0]["body"] != "lgtm" {
		t.Errorf("body = %v", rs.bodies[0])
	}
}

func TestReviewPR(t *testing.T) {
	rs, s := newRecordingServer(t, func(w http.ResponseWriter) { w.WriteHeader(http.StatusCreated) })
	defer s.Close()
	c := New(s.URL, "tok")
	if err := c.ReviewPR(context.Background(), "owner/repo.git", 5, "APPROVE", "ship"); err != nil {
		t.Fatalf("ReviewPR: %v", err)
	}
	if rs.paths[0] != "/repos/owner/repo/pulls/5/reviews" {
		t.Errorf("path = %v", rs.paths)
	}
	if rs.bodies[0]["event"] != "APPROVE" || rs.bodies[0]["body"] != "ship" {
		t.Errorf("body = %v", rs.bodies[0])
	}
}

func TestPRs_RejectMalformedRepo(t *testing.T) {
	c := New("https://api.github.com", "tok")
	if _, err := c.GetPR(context.Background(), "no-slash", 1); err == nil {
		t.Error("expected error for repo with no owner/name slash")
	}
}