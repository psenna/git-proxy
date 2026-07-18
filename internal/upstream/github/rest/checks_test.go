package rest

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/psenna/git-proxy/internal/port"
)

func TestListCheckRuns(t *testing.T) {
	page := 0
	mux := http.NewServeMux()
	mux.HandleFunc("/repos/o/r/commits/abc/check-runs", func(w http.ResponseWriter, r *http.Request) {
		page++
		if page == 1 {
			q := r.URL.Query()
			q.Set("page", "2")
			w.Header().Set("Link", `<`+r.URL.Path+`?`+q.Encode()+`>; rel="next"`)
			_, _ = w.Write([]byte(`{"total_count":2,"check_runs":[{"name":"ci","status":"completed","conclusion":"success"}]}`))
			return
		}
		_, _ = w.Write([]byte(`{"total_count":2,"check_runs":[{"name":"lint","status":"in_progress","conclusion":""}]}`))
	})
	s := httptest.NewServer(mux)
	defer s.Close()
	c := New(s.URL, "tok")
	runs, err := c.ListCheckRuns(context.Background(), "o/r.git", "abc")
	if err != nil {
		t.Fatalf("ListCheckRuns: %v", err)
	}
	if len(runs) != 2 || runs[0].Name != "ci" || runs[1].Name != "lint" {
		t.Errorf("runs = %+v", runs)
	}
}

func TestListCheckRuns_NotFound(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNotFound) })
	s := httptest.NewServer(mux)
	defer s.Close()
	c := New(s.URL, "tok")
	if _, err := c.ListCheckRuns(context.Background(), "o/r.git", "abc"); !errors.Is(err, port.ErrNotFound) {
		t.Errorf("err = %v, want ErrNotFound", err)
	}
}

func TestListWorkflowRuns(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/repos/o/r/actions/runs", func(w http.ResponseWriter, r *http.Request) {
		if sha := r.URL.Query().Get("head_sha"); sha != "abc" {
			t.Errorf("head_sha query = %q, want abc", sha)
		}
		_, _ = w.Write([]byte(`{"workflow_runs":[{"name":"build","status":"completed","conclusion":"success","html_url":"u"}]}`))
	})
	s := httptest.NewServer(mux)
	defer s.Close()
	c := New(s.URL, "tok")
	runs, err := c.ListWorkflowRuns(context.Background(), "o/r.git", "abc")
	if err != nil {
		t.Fatalf("ListWorkflowRuns: %v", err)
	}
	if len(runs) != 1 || runs[0].Name != "build" || runs[0].HTMLURL != "u" {
		t.Errorf("runs = %+v", runs)
	}
}

func TestRollupCI(t *testing.T) {
	cases := []struct {
		name      string
		checks    []CheckRun
		workflows []WorkflowRun
		want      string
	}{
		{"none", nil, nil, StateNone},
		{"all success", []CheckRun{{Status: "completed", Conclusion: "success"}}, []WorkflowRun{{Status: "completed", Conclusion: "success"}}, StateSuccess},
		{"one failure dominates", []CheckRun{{Status: "completed", Conclusion: "success"}, {Status: "completed", Conclusion: "failure"}}, nil, StateFailure},
		{"in_progress pending", []CheckRun{{Status: "in_progress", Conclusion: ""}}, nil, StatePending},
		{"queued pending", nil, []WorkflowRun{{Status: "queued", Conclusion: ""}}, StatePending},
		{"completed no conclusion pending", []CheckRun{{Status: "completed", Conclusion: ""}}, nil, StatePending},
		{"failure beats pending", []CheckRun{{Status: "in_progress", Conclusion: ""}, {Status: "completed", Conclusion: "cancelled"}}, nil, StateFailure},
		{"neutral counts as success", []CheckRun{{Status: "completed", Conclusion: "neutral"}}, nil, StateSuccess},
		{"skipped counts as success", []CheckRun{{Status: "completed", Conclusion: "skipped"}}, nil, StateSuccess},
		{"unknown conclusion", []CheckRun{{Status: "completed", Conclusion: "weird"}}, nil, StateUnknown},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := rollupCI(tc.checks, tc.workflows).Overall
			if got != tc.want {
				t.Errorf("Overall = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestSummary_HTTP(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/repos/o/r/commits/abc/check-runs", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"check_runs":[{"name":"ci","status":"completed","conclusion":"success"}]}`))
	})
	mux.HandleFunc("/repos/o/r/actions/runs", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"workflow_runs":[{"name":"build","status":"completed","conclusion":"failure"}]}`))
	})
	s := httptest.NewServer(mux)
	defer s.Close()
	c := New(s.URL, "tok")
	summary, err := c.Summary(context.Background(), "o/r.git", "abc")
	if err != nil {
		t.Fatalf("Summary: %v", err)
	}
	if summary.Overall != StateFailure {
		t.Errorf("Overall = %q, want failure (workflow failed dominates)", summary.Overall)
	}
	if len(summary.Checks) != 1 || len(summary.Workflows) != 1 {
		t.Errorf("bundle = %+v", summary)
	}
}