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

func TestParseJobIDFromDetailsURL(t *testing.T) {
	cases := []struct {
		name       string
		detailsURL string
		wantRun    int64
		wantJob    int64
		wantOK     bool
	}{
		{
			name:       "github actions job url",
			detailsURL: "https://github.com/actions/checkout/actions/runs/32631582718/job/97175096434",
			wantRun:    32631582718,
			wantJob:    97175096434,
			wantOK:     true,
		},
		{
			name:       "third-party check app (socket.dev)",
			detailsURL: "https://socket.dev/dashboard/org/vercel/sbom/bddea2cb-example",
			wantOK:     false,
		},
		{
			name:       "third-party check app (pkg.pr.new, no path)",
			detailsURL: "https://pkg.pr.new",
			wantOK:     false,
		},
		{
			name:       "empty",
			detailsURL: "",
			wantOK:     false,
		},
		{
			name:       "malformed url",
			detailsURL: "://not-a-url",
			wantOK:     false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			runID, jobID, ok := parseJobIDFromDetailsURL(tc.detailsURL)
			if ok != tc.wantOK {
				t.Fatalf("ok = %v, want %v", ok, tc.wantOK)
			}
			if !tc.wantOK {
				return
			}
			if runID != tc.wantRun || jobID != tc.wantJob {
				t.Errorf("runID=%d jobID=%d, want runID=%d jobID=%d", runID, jobID, tc.wantRun, tc.wantJob)
			}
		})
	}
}

func TestTailRead(t *testing.T) {
	t.Run("below cap", func(t *testing.T) {
		text, truncated, err := tailRead(strings.NewReader("hello"), 10)
		if err != nil {
			t.Fatalf("tailRead: %v", err)
		}
		if truncated {
			t.Error("truncated = true, want false")
		}
		if text != "hello" {
			t.Errorf("text = %q, want %q", text, "hello")
		}
	})
	t.Run("exactly at cap", func(t *testing.T) {
		text, truncated, err := tailRead(strings.NewReader("abc"), 3)
		if err != nil {
			t.Fatalf("tailRead: %v", err)
		}
		if truncated {
			t.Error("truncated = true, want false")
		}
		if text != "abc" {
			t.Errorf("text = %q, want %q", text, "abc")
		}
	})
	t.Run("above cap keeps exact tail", func(t *testing.T) {
		text, truncated, err := tailRead(strings.NewReader("ABCDEFGHIJ"), 4)
		if err != nil {
			t.Fatalf("tailRead: %v", err)
		}
		if !truncated {
			t.Error("truncated = false, want true")
		}
		if text != "GHIJ" {
			t.Errorf("text = %q, want %q (exact tail)", text, "GHIJ")
		}
	})
	t.Run("above cap, multiple reads", func(t *testing.T) {
		// Feed the reader in small chunks to exercise the circular-buffer
		// wraparound across multiple Read calls, not just one big buffer.
		var parts []io.Reader
		for _, s := range []string{"aaaaa", "bbbbb", "ccccc", "ddddd", "eeeee"} {
			parts = append(parts, strings.NewReader(s))
		}
		text, truncated, err := tailRead(io.MultiReader(parts...), 7)
		if err != nil {
			t.Fatalf("tailRead: %v", err)
		}
		if !truncated {
			t.Error("truncated = false, want true")
		}
		full := "aaaaabbbbbcccccdddddeeeee"
		wantTail := full[len(full)-7:]
		if text != wantTail {
			t.Errorf("text = %q, want %q", text, wantTail)
		}
	})
	t.Run("zero maxBytes", func(t *testing.T) {
		text, truncated, err := tailRead(strings.NewReader("abc"), 0)
		if err != nil {
			t.Fatalf("tailRead: %v", err)
		}
		if !truncated {
			t.Error("truncated = false, want true (any input truncated at cap 0)")
		}
		if text != "" {
			t.Errorf("text = %q, want empty", text)
		}
	})
	t.Run("empty input", func(t *testing.T) {
		text, truncated, err := tailRead(strings.NewReader(""), 10)
		if err != nil {
			t.Fatalf("tailRead: %v", err)
		}
		if truncated {
			t.Error("truncated = true, want false")
		}
		if text != "" {
			t.Errorf("text = %q, want empty", text)
		}
	})
}

// TestJobLog_NoTokenLeakOnRedirect is the load-bearing no-leak test: the
// job-logs endpoint responds with a 302 to a "signed URL" host, and that host
// MUST NOT see the proxy's Authorization header.
func TestJobLog_NoTokenLeakOnRedirect(t *testing.T) {
	const wantBody = "line one\nline two\nline three\n"
	var signedHit bool
	signed := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		signedHit = true
		if auth := r.Header.Get("Authorization"); auth != "" {
			t.Errorf("signed URL received Authorization header: %q (token must never leak to the redirect target)", auth)
		}
		_, _ = w.Write([]byte(wantBody))
	}))
	defer signed.Close()

	mux := http.NewServeMux()
	mux.HandleFunc("/repos/o/r/actions/jobs/123/logs", func(w http.ResponseWriter, r *http.Request) {
		if auth := r.Header.Get("Authorization"); auth != "Bearer tok" {
			t.Errorf("jobs/logs request Authorization = %q, want Bearer tok", auth)
		}
		http.Redirect(w, r, signed.URL+"/blob", http.StatusFound)
	})
	s := httptest.NewServer(mux)
	defer s.Close()

	c := New(s.URL, "tok")
	text, truncated, err := c.JobLog(context.Background(), "o/r.git", 123, 1024)
	if err != nil {
		t.Fatalf("JobLog: %v", err)
	}
	if !signedHit {
		t.Fatal("signed URL host was never hit — redirect not followed")
	}
	if truncated {
		t.Error("truncated = true, want false")
	}
	if text != wantBody {
		t.Errorf("text = %q, want %q", text, wantBody)
	}
}

func TestJobLog_NotFound(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNotFound) })
	s := httptest.NewServer(mux)
	defer s.Close()
	c := New(s.URL, "tok")
	if _, _, err := c.JobLog(context.Background(), "o/r.git", 999, 1024); !errors.Is(err, port.ErrNotFound) {
		t.Errorf("err = %v, want ErrNotFound", err)
	}
}

func TestCheckLogForCheck(t *testing.T) {
	t.Run("happy path resolves job from details_url", func(t *testing.T) {
		var jobHit string
		signed := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte("the log"))
		}))
		defer signed.Close()

		mux := http.NewServeMux()
		mux.HandleFunc("/repos/o/r/commits/abc/check-runs", func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte(`{"check_runs":[
				{"id":1,"name":"other","status":"completed","conclusion":"success","details_url":"https://github.com/o/r/actions/runs/1/job/11"},
				{"id":2,"name":"kind e2e","status":"completed","conclusion":"failure","details_url":"https://github.com/o/r/actions/runs/2/job/22"},
				{"id":3,"name":"kind e2e","status":"completed","conclusion":"failure","details_url":"https://github.com/o/r/actions/runs/2/job/33"}
			]}`))
		})
		mux.HandleFunc("/repos/o/r/actions/jobs/33/logs", func(w http.ResponseWriter, r *http.Request) {
			jobHit = "33"
			http.Redirect(w, r, signed.URL, http.StatusFound)
		})
		mux.HandleFunc("/repos/o/r/actions/jobs/22/logs", func(w http.ResponseWriter, r *http.Request) {
			jobHit = "22"
			http.Redirect(w, r, signed.URL, http.StatusFound)
		})
		s := httptest.NewServer(mux)
		defer s.Close()
		c := New(s.URL, "tok")

		text, truncated, err := c.CheckLogForCheck(context.Background(), "o/r.git", "abc", "kind e2e", 1024)
		if err != nil {
			t.Fatalf("CheckLogForCheck: %v", err)
		}
		if truncated {
			t.Error("truncated = true, want false")
		}
		if text != "the log" {
			t.Errorf("text = %q, want %q", text, "the log")
		}
		// Two check-runs are named "kind e2e" (id 2 and id 3); the tiebreak
		// picks the highest ID (3), whose details_url points at job 33.
		if jobHit != "33" {
			t.Errorf("job hit = %q, want 33 (highest-ID tiebreak)", jobHit)
		}
	})

	t.Run("unknown check name is not found", func(t *testing.T) {
		mux := http.NewServeMux()
		mux.HandleFunc("/repos/o/r/commits/abc/check-runs", func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte(`{"check_runs":[{"id":1,"name":"ci","status":"completed","conclusion":"success","details_url":"https://github.com/o/r/actions/runs/1/job/11"}]}`))
		})
		s := httptest.NewServer(mux)
		defer s.Close()
		c := New(s.URL, "tok")
		if _, _, err := c.CheckLogForCheck(context.Background(), "o/r.git", "abc", "does-not-exist", 1024); !errors.Is(err, port.ErrNotFound) {
			t.Errorf("err = %v, want ErrNotFound", err)
		}
	})

	t.Run("non-actions check (third-party) is not found", func(t *testing.T) {
		mux := http.NewServeMux()
		mux.HandleFunc("/repos/o/r/commits/abc/check-runs", func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte(`{"check_runs":[{"id":1,"name":"socket","status":"completed","conclusion":"success","details_url":"https://socket.dev/dashboard/org/vercel/sbom/xyz"}]}`))
		})
		s := httptest.NewServer(mux)
		defer s.Close()
		c := New(s.URL, "tok")
		if _, _, err := c.CheckLogForCheck(context.Background(), "o/r.git", "abc", "socket", 1024); !errors.Is(err, port.ErrNotFound) {
			t.Errorf("err = %v, want ErrNotFound", err)
		}
	})
}
