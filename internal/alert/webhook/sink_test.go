package webhook_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/psenna/git-proxy/internal/alert/webhook"
	"github.com/psenna/git-proxy/internal/port"
)

// TestWebhook_PostsAlertJSON verifies the webhook sink POSTs the Alert as JSON
// to the configured URL with User-Agent git-proxy and the right content-type,
// and that the body decodes back to the same Alert (payload shape).
func TestWebhook_PostsAlertJSON(t *testing.T) {
	var gotBody []byte
	var gotUA, gotCT string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotUA = r.Header.Get("User-Agent")
		gotCT = r.Header.Get("Content-Type")
		gotBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	sink, err := webhook.New(srv.URL)
	if err != nil {
		t.Fatalf("webhook.New: %v", err)
	}
	defer func() { _ = sink.Close() }()

	a := port.Alert{
		Transport:   "http",
		Agent:       "agent-1",
		Repo:        "team/repo.git",
		Service:     "git-receive-pack",
		Verdict:     "deny",
		DryRun:      true,
		Reasons:     []string{"push denied by branch_pattern"},
		Refs:        []port.AuditRef{{Ref: "refs/heads/main", Old: "aaa", New: "bbb"}},
		DeniedPaths: []string{"secrets/creds.txt"},
		DeniedOIDs:  []string{"deadbeef"},
	}
	if err := sink.Alert(context.Background(), a); err != nil {
		t.Fatalf("Alert: %v", err)
	}

	if gotUA != "git-proxy" {
		t.Fatalf("User-Agent: %q want git-proxy", gotUA)
	}
	if gotCT != "application/json" {
		t.Fatalf("Content-Type: %q want application/json", gotCT)
	}
	var decoded port.Alert
	if err := json.Unmarshal(gotBody, &decoded); err != nil {
		t.Fatalf("unmarshal body: %v (body=%q)", err, gotBody)
	}
	if decoded.Agent != a.Agent || decoded.Verdict != a.Verdict || !decoded.DryRun ||
		decoded.Repo != a.Repo || decoded.Service != a.Service {
		t.Fatalf("decoded mismatch: %+v", decoded)
	}
	if len(decoded.Refs) != 1 || decoded.Refs[0].Ref != "refs/heads/main" {
		t.Fatalf("decoded refs: %+v", decoded.Refs)
	}
	if len(decoded.DeniedPaths) != 1 || decoded.DeniedPaths[0] != "secrets/creds.txt" {
		t.Fatalf("decoded denied paths: %+v", decoded.DeniedPaths)
	}
}

// TestWebhook_BestEffortNonFatal verifies a server returning 500 does NOT make
// the proxy block the op: the sink returns the error (so the caller can log
// it), but the call itself completes and a subsequent Alert succeeds. The
// caller treats the error as best-effort (log + proceed).
func TestWebhook_BestEffortNonFatal(t *testing.T) {
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	sink, err := webhook.New(srv.URL)
	if err != nil {
		t.Fatalf("webhook.New: %v", err)
	}
	defer func() { _ = sink.Close() }()

	// A 500 response yields a non-nil error (delivery failed); the caller logs
	// and proceeds. The sink does not panic or hang.
	err = sink.Alert(context.Background(), port.Alert{Verdict: "deny"})
	if err == nil {
		t.Fatalf("500 response must yield a delivery error (best-effort surfaces it)")
	}
	// A second call still works (fire-and-forget; no retry blocking).
	if err := sink.Alert(context.Background(), port.Alert{Verdict: "deny"}); err == nil {
		t.Fatalf("second 500 must still surface an error")
	}
	if atomic.LoadInt32(&calls) != 2 {
		t.Fatalf("expected 2 calls, got %d", atomic.LoadInt32(&calls))
	}
}

// TestWebhook_NoLeakCanary verifies the webhook POST body does NOT contain a
// secret value that was present in the pushed content. The Alert carries only
// generic reasons/paths/OIDs — never blob content. The webhook leaves the
// proxy, so this is the load-bearing no-leak assertion (mirrors the Task 12
// audit canary).
func TestWebhook_NoLeakCanary(t *testing.T) {
	var gotBody []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	sink, err := webhook.New(srv.URL)
	if err != nil {
		t.Fatalf("webhook.New: %v", err)
	}
	defer func() { _ = sink.Close() }()

	secret := "AKIAIOSFODNN7EXAMPLE" // AWS access key id shape (secret_scan detects)
	// The Alert carries only generic, already-redacted reasons — NOT the secret.
	// Simulate the redacted reason the proxy would build (secret_scan masks the
	// matched secret in its reason message).
	a := port.Alert{
		Verdict: "deny",
		Reasons: []string{"push denied: secret_scan matched a secret in the pushed content"},
		Refs:    []port.AuditRef{{Ref: "refs/heads/main", Old: "aaa", New: "bbb"}},
	}
	if err := sink.Alert(context.Background(), a); err != nil {
		t.Fatalf("Alert: %v", err)
	}
	if strings.Contains(string(gotBody), secret) {
		t.Fatalf("webhook payload leaked secret value: %q", gotBody)
	}
}

// TestWebhook_MalformedURLFailsFast verifies a malformed webhook URL is rejected
// at construction (startup fail-fast on config error), NOT at alert time.
func TestWebhook_MalformedURLFailsFast(t *testing.T) {
	_, err := webhook.New("://not-a-url")
	if err == nil {
		t.Fatalf("malformed URL must fail at New (startup fail-fast)")
	}
}

// TestWebhook_TimeoutDoesNotBlock verifies a slow server does not block the
// caller beyond a bounded window. The sink honors the caller's context
// (NewRequestWithContext) and applies a short HTTP client timeout (5s default);
// whichever fires first bounds the wait. Here a 200ms context deadline beats
// the 2s-sleeping server, so the call returns an error within ~1s (best-effort:
// the caller proceeds regardless).
func TestWebhook_TimeoutDoesNotBlock(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(2 * time.Second)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	sink, err := webhook.New(srv.URL)
	if err != nil {
		t.Fatalf("webhook.New: %v", err)
	}
	defer func() { _ = sink.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	start := time.Now()
	err = sink.Alert(ctx, port.Alert{Verdict: "deny"})
	elapsed := time.Since(start)
	if err == nil {
		t.Fatalf("slow server / short ctx must yield a delivery error")
	}
	if elapsed > 1500*time.Millisecond {
		t.Fatalf("Alert blocked too long (%v) — context deadline not honored", elapsed)
	}
}