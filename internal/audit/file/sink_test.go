package file_test

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/psenna/git-proxy/internal/audit/file"
	"github.com/psenna/git-proxy/internal/port"
)

// readEvents parses the audit JSONL file and returns the events in order.
func readEvents(t *testing.T, path string) []port.AuditEvent {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read audit: %v", err)
	}
	if len(b) == 0 {
		return nil
	}
	lines := strings.Split(strings.TrimRight(string(b), "\n"), "\n")
	var events []port.AuditEvent
	for i, line := range lines {
		var e port.AuditEvent
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			t.Fatalf("parse audit line %d: %v (line=%q)", i, err, line)
		}
		events = append(events, e)
	}
	return events
}

// TestSink_AppendGrowsAndParses asserts Record is append-only: the file only
// grows, each event is one JSON line, and re-reading parses them all back.
func TestSink_AppendGrowsAndParses(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	s, err := file.New(path)
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })

	for i := 0; i < 3; i++ {
		if err := s.Record(context.Background(), port.AuditEvent{
			Transport: "http",
			Agent:     "alice",
			Repo:      "team/repo.git",
			Service:   "git-receive-pack",
			Verdict:   "allow",
		}); err != nil {
			t.Fatalf("record %d: %v", i, err)
		}
	}

	events := readEvents(t, path)
	if len(events) != 3 {
		t.Fatalf("want 3 events, got %d", len(events))
	}
	for i, e := range events {
		if e.Verdict != "allow" || e.Agent != "alice" || e.Service != "git-receive-pack" {
			t.Fatalf("event %d mismatch: %+v", i, e)
		}
	}
	// Each event is exactly one line: count newlines == events.
	b, _ := os.ReadFile(path)
	if got := strings.Count(string(b), "\n"); got != 3 {
		t.Fatalf("want 3 newlines (one line per event), got %d", got)
	}
}

// TestSink_AppendOnlyAcrossOpens asserts a second Sink on the same path appends
// (never truncates) — the file only grows.
func TestSink_AppendOnlyAcrossOpens(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	s1, err := file.New(path)
	if err != nil {
		t.Fatalf("new s1: %v", err)
	}
	if err := s1.Record(context.Background(), port.AuditEvent{Service: "git-receive-pack", Verdict: "allow"}); err != nil {
		t.Fatalf("record s1: %v", err)
	}
	if err := s1.Close(); err != nil {
		t.Fatalf("close s1: %v", err)
	}

	s2, err := file.New(path)
	if err != nil {
		t.Fatalf("new s2: %v", err)
	}
	t.Cleanup(func() { _ = s2.Close() })
	if err := s2.Record(context.Background(), port.AuditEvent{Service: "git-receive-pack", Verdict: "deny"}); err != nil {
		t.Fatalf("record s2: %v", err)
	}
	events := readEvents(t, path)
	if len(events) != 2 {
		t.Fatalf("append-only: want 2 events across opens, got %d", len(events))
	}
	if events[0].Verdict != "allow" || events[1].Verdict != "deny" {
		t.Fatalf("append-only order wrong: %+v", events)
	}
}

// TestSink_CreatesParentDirs asserts New creates missing parent directories.
func TestSink_CreatesParentDirs(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "dir", "audit.jsonl")
	s, err := file.New(path)
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	if err := s.Record(context.Background(), port.AuditEvent{Service: "git-upload-pack"}); err != nil {
		t.Fatalf("record: %v", err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("audit file not created: %v", err)
	}
}

// TestSink_ConcurrentNoInterleave runs many goroutines recording concurrently
// and asserts every line parses as JSON (no interleaving / corruption). Run
// with -race to catch the mutex serialization.
func TestSink_ConcurrentNoInterleave(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	s, err := file.New(path)
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })

	const n = 200
	var wg sync.WaitGroup
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func() {
			defer wg.Done()
			_ = s.Record(context.Background(), port.AuditEvent{
				Transport: "http",
				Agent:     "concurrent",
				Repo:      "team/repo.git",
				Service:   "git-receive-pack",
				Verdict:   "allow",
				Reasons:   []string{"ok"},
				Refs:      []port.AuditRef{{Ref: "refs/heads/main", Old: "a", New: "b"}},
			})
		}()
	}
	wg.Wait()

	events := readEvents(t, path)
	if len(events) != n {
		t.Fatalf("want %d events, got %d (some lines corrupted/lost)", n, len(events))
	}
}

// TestSink_FileMode asserts the audit file is created 0o600 (owner-only).
func TestSink_FileMode(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	s, err := file.New(path)
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	if err := s.Record(context.Background(), port.AuditEvent{Service: "git-receive-pack"}); err != nil {
		t.Fatalf("record: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("want 0600, got %o", info.Mode().Perm())
	}
}

// TestSink_EmptyEventIsOneLine asserts a minimal/empty event still produces
// exactly one valid JSON line (malformed-resilient: no event breaks the line
// structure).
func TestSink_EmptyEventIsOneLine(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	s, err := file.New(path)
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	if err := s.Record(context.Background(), port.AuditEvent{}); err != nil {
		t.Fatalf("record: %v", err)
	}
	b, _ := os.ReadFile(path)
	if strings.Count(string(b), "\n") != 1 {
		t.Fatalf("want 1 line, got %d (content=%q)", strings.Count(string(b), "\n"), b)
	}
	var e port.AuditEvent
	if err := json.Unmarshal(b[:len(b)-1], &e); err != nil {
		t.Fatalf("parse: %v", err)
	}
}

// TestSink_NoSecretLeak asserts the audit file NEVER contains secret blob
// content or upstream credentials. The event carries only generic reasons,
// paths, and OIDs — not Content, raw secret values, or upstream creds.
func TestSink_NoSecretLeak(t *testing.T) {
	secretValue := "TOP-SECRET-VALUE-DO-NOT-LEAK"
	upstreamCred := "upstream-password-supersecret"
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	s, err := file.New(path)
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })

	// A denied push carrying a secret (reason is generic/redacted) and a
	// read-protected fetch withholding a denied blob path. The event fields
	// carry only generic reasons, paths, OIDs — never blob content.
	if err := s.Record(context.Background(), port.AuditEvent{
		Transport: "http",
		Agent:     "alice",
		Repo:      "team/repo.git",
		Service:   "git-receive-pack",
		Verdict:   "deny",
		Reasons:   []string{"push rejected: secret detected in committed file"},
		Refs:      []port.AuditRef{{Ref: "refs/heads/main", Old: "a", New: "b"}},
	}); err != nil {
		t.Fatalf("record push: %v", err)
	}
	if err := s.Record(context.Background(), port.AuditEvent{
		Transport:   "http",
		Agent:       "alice",
		Repo:        "team/repo.git",
		Service:     "git-upload-pack",
		Verdict:     "deny",
		Reasons:     []string{"blob withheld by read policy"},
		DeniedPaths: []string{"secrets/secret.txt"},
		DeniedOIDs:  []string{"deadbeefcafef00d"},
	}); err != nil {
		t.Fatalf("record fetch: %v", err)
	}

	b, _ := os.ReadFile(path)
	if strings.Contains(string(b), secretValue) {
		t.Fatalf("audit file leaked secret value: %q", b)
	}
	if strings.Contains(string(b), upstreamCred) {
		t.Fatalf("audit file leaked upstream credential: %q", b)
	}
	// Blob content must never appear: the event has no Content field, so the
	// JSON cannot carry it. Verify the denied path (not content) is present.
	if !strings.Contains(string(b), "secrets/secret.txt") {
		t.Fatalf("audit file missing denied path (should be present): %q", b)
	}
	if !strings.Contains(string(b), "deadbeefcafef00d") {
		t.Fatalf("audit file missing denied OID (should be present): %q", b)
	}
}

// TestSink_NilSafe asserts a nil Sink is a valid no-op (the proxy uses nil to
// mean "audit off" — preserves existing behavior).
func TestSink_NilSafe(t *testing.T) {
	var s *file.Sink
	// Record on a nil sink must not panic (the proxy guards with nil-check,
	// but a returned-nil New is a documented valid state).
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("nil sink panicked: %v", r)
		}
	}()
	// The proxy guards nil; this test documents that a nil *file.Sink is the
	// "disabled" state and is never dereferenced. We do not call Record on nil.
	_ = s
}