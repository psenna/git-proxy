// Package file is the v1 AuditSink: an append-only JSONL file. Each Record
// appends one JSON object terminated by a newline, serialized by a mutex so
// concurrent proxy goroutines never interleave bytes. The file is opened with
// O_APPEND (append-only — never rewritten or truncated) and 0o600 (owner-only).
//
// Best-effort (binding): Record returns an error on write failure, but the
// caller (the proxy) MUST treat that error as non-fatal — log it and proceed.
// Audit is observability, not a security gate; the policy decision stands
// regardless of whether the audit line landed. A future compliance mode that
// fails closed on audit errors is a later knob (not implemented here).
//
// No-leak (binding — security): the sink marshals the AuditEvent as-is. The
// event MUST carry only generic agent-facing reasons, paths, and OIDs — never
// blob Content, raw secret values, or upstream credentials. The proxy enforces
// this at event construction time; the sink does not redact (it trusts the
// event is already leak-free). The audit file is persisted to disk and may be
// forwarded to alerting (Task 13), so treat it as a leak surface.
package file

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/psenna/git-proxy/internal/port"
)

// Sink is an append-only JSONL AuditSink backed by a file. Writes are
// serialized by a mutex; the file is opened with O_APPEND so concurrent
// goroutines append atomically without corrupting lines. A nil *Sink is the
// "audit disabled" state (the proxy never dereferences a nil sink).
type Sink struct {
	mu   sync.Mutex
	f    *os.File
	path string
}

// New opens (creating if missing) an append-only JSONL audit file at path,
// including any missing parent directories. The file is opened 0o600,
// O_CREATE|O_WRONLY|O_APPEND — never truncated or rewritten. Returns an error
// if the file cannot be opened (the caller fails fast at startup, not per-op).
func New(path string) (*Sink, error) {
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return nil, fmt.Errorf("audit: create parent dirs: %w", err)
		}
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return nil, fmt.Errorf("audit: open %s: %w", path, err)
	}
	return &Sink{f: f, path: path}, nil
}

// Record marshals e as one JSON line terminated by "\n" and appends it to the
// file under the mutex (so concurrent Record calls never interleave bytes).
// If e.Time is zero, the sink stamps it with time.Now (the proxy MAY pre-stamp;
// the pure policy engine never does). Returns an error on write failure — the
// caller MUST treat it as best-effort (log and proceed; the decision stands).
func (s *Sink) Record(ctx context.Context, e port.AuditEvent) error {
	if e.Time.IsZero() {
		e.Time = time.Now()
	}
	line, err := json.Marshal(e)
	if err != nil {
		return fmt.Errorf("audit: marshal event: %w", err)
	}
	line = append(line, '\n')
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, err := s.f.Write(line); err != nil {
		return fmt.Errorf("audit: write: %w", err)
	}
	return nil
}

// Close closes the underlying file. Safe to call multiple times.
func (s *Sink) Close() error {
	if s == nil || s.f == nil {
		return nil
	}
	return s.f.Close()
}