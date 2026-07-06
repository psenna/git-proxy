// Package webhook is the v1 AlertSink: it POSTs each Alert as JSON to a
// configured URL. Fire-and-forget (no retries for v1), best-effort: a POST
// failure (non-2xx, timeout, unreachable server) is returned to the caller,
// which logs it and proceeds — the policy decision stands regardless. The
// webhook leaves the proxy, so the Alert payload is treated as a leak surface
// (no blob content, raw secrets, upstream URLs/creds, or packfile bytes —
// see the port.Alert no-leak contract).
package webhook

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	neturl "net/url"
	"net/http"
	"time"

	"github.com/psenna/git-proxy/internal/port"
)

// defaultTimeout is the per-POST HTTP client timeout. Short so an unreachable
// webhook does not stall a git op beyond a bounded window (best-effort:
// delivery is observability, not a gate). v1: fire-and-forget, no retries.
const defaultTimeout = 5 * time.Second

// Sink is an AlertSink that POSTs each Alert as JSON to URL. It is safe for
// concurrent use (the underlying http.Client is goroutine-safe). A nil *Sink
// is the "alerts disabled" state (the proxy never dereferences a nil sink).
type Sink struct {
	url    string
	client *http.Client
}

// New returns a webhook AlertSink that POSTs to url. The URL is parsed/validated
// at construction so a malformed webhook URL fails fast at startup (a config
// error), NOT at alert time. An unreachable server at runtime is best-effort
// (returned as a delivery error, never a startup failure). Returns an error
// for a malformed URL (empty scheme/host or unparseable).
func New(url string) (*Sink, error) {
	if url == "" {
		return nil, fmt.Errorf("alert/webhook: empty url")
	}
	if err := validateURL(url); err != nil {
		return nil, fmt.Errorf("alert/webhook: malformed url: %w", err)
	}
	return &Sink{
		url:    url,
		client: &http.Client{Timeout: defaultTimeout},
	}, nil
}

// validateURL parses u and requires an http(s) scheme + host so a malformed
// config (e.g. "://not-a-url" or "not a url") fails at startup, not at alert
// time. The scheme is allowlisted to http/https only: the webhook POST leaves
// the proxy, and a non-http(s) scheme (file://, gopher://, ftp://) is never a
// legitimate alert destination — rejecting it at startup is fail-fast
// defense-in-depth (an http.Client would error at send time anyway, but a
// typo'd scheme should be caught before any alert is dropped).
func validateURL(u string) error {
	parsed, err := neturl.Parse(u)
	if err != nil {
		return err
	}
	if parsed.Scheme == "" || parsed.Host == "" {
		return fmt.Errorf("missing scheme or host")
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return fmt.Errorf("unsupported scheme %q (http/https only)", parsed.Scheme)
	}
	return nil
}

// Alert POSTs a as JSON to the configured URL with User-Agent: git-proxy and
// Content-Type: application/json. It returns an error on any delivery failure
// (network error, timeout, non-2xx status); the caller MUST treat it as
// best-effort (log and proceed — the verdict stands regardless). Fire-and-forget:
// v1 does not retry. The body is the JSON Alert (no secret/cred content per the
// port.Alert no-leak contract; the proxy enforces this at Alert construction).
//
// The POST is detached from the caller's ctx: it uses context.Background() (the
// client's defaultTimeout bounds the round-trip). The inbound request ctx is
// propagated by the proxy and would be cancelled if the agent — including the
// agent being denied — disconnects; tying alert delivery to that lifetime would
// let a denied client silence notification of its own denial by closing the
// connection. The durable audit record (a file write, ctx-unaware) survives
// regardless; detaching the webhook keeps the real-time alert equally resilient.
func (s *Sink) Alert(_ context.Context, a port.Alert) error {
	body, err := json.Marshal(a)
	if err != nil {
		return fmt.Errorf("alert/webhook: marshal: %w", err)
	}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, s.url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("alert/webhook: build request: %w", err)
	}
	req.Header.Set("User-Agent", "git-proxy")
	req.Header.Set("Content-Type", "application/json")
	resp, err := s.client.Do(req)
	if err != nil {
		return fmt.Errorf("alert/webhook: post: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("alert/webhook: post returned %s", resp.Status)
	}
	return nil
}

// Close closes idle connections held by the HTTP client. Safe to call
// multiple times. The caller (main.go) closes the sink on shutdown alongside
// the audit sink.
func (s *Sink) Close() error {
	if s == nil {
		return nil
	}
	s.client.CloseIdleConnections()
	return nil
}