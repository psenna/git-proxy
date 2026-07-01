package port

import (
	"context"
	"time"
)

// AuditEvent is one policy decision recorded by the proxy. It is the durable
// record of an allow/deny on a push (git-receive-pack) or a read-protected
// fetch (git-upload-pack). It MUST NOT carry secret content or upstream
// credentials (see the no-leak contract below) — it is persisted to disk and
// may be forwarded to alerting (Task 13), so it is treated as a leak surface.
//
// No-leak contract (binding — security): the event carries ONLY the generic
// agent-facing reason strings (port.Reason.Message, already redacted by the
// rules — secret_scan snippets are redacted; mirror errors are redacted via
// redactCreds). It MUST NOT include blob Content, raw secret values, upstream
// URLs/credentials, or full ref/packfile bytes. DeniedPaths and DeniedOIDs are
// paths and object ids — not blob content — so they are safe to log.
//
// Best-effort contract (binding): an audit write failure MUST NOT change the
// policy decision or block the git operation. The decision is enforced
// independently of audit. The sink's Record returns an error on write failure;
// the caller (the proxy) logs the error and proceeds. Audit is observability,
// not a security gate.
type AuditEvent struct {
	// Time is when the decision was made. The proxy stamps it at record time
	// (the pure policy engine never calls time — keep internal/policy pure;
	// audit recording is I/O in gitproto/the sink, which MAY use time.Now).
	Time time.Time

	// Transport is which frontend carried the op: "http" or "ssh". The proxy
	// does not infer it from the request; each frontend stamps its proxy via
	// SetTransport at wiring time.
	Transport string

	// Agent is the authenticated agent name (auth.AgentIdentity.Name), or ""
	// when auth is off. Rules applied per their applicability logic.
	Agent string

	// Repo is the upstream repository path the op targeted.
	Repo string

	// Service is "git-receive-pack" (push) or "git-upload-pack" (fetch).
	Service string

	// Verdict is "allow" or "deny".
	Verdict string

	// Reasons are the agent-facing reason messages (port.Reason.Message),
	// generic — NO secrets/creds. Empty for a bare allow (e.g. passthrough).
	Reasons []string

	// Refs is the ref updates attempted (push-specific). nil for fetch.
	Refs []AuditRef

	// DeniedPaths are blob paths withheld from the packfile (read-protection,
	// Task 9). nil for push and for non-read-protected fetches.
	DeniedPaths []string

	// DeniedOIDs are on-demand blob OIDs refused with ERR (Task 10). nil for
	// push and for non-read-protected fetches.
	DeniedOIDs []string
}

// AuditRef is one ref update in a pushed receive-pack command, for the audit
// record. The fields are the structured metadata of the attempted update; they
// are not secret (refs/old/new OIDs are not blob content).
type AuditRef struct {
	Ref   string
	Old   string
	New   string
	Force bool
}

// AuditSink records policy decisions. The v1 implementation is an append-only
// JSONL file (internal/audit/file); a nil sink means no audit (preserves the
// pre-audit behavior). The interface is pluggable so dry-run mode and alerting
// (Task 13) can reuse the AuditEvent shape without changing the proxy.
type AuditSink interface {
	// Record persists one audit event. It returns an error on write failure;
	// the caller MUST treat the error as best-effort (log and proceed — the
	// decision stands regardless). Record MUST NOT be called with events
	// carrying secret content (enforced by the proxy at construction time).
	Record(ctx context.Context, e AuditEvent) error
}