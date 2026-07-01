package port

import (
	"context"
	"time"
)

// Alert is a violation notification: a deny (enforced or dry-run) that an
// operator should know about in real time (vs. reading the audit log after
// the fact). It is fired by the proxy at every deny decision site (push deny,
// read-protection withhold, on-demand deny, dry-run deny) to a pluggable
// AlertSink (the v1 implementation is an HTTP webhook; a nil sink means alerts
// are off — today's behavior).
//
// No-leak contract (binding — security): the Alert carries ONLY generic
// agent-facing reason strings (port.Reason.Message, already redacted by the
// rules — secret_scan snippets are masked; mirror errors are redacted via
// redactCreds), paths, and object ids. It MUST NOT include blob Content, raw
// secret values, upstream URLs/credentials, or packfile bytes. The webhook
// POST body leaves the proxy (it is a leak surface), so the Alert is treated
// as a leak surface exactly like AuditEvent. DeniedPaths and DeniedOIDs are
// paths and object ids — not blob content — so they are safe to send.
//
// Best-effort contract (binding): an alert failure MUST NOT change the policy
// decision or block the git operation. The deny already happened (or, in
// dry-run, the forward already happened); the alert is observability, not a
// gate. The sink's Alert returns an error on delivery failure; the caller (the
// proxy) logs the error and proceeds — the verdict stands regardless.
type Alert struct {
	// Time is when the violation was detected. The proxy stamps it at fire
	// time (the pure policy engine never calls time — keep internal/policy
	// pure; alert firing is I/O in gitproto/the sink, which MAY use time.Now).
	Time time.Time

	// Transport is which frontend carried the op: "http" or "ssh". Stamped by
	// the proxy from its transport tag (set via SetTransport at wiring time).
	Transport string

	// Agent is the authenticated agent name, or "" when auth is off.
	Agent string

	// Repo is the upstream repository path the op targeted.
	Repo string

	// Service is "git-receive-pack" (push) or "git-upload-pack" (fetch).
	Service string

	// Verdict is always "deny" (alerts only fire on deny). Carried explicitly
	// so a sink does not have to infer it.
	Verdict string

	// DryRun is true when the op was forwarded despite the deny (dry-run mode:
	// the proxy observed and recorded the violation but did not enforce it).
	// false when the deny was enforced (the op was blocked / the blob withheld).
	DryRun bool

	// Reasons are the generic agent-facing reason messages (port.Reason.Message
	// for push; synthetic generic reasons for read-protection denies). NO
	// secrets/creds/raw blob content (no-leak contract).
	Reasons []string

	// Refs is the ref updates attempted (push-specific). nil for fetch. Reuses
	// AuditRef from port/audit.go (no duplication) — the ref/old/new OIDs are
	// not blob content, so they are safe to send.
	Refs []AuditRef

	// DeniedPaths are blob paths withheld from the packfile (read-protection,
	// Task 9). nil for push and for non-read-protected fetches.
	DeniedPaths []string

	// DeniedOIDs are on-demand blob OIDs refused with ERR (Task 10). nil for
	// push and for non-read-protected fetches.
	DeniedOIDs []string
}

// AlertSink delivers a violation Alert to an operator-facing sink. The v1
// implementation is an HTTP webhook (internal/alert/webhook); a log sink
// (internal/alert/log) and a fan-out MultiAlertSink are also provided. A nil
// sink means alerts are disabled (the proxy guards every call — preserves the
// pre-alert behavior). The interface is pluggable so deployments can wire
// custom sinks (e.g. a cloud messaging connector) without changing the proxy.
//
// Best-effort (binding): the caller (the proxy) MUST treat an Alert error as
// non-fatal — log it and proceed. The policy decision stands regardless of
// whether the alert was delivered. Alert MUST NOT be called with an Alert
// carrying secret content (enforced by the proxy at construction time).
type AlertSink interface {
	// Alert delivers one violation notification. It returns an error on
	// delivery failure; the caller MUST treat the error as best-effort (log
	// and proceed — the verdict stands regardless).
	Alert(ctx context.Context, a Alert) error
}