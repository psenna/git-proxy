// Package gitproto orchestrates git smart-HTTP protocol streams between the
// agent and the upstream. The Proxy owns a port.Upstream and parses the
// upload-pack and receive-pack state machines as they flow through, then
// forwards the bytes verbatim: parse-and-forward. No policy is applied yet; the
// parsed structures are the inspection seam later milestones (push
// enforcement, read protection) build on.
package gitproto

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log"
	"strings"
	"time"

	"github.com/go-git/go-git/v5/plumbing/protocol/packp/sideband"
	"github.com/psenna/git-proxy/internal/auth"
	"github.com/psenna/git-proxy/internal/gitproto/pktline"
	"github.com/psenna/git-proxy/internal/gitx"
	"github.com/psenna/git-proxy/internal/pathmatch"
	"github.com/psenna/git-proxy/internal/policy"
	"github.com/psenna/git-proxy/internal/port"
)

// DefaultMaxPackfileBytes lives in internal/config (the single source of truth
// for the push size cap default); cmd/git-proxy passes
// config.PolicyConfig.MaxPackfileBytesOrDefault() into SetEnforcement, so the
// proxy layer does not redefine it.

// MirrorOpener opens (or returns a cached) read-only inspection mirror for a
// repository. The opener owns mirroring policy (caching, root directory); the
// proxy calls it once per push to obtain a mirror to inspect the push against.
// A nil MirrorOpener (or nil engine) means the proxy runs in passthrough mode.
type MirrorOpener func(ctx context.Context, repo string) (*gitx.Mirror, error)

// Proxy parses git protocol operations flowing from an agent-facing body to an
// upstream and copies the upstream response back to the agent. With no
// enforcement dependencies wired it is behaviorally passthrough: bytes are
// forwarded untouched. With an engine and mirror opener wired, receive-pack
// (push) is inspected against the mirror and the policy engine; allowed pushes
// are forwarded verbatim, denied pushes are rejected via a report-status
// response and the upstream is left unchanged.
type Proxy struct {
	up               port.Upstream
	engine           *policy.Engine    // nil → passthrough (policy off)
	mirrorOpener     MirrorOpener      // nil → passthrough
	maxPackfileBytes int64             // cap when enforcement is on; 0 → default
	readDenyMatcher  *pathmatch.Matcher // nil → passthrough (read protection off)
	audit            port.AuditSink    // nil → no audit (preserves existing behavior)
	alerts           port.AlertSink    // nil → no alerts (preserves existing behavior)
	transport        string            // "http" | "ssh" — which frontend carried the op
	dryRun           bool              // dry-run: forward on clean engine Deny (policy denies only, NOT inspection errors)
}

// New returns a Proxy that forwards through up in passthrough mode (no policy).
// Existing passthrough/auth tests rely on this default.
func New(up port.Upstream) *Proxy {
	return &Proxy{up: up}
}

// SetEnforcement wires push enforcement dependencies: the policy engine, a
// mirror opener for inspection, and the max receive-pack request body size in
// bytes (the proxy denies pushes larger than this fail-closed). maxBytes must be
// greater than 0; the caller is responsible for defaulting (cmd/git-proxy uses
// config.PolicyConfig.MaxPackfileBytesOrDefault). With engine == nil or
// mirrorOpener == nil the proxy stays passthrough (policy off). A non-positive
// maxBytes yields fail-closed denial of every non-empty push (no forward).
func (p *Proxy) SetEnforcement(engine *policy.Engine, opener MirrorOpener, maxBytes int64) {
	p.engine = engine
	p.mirrorOpener = opener
	p.maxPackfileBytes = maxBytes
}

// SetReadDeny wires the read-protection fetch path: when matcher is non-nil, the
// proxy ASSEMBLES the upload-pack packfile (it does not forward) and withholds
// blobs whose path matches the matcher, serving a v0 response. When matcher is
// nil, read protection is OFF and UploadPack stays passthrough (forward to
// upstream, which speaks whatever the client negotiated) — existing
// fetch/clone/passthrough behavior is preserved. Read protection is a
// PROXY-LEVEL path matcher (pathmatch), NOT the engine's all-or-nothing
// EvaluateFetch; it is not routed through the policy engine. The mirror opener
// (shared with push enforcement) is used to fetch the object set; if it is nil
// when a matcher is set, every read-protected fetch fails closed (deny).
func (p *Proxy) SetReadDeny(matcher *pathmatch.Matcher) {
	p.readDenyMatcher = matcher
}

// SetAuditSink wires an optional audit sink. A nil sink means no audit (the
// pre-audit behavior is preserved — no event is recorded). Call before Serve.
// The sink is best-effort: a Record error is logged and does NOT change the
// verdict or block the git op (the decision stands regardless of audit).
func (p *Proxy) SetAuditSink(s port.AuditSink) { p.audit = s }

// SetTransport stamps the frontend tag ("http" or "ssh") carried in audit
// events. Each frontend owns its own *Proxy and stamps its tag once at wiring.
// The default "" is valid (the field is informational in the audit record).
func (p *Proxy) SetTransport(tag string) { p.transport = tag }

// SetDryRun enables/disables dry-run mode. When dry-run is ON, the proxy
// FORWARDS a clean engine push-deny to the upstream (instead of writing the
// deny response) and records the TRUE verdict (deny) with DryRun=true, so
// teams observe violations before turning on enforcement. Dry-run softens
// POLICY denies only, NOT inspection failures: an inspection-error deny
// (mirror/ancestry/ingest/parse — the proxy could not inspect the push) STILL
// fail-closes even in dry-run (you cannot safely forward an uninspected push,
// even to observe it). Read-protection dry-run is OUT of v1 scope: read
// protection withholds/denies regardless of dry-run (never serve a denied
// blob to "observe"). Call before Serve. The engine stays pure — it returns
// the true verdict regardless; dry-run is a proxy-level concern. Default
// false preserves the existing enforce-on-deny behavior.
func (p *Proxy) SetDryRun(on bool) { p.dryRun = on }

// SetAlertSink wires an optional alert sink. A nil sink means no alerts (the
// pre-alert behavior is preserved — no Alert is fired). Call before Serve.
// The sink is best-effort: an Alert error is logged and does NOT change the
// verdict, block the op, or alter the forward/deny (the decision stands
// regardless of whether the alert was delivered). The Alert carries only
// generic reasons/paths/OIDs — never blob content, raw secrets, upstream
// URLs/creds, or packfile bytes (no-leak contract; the webhook leaves the
// proxy, so the payload is a leak surface).
func (p *Proxy) SetAlertSink(s port.AlertSink) { p.alerts = s }

// ReadDenyOn reports whether read protection is wired on this proxy (the
// read-deny matcher is non-nil). Transports use it to decide whether to
// re-emit the upload-pack advertisement as v0 + filter cap (the read-protected
// path) or pass it through verbatim. It mirrors the per-frontend matcher state
// the HTTP frontend holds separately (frontend.go readDeny field); the SSH
// frontend does not hold its own copy and queries the proxy it owns.
func (p *Proxy) ReadDenyOn() bool { return p.readDenyMatcher != nil }

// UploadPack handles a git-upload-pack (fetch/clone) exchange. With read
// protection OFF (readDenyMatcher == nil) it is passthrough: the agent's request
// body is parsed for the inspection seam and forwarded to the upstream, and the
// upstream's response is streamed back byte-exact. With read protection ON
// (readDenyMatcher != nil) the proxy ASSEMBLES the packfile (it does not
// forward): it opens the inspection mirror, computes the wanted object set,
// withholds blobs whose path matches the deny matcher, packs the rest, and
// serves a v0 upload-pack response. Fail-closed: any error in the read-enforce
// path returns an error and the caller MUST deny the fetch (no unprotected
// packfile, no passthrough fallback when read protection is on).
func (p *Proxy) UploadPack(ctx context.Context, repo string, body io.Reader, w io.Writer) error {
	// DoS hardening: cap the upload-pack REQUEST read at
	// MaxUploadPackRequestBytes (1 MiB). A real upload-pack request is tiny
	// (wants/haves/caps — the packfile is in the *response*, never the request),
	// so 1 MiB is a generous ceiling. The +1 lets us detect truncation: a body
	// of exactly max+1 bytes was truncated by the LimitReader. This applies to
	// BOTH the passthrough and read-protected branches below — an oversized or
	// truncated request is denied fail-closed (no forward, no assembly). This
	// is DISTINCT from the 256 MiB push packfile cap (receive-pack path).
	lr := &io.LimitedReader{R: body, N: MaxUploadPackRequestBytes + 1}
	buf, err := io.ReadAll(lr)
	if err != nil {
		return fmt.Errorf("gitproto: read upload-pack request: %w", err)
	}
	if int64(len(buf)) > MaxUploadPackRequestBytes {
		log.Printf("gitproto: upload-pack deny: request exceeds %d bytes for repo %q", MaxUploadPackRequestBytes, repo)
		return fmt.Errorf("gitproto: upload-pack request exceeds %d bytes", MaxUploadPackRequestBytes)
	}

	// Read protection OFF → passthrough (existing behavior preserved). The
	// request is parsed for the inspection seam but failures are non-fatal.
	if p.readDenyMatcher == nil {
		if _, perr := ParseUploadPackRequest(bytes.NewReader(buf)); perr != nil {
			log.Printf("gitproto: upload-pack request parse: %v", perr)
		}
		rc, err := p.up.UploadPack(ctx, repo, bytes.NewReader(buf))
		if err != nil {
			return fmt.Errorf("gitproto: upload-pack: %w", err)
		}
		defer func() { _ = rc.Close() }()
		// Audit the fetch passthrough for parity with push passthrough (which
		// records a bare "allow") — a full traffic audit covers both legs.
		// Best-effort: recordAudit logs+swallows any sink error (a sink failure
		// never changes the verdict or blocks the op).
		p.recordAudit(ctx, "git-upload-pack", agentName(ctx), repo, "allow",
			nil, nil, nil, nil, false)
		return forwardStream(rc, w)
	}

	// --- Read protection ON (fail-closed) ---
	// A read-protected fetch requires a mirror to compute the object set. No
	// mirror opener means the proxy cannot safely assemble a packfile → deny.
	agent := agentName(ctx)
	if p.mirrorOpener == nil {
		log.Printf("gitproto: upload-pack deny: read protection on but no mirror opener for repo %q", repo)
		p.recordAudit(ctx, "git-upload-pack", agent, repo, "deny",
			[]string{"read protection on but no mirror opener"}, nil, nil, nil, false)
		return fmt.Errorf("gitproto: upload-pack enforce: mirror unavailable")
	}
	// Parse the request strictly. An unparseable request cannot be safely
	// enforced → fail closed (do not forward an uninspected request).
	req, perr := ParseUploadPackRequest(bytes.NewReader(buf))
	if perr != nil {
		log.Printf("gitproto: upload-pack deny: unparseable request for repo %q: %v", repo, perr)
		p.recordAudit(ctx, "git-upload-pack", agent, repo, "deny",
			[]string{"unparseable upload-pack request"}, nil, nil, nil, false)
		return fmt.Errorf("gitproto: upload-pack enforce: parse request: %w", perr)
	}
	mirror, err := p.mirrorOpener(ctx, repo)
	if err != nil {
		log.Printf("gitproto: upload-pack deny: mirror open for repo %q: %v", repo, err)
		p.recordAudit(ctx, "git-upload-pack", agent, repo, "deny",
			[]string{"inspection mirror unavailable"}, nil, nil, nil, false)
		return fmt.Errorf("gitproto: upload-pack enforce: mirror open: %w", err)
	}
	result, err := ServeUploadPackEnforced(ctx, w, req, mirror, p.readDenyMatcher, repo)
	if err != nil {
		log.Printf("gitproto: upload-pack deny: enforce for repo %q: %v", repo, err)
		p.recordAudit(ctx, "git-upload-pack", agent, repo, "deny",
			[]string{"upload-pack enforce failed"}, nil, nil, nil, false)
		return fmt.Errorf("gitproto: upload-pack enforce: %w", err)
	}
	// Success: decide the audit verdict from the withheld/denied summary. A
	// fully-allowed read-protected fetch (zero denials) records an "allow" event
	// with empty DeniedPaths/OIDs so the log shows the op happened (flagged
	// choice). Any withheld path or on-demand-denied OID → "deny" event.
	//
	// Read-protection dry-run is OUT of v1 scope (binding — flagged): read
	// protection withholds/denies regardless of p.dryRun (never serve a denied
	// blob to "observe"). So dryRun is always false here — the deny is enforced
	// and the alert carries DryRun=false. Documented limitation.
	verdict := "allow"
	var reasons []string
	if len(result.DeniedOIDs) > 0 {
		verdict = "deny"
		reasons = []string{"on-demand blob denied by read policy"}
	} else if len(result.DeniedPaths) > 0 {
		verdict = "deny"
		reasons = []string{"blob withheld by read policy"}
	}
	p.recordAudit(ctx, "git-upload-pack", agent, repo, verdict, reasons, nil,
		result.DeniedPaths, result.DeniedOIDs, false)
	return nil
}

// ReceivePack handles a git-receive-pack (push) exchange. The agent's request
// body (ref-update commands + packfile) is buffered and parsed. With
// enforcement off (no engine or mirror opener wired) it is forwarded verbatim
// to the upstream and the upstream response is streamed back byte-exact — the
// original passthrough behavior. With enforcement on:
//
//  1. The buffered body is size-capped (push.max_packfile_bytes); an oversized
//     push is denied fail-closed without forwarding.
//  2. The inspection mirror is opened and refreshed, and the pushed packfile
//     (if any) is ingested into it so both old and new objects are present.
//  3. EnforceReceivePack builds a PushRequest and evaluates it against the
//     engine. An enforcement/ancestry error fails closed (deny).
//  4. Allow → the original buffered bytes are forwarded to the upstream and
//     the upstream response is streamed back. Deny → a report-status deny
//     response is written to the agent and the upstream is left untouched.
//
// The agent identity is read from ctx (auth.FromContext); when auth is off the
// agent name is "" and rules apply per their applicability logic.
func (p *Proxy) ReceivePack(ctx context.Context, repo string, body io.Reader, w io.Writer) error {
	max := p.maxPackfileBytes
	enforce := p.engine != nil && p.mirrorOpener != nil

	// When enforcement is on, cap the read at max+1 bytes so a malicious agent
	// cannot force an unbounded allocation before the size check runs. The +1
	// lets us detect overflow: a body of exactly max+1 bytes was truncated. In
	// passthrough mode the body is forwarded verbatim, so read it all.
	var buf []byte
	var err error
	if enforce {
		lr := &io.LimitedReader{R: body, N: max + 1}
		buf, err = io.ReadAll(lr)
	} else {
		buf, err = io.ReadAll(body)
	}
	if err != nil {
		return fmt.Errorf("gitproto: read receive-pack request: %w", err)
	}
	req, perr := ParseReceivePackRequest(bytes.NewReader(buf))
	if perr != nil {
		log.Printf("gitproto: receive-pack request parse: %v", perr)
	}

	// Passthrough when enforcement is off (no engine or no mirror opener).
	// This preserves the existing passthrough/auth behavior when policy is
	// unconfigured. Audit decision (flagged): record a bare "allow" event so
	// the audit log reflects all git traffic (useful for forensics) — the event
	// carries the pushed refs (if the request parsed) and NO reasons. If this
	// adds risk in a future compliance mode, scope to policy-active ops and
	// document the gap; for v1 the bare allow is cheap and observability-useful.
	if !enforce {
		p.recordAudit(ctx, "git-receive-pack", agentName(ctx), repo, "allow",
			nil, auditRefsFromRequest(req), nil, nil, false)
		return p.forwardReceivePack(ctx, repo, buf, w)
	}

	// --- Enforcement on ---
	// Oversized: deny fail-closed without forwarding. The request header
	// (commands + capabilities + flush) is small relative to max, so a
	// truncated body still parses and the report-status reject is emitted; a
	// pathological tiny max that breaks parsing falls through to the
	// unparseable branch below (still no forward).
	if int64(len(buf)) > max {
		dec := port.Decision{
			Verdict: port.VerdictDeny,
			Reasons: []port.Reason{{Rule: "enforcement",
				Message: "push rejected: packfile too large"}},
		}
		log.Printf("gitproto: receive-pack deny: oversize %d > %d for repo %q", len(buf), max, repo)
		if req != nil {
			p.writeDenyResponse(w, req, dec)
		}
		p.recordPushAudit(ctx, repo, req, dec, false)
		return nil
	}

	// Fail-closed on an unparseable request: without commands/refs the proxy
	// cannot compute a decision, so it must not forward. There is no
	// structured report-status channel (no parsed capabilities), so close the
	// stream; the agent sees a failed push. Real git always sends parseable
	// requests, so this is an edge case. Dry-run does NOT soften this: it is an
	// inspection failure (parse error), and dry-run only softens POLICY denies.
	if perr != nil || req == nil {
		log.Printf("gitproto: receive-pack deny: unparseable request for repo %q: %v", repo, perr)
		p.recordAudit(ctx, "git-receive-pack", agentName(ctx), repo, "deny",
			[]string{"push rejected: unparseable request"}, nil, nil, nil, false)
		return nil
	}

	mirror, err := p.mirrorOpener(ctx, repo)
	if err != nil {
		dec := port.Decision{
			Verdict: port.VerdictDeny,
			Reasons: []port.Reason{{Rule: "enforcement",
				Message: "push rejected: inspection mirror unavailable"}},
		}
		log.Printf("gitproto: receive-pack deny: mirror open for repo %q: %v", repo, err)
		p.writeDenyResponse(w, req, dec)
		p.recordPushAudit(ctx, repo, req, dec, false)
		return nil
	}
	if err := mirror.Refresh(ctx); err != nil {
		dec := port.Decision{
			Verdict: port.VerdictDeny,
			Reasons: []port.Reason{{Rule: "enforcement",
				Message: "push rejected: inspection mirror unavailable"}},
		}
		log.Printf("gitproto: receive-pack deny: mirror refresh for repo %q: %v", repo, err)
		p.writeDenyResponse(w, req, dec)
		p.recordPushAudit(ctx, repo, req, dec, false)
		return nil
	}
	if req.PackfileOffset >= 0 && int64(len(buf)) > req.PackfileOffset {
		pack := buf[req.PackfileOffset:]
		if err := mirror.IngestPackfile(ctx, bytes.NewReader(pack)); err != nil {
			dec := port.Decision{
				Verdict: port.VerdictDeny,
				Reasons: []port.Reason{{Rule: "enforcement",
					Message: "push rejected: inspection failed"}},
			}
			log.Printf("gitproto: receive-pack deny: ingest packfile for repo %q: %v", repo, err)
			p.writeDenyResponse(w, req, dec)
			p.recordPushAudit(ctx, repo, req, dec, false)
			return nil
		}
	}

	agent := agentName(ctx)
	dec, enErr := EnforceReceivePack(ctx, req, mirror, p.engine, agent, repo)
	if enErr != nil {
		log.Printf("gitproto: receive-pack enforcement error for repo %q: %v", repo, enErr)
	}
	if dec.Verdict == port.VerdictAllow {
		p.recordPushAudit(ctx, repo, req, dec, false)
		return p.forwardReceivePack(ctx, repo, buf, w)
	}
	// Deny. Dry-run softens POLICY denies only, NOT inspection failures (binding
	// — flagged). A CLEAN engine deny (enErr == nil — the engine evaluated the
	// push and said deny) is FORWARDED in dry-run so teams observe the violation
	// without enforcing it: the audit records the TRUE verdict (deny) with
	// DryRun=true and an alert fires with DryRun=true. An inspection-error deny
	// (enErr != nil — ancestry/commit/blob extraction failed; the proxy could
	// not inspect the push) STILL fail-closes even in dry-run: the proxy writes
	// the deny response and records DryRun=false, because forwarding an
	// uninspected push is unsafe regardless of dry-run (you observe policy
	// verdicts, not bypass inspection). The engine stays pure — it returns the
	// true verdict; dry-run is a proxy-level forwarding decision.
	if p.dryRun && enErr == nil {
		log.Printf("gitproto: receive-pack dry-run forward for repo %q agent %q (would-deny): %v",
			repo, agent, dec.Reasons)
		p.recordPushAudit(ctx, repo, req, dec, true)
		return p.forwardReceivePack(ctx, repo, buf, w)
	}
	log.Printf("gitproto: receive-pack deny for repo %q agent %q: %v", repo, agent, dec.Reasons)
	p.writeDenyResponse(w, req, dec)
	p.recordPushAudit(ctx, repo, req, dec, false)
	return nil
}

// forwardReceivePack forwards the original buffered request bytes to the
// upstream and streams the upstream response back to the agent byte-exact.
func (p *Proxy) forwardReceivePack(ctx context.Context, repo string, buf []byte, w io.Writer) error {
	rc, err := p.up.ReceivePack(ctx, repo, bytes.NewReader(buf))
	if err != nil {
		return fmt.Errorf("gitproto: receive-pack: %w", err)
	}
	defer func() { _ = rc.Close() }()
	return forwardStream(rc, w)
}

// writeDenyResponse writes a report-status deny response to the agent for the
// denied push. If the agent did not request report-status, there is no
// structured channel: write nothing (the agent sees a truncated/empty stream
// and treats the push as failed). Real git always requests report-status.
//
// When the agent requested side-band-64k (the common case), the report-status
// is multiplexed over sideband channel 1 (PackData) and the sideband stream is
// terminated with a flush-pkt — matching what a real git server sends. Without
// sideband, the plain report-status is written directly.
func (p *Proxy) writeDenyResponse(w io.Writer, req *ReceivePackRequest, dec port.Decision) {
	if !hasReportStatus(req) {
		return
	}
	var buf bytes.Buffer
	if err := EncodeReportStatusDeny(&buf, deniedRefs(req), dec); err != nil {
		log.Printf("gitproto: encode report-status deny: %v", err)
		return
	}
	switch sidebandType(req) {
	case sideband.Sideband64k:
		m := sideband.NewMuxer(sideband.Sideband64k, w)
		if _, err := m.Write(buf.Bytes()); err != nil {
			log.Printf("gitproto: mux report-status deny: %v", err)
			return
		}
		// Terminate the sideband stream with a flush-pkt.
		if _, err := w.Write([]byte("0000")); err != nil {
			log.Printf("gitproto: flush sideband deny: %v", err)
		}
	case sideband.Sideband:
		m := sideband.NewMuxer(sideband.Sideband, w)
		if _, err := m.Write(buf.Bytes()); err != nil {
			log.Printf("gitproto: mux report-status deny: %v", err)
			return
		}
		if _, err := w.Write([]byte("0000")); err != nil {
			log.Printf("gitproto: flush sideband deny: %v", err)
		}
	default:
		if _, err := w.Write(buf.Bytes()); err != nil {
			log.Printf("gitproto: write report-status deny: %v", err)
		}
	}
}

// sidebandType reports which sideband capability (if any) the agent advertised.
// Returns sideband.Sideband64k for "side-band-64k", sideband.Sideband for
// "side-band", and an invalid value (defaulted to plain) when neither is present.
func sidebandType(req *ReceivePackRequest) sideband.Type {
	for _, cmd := range req.Commands {
		for _, cap := range cmd.Caps {
			if cap == "side-band-64k" || strings.HasPrefix(cap, "side-band-64k=") {
				return sideband.Sideband64k
			}
			if cap == "side-band" || strings.HasPrefix(cap, "side-band=") {
				return sideband.Sideband
			}
		}
	}
	return sideband.Type(-1) // sentinel: no sideband
}

// agentName extracts the authenticated agent name from ctx, or "" when no
// identity is present (auth off). Rules with an empty agent apply per their
// applicability logic.
func agentName(ctx context.Context) string {
	if a, ok := auth.FromContext(ctx); ok {
		return a.Name
	}
	return ""
}

// recordAudit is the best-effort audit recorder. A nil sink → no-op (preserves
// the pre-audit behavior). A Record error is LOGGED and swallowed: the policy
// decision is enforced independently of audit (audit is observability, not a
// gate — a disk-full audit must NOT change the verdict or block the git op).
// The event is stamped with time.Now here (in the I/O layer, NOT in the pure
// policy engine) and the frontend's transport tag. dryRun is set on the event
// (true only on the dry-run forward path — a deny forwarded despite the
// verdict; false for enforced denies and all allows). When verdict is "deny",
// recordAudit ALSO fires an alert via recordAlert (best-effort, same fields),
// so operators are notified of every policy violation in real time.
func (p *Proxy) recordAudit(ctx context.Context, service, agent, repo, verdict string,
	reasons []string, refs []port.AuditRef, deniedPaths, deniedOIDs []string, dryRun bool) {
	if p.audit != nil {
		e := port.AuditEvent{
			Time:        time.Now(),
			Transport:   p.transport,
			Agent:       agent,
			Repo:        repo,
			Service:     service,
			Verdict:     verdict,
			Reasons:     reasons,
			Refs:        refs,
			DeniedPaths: deniedPaths,
			DeniedOIDs:  deniedOIDs,
			DryRun:      dryRun,
		}
		if err := p.audit.Record(ctx, e); err != nil {
			log.Printf("gitproto: audit record: %v", err)
		}
	}
	// Fire an alert on every deny (enforced or dry-run). Alerts are observability
	// (best-effort, non-fatal); a nil alert sink → no-op. The alert carries the
	// same generic fields as the audit event (no-leak contract).
	if verdict == "deny" {
		p.recordAlert(ctx, service, agent, repo, dryRun, reasons, refs, deniedPaths, deniedOIDs)
	}
}

// recordAlert is the best-effort alert recorder. A nil sink → no-op (preserves
// the pre-alert behavior). An Alert error is LOGGED and swallowed: the policy
// decision is enforced independently of alerting (alerting is observability,
// not a gate — a down webhook MUST NOT change the verdict or block the git op).
// The alert is stamped with time.Now here (in the I/O layer, NOT in the pure
// policy engine) and the frontend's transport tag. The Alert carries only
// generic reasons/paths/OIDs — never blob content, raw secrets, upstream
// URLs/creds, or packfile bytes (no-leak contract; the webhook leaves the
// proxy, so the payload is a leak surface).
func (p *Proxy) recordAlert(ctx context.Context, service, agent, repo string, dryRun bool,
	reasons []string, refs []port.AuditRef, deniedPaths, deniedOIDs []string) {
	if p.alerts == nil {
		return
	}
	a := port.Alert{
		Time:        time.Now(),
		Transport:   p.transport,
		Agent:       agent,
		Repo:        repo,
		Service:     service,
		Verdict:     "deny",
		DryRun:      dryRun,
		Reasons:     reasons,
		Refs:        refs,
		DeniedPaths: deniedPaths,
		DeniedOIDs:  deniedOIDs,
	}
	if err := p.alerts.Alert(ctx, a); err != nil {
		log.Printf("gitproto: alert: %v", err)
	}
}

// auditRefsFromRequest builds the AuditRef list from a parsed receive-pack
// request's commands. The ref/old/new OIDs are not blob content — safe to log.
// Force is left false here: the wire command carries no force flag (force is a
// derived property computed inside EnforceReceivePack's ancestry walk, not
// re-derived for the audit record). The ref/old/new are the load-bearing
// fields for forensics.
func auditRefsFromRequest(req *ReceivePackRequest) []port.AuditRef {
	if req == nil {
		return nil
	}
	refs := make([]port.AuditRef, 0, len(req.Commands))
	for _, c := range req.Commands {
		refs = append(refs, port.AuditRef{Ref: c.Ref, Old: c.Old, New: c.New})
	}
	return refs
}

// reasonsFromDecision extracts the agent-facing reason messages from a Decision.
// These are the generic, already-redacted port.Reason.Message strings — never
// blob content or upstream creds (the no-leak contract).
func reasonsFromDecision(dec port.Decision) []string {
	if len(dec.Reasons) == 0 {
		return nil
	}
	out := make([]string, 0, len(dec.Reasons))
	for _, r := range dec.Reasons {
		out = append(out, r.Message)
	}
	return out
}

// verdictString maps a port.Verdict to the audit verdict string.
func verdictString(v port.Verdict) string {
	if v == port.VerdictDeny {
		return "deny"
	}
	return "allow"
}

// recordPushAudit records a push (git-receive-pack) decision. It carries the
// agent, repo, verdict, the pushed refs, and the generic reasons. nil sink →
// no-op. Best-effort: a Record error is logged, never returned. dryRun is set
// on the event (true only on the dry-run forward path). Fires an alert on deny.
func (p *Proxy) recordPushAudit(ctx context.Context, repo string, req *ReceivePackRequest, dec port.Decision, dryRun bool) {
	p.recordAudit(ctx, "git-receive-pack", agentName(ctx), repo,
		verdictString(dec.Verdict), reasonsFromDecision(dec), auditRefsFromRequest(req), nil, nil, dryRun)
}

// deniedRefs returns the refs of every command in the request, for use as the
// per-ref ng list in the report-status deny response. When the engine denies,
// no command is applied, so every pushed ref is reported as rejected.
func deniedRefs(req *ReceivePackRequest) []string {
	refs := make([]string, 0, len(req.Commands))
	for _, cmd := range req.Commands {
		refs = append(refs, cmd.Ref)
	}
	return refs
}

// hasReportStatus reports whether the agent's capabilities include a
// report-status capability (the structured channel the proxy uses to reject
// refs). Real git advertises "report-status" and/or "report-status-v2"; both
// carry the "ng <ref> <reason>" line the proxy emits. A client that advertises
// neither gets a bare stream close (the push fails without a structured reason).
func hasReportStatus(req *ReceivePackRequest) bool {
	for _, cmd := range req.Commands {
		for _, cap := range cmd.Caps {
			if cap == "report-status" || strings.HasPrefix(cap, "report-status=") ||
				cap == "report-status-v2" || strings.HasPrefix(cap, "report-status-v2=") {
				return true
			}
		}
	}
	return false
}

// forwardStream copies the upstream response to the agent writer using
// structured pkt-line parsing: each pkt-line is read via the codec and its raw
// bytes are written through verbatim, preserving byte-exact passthrough. When
// the scanner reaches a non-pkt-line section (the packfile body of a non-
// sideband upload-pack response), it switches to raw copy for the remainder.
func forwardStream(rc io.Reader, w io.Writer) error {
	s := pktline.NewScanner(rc)
	for s.Scan() {
		if _, err := w.Write(s.Raw()); err != nil {
			return fmt.Errorf("gitproto: forward pkt-line: %w", err)
		}
	}
	if err := s.Err(); err != nil {
		return fmt.Errorf("gitproto: scan response: %w", err)
	}
	// A Raw marker means the scanner read bytes that are not a pkt-line prefix
	// (typically the PACK magic of a packfile). Forward those bytes and copy the
	// rest of the stream raw, byte-exact.
	if s.Marker() == pktline.Raw {
		if _, err := w.Write(s.Pending()); err != nil {
			return fmt.Errorf("gitproto: forward raw head: %w", err)
		}
		if _, err := io.Copy(w, rc); err != nil {
			return fmt.Errorf("gitproto: forward raw body: %w", err)
		}
	}
	return nil
}
