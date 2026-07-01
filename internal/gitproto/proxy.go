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
	buf, err := io.ReadAll(body)
	if err != nil {
		return fmt.Errorf("gitproto: read upload-pack request: %w", err)
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
		return forwardStream(rc, w)
	}

	// --- Read protection ON (fail-closed) ---
	// A read-protected fetch requires a mirror to compute the object set. No
	// mirror opener means the proxy cannot safely assemble a packfile → deny.
	if p.mirrorOpener == nil {
		log.Printf("gitproto: upload-pack deny: read protection on but no mirror opener for repo %q", repo)
		return fmt.Errorf("gitproto: upload-pack enforce: mirror unavailable")
	}
	// Parse the request strictly. An unparseable request cannot be safely
	// enforced → fail closed (do not forward an uninspected request).
	req, perr := ParseUploadPackRequest(bytes.NewReader(buf))
	if perr != nil {
		log.Printf("gitproto: upload-pack deny: unparseable request for repo %q: %v", repo, perr)
		return fmt.Errorf("gitproto: upload-pack enforce: parse request: %w", perr)
	}
	mirror, err := p.mirrorOpener(ctx, repo)
	if err != nil {
		log.Printf("gitproto: upload-pack deny: mirror open for repo %q: %v", repo, err)
		return fmt.Errorf("gitproto: upload-pack enforce: mirror open: %w", err)
	}
	if err := ServeUploadPackEnforced(ctx, w, req, mirror, p.readDenyMatcher, repo); err != nil {
		log.Printf("gitproto: upload-pack deny: enforce for repo %q: %v", repo, err)
		return fmt.Errorf("gitproto: upload-pack enforce: %w", err)
	}
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
	// unconfigured.
	if !enforce {
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
		return nil
	}

	// Fail-closed on an unparseable request: without commands/refs the proxy
	// cannot compute a decision, so it must not forward. There is no
	// structured report-status channel (no parsed capabilities), so close the
	// stream; the agent sees a failed push. Real git always sends parseable
	// requests, so this is an edge case.
	if perr != nil || req == nil {
		log.Printf("gitproto: receive-pack deny: unparseable request for repo %q: %v", repo, perr)
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
			return nil
		}
	}

	agent := agentName(ctx)
	dec, enErr := EnforceReceivePack(ctx, req, mirror, p.engine, agent, repo)
	if enErr != nil {
		log.Printf("gitproto: receive-pack enforcement error for repo %q: %v", repo, enErr)
	}
	if dec.Verdict == port.VerdictAllow {
		return p.forwardReceivePack(ctx, repo, buf, w)
	}
	log.Printf("gitproto: receive-pack deny for repo %q agent %q: %v", repo, agent, dec.Reasons)
	p.writeDenyResponse(w, req, dec)
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
