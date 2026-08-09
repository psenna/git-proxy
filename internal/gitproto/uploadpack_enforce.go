package gitproto

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"strings"

	"github.com/go-git/go-git/v5/plumbing/protocol/packp/sideband"
	"github.com/psenna/git-proxy/internal/gitproto/pktline"
	"github.com/psenna/git-proxy/internal/gitx"
	"github.com/psenna/git-proxy/internal/pathmatch"
)

// UploadPackEnforceResult summarizes a read-protected fetch enforcement pass
// for audit: DeniedPaths are the blob paths withheld from the packfile (Task 9),
// DeniedOIDs are the on-demand blob OIDs refused with ERR (Task 10). A zero
// value (both empty) means the fetch was fully allowed — no withholdings, no
// on-demand denials. The caller (proxy.go) uses it to build the audit event:
// any non-empty DeniedPaths/DeniedOIDs → verdict deny; both empty → allow.
// Paths and OIDs are not blob content — safe to log (no-leak contract).
type UploadPackEnforceResult struct {
	DeniedPaths  []string // blob paths withheld from the packfile (Task 9)
	DeniedOIDs   []string // on-demand blob OIDs refused with ERR (Task 10)
	DeniedReason string   // actionable plain-clone rejection reason (empty otherwise)
}

// errPlainCloneNeedsFilter is the actionable, fail-closed reason emitted when a
// read-protected fetch would withhold a denied-path blob but the client did not
// request a filtered (partial) fetch. A plain clone cannot tolerate the
// withheld blobs (a tree referencing a missing blob), so the proxy refuses
// rather than serving a structurally-incomplete packfile the client would reject
// with a cryptic "missing blob object". Generic: no credentials, no secret
// content, no paths/OIDs.
const errPlainCloneNeedsFilter = "read-protected repository requires a partial clone; retry with --filter=blob:none"

// clientRequestedFilter reports whether the agent's upload-pack request asked
// for a filtered (partial) fetch — i.e. it advertised the `filter` capability.
// A plain clone/fetch does not, and cannot tolerate the blobs read protection
// withholds, so the caller refuses it with an actionable ERR rather than
// serving a structurally-incomplete packfile.
//
// req.Caps entries are "name" or "name=value"; splitCaps splits on whitespace,
// so a real `filter blob:none` cap appears as two entries ("filter" and
// "blob:none"). Matching the "filter" name in either the bare or name=value
// form covers both tokenizations.
func clientRequestedFilter(caps []string) bool {
	for _, c := range caps {
		if c == "filter" || strings.HasPrefix(c, "filter=") {
			return true
		}
	}
	return false
}

// ServeUploadPackEnforced assembles a filtered packfile for a read-protected
// fetch and writes a v0 upload-pack response to w. It withholds blobs whose path
// matches readDenyMatcher, keeping commits and trees intact, so the agent sees
// the tree entry pointing at a now-missing blob (the on-demand fetch for that
// blob is denied by Task 10). The proxy — not the client — assembles the
// packfile, so denial is enforced regardless of client cooperation. It returns
// an UploadPackEnforceResult summarizing what was withheld/denied for audit
// (the caller records the audit event — recording stays in the I/O layer).
//
// Behavior (mirrors the push enforce fail-closed discipline):
//  1. Refresh the inspection mirror (fail-closed on error).
//  2. WantedObjects(wants, haves) over the mirror -> (oid, path) pairs.
//  3. ObjectTypes over the unique OIDs to identify blobs (subtrees carry a
//     non-empty path too, so path alone is insufficient to identify blobs;
//     only blobs are ever withheld — trees and commits are always kept).
//  4. For each blob OID, collect its paths; if ANY path matches the deny
//     matcher, OMIT the OID from the pack list. Otherwise keep it.
//  5. PackObjects(allowedOIDs, thin) builds the filtered packfile from an
//     explicit OID list (no reachability walk), so denied blobs are genuinely
//     excluded even when referenced by trees.
//  6. Write the v0 response: a NAK pkt-line, then the packfile muxed over
//     side-band-64k channel 1 (with a terminating flush-pkt) when the client
//     requested side-band-64k, over side-band when it requested the legacy
//     side-band cap, or raw after the NAK pkt-line when neither was requested.
//
// Fail-closed: ANY error (refresh, rev-list, type lookup, pack-objects, encode)
// returns an error and the caller MUST deny the fetch — no unprotected packfile
// is written and no passthrough fallback when read protection is on. The agent
// never sees upstream credentials (mirror errors are already redacted by gitx).
//
// Self-healing: if the first attempt fails with a corruption error (missing or
// damaged object in the mirror), the mirror is repaired (re-cloned from
// upstream) and the enforce is retried once. Corruption errors are detected by
// gitx.IsCorruptionError, which matches git error patterns like "bad object",
// "missing object", "corrupt", "loose object", and "unable to unpack". If the
// repair or the retry fails, the original error is returned (fail-closed).
// Policy denials and parse errors are NOT retried — only corruption errors.
// No bytes have been written to w before corruption errors occur, so retry is
// safe (the HTTP response is still unwritten).
//
// This is a PROXY-LEVEL per-path filter (pathmatch), NOT the engine's
// all-or-nothing EvaluateFetch; it is not routed through the policy engine.
//
// Protocol scope: v0 only for the read-protected fetch path (v1 decision). The
// frontend re-emits the upstream ref advertisement as v0 (stripping version 2)
// so the client negotiates v0 here. v2 fetch support is a documented v1
// follow-up.
func ServeUploadPackEnforced(ctx context.Context, w io.Writer, req *UploadPackRequest,
	mirror *gitx.Mirror, readDenyMatcher *pathmatch.Matcher, repo string) (UploadPackEnforceResult, error) {

	result, err := serveUploadPackEnforcedInner(ctx, w, req, mirror, readDenyMatcher, repo)
	if err != nil && gitx.IsCorruptionError(err) {
		log.Printf("upload-pack enforce: mirror corruption detected for repo %q: %v; attempting repair", repo, err)
		if repairErr := mirror.Repair(ctx); repairErr != nil {
			log.Printf("upload-pack enforce: mirror repair failed for repo %q: %v", repo, repairErr)
			return result, err
		}
		// Defense-in-depth refresh after repair. The inner function also calls
		// Refresh, but this ensures the mirror is up-to-date even if the inner
		// Refresh is ever removed or restructured.
		if refreshErr := mirror.Refresh(ctx); refreshErr != nil {
			log.Printf("upload-pack enforce: mirror refresh after repair failed for repo %q: %v", repo, refreshErr)
			return result, err
		}
		result, err = serveUploadPackEnforcedInner(ctx, w, req, mirror, readDenyMatcher, repo)
	}
	return result, err
}

// serveUploadPackEnforcedInner is the core read-protected fetch enforcement
// logic, extracted from ServeUploadPackEnforced for the retry-on-corruption
// wrapper. See ServeUploadPackEnforced for full documentation.
func serveUploadPackEnforcedInner(ctx context.Context, w io.Writer, req *UploadPackRequest,
	mirror *gitx.Mirror, readDenyMatcher *pathmatch.Matcher, repo string) (UploadPackEnforceResult, error) {

	if err := mirror.Refresh(ctx); err != nil {
		return UploadPackEnforceResult{}, fmt.Errorf("gitproto: upload-pack enforce: refresh mirror: %w", err)
	}

	// --- Task 10: on-demand blob fetch classification (M7b) ---
	//
	// An on-demand fetch's want is a BLOB oid (the agent's git, after a
	// --filter=blob:none clone, lazily fetching a specific blob it needs). A
	// full clone's want is a commit (or tag) oid. Classify each want oid by
	// type and, for blob wants, resolve the OID back to its path(s) so the
	// read deny matcher can evaluate them. The existing Task 9 withholding
	// path below works over the wanted SET and cannot deny an on-demand blob:
	// `git rev-list --objects <blob-oid>` yields the blob with NO path, so
	// the deny matcher has nothing to match and the blob would be served. The
	// on-demand path closes that gap.
	//
	// Fail-closed (binding):
	//   - ANY on-demand blob whose resolving path matches the deny matcher →
	//     REFUSE the whole fetch with an `ERR <reason>\n` pkt-line (no NAK, no
	//     packfile). A mixed request (commit want + denied blob want) is also
	//     REFUSED — never partially serve a fetch containing a denied blob.
	//   - A blob want whose path(s) cannot be resolved (Resolve error OR zero
	//     paths) → REFUSE with ERR. The proxy cannot prove an unresolvable
	//     blob is not a denied blob, so it DENIES it (the safer choice for a
	//     security filter). This is the documented fail-closed decision; it is
	//     stricter than fail-open and may over-deny, but never under-deny.
	//   - Commit/tag/tree wants and allowed blob wants fall through to the
	//     existing withholding path, which serves the (allowed) blob.
	if reason, deniedOID, deny := onDemandBlobDenyReason(ctx, mirror, req.Wants, readDenyMatcher, repo); deny {
		log.Printf("gitproto: upload-pack enforce: refusing on-demand fetch for repo %q: %s", repo, reason)
		err := writeUploadPackErr(w, reason)
		return UploadPackEnforceResult{DeniedOIDs: []string{deniedOID}}, err
	}

	// --- Shallow / `deepen` fetch handling ---
	//
	// A `git fetch --depth=N` (or `--shallow-exclude` / `--shallow-since`) sends
	// `deepen`/`deepen-not`/`deepen-since` lines (parsed in ParseUploadPackRequest).
	// The read-protected path must compute a shallow object set and emit a
	// `shallow`/`unshallow` preamble BEFORE the NAK — without it the client fails
	// with `expected shallow/unshallow, got NAK` (the user's reported bug). The
	// plain (non-deepen) path is unchanged (WantedObjects + withhold, no
	// preamble).
	//
	// A request carrying ONLY client `shallow` lines (no `deepen`/`deepen-not`/
	// `deepen-since`) is a shallow client doing an incremental fetch with no new
	// cut: the server applies no new boundary and emits no preamble — fall
	// through to the plain path (the client's existing shallows are unchanged).
	//
	// `deepen-since` (date-based boundary) is deferred: emit an actionable ERR
	// instead of the current silent cryptic NAK (a documented gap, not a
	// regression — strict improvement over the v0.0.2 behavior).
	if req.DeepenSince != "" {
		log.Printf("gitproto: upload-pack enforce: refusing shallow-since fetch for repo %q (unsupported)", repo)
		reason := errDeepenSinceUnsupported
		if err := writeUploadPackErr(w, reason); err != nil {
			return UploadPackEnforceResult{DeniedReason: reason}, err
		}
		return UploadPackEnforceResult{DeniedReason: reason}, nil
	}

	var shallowLines []string
	var objs []gitx.ObjectPath
	var err error
	if req.Deepen > 0 || len(req.DeepenNot) > 0 {
		plan, perr := planShallowFetch(ctx, mirror, req, repo)
		if perr != nil {
			return UploadPackEnforceResult{}, fmt.Errorf("gitproto: upload-pack enforce: %w", perr)
		}
		objs = plan.objects
		shallowLines = plan.shallowLines
	} else {
		// Plain (non-deepen) stateless negotiation. A request WITHOUT `done` is a
		// preliminary round in which the client advertises haves to discover common
		// ground (git flushes its first 16 haves with no `done` once a fetch has
		// that many to send). The server response is the ACK/NAK section with NO
		// packfile — verified against real `git upload-pack --stateless-rpc`, which
		// emits `ACK <oid> common` per common have, then `ACK <last> ready`, then
		// `NAK`, and STOP: critically it sends NO terminating flush-pkt (the
		// stateless HTTP response body boundary delimits the round). Emitting the
		// pack here (pre-#64) made the client parse the sideband channel byte (\x01)
		// + PACK magic as an ACK/NAK line -> `expected ACK/NAK, got '?PACK'`. A
		// trailing flush-pkt after the NAK (the first #64 attempt) is ALSO wrong:
		// git's multi_ack_detailed state machine, on reading NAK, breaks out of the
		// ACK loop WITHOUT consuming a trailing flush, leaving it in the read
		// buffer; the next round then reads that leftover `0000` first -> `expected
		// ACK/NAK, got a flush packet`. So the preliminary response is a single
		// `NAK` pkt-line and NOTHING else (no pack, no flush). NAK (no common
		// reported) is valid — the client sends more haves, then `done`, and the
		// done-round WantedObjects(wants, haves) excludes the haves server-side, so
		// the served pack is incremental regardless of the negotiation's ACKs.
		// (Sending `ACK <oid> common`/`ready` to collapse the rounds is a
		// documented efficiency follow-up; correctness is NAK-only here.)
		if !req.Done {
			e := pktline.NewEncoder(w)
			if err := e.EncodeString("NAK\n"); err != nil {
				return UploadPackEnforceResult{}, fmt.Errorf("gitproto: upload-pack enforce: encode NAK (preliminary): %w", err)
			}
			return UploadPackEnforceResult{}, nil
		}
		objs, err = mirror.WantedObjects(ctx, req.Wants, req.Haves)
		if err != nil {
			return UploadPackEnforceResult{}, fmt.Errorf("gitproto: upload-pack enforce: wanted objects: %w", err)
		}
	}

	// Stateless deepen is a multi-round negotiation (verified against real
	// `git upload-pack --stateless-rpc` + the fetch-pack state machine): the
	// client sends a preliminary round (want+deepen+flush, NO haves, NO done)
	// to learn the shallow boundaries, then rounds with haves, and a final round
	// with `done` that carries the pack. For every round the client reads a
	// shallow preamble (the initial `if(deepen)` block, then consume_shallow_list
	// per round) — so the preamble MUST be emitted on every round, including the
	// no-`done` ones. But the pack MUST be sent ONLY on the final (`done`)
	// round: emitting NAK+pack on a no-`done` round leaves a pack leftover that
	// the streaming HTTP response does not fully drain, and it leaks into the
	// next round's read (reproduced: `expected shallow list`). So for a shallow
	// request without `done`, emit ONLY the shallow preamble (shallow/unshallow
	// lines + a flush) and stop — no NAK, no pack. The boundaries are commit
	// OIDs (not blob paths), so nothing secret is emitted and the deny
	// withholding (which only strips pack blobs) does not apply.
	if (req.Deepen > 0 || len(req.DeepenNot) > 0) && !req.Done {
		e := pktline.NewEncoder(w)
		for _, line := range shallowLines {
			if err := e.EncodeString(line + "\n"); err != nil {
				return UploadPackEnforceResult{}, fmt.Errorf("gitproto: upload-pack enforce: encode shallow line: %w", err)
			}
		}
		if err := e.Flush(); err != nil {
			return UploadPackEnforceResult{}, fmt.Errorf("gitproto: upload-pack enforce: flush shallow section: %w", err)
		}
		return UploadPackEnforceResult{}, nil
	}

	// Collect unique OIDs (in first-seen order) and their resolving paths. Only
	// non-empty paths are matcher candidates; commits and the root tree have an
	// empty path and are never withheld.
	oidOrder := make([]string, 0, len(objs))
	oidPaths := make(map[string][]string, len(objs))
	for _, op := range objs {
		if _, ok := oidPaths[op.OID]; !ok {
			oidOrder = append(oidOrder, op.OID)
		}
		if op.Path != "" {
			oidPaths[op.OID] = append(oidPaths[op.OID], op.Path)
		}
	}

	types, err := mirror.ObjectTypes(ctx, oidOrder)
	if err != nil {
		return UploadPackEnforceResult{}, fmt.Errorf("gitproto: upload-pack enforce: object types: %w", err)
	}

	// Build the allowed OID list: keep commits and trees unconditionally; for
	// blobs, withhold if ANY resolving path matches the deny matcher. A nil
	// matcher matches nothing (read protection off at the path level).
	allowed := make([]string, 0, len(oidOrder))
	withheld := 0
	deniedPaths := make([]string, 0)
	for _, oid := range oidOrder {
		if types[oid] != "blob" {
			allowed = append(allowed, oid)
			continue
		}
		paths := oidPaths[oid]
		if readDenyMatcher != nil {
			denied := false
			for _, p := range paths {
				if readDenyMatcher.Match(p) {
					denied = true
					break
				}
			}
			if denied {
				withheld++
				deniedPaths = append(deniedPaths, paths...)
				log.Printf("gitproto: upload-pack enforce: withholding blob %s in repo %q (denied path(s): %v)",
					oid, repo, paths)
				continue
			}
		}
		allowed = append(allowed, oid)
	}
	if withheld > 0 {
		log.Printf("gitproto: upload-pack enforce: withheld %d blob(s) for repo %q", withheld, repo)
	}

	// Plain-clone rejection: if any blob was withheld and the client did not
	// request a filtered (partial) fetch, the served packfile would be
	// structurally incomplete (a tree referencing a missing blob) and the
	// client would fail with a cryptic "missing blob object". Refuse the fetch
	// with an actionable ERR pointing at --filter=blob:none instead. Fail-closed:
	// the denied blob is never served. This mirrors the on-demand deny pattern
	// (write ERR to w, return a populated result + nil error so the caller's
	// audit mapping records the deny).
	if withheld > 0 && !clientRequestedFilter(req.Caps) {
		log.Printf("gitproto: upload-pack enforce: refusing plain clone of read-protected repo %q (%d denied blob(s)); client must use --filter=blob:none", repo, withheld)
		reason := errPlainCloneNeedsFilter
		if err := writeUploadPackErr(w, reason); err != nil {
			return UploadPackEnforceResult{DeniedPaths: deniedPaths, DeniedReason: reason}, err
		}
		return UploadPackEnforceResult{DeniedPaths: deniedPaths, DeniedReason: reason}, nil
	}

	// Assemble the filtered packfile from the explicit allowed OID list. The
	// pack is ALWAYS non-thin (self-contained): `git pack-objects --thin` without
	// a receiver have-set walks the listed objects' references and INCLUDES the
	// referenced-but-unlisted blobs (the withheld ones) as delta bases, which
	// would break the read-protection guarantee. A non-thin pack is always
	// acceptable to a client that advertised thin-pack (thin-pack is a "may"
	// capability the server may decline, not a "must"); the client's checkout
	// only needs the objects it actually received. Documented v1 deviation from
	// the "pass --thin when the client requested it" guidance. The
	// readEnforceThin constant hardens against accidental re-enablement.
	packReader, packWait, err := mirror.PackObjectsStream(ctx, allowed, gitx.ReadEnforceThin)
	if err != nil {
		return UploadPackEnforceResult{}, fmt.Errorf("gitproto: upload-pack enforce: pack-objects: %w", err)
	}

	if err := writeV0UploadPackResponse(w, packReader, packWait, req.Caps, shallowLines); err != nil {
		return UploadPackEnforceResult{DeniedPaths: deniedPaths}, err
	}
	return UploadPackEnforceResult{DeniedPaths: deniedPaths}, nil
}

// writeV0UploadPackResponse writes a v0 upload-pack response to w: an optional
// shallow preamble (`shallow`/`unshallow` lines + a flush-pkt, only for a
// `deepen` fetch), then a NAK pkt-line, then the packfile (read from pack and
// produced by pack-objects) muxed over side-band-64k (or side-band) channel 1
// with a terminating flush-pkt when the client requested a sideband capability,
// or the packfile raw after the NAK pkt-line when no sideband was negotiated. A
// real git clone always requests side-band-64k, so the muxed path is the
// validated one; the raw path covers non-sideband clients.
//
// SHALLOW FRAMING: real git's v0 stateless upload-pack emits the shallow
// preamble BEFORE the NAK (verified by capturing `git upload-pack
// --stateless-rpc` with a `deepen` request): `shallow <sha>\n` / `unshallow
// <sha>\n` lines, a `0000` flush terminating the shallow section, then the NAK
// (+ ACK lines when haves are common), then the sideband/raw pack, then `0000`.
// shallowLines carries the `shallow <sha>` / `unshallow <sha>` payloads (without
// trailing newline — the encoder adds it); an empty slice means a plain
// (non-deepen) fetch and the preamble is omitted, keeping the response
// byte-identical to the pre-shallow behavior.
//
// STREAMING + FAIL-CLOSED: the packfile is streamed through the side-band muxer
// in bounded chunks (the muxer splits each Write into MaxPackedSize64k frames;
// io.Copy uses a 32 KiB read buffer) so the full packfile is NEVER materialized
// in memory — memory is bounded by the chunk size regardless of packfile size,
// closing the read-path OOM gap (the push path caps request size; the read path
// caps served size by streaming).
//
// To preserve fail-closed semantics with streaming, the function:
//  1. Reads the FIRST chunk of pack-objects output BEFORE writing anything to w.
//     If pack-objects fails to start (no output + a wait error), the error is
//     returned and NOTHING is written — the caller denies the fetch, no
//     unprotected/partial packfile reaches the agent.
//  2. For an empty pack, confirms pack-objects succeeded (packWait) BEFORE
//     writing the shallow preamble + NAK, so a pack-objects error still writes
//     nothing.
//  3. Once a non-empty head chunk is in hand, commits to streaming (writes the
//     shallow preamble + NAK + head + remainder). If pack-objects then fails
//     MID-STREAM, the wait error is surfaced and the sideband flush-pkt ("0000")
//     is NOT written, so the agent receives a truncated, trailer-less packfile
//     that does not look complete rather than a valid-looking pack —
//     fail-closed in the sense that no valid complete pack is served. The
//     returned error lets the caller log the failure.
//
// packWait MUST be called exactly once after the reader is drained or abandoned;
// it closes the reader (unblocking the producer goroutine) and returns the
// pack-objects exit error.
func writeV0UploadPackResponse(w io.Writer, pack io.Reader, packWait func() error, caps []string, shallowLines []string) error {
	// Read the first chunk to detect a pack-objects startup failure BEFORE
	// committing any bytes to w. 4 KiB is large enough to be meaningful yet
	// bounded; the muxer re-chunks the remainder regardless.
	const headSize = 4096
	head := make([]byte, headSize)
	n, readErr := io.ReadFull(pack, head)
	// io.ReadFull returns io.EOF when no bytes were read at all (empty pack)
	// and io.ErrUnexpectedEOF when some but fewer than headSize bytes were read
	// (pack smaller than headSize); both are normal end-of-input, not errors.
	if readErr != nil && !errors.Is(readErr, io.EOF) && !errors.Is(readErr, io.ErrUnexpectedEOF) {
		// Genuine read error before any data: fail closed without writing.
		_ = packWait()
		return fmt.Errorf("gitproto: read pack head: %w", readErr)
	}

	// Empty pack (n == 0): nothing to stream. Confirm pack-objects succeeded
	// BEFORE writing anything (fail-closed: a pack-objects error writes no
	// response — no shallow preamble, no NAK).
	if n == 0 {
		if werr := packWait(); werr != nil {
			return fmt.Errorf("gitproto: pack-objects: %w", werr)
		}
	}

	// Shallow preamble: for a `deepen` fetch, emit the `shallow <sha>` /
	// `unshallow <sha>` boundary lines followed by a flush-pkt BEFORE the NAK
	// (matching real git's v0 stateless framing). Emitted after the head-read
	// (and, for the empty-pack case, after pack-objects success) so a
	// pack-objects failure writes nothing. An empty shallowLines slice (plain
	// fetch) skips this entirely — the response stays byte-identical to the
	// pre-shallow behavior.
	e := pktline.NewEncoder(w)
	for _, line := range shallowLines {
		if err := e.EncodeString(line + "\n"); err != nil {
			_ = packWait()
			return fmt.Errorf("gitproto: encode shallow line: %w", err)
		}
	}
	if len(shallowLines) > 0 {
		if err := e.Flush(); err != nil {
			_ = packWait()
			return fmt.Errorf("gitproto: flush shallow section: %w", err)
		}
	}

	// Empty pack: NAK + sideband flush only (or NAK only for raw).
	if n == 0 {
		if err := e.EncodeString("NAK\n"); err != nil {
			return fmt.Errorf("gitproto: encode NAK: %w", err)
		}
		if uploadPackSidebandType(caps) != noSideband {
			if _, err := w.Write([]byte("0000")); err != nil {
				return fmt.Errorf("gitproto: flush sideband (empty): %w", err)
			}
		}
		return nil
	}

	// n > 0: commit to streaming. Write the NAK, then stream the head chunk and
	// the remainder through the muxer (or raw). The muxer splits each Write into
	// MaxPackedSize64k (or MaxPackedSize) frames internally, so memory stays
	// bounded by io.Copy's 32 KiB buffer + one muxer frame.
	if err := e.EncodeString("NAK\n"); err != nil {
		return fmt.Errorf("gitproto: encode NAK: %w", err)
	}
	switch uploadPackSidebandType(caps) {
	case sideband.Sideband64k:
		m := sideband.NewMuxer(sideband.Sideband64k, w)
		if _, err := m.Write(head[:n]); err != nil {
			_ = packWait()
			return fmt.Errorf("gitproto: mux packfile head (64k): %w", err)
		}
		if _, err := io.Copy(m, pack); err != nil {
			_ = packWait()
			return fmt.Errorf("gitproto: stream packfile (64k): %w", err)
		}
		// Fail-closed: check the producer's exit error BEFORE the final flush.
		// On mid-stream pack-objects failure, return WITHOUT writing the
		// flush-pkt so the agent sees a truncated, incomplete packfile.
		if werr := packWait(); werr != nil {
			return fmt.Errorf("gitproto: pack-objects failed mid-stream: %w", werr)
		}
		if _, err := w.Write([]byte("0000")); err != nil {
			return fmt.Errorf("gitproto: flush sideband (64k): %w", err)
		}
	case sideband.Sideband:
		m := sideband.NewMuxer(sideband.Sideband, w)
		if _, err := m.Write(head[:n]); err != nil {
			_ = packWait()
			return fmt.Errorf("gitproto: mux packfile head: %w", err)
		}
		if _, err := io.Copy(m, pack); err != nil {
			_ = packWait()
			return fmt.Errorf("gitproto: stream packfile: %w", err)
		}
		if werr := packWait(); werr != nil {
			return fmt.Errorf("gitproto: pack-objects failed mid-stream: %w", werr)
		}
		if _, err := w.Write([]byte("0000")); err != nil {
			return fmt.Errorf("gitproto: flush sideband: %w", err)
		}
	default:
		// No sideband negotiated: write the packfile raw after the NAK pkt-line.
		if _, err := w.Write(head[:n]); err != nil {
			_ = packWait()
			return fmt.Errorf("gitproto: write packfile head: %w", err)
		}
		if _, err := io.Copy(w, pack); err != nil {
			_ = packWait()
			return fmt.Errorf("gitproto: stream packfile: %w", err)
		}
		if werr := packWait(); werr != nil {
			return fmt.Errorf("gitproto: pack-objects failed mid-stream: %w", werr)
		}
	}
	return nil
}

// writeUploadPackErr writes a single v0 upload-pack `ERR <reason>\n` pkt-line to
// w. v0 upload-pack lets the server send an ERR pkt-line at any point to abort
// the negotiation with an error the git client surfaces; the on-demand
// blob-denial path uses it to refuse a denied on-demand blob fetch with a
// structured reason instead of a silent empty pack (fail-closed: the agent
// gets a clear error, not an uninspected blob and not a partial packfile).
//
// The encoded form is a normal data pkt-line whose payload is exactly
// "ERR <reason>\n" (the trailing newline is part of the payload, matching git's
// upload-pack ERR convention). The reason MUST be generic and fail-closed: no
// upstream credentials, no secret content, no internal OID-path details beyond
// what is needed to tell the agent the fetch was denied by policy. Returns the
// underlying encode error if w fails; the caller is expected to also fail
// closed if the write itself fails.
func writeUploadPackErr(w io.Writer, reason string) error {
	e := pktline.NewEncoder(w)
	return e.EncodeString("ERR " + reason + "\n")
}

// WriteUploadPackErr writes a single v0 upload-pack `ERR <reason>\n` pkt-line to
// w. It is the exported form of writeUploadPackErr, reused by the SSH frontend
// to abort a fetch with a structured error when the ref advertisement fetch,
// parse, or emit fails (fail-closed: the agent gets a clear error and the
// session does NOT proceed to negotiation, so no unprotected objects are
// served). The reason MUST be generic and fail-closed (no upstream creds, no
// secret content).
func WriteUploadPackErr(w io.Writer, reason string) error {
	return writeUploadPackErr(w, reason)
}

// onDemandBlobDenyReason classifies the want OIDs by git object type and, for
// each BLOB want (an on-demand blob fetch), resolves the OID back to its
// path(s) via oidpath.Resolve and checks the read deny matcher. It returns
// (reason, true) when the fetch MUST be refused with an ERR pkt-line:
//
//   - ANY on-demand blob whose resolved path matches the deny matcher (a blob
//     at multiple paths is denied if ANY path is denied);
//   - ANY on-demand blob whose OID does not resolve to a path (zero paths) —
//     fail-closed: the proxy cannot prove an unresolvable blob is not denied;
//   - ANY on-demand blob whose Resolve call errors — fail-closed.
//
// A request mixing commit/tag/tree wants with a denied blob want is refused
// whole (the first denied blob want short-circuits). Commit/tag/tree wants and
// allowed blob wants do not deny; the caller then runs the existing Task 9
// withholding path, which serves allowed blobs and withholds denied-path blobs
// from the full-clone reachable set.
//
// A nil/empty wants list denies nothing (the existing path handles it). A nil
// matcher (read protection off at the path level) denies nothing — but this
// function is only reached when readDenyMatcher is non-nil (proxy.go routes
// nil-matcher fetches through passthrough), so the nil branch is defensive.
//
// The reason is generic and fail-closed: it names the OID the agent sent and
// the policy, and reveals NO upstream credentials, NO secret content, and NO
// internal path details (a uniform reason for denied-by-path, unresolvable, and
// resolve-error avoids leaking which paths exist).
func onDemandBlobDenyReason(ctx context.Context, mirror *gitx.Mirror, wants []string, readDenyMatcher *pathmatch.Matcher, repo string) (reason string, deniedOID string, deny bool) {
	if len(wants) == 0 || readDenyMatcher == nil {
		return "", "", false
	}
	types, err := mirror.ObjectTypes(ctx, wants)
	if err != nil {
		// Fail-closed: if the proxy cannot classify the wants, it cannot safely
		// serve any of them. Report a generic reason for the first want.
		// (This path is unusual — the existing withholding path would also
		// fail — but we refuse with a structured ERR rather than a bare 500.)
		oid := firstNonEmpty(wants)
		return fmt.Sprintf("access to object %s denied by read policy", oid), oid, true
	}
	for _, oid := range wants {
		if types[oid] != "blob" {
			continue // commit/tag/tree want → full-clone path (existing withholding)
		}
		// On-demand blob want: resolve its path(s) and check the deny matcher.
		paths, rerr := gitx.Resolve(ctx, mirror, oid)
		if rerr != nil {
			reason := fmt.Sprintf("access to object %s denied by read policy", oid)
			log.Printf("gitproto: upload-pack enforce: on-demand resolve error for blob %s in repo %q: %v (denying fail-closed)", oid, repo, rerr)
			return reason, oid, true
		}
		if len(paths) == 0 {
			// Fail-closed: an unresolvable blob (no tree references it) cannot
			// be proven to be non-denied. Deny with a uniform reason.
			log.Printf("gitproto: upload-pack enforce: on-demand blob %s in repo %q resolves to no path (denying fail-closed)", oid, repo)
			return fmt.Sprintf("access to object %s denied by read policy", oid), oid, true
		}
		for _, p := range paths {
			if readDenyMatcher.Match(p) {
				log.Printf("gitproto: upload-pack enforce: on-demand blob %s in repo %q denied by path %q (paths=%v)", oid, repo, p, paths)
				return fmt.Sprintf("access to object %s denied by read policy", oid), oid, true
			}
		}
		// Allowed blob want: fall through to the existing withholding path,
		// which serves it.
	}
	return "", "", false
}

// firstNonEmpty returns the first non-empty string in s, or "" if all are
// empty. Used to pick a representative OID for a generic deny reason.
func firstNonEmpty(s []string) string {
	for _, v := range s {
		if v != "" {
			return v
		}
	}
	return ""
}

// noSideband is the sentinel sideband type meaning the agent did not negotiate
// side-band-64k or side-band (compare against uploadPackSidebandType's result).
const noSideband = sideband.Type(-1)

// uploadPackSidebandType reports which sideband capability (if any) the agent
// advertised in its upload-pack request capabilities. Returns sideband.Sideband64k
// for "side-band-64k", sideband.Sideband for "side-band", and an invalid value
// (defaulted to plain) when neither is present.
func uploadPackSidebandType(caps []string) sideband.Type {
	for _, cap := range caps {
		if cap == "side-band-64k" || strings.HasPrefix(cap, "side-band-64k=") {
			return sideband.Sideband64k
		}
		if cap == "side-band" || strings.HasPrefix(cap, "side-band=") {
			return sideband.Sideband
		}
	}
	return sideband.Type(-1) // sentinel: no sideband
}

// errDeepenSinceUnsupported is the actionable, fail-closed reason emitted when a
// read-protected fetch requests `deepen-since` (--shallow-since): the date-based
// boundary semantics are not implemented on the enforce path. Generic: no
// credentials, no secret content, no paths/OIDs — names the unsupported flag so
// the agent can retry without it.
const errDeepenSinceUnsupported = "shallow-since fetches (--shallow-since / deepen-since) are not yet supported through the read-protected path; retry without --shallow-since"

// shallowPlan is the output of planShallowFetch: the shallow packfile's object
// set (replacing WantedObjects for a `deepen` fetch, with the SAME deny
// withholding applied downstream) and the `shallow <sha>` / `unshallow <sha>`
// preamble lines emitted before the NAK. shallowLines payloads carry no trailing
// newline — the pkt-line encoder adds it.
type shallowPlan struct {
	objects      []gitx.ObjectPath
	shallowLines []string
}

// planShallowFetch computes the shallow object set and the shallow/unshallow
// boundary lines for a `deepen N` or `deepen-not <sha>` fetch, using the unified
// "excluded set E" mechanism:
//
//   - E = the commits the shallow cut removes.
//   - `deepen N`: E = commits at generation ≥ N from the wants (BFS over the
//     full ancestry — no `--not`, so a have at a low generation correctly
//     suppresses a boundary; verified against real-git captures).
//   - `deepen-not <sha>`: E = the ancestry of the exclude refs.
//   - objects = `git rev-list --objects <wants> --not <E> --not <haves>`
//     (mirror.ShallowObjects): the packfile's object set within the cut,
//     excluding the boundary commits' objects and the client's haves. Denied
//     blobs are withheld from this set by the EXISTING loop in
//     ServeUploadPackEnforced (unchanged).
//   - shallow boundaries = included commits (in the graph, NOT in E) with at
//     least one parent in E. Haves do NOT create boundaries: a have at a low
//     generation is included (suppresses the boundary); a have at/after the cut
//     is in E (excluded). This matches the V3 capture (want B, have A, deepen 1
//     → `shallow B`; with deepen 5, B is NOT shallow because A at gen 1 < 5).
//   - unshallow = client `req.Shallows` now fully included (in the graph, not in
//     E, all parents present and not in E) — the new walk extended past the
//     client's old cut.
//
// `deepen-since` is handled by the caller (ServeUploadPackEnforced) before this
// runs. A request carrying only client `shallow` lines (no new cut) takes the
// plain path and never reaches here.
//
// Memory note (v1): the `deepen N` BFS loads all commits reachable from wants
// (no `--not`), comparable to WantedObjects' object traversal. Acceptable for
// v1; documented. Fail-closed: any git error returns an error and the caller
// denies the fetch (no unprotected pack).
func planShallowFetch(ctx context.Context, mirror *gitx.Mirror, req *UploadPackRequest, repo string) (*shallowPlan, error) {
	cps, err := mirror.CommitParents(ctx, req.Wants)
	if err != nil {
		return nil, fmt.Errorf("shallow commit graph: %w", err)
	}
	parentOf := make(map[string][]string, len(cps))
	present := make(map[string]bool, len(cps))
	for _, cp := range cps {
		parentOf[cp.OID] = cp.Parents
		present[cp.OID] = true
	}

	// E = the excluded (shallow-cut) commit set.
	var eSet map[string]bool
	switch {
	case req.Deepen > 0:
		eSet = depthExcludedSet(req.Wants, parentOf, req.Deepen)
	default: // len(req.DeepenNot) > 0 (caller only reaches here for Deepen or DeepenNot)
		anc, aerr := mirror.Ancestors(ctx, req.DeepenNot)
		if aerr != nil {
			return nil, fmt.Errorf("shallow deepen-not: %w", aerr)
		}
		eSet = make(map[string]bool, len(anc))
		for _, o := range anc {
			eSet[o] = true
		}
	}

	// Shallow pack object set: objects reachable from wants, not from E, not
	// from haves. Denied blobs are withheld downstream by the existing loop.
	excludes := make([]string, 0, len(eSet))
	for o := range eSet {
		excludes = append(excludes, o)
	}
	objs, oerr := mirror.ShallowObjects(ctx, req.Wants, excludes, req.Haves)
	if oerr != nil {
		return nil, fmt.Errorf("shallow objects: %w", oerr)
	}

	clientShallows := make(map[string]bool, len(req.Shallows))
	for _, s := range req.Shallows {
		clientShallows[s] = true
	}

	// Shallow boundaries: included commits (in the graph, not in E) with at
	// least one parent in E. Iterate the graph in rev-list order (stable, and
	// already deduplicated by OID).
	var shallowLines []string
	emitted := make(map[string]bool)
	for _, cp := range cps {
		if eSet[cp.OID] {
			continue // excluded by the cut — not an included commit
		}
		boundary := false
		for _, p := range cp.Parents {
			if eSet[p] {
				boundary = true
				break
			}
		}
		if boundary && !clientShallows[cp.OID] && !emitted[cp.OID] {
			shallowLines = append(shallowLines, "shallow "+cp.OID)
			emitted[cp.OID] = true
		}
	}

	// Unshallow: client shallows now fully included (reachable, not in E, and
	// every parent reachable and not in E). A root commit that was a client
	// shallow and is now included has no parents and is resolved → unshallow.
	for _, s := range req.Shallows {
		if !present[s] || eSet[s] || emitted[s] {
			continue // not reachable, still cut, or already emitted as a boundary
		}
		resolved := true
		for _, p := range parentOf[s] {
			if eSet[p] || !present[p] {
				resolved = false
				break
			}
		}
		if resolved {
			shallowLines = append(shallowLines, "unshallow "+s)
			emitted[s] = true
		}
	}

	if len(shallowLines) > 0 {
		log.Printf("gitproto: upload-pack enforce: shallow fetch for repo %q: %d shallow line(s)", repo, len(shallowLines))
	}
	return &shallowPlan{objects: objs, shallowLines: shallowLines}, nil
}

// depthExcludedSet computes the `deepen N` excluded set E = commits at
// generation ≥ N from the wants. Generation is the BFS distance (number of
// parent edges) from the nearest want, so a want is gen 0, its parents gen 1,
// etc. BFS first-visit is the shortest path on the unweighted commit DAG, so the
// first assigned generation is the minimum (no relax step needed). Commits not
// reachable from any want are absent from E (and from the graph) — unreachable
// objects are not the server's concern. wants not in parentOf (bogus want)
// surface as an error upstream (CommitParents errors on unknown revisions).
func depthExcludedSet(wants []string, parentOf map[string][]string, depth int) map[string]bool {
	gen := make(map[string]int, len(parentOf))
	queue := make([]string, 0, len(wants))
	for _, w := range wants {
		if _, ok := gen[w]; !ok {
			gen[w] = 0
			queue = append(queue, w)
		}
	}
	for head := 0; head < len(queue); head++ {
		c := queue[head]
		g := gen[c]
		for _, p := range parentOf[c] {
			if _, ok := gen[p]; !ok {
				gen[p] = g + 1
				queue = append(queue, p)
			}
		}
	}
	eSet := make(map[string]bool, len(parentOf))
	for o, g := range gen {
		if g >= depth {
			eSet[o] = true
		}
	}
	return eSet
}
