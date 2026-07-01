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

// ServeUploadPackEnforced assembles a filtered packfile for a read-protected
// fetch and writes a v0 upload-pack response to w. It withholds blobs whose path
// matches readDenyMatcher, keeping commits and trees intact, so the agent sees
// the tree entry pointing at a now-missing blob (the on-demand fetch for that
// blob is denied by Task 10). The proxy — not the client — assembles the
// packfile, so denial is enforced regardless of client cooperation.
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
// This is a PROXY-LEVEL per-path filter (pathmatch), NOT the engine's
// all-or-nothing EvaluateFetch; it is not routed through the policy engine.
//
// Protocol scope: v0 only for the read-protected fetch path (v1 decision). The
// frontend re-emits the upstream ref advertisement as v0 (stripping version 2)
// so the client negotiates v0 here. v2 fetch support is a documented v1
// follow-up.
func ServeUploadPackEnforced(ctx context.Context, w io.Writer, req *UploadPackRequest,
	mirror *gitx.Mirror, readDenyMatcher *pathmatch.Matcher, repo string) error {

	if err := mirror.Refresh(ctx); err != nil {
		return fmt.Errorf("gitproto: upload-pack enforce: refresh mirror: %w", err)
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
	if reason, deny := onDemandBlobDenyReason(ctx, mirror, req.Wants, readDenyMatcher, repo); deny {
		log.Printf("gitproto: upload-pack enforce: refusing on-demand fetch for repo %q: %s", repo, reason)
		return writeUploadPackErr(w, reason)
	}

	objs, err := mirror.WantedObjects(ctx, req.Wants, req.Haves)
	if err != nil {
		return fmt.Errorf("gitproto: upload-pack enforce: wanted objects: %w", err)
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
		return fmt.Errorf("gitproto: upload-pack enforce: object types: %w", err)
	}

	// Build the allowed OID list: keep commits and trees unconditionally; for
	// blobs, withhold if ANY resolving path matches the deny matcher. A nil
	// matcher matches nothing (read protection off at the path level).
	allowed := make([]string, 0, len(oidOrder))
	withheld := 0
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
		return fmt.Errorf("gitproto: upload-pack enforce: pack-objects: %w", err)
	}

	return writeV0UploadPackResponse(w, packReader, packWait, req.Caps)
}

// writeV0UploadPackResponse writes a v0 upload-pack response to w: a NAK
// pkt-line, then the packfile (read from pack and produced by pack-objects)
// muxed over side-band-64k (or side-band) channel 1 with a terminating
// flush-pkt when the client requested a sideband capability, or the packfile
// raw after the NAK pkt-line when no sideband was negotiated. A real git clone
// always requests side-band-64k, so the muxed path is the validated one; the
// raw path covers non-sideband clients.
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
//  2. Once a non-empty head chunk is in hand, commits to streaming (writes the
//     NAK + head + remainder). If pack-objects then fails MID-STREAM, the wait
//     error is surfaced and the sideband flush-pkt ("0000") is NOT written, so
//     the agent receives a truncated, trailer-less packfile that does not look
//     complete rather than a valid-looking pack — fail-closed in the sense that
//     no valid complete pack is served. The returned error lets the caller log
//     the failure.
//
// packWait MUST be called exactly once after the reader is drained or abandoned;
// it closes the reader (unblocking the producer goroutine) and returns the
// pack-objects exit error.
func writeV0UploadPackResponse(w io.Writer, pack io.Reader, packWait func() error, caps []string) error {
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

	// Empty pack (n == 0): nothing to stream. Check packWait for a hidden
	// error, then emit NAK + sideband flush only (or NAK only for raw).
	if n == 0 {
		if werr := packWait(); werr != nil {
			return fmt.Errorf("gitproto: pack-objects: %w", werr)
		}
		e := pktline.NewEncoder(w)
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
	e := pktline.NewEncoder(w)
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
func onDemandBlobDenyReason(ctx context.Context, mirror *gitx.Mirror, wants []string, readDenyMatcher *pathmatch.Matcher, repo string) (reason string, deny bool) {
	if len(wants) == 0 || readDenyMatcher == nil {
		return "", false
	}
	types, err := mirror.ObjectTypes(ctx, wants)
	if err != nil {
		// Fail-closed: if the proxy cannot classify the wants, it cannot safely
		// serve any of them. Report a generic reason for the first want.
		// (This path is unusual — the existing withholding path would also
		// fail — but we refuse with a structured ERR rather than a bare 500.)
		return fmt.Sprintf("access to object %s denied by read policy", firstNonEmpty(wants)), true
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
			return reason, true
		}
		if len(paths) == 0 {
			// Fail-closed: an unresolvable blob (no tree references it) cannot
			// be proven to be non-denied. Deny with a uniform reason.
			log.Printf("gitproto: upload-pack enforce: on-demand blob %s in repo %q resolves to no path (denying fail-closed)", oid, repo)
			return fmt.Sprintf("access to object %s denied by read policy", oid), true
		}
		for _, p := range paths {
			if readDenyMatcher.Match(p) {
				log.Printf("gitproto: upload-pack enforce: on-demand blob %s in repo %q denied by path %q (paths=%v)", oid, repo, p, paths)
				return fmt.Sprintf("access to object %s denied by read policy", oid), true
			}
		}
		// Allowed blob want: fall through to the existing withholding path,
		// which serves it.
	}
	return "", false
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