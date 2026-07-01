package gitproto

import (
	"context"
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
	// the "pass --thin when the client requested it" guidance.
	pack, err := mirror.PackObjects(ctx, allowed, false)
	if err != nil {
		return fmt.Errorf("gitproto: upload-pack enforce: pack-objects: %w", err)
	}

	return writeV0UploadPackResponse(w, pack, req.Caps)
}

// writeV0UploadPackResponse writes a v0 upload-pack response containing pack
// to w: a NAK pkt-line, then the packfile muxed over side-band-64k (or
// side-band) channel 1 with a terminating flush-pkt when the client requested a
// sideband capability, or the packfile raw after the NAK pkt-line when no
// sideband was negotiated. A real git clone always requests side-band-64k, so
// the muxed path is the validated one; the raw path covers non-sideband clients.
func writeV0UploadPackResponse(w io.Writer, pack []byte, caps []string) error {
	e := pktline.NewEncoder(w)
	if err := e.EncodeString("NAK\n"); err != nil {
		return fmt.Errorf("gitproto: encode NAK: %w", err)
	}
	switch uploadPackSidebandType(caps) {
	case sideband.Sideband64k:
		m := sideband.NewMuxer(sideband.Sideband64k, w)
		if _, err := m.Write(pack); err != nil {
			return fmt.Errorf("gitproto: mux packfile (64k): %w", err)
		}
		if _, err := w.Write([]byte("0000")); err != nil {
			return fmt.Errorf("gitproto: flush sideband (64k): %w", err)
		}
	case sideband.Sideband:
		m := sideband.NewMuxer(sideband.Sideband, w)
		if _, err := m.Write(pack); err != nil {
			return fmt.Errorf("gitproto: mux packfile: %w", err)
		}
		if _, err := w.Write([]byte("0000")); err != nil {
			return fmt.Errorf("gitproto: flush sideband: %w", err)
		}
	default:
		// No sideband negotiated: write the packfile raw after the NAK pkt-line.
		if _, err := w.Write(pack); err != nil {
			return fmt.Errorf("gitproto: write packfile: %w", err)
		}
	}
	return nil
}

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