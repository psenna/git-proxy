package gitproto

import (
	"fmt"
	"io"
	"strings"

	"github.com/psenna/git-proxy/internal/gitproto/pktline"
)

// EmitRefAdvertisementV0 writes a smart-HTTP v0 ref advertisement to w for adv,
// appending extraCaps to the capability list on the first ref line and stripping
// any `version 2` capability so the client falls back to v0 for the subsequent
// upload-pack request. Used by the read-protected fetch path: the proxy fetches
// the upstream advertisement, parses it, and re-emits it as v0 + filter cap so
// the client may request a partial clone (`--filter=blob:none`) and negotiates
// v0 (the read-protected upload-pack response is v0-only in v1).
//
// Wire format:
//
//	# service=<service>\n    (pkt-line)
//	0000                      (flush)
//	<hash> <ref>\0<caps>\n    (first ref, capabilities after NUL)
//	<hash> <ref>\n            (subsequent refs)
//	0000                      (flush)
//
// Refs are re-emitted verbatim (v1 does not hide refs the agent cannot read —
// noted as a follow-up; only blobs are withheld, not ref existence). When adv
// has no refs (empty repo), the standard `<zerohash> capabilities^{}\0<caps>`
// pseudo-ref line is emitted so the client still sees the capability list.
func EmitRefAdvertisementV0(w io.Writer, adv *RefAdvertisement, extraCaps []string) error {
	e := pktline.NewEncoder(w)
	if err := e.EncodeString("# service=" + adv.Service + "\n"); err != nil {
		return fmt.Errorf("gitproto: emit ref advertisement: service: %w", err)
	}
	if err := e.Flush(); err != nil {
		return fmt.Errorf("gitproto: emit ref advertisement: flush: %w", err)
	}
	caps := buildV0Caps(adv.Caps, extraCaps)
	if len(adv.Refs) == 0 {
		// Empty-repo pseudo-ref: the capabilities are advertised on a line
		// pointing the zero OID at the magic name "capabilities^{}".
		line := strings.Repeat("0", 40) + " capabilities^{}\x00" + strings.Join(caps, " ") + "\n"
		if err := e.EncodeString(line); err != nil {
			return fmt.Errorf("gitproto: emit ref advertisement: empty cap line: %w", err)
		}
	} else {
		for i, ref := range adv.Refs {
			var line string
			if i == 0 {
				line = ref.Hash + " " + ref.Name + "\x00" + strings.Join(caps, " ") + "\n"
			} else {
				line = ref.Hash + " " + ref.Name + "\n"
			}
			if err := e.EncodeString(line); err != nil {
				return fmt.Errorf("gitproto: emit ref advertisement: ref %s: %w", ref.Name, err)
			}
		}
	}
	if err := e.Flush(); err != nil {
		return fmt.Errorf("gitproto: emit ref advertisement: terminating flush: %w", err)
	}
	return nil
}

// buildV0Caps merges the upstream capabilities with extraCaps, stripping any
// `version 2` capability (so the client falls back to v0) and de-duplicating so
// an extra cap already present is not repeated. The order preserves the
// upstream order with extra caps appended.
func buildV0Caps(upstream, extra []string) []string {
	seen := make(map[string]bool, len(upstream)+len(extra))
	merged := make([]string, 0, len(upstream)+len(extra))
	for _, c := range upstream {
		if c == "version 2" {
			continue
		}
		if seen[c] {
			continue
		}
		seen[c] = true
		merged = append(merged, c)
	}
	for _, c := range extra {
		if seen[c] {
			continue
		}
		seen[c] = true
		merged = append(merged, c)
	}
	return merged
}