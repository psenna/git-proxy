package gitproto

import (
	"fmt"
	"io"
	"strings"

	"github.com/psenna/git-proxy/internal/gitproto/pktline"
)

// EmitRefAdvertisementRaw emits a v0 ref advertisement WITHOUT the smart-HTTP
// "# service=" preamble and leading flush — the form the SSH git protocol
// carries (refs + caps on the first ref, terminating flush). It is the raw
// counterpart of EmitRefAdvertisementV0 (which is smart-HTTP).
//
// Wire format:
//
//	<hash> <ref>\0<caps>\n    (first ref, capabilities after NUL)
//	<hash> <ref>\n            (subsequent refs)
//	0000                      (flush)
//
// When adv has no refs (empty repo), the standard `<zerohash> capabilities^{}\0<caps>`
// pseudo-ref line is emitted so the client still sees the capability list. Caps
// are merged from adv.Caps with extraCaps (de-duplicated, `version 2` stripped
// so the client falls back to v0 — the SSH path is v0-only in v1, consistent with
// the read-protected HTTP path).
func EmitRefAdvertisementRaw(w io.Writer, adv *RefAdvertisement, extraCaps []string) error {
	e := pktline.NewEncoder(w)
	caps := buildV0Caps(adv.Caps, extraCaps)
	if len(adv.Refs) == 0 {
		// Empty-repo pseudo-ref: the capabilities are advertised on a line
		// pointing the zero OID at the magic name "capabilities^{}".
		line := strings.Repeat("0", 40) + " capabilities^{}\x00" + strings.Join(caps, " ") + "\n"
		if err := e.EncodeString(line); err != nil {
			return fmt.Errorf("gitproto: emit raw ref advertisement: empty cap line: %w", err)
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
				return fmt.Errorf("gitproto: emit raw ref advertisement: ref %s: %w", ref.Name, err)
			}
		}
	}
	if err := e.Flush(); err != nil {
		return fmt.Errorf("gitproto: emit raw ref advertisement: terminating flush: %w", err)
	}
	return nil
}