package sshfront

import (
	"bytes"
	"fmt"
	"io"
	"strings"

	"github.com/psenna/git-proxy/internal/gitproto"
	"github.com/psenna/git-proxy/internal/gitproto/pktline"
)

// readUploadPackRequest reads a v0 git-upload-pack request from r (the SSH
// channel's stdin) until the terminating `done` pkt-line + flush, and returns
// the raw request bytes. This frames the SSH channel's duplex stream into the
// bounded request body the HTTP-shaped *gitproto.Proxy expects (Proxy.UploadPack
// does io.ReadAll(body), which on a live SSH channel would block forever — the
// git client does NOT send EOF after `done`; it keeps the channel open for the
// response). The framed bytes are forwarded verbatim to the upstream by the
// proxy, exactly as the HTTP frontend forwards a POST body.
//
// v0 upload-pack request shape (the terminator is `done` followed by a flush):
//
//	want <sha> <caps>\n
//	want <sha>\n
//	...
//	0000                    (flush between wants and haves)
//	have <sha>\n
//	...
//	done\n
//	0000                    (terminating flush)
//
// A clone (no haves) sends wants, flush, done, flush. Multi-round negotiation
// (haves with server ACK/NAK between rounds) is NOT supported by this single-
// shot framing and is out of scope for v1-over-SSH (v0-only, single-round fetch
// — consistent with the v0-only-over-SSH decision); documented as a deviation.
// The request is small (refs + caps + haves), so buffering is fine.
//
// DoS hardening: the buffer is capped at gitproto.MaxUploadPackRequestBytes
// (1 MiB). A real upload-pack request is tiny (wants/haves/caps — the packfile
// is in the *response*, never the request), so 1 MiB is a generous ceiling. A
// rogue authorized agent that streams `want` lines without `done` would
// otherwise accumulate into an unbounded bytes.Buffer (OOM); the cap fails
// closed with an error, and runGitSession writes a structured ERR + exits 1
// (the existing fail-closed path — no negotiation proceeds).
func readUploadPackRequest(r io.Reader) ([]byte, error) {
	s := pktline.NewScanner(r)
	var buf bytes.Buffer
	for s.Scan() {
		buf.Write(s.Raw())
		// Fail-closed size cap: an upload-pack request exceeding
		// MaxUploadPackRequestBytes is a rogue/stream-truncated request (no
		// `done` reached). Deny rather than accumulate unboundedly.
		if buf.Len() > int(gitproto.MaxUploadPackRequestBytes) {
			return nil, fmt.Errorf("sshfront: upload-pack request exceeds %d bytes (no done)", gitproto.MaxUploadPackRequestBytes)
		}
		switch s.Marker() {
		case pktline.Data:
			// `done` is the LAST pkt-line of a v0 upload-pack request — git
			// does NOT send a trailing flush after it. The client then waits
			// for the server's NAK/packfile, so the next Scan would block.
			// Terminate at `done`.
			if strings.TrimRight(string(s.Bytes()), "\n") == "done" {
				return buf.Bytes(), nil
			}
		}
	}
	if err := s.Err(); err != nil {
		return nil, fmt.Errorf("sshfront: read upload-pack request: %w", err)
	}
	// Clean EOF without done+flush: a malformed/truncated request. Treat as
	// end of body (the proxy will parse and fail-closed on an incomplete request).
	return buf.Bytes(), nil
}