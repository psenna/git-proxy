package gitproto

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"strings"

	"github.com/psenna/git-proxy/internal/gitproto/pktline"
)

// RefUpdate is a single receive-pack command: "<old> <new> <ref>". The first
// command in a request also carries the agent's capabilities (after a NUL byte
// on the command line).
type RefUpdate struct {
	Old  string
	New  string
	Ref  string
	Caps []string // non-nil only on the first command
}

// ReceivePackRequest is a parsed git-receive-pack request body: the ref-update
// commands followed by an optional packfile.
type ReceivePackRequest struct {
	Commands []RefUpdate
	// PackfileOffset is the byte offset in the source stream where the packfile
	// begins (immediately after the flush terminating the command list). It is
	// -1 when no packfile follows the commands (e.g. a delete-only push).
	PackfileOffset int64
}

// ParseReceivePackRequest parses a git-receive-pack request pkt-line stream. It
// reads the command list (capabilities attached to the first command via a NUL
// byte), the terminating flush, and locates the packfile boundary that follows.
func ParseReceivePackRequest(r io.Reader) (*ReceivePackRequest, error) {
	br := bufio.NewReader(r)
	counter := &countingReader{r: br}
	s := pktline.NewScanner(counter)
	req := &ReceivePackRequest{PackfileOffset: -1}

	for s.Scan() {
		if s.Marker() == pktline.Flush {
			break
		}
		if s.Marker() != pktline.Data {
			continue
		}
		cmd, caps, ok := parseCommand(s.Bytes())
		if !ok {
			return nil, fmt.Errorf("gitproto: receive-pack: malformed command %q", s.Bytes())
		}
		if caps != nil && len(req.Commands) == 0 {
			cmd.Caps = caps
		}
		req.Commands = append(req.Commands, cmd)
	}
	if err := s.Err(); err != nil {
		return nil, fmt.Errorf("gitproto: receive-pack: %w", err)
	}

	if len(req.Commands) == 0 {
		return nil, fmt.Errorf("gitproto: receive-pack: no commands")
	}

	// After the terminating flush, a packfile may follow (raw bytes, not a
	// pkt-line). Peek to detect its boundary without consuming it.
	packStart := counter.n
	if peek, err := br.Peek(4); err == nil && len(peek) == 4 && bytes.Equal(peek, []byte("PACK")) {
		req.PackfileOffset = packStart
	}
	return req, nil
}

// parseCommand parses a receive-pack command line "<old> <new> <ref>\0<caps>"
// (first command) or "<old> <new> <ref>" (subsequent). caps is non-nil only when
// capabilities were present.
func parseCommand(b []byte) (cmd RefUpdate, caps []string, ok bool) {
	line := b
	var capPart []byte
	if i := bytesIndexNul(line); i >= 0 {
		capPart = line[i+1:]
		line = line[:i]
	}
	trimmed := strings.TrimRight(string(line), "\n")
	// Split into at most 3 fields: the ref name may contain spaces in pathological
	// cases, but git refs cannot, so a 3-way split is correct for the protocol.
	fields := strings.SplitN(trimmed, " ", 3)
	if len(fields) < 3 {
		return RefUpdate{}, nil, false
	}
	cmd = RefUpdate{Old: fields[0], New: fields[1], Ref: fields[2]}
	if capPart != nil {
		caps = splitCaps(strings.TrimRight(string(capPart), "\n"))
	}
	return cmd, caps, true
}

// countingReader wraps a reader and counts the bytes read, so the parser can
// report packfile byte offsets without buffering the whole stream.
type countingReader struct {
	r io.Reader
	n int64
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += int64(n)
	return n, err
}
