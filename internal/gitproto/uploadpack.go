package gitproto

import (
	"fmt"
	"io"
	"strings"

	"github.com/psenna/git-proxy/internal/gitproto/pktline"
)

// AdvertisedRef is a single entry in a ref advertisement: a hash and the ref
// name it points at.
type AdvertisedRef struct {
	Hash string
	Name string
}

// RefAdvertisement is a parsed smart-HTTP info/refs response for either
// git-upload-pack or git-receive-pack. It carries the service name, the
// advertised refs, and the server's capabilities (declared on the first ref
// line after a NUL byte).
type RefAdvertisement struct {
	// Service is "git-upload-pack" or "git-receive-pack".
	Service string
	// Refs is the advertised refs. The first is typically HEAD.
	Refs []AdvertisedRef
	// Caps is the capability list from the first ref line (space-separated,
	// each entry is "name" or "name=value").
	Caps []string
}

// ParseRefAdvertisement parses a smart-HTTP info/refs pkt-line stream. It reads
// the service banner, a flush, the ref list (capabilities attached to the first
// ref via a NUL byte), and a terminating flush.
func ParseRefAdvertisement(r io.Reader) (*RefAdvertisement, error) {
	s := pktline.NewScanner(r)
	adv := &RefAdvertisement{}

	// First pkt-line: "# service=<name>\n".
	if !s.Scan() {
		return nil, fmt.Errorf("gitproto: ref advertisement: empty stream")
	}
	if s.Marker() != pktline.Data {
		return nil, fmt.Errorf("gitproto: ref advertisement: expected service line, got %v", s.Marker())
	}
	service, ok := parseServiceLine(s.Bytes())
	if !ok {
		return nil, fmt.Errorf("gitproto: ref advertisement: malformed service line %q", s.Bytes())
	}
	adv.Service = service

	// Flush after the service banner.
	if !s.Scan() || s.Marker() != pktline.Flush {
		return nil, fmt.Errorf("gitproto: ref advertisement: expected flush after service banner")
	}

	// Ref lines until the terminating flush.
	for s.Scan() {
		if s.Marker() == pktline.Flush {
			break
		}
		if s.Marker() != pktline.Data {
			continue // tolerate delim/response-end from v2 servers
		}
		ref, caps, ok := parseRefLine(s.Bytes())
		if !ok {
			return nil, fmt.Errorf("gitproto: ref advertisement: malformed ref line %q", s.Bytes())
		}
		adv.Refs = append(adv.Refs, ref)
		if caps != nil {
			adv.Caps = caps
		}
	}
	if err := s.Err(); err != nil {
		return nil, fmt.Errorf("gitproto: ref advertisement: %w", err)
	}
	return adv, nil
}

// UploadPackRequest is a parsed git-upload-pack request body: the want/have
// negotiation. The first want line may carry capabilities (space-separated).
type UploadPackRequest struct {
	Wants []string
	Haves []string
	Done  bool
	Caps  []string
}

// ParseUploadPackRequest parses a git-upload-pack request pkt-line stream. It
// collects want/have lines, the done terminator, and the capabilities attached
// to the first want.
func ParseUploadPackRequest(r io.Reader) (*UploadPackRequest, error) {
	s := pktline.NewScanner(r)
	req := &UploadPackRequest{}
	for s.Scan() {
		switch s.Marker() {
		case pktline.Flush:
			// Section separators between wants/haves; not significant here.
			continue
		case pktline.Data:
			line := strings.TrimRight(string(s.Bytes()), "\n")
			switch {
			case strings.HasPrefix(line, "want "):
				rest := strings.TrimPrefix(line, "want ")
				sha, caps := splitWant(rest)
				req.Wants = append(req.Wants, sha)
				if caps != nil && req.Caps == nil {
					req.Caps = caps
				}
			case strings.HasPrefix(line, "have "):
				req.Haves = append(req.Haves, strings.TrimSpace(strings.TrimPrefix(line, "have ")))
			case line == "done":
				req.Done = true
			}
		}
	}
	if err := s.Err(); err != nil {
		return nil, fmt.Errorf("gitproto: upload-pack request: %w", err)
	}
	if len(req.Wants) == 0 {
		return nil, fmt.Errorf("gitproto: upload-pack request: no wants")
	}
	return req, nil
}

// parseServiceLine parses "# service=<name>\n" and returns the service name.
func parseServiceLine(b []byte) (string, bool) {
	const prefix = "# service="
	s := strings.TrimRight(string(b), "\n")
	if !strings.HasPrefix(s, prefix) {
		return "", false
	}
	service := strings.TrimSpace(strings.TrimPrefix(s, prefix))
	if service == "" {
		return "", false
	}
	return service, true
}

// parseRefLine parses a ref advertisement line. The first ref line carries
// capabilities after a NUL byte: "<hash> <name>\0<caps>\n". Subsequent lines
// are "<hash> <name>\n". caps is non-nil only when capabilities were present.
func parseRefLine(b []byte) (ref AdvertisedRef, caps []string, ok bool) {
	line := b
	var capPart []byte
	if i := bytesIndexNul(line); i >= 0 {
		capPart = line[i+1:]
		line = line[:i]
	}
	trimmed := strings.TrimRight(string(line), "\n")
	sp := strings.IndexByte(trimmed, ' ')
	if sp < 0 {
		return AdvertisedRef{}, nil, false
	}
	ref = AdvertisedRef{Hash: trimmed[:sp], Name: trimmed[sp+1:]}
	if capPart != nil {
		caps = splitCaps(strings.TrimRight(string(capPart), "\n"))
	}
	return ref, caps, true
}

// splitWant splits a "want" payload remainder ("<sha> [caps...]") into the SHA
// and the capability list. caps is nil when no capabilities are present.
func splitWant(rest string) (sha string, caps []string) {
	rest = strings.TrimRight(rest, "\n")
	sp := strings.IndexByte(rest, ' ')
	if sp < 0 {
		return strings.TrimSpace(rest), nil
	}
	sha = rest[:sp]
	capStr := strings.TrimSpace(rest[sp+1:])
	if capStr == "" {
		return sha, nil
	}
	return sha, splitCaps(capStr)
}

// splitCaps splits a space-separated capability list, keeping name=value
// entries intact.
func splitCaps(s string) []string {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	return strings.Fields(s)
}

// bytesIndexNul returns the index of the first NUL byte in b, or -1.
func bytesIndexNul(b []byte) int {
	for i, c := range b {
		if c == 0 {
			return i
		}
	}
	return -1
}