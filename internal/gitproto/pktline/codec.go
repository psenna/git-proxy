// Package pktline is a thin codec over the git pkt-line wire format. It leans
// on go-git's encoder for writing data and flush pkt-lines, and adds support
// for the protocol-v2 delimiter (0001) and response-end (0002) markers that
// go-git's stock scanner rejects. The Scanner also surfaces non-pkt-line
// sections (a packfile body following a flush) as a Raw marker so callers can
// switch to byte-exact copy mode when forwarding.
package pktline

import (
	"errors"
	"fmt"
	"io"

	gogit "github.com/go-git/go-git/v5/plumbing/format/pktline"
)

// Marker classifies a parsed pkt-line (or a raw section boundary).
type Marker int

const (
	// Data is a normal payload pkt-line.
	Data Marker = iota
	// Flush is the 0000 flush-pkt.
	Flush
	// Delim is the 0001 delimiter (protocol v2).
	Delim
	// ResponseEnd is the 0002 response-end marker (protocol v2).
	ResponseEnd
	// Raw marks a non-pkt-line section: the scanner read bytes that are not a
	// valid pkt-line prefix (typically a packfile body). The bytes read are
	// available via Pending; the caller should forward them and copy the rest
	// of the stream raw.
	Raw
)

// Limits reused from go-git so callers can validate without importing it.
const (
	// MaxPayloadSize is the maximum payload size of a pkt-line in bytes.
	MaxPayloadSize = gogit.MaxPayloadSize
)

// Sentinel errors.
var (
	// ErrPayloadTooLong is returned by the Encoder when a payload exceeds
	// MaxPayloadSize.
	ErrPayloadTooLong = gogit.ErrPayloadTooLong
	// ErrInvalidPktLen is returned by the Scanner when a pkt-line length prefix
	// is malformed or out of range.
	ErrInvalidPktLen = errors.New("invalid pkt-len")
)

// Raw pkt-line marker bytes for delim and response-end (flush is written via
// go-git's encoder).
var (
	delimPkt       = []byte("0001")
	responseEndPkt = []byte("0002")
)

// Encoder writes pkt-lines to an output stream. It wraps go-git's encoder for
// data and flush pkt-lines and adds Delim/ResponseEnd, writing those marker
// bytes directly to the same underlying writer.
type Encoder struct {
	enc *gogit.Encoder
	w   io.Writer
}

// NewEncoder returns an Encoder that writes to w.
func NewEncoder(w io.Writer) *Encoder {
	return &Encoder{enc: gogit.NewEncoder(w), w: w}
}

// Encode writes one pkt-line per payload. An empty payload encodes as a
// flush-pkt.
func (e *Encoder) Encode(payloads ...[]byte) error {
	return e.enc.Encode(payloads...)
}

// EncodeString writes one pkt-line per string payload.
func (e *Encoder) EncodeString(payloads ...string) error {
	return e.enc.EncodeString(payloads...)
}

// Flush writes a flush-pkt (0000).
func (e *Encoder) Flush() error {
	return e.enc.Flush()
}

// Delim writes a delimiter pkt-line (0001), used by protocol v2.
func (e *Encoder) Delim() error {
	_, err := e.w.Write(delimPkt)
	return err
}

// ResponseEnd writes a response-end pkt-line (0002), used by protocol v2.
func (e *Encoder) ResponseEnd() error {
	_, err := e.w.Write(responseEndPkt)
	return err
}

// Scanner reads pkt-lines from a source, classifying each as Data, Flush,
// Delim, ResponseEnd, or Raw (a non-pkt-line section boundary).
type Scanner struct {
	r       io.Reader
	prefix  [4]byte
	payload []byte
	raw     []byte // raw bytes (prefix + payload) of the last pkt-line
	pending []byte // bytes read but not a valid pkt-line (Raw marker)
	marker  Marker
	err     error
}

// NewScanner returns a Scanner that reads from r.
func NewScanner(r io.Reader) *Scanner {
	return &Scanner{r: r}
}

// Scan advances to the next pkt-line. It returns true when a pkt-line (Data,
// Flush, Delim, or ResponseEnd) was read, and false at EOF, on error, or when a
// non-pkt-line section is reached (Raw marker). After Scan returns false,
// consult Err and Marker.
func (s *Scanner) Scan() bool {
	if _, err := io.ReadFull(s.r, s.prefix[:]); err != nil {
		if err == io.EOF || err == io.ErrUnexpectedEOF {
			// io.ReadFull returns io.EOF only when zero bytes were read; a
			// short read surfaces as io.ErrUnexpectedEOF which we treat as a
			// malformed prefix.
			if err == io.EOF {
				s.err = nil
				return false
			}
			s.err = ErrInvalidPktLen
			return false
		}
		s.err = err
		return false
	}

	n, ok := decodeLen(s.prefix)
	if !ok {
		// Not a valid pkt-line prefix: this is the raw (packfile) section.
		s.marker = Raw
		s.pending = append(s.pending[:0], s.prefix[:]...)
		s.err = nil
		return false
	}

	switch n {
	case 0:
		s.marker = Flush
		s.raw = append(s.raw[:0], s.prefix[:]...)
		s.payload = s.payload[:0]
		return true
	case 1:
		s.marker = Delim
		s.raw = append(s.raw[:0], s.prefix[:]...)
		s.payload = s.payload[:0]
		return true
	case 2:
		s.marker = ResponseEnd
		s.raw = append(s.raw[:0], s.prefix[:]...)
		s.payload = s.payload[:0]
		return true
	default:
		if n < 4 || n > gogit.OversizePayloadMax+4 {
			s.err = fmt.Errorf("%w: %d", ErrInvalidPktLen, n)
			return false
		}
		l := n - 4
		if cap(s.payload) < l {
			s.payload = make([]byte, l)
		} else {
			s.payload = s.payload[:l]
		}
		if _, err := io.ReadFull(s.r, s.payload); err != nil {
			s.err = err
			return false
		}
		s.marker = Data
		s.raw = append(append(s.raw[:0], s.prefix[:]...), s.payload...)
		return true
	}
}

// Marker returns the marker for the most recent Scan.
func (s *Scanner) Marker() Marker { return s.marker }

// Bytes returns the payload of the most recent Data pkt-line. For flush/delim/
// response-end it is empty. The slice is invalidated by the next Scan call.
func (s *Scanner) Bytes() []byte { return s.payload }

// Raw returns the raw wire bytes (prefix + payload) of the most recent
// pkt-line, so a forwarder can write them through byte-exact.
func (s *Scanner) Raw() []byte { return s.raw }

// Pending returns the bytes read that are not a valid pkt-line prefix, only
// valid when Marker() == Raw. A forwarder should write these bytes then copy
// the rest of the stream raw.
func (s *Scanner) Pending() []byte { return s.pending }

// Err returns the first error encountered by the Scanner (nil at clean EOF or
// Raw boundary).
func (s *Scanner) Err() error { return s.err }

// decodeLen parses the 4-byte hexadecimal pkt-line length prefix into its
// numeric value. ok is false when the prefix is not valid hexadecimal (i.e. the
// bytes are not a pkt-line at all, such as the PACK magic of a packfile).
func decodeLen(p [4]byte) (int, bool) {
	n := 0
	for _, b := range p {
		d, ok := hexDigit(b)
		if !ok {
			return 0, false
		}
		n = n*16 + int(d)
	}
	return n, true
}

func hexDigit(b byte) (byte, bool) {
	switch {
	case b >= '0' && b <= '9':
		return b - '0', true
	case b >= 'a' && b <= 'f':
		return b - 'a' + 10, true
	case b >= 'A' && b <= 'F':
		return b - 'A' + 10, true
	default:
		return 0, false
	}
}

// IsFlush reports whether b is a flush-pkt payload (empty), for callers that
// want to distinguish flush from data without a Scanner.
func IsFlush(b []byte) bool { return len(b) == 0 }