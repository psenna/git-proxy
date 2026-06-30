package pktline_test

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/psenna/git-proxy/internal/gitproto/pktline"
)

// TestRoundTripDataAndFlush encodes data pkt-lines and a flush, then decodes
// them and asserts the same payloads and markers come back.
func TestRoundTripDataAndFlush(t *testing.T) {
	var buf bytes.Buffer
	e := pktline.NewEncoder(&buf)
	if err := e.EncodeString("hello\n", "world\n"); err != nil {
		t.Fatalf("encode: %v", err)
	}
	if err := e.Flush(); err != nil {
		t.Fatalf("flush: %v", err)
	}

	s := pktline.NewScanner(&buf)
	if !s.Scan() {
		t.Fatalf("scan 1: false, err=%v", s.Err())
	}
	if s.Marker() != pktline.Data {
		t.Fatalf("marker 1 = %v, want Data", s.Marker())
	}
	if got := string(s.Bytes()); got != "hello\n" {
		t.Fatalf("payload 1 = %q, want %q", got, "hello\n")
	}
	if !s.Scan() {
		t.Fatalf("scan 2: false, err=%v", s.Err())
	}
	if string(s.Bytes()) != "world\n" {
		t.Fatalf("payload 2 = %q", s.Bytes())
	}
	if !s.Scan() {
		t.Fatalf("scan 3: false, err=%v", s.Err())
	}
	if s.Marker() != pktline.Flush {
		t.Fatalf("marker 3 = %v, want Flush", s.Marker())
	}
	if s.Scan() {
		t.Fatalf("unexpected extra pkt-line")
	}
	if err := s.Err(); err != nil {
		t.Fatalf("err = %v, want nil", err)
	}
}

// TestRoundTripDelimAndResponseEnd verifies the v2 markers (delim 0001 and
// response-end 0002) round-trip, which go-git's stock scanner rejects.
func TestRoundTripDelimAndResponseEnd(t *testing.T) {
	var buf bytes.Buffer
	e := pktline.NewEncoder(&buf)
	if err := e.EncodeString("before\n"); err != nil {
		t.Fatalf("encode: %v", err)
	}
	if err := e.Delim(); err != nil {
		t.Fatalf("delim: %v", err)
	}
	if err := e.EncodeString("after\n"); err != nil {
		t.Fatalf("encode after: %v", err)
	}
	if err := e.ResponseEnd(); err != nil {
		t.Fatalf("response-end: %v", err)
	}

	s := pktline.NewScanner(&buf)
	check := func(want pktline.Marker, wantPayload string) {
		t.Helper()
		if !s.Scan() {
			t.Fatalf("scan: false, err=%v", s.Err())
		}
		if s.Marker() != want {
			t.Fatalf("marker = %v, want %v", s.Marker(), want)
		}
		if wantPayload != "" && string(s.Bytes()) != wantPayload {
			t.Fatalf("payload = %q, want %q", s.Bytes(), wantPayload)
		}
	}
	check(pktline.Data, "before\n")
	check(pktline.Delim, "")
	check(pktline.Data, "after\n")
	check(pktline.ResponseEnd, "")
	if s.Scan() {
		t.Fatalf("unexpected extra pkt-line")
	}
	if err := s.Err(); err != nil {
		t.Fatalf("err = %v", err)
	}
}

// TestScannerRawSection verifies that non-pkt-line bytes (a packfile body
// following a flush) are surfaced as a Raw marker with the consumed bytes
// available via Pending, so a forwarder can switch to raw copy mode.
func TestScannerRawSection(t *testing.T) {
	var buf bytes.Buffer
	e := pktline.NewEncoder(&buf)
	if err := e.EncodeString("NAK\n"); err != nil {
		t.Fatalf("encode: %v", err)
	}
	if err := e.Flush(); err != nil {
		t.Fatalf("flush: %v", err)
	}
	// Append a raw packfile (non-pkt-line) section.
	buf.WriteString("PACK\x00\x00\x00\x02deadbeef")

	s := pktline.NewScanner(&buf)
	if !s.Scan() || s.Marker() != pktline.Data || string(s.Bytes()) != "NAK\n" {
		t.Fatalf("expected NAK data line, got marker=%v bytes=%q err=%v", s.Marker(), s.Bytes(), s.Err())
	}
	if !s.Scan() || s.Marker() != pktline.Flush {
		t.Fatalf("expected flush, got marker=%v err=%v", s.Marker(), s.Err())
	}
	// Next Scan should hit the raw PACK bytes.
	if s.Scan() {
		t.Fatalf("expected Scan to stop at raw section, got marker=%v", s.Marker())
	}
	if s.Err() != nil {
		t.Fatalf("err = %v, want nil (raw is not an error)", s.Err())
	}
	if s.Marker() != pktline.Raw {
		t.Fatalf("marker = %v, want Raw", s.Marker())
	}
	if string(s.Pending()) != "PACK" {
		t.Fatalf("pending = %q, want %q", s.Pending(), "PACK")
	}
}

// TestScannerEOFOnEmpty verifies a clean empty stream scans to EOF with no
// error.
func TestScannerEOFOnEmpty(t *testing.T) {
	s := pktline.NewScanner(strings.NewReader(""))
	if s.Scan() {
		t.Fatalf("unexpected pkt-line on empty stream")
	}
	if err := s.Err(); err != nil {
		t.Fatalf("err = %v, want nil", err)
	}
	if s.Marker() != pktline.Data {
		t.Fatalf("marker = %v, want default Data", s.Marker())
	}
}

// TestEncodeTooLong verifies oversized payloads are rejected.
func TestEncodeTooLong(t *testing.T) {
	var buf bytes.Buffer
	e := pktline.NewEncoder(&buf)
	payload := make([]byte, pktline.MaxPayloadSize+1)
	if err := e.Encode(payload); !errors.Is(err, pktline.ErrPayloadTooLong) {
		t.Fatalf("err = %v, want ErrPayloadTooLong", err)
	}
}

// TestScannerInvalidPktLen verifies malformed length prefixes are errors.
func TestScannerInvalidPktLen(t *testing.T) {
	s := pktline.NewScanner(strings.NewReader("0003xx"))
	if s.Scan() {
		t.Fatalf("unexpected pkt-line for invalid length")
	}
	if err := s.Err(); err == nil {
		t.Fatalf("expected error for invalid pkt-len")
	}
}

// TestScannerFromReader verifies the scanner reads from an arbitrary reader
// (not just bytes.Buffer), mirroring how the proxy feeds it an upstream body.
func TestScannerFromReader(t *testing.T) {
	var buf bytes.Buffer
	e := pktline.NewEncoder(&buf)
	if err := e.EncodeString("line\n"); err != nil {
		t.Fatalf("encode: %v", err)
	}
	if err := e.Flush(); err != nil {
		t.Fatalf("flush: %v", err)
	}
	s := pktline.NewScanner(struct{ io.Reader }{&buf})
	if !s.Scan() || string(s.Bytes()) != "line\n" {
		t.Fatalf("scan = %v %q err=%v", s.Marker(), s.Bytes(), s.Err())
	}
	if !s.Scan() || s.Marker() != pktline.Flush {
		t.Fatalf("expected flush, got %v err=%v", s.Marker(), s.Err())
	}
}
