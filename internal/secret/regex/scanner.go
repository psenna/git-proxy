// Package regex implements a pure, deterministic port.SecretScanner using
// regular expressions plus a Shannon-entropy heuristic for high-entropy
// secrets. It performs no I/O and uses no time or randomness; the caller
// provides the bytes. Snippets in returned findings are redacted so the matched
// secret value is never exposed to agent-facing deny reasons.
package regex

import (
	"bytes"
	"fmt"
	"math"
	"regexp"
	"strings"

	"github.com/psenna/git-proxy/internal/port"
)

// Pattern is one configurable detection pattern: a compiled-from-Regex named
// rule appended to the built-in defaults.
type Pattern struct {
	Regex string
	Name  string
}

// defaultPattern is a built-in detection pattern always present on a Scanner.
type defaultPattern struct {
	re   *regexp.Regexp
	name string
}

// Scanner is a port.SecretScanner backed by regexes + entropy. The zero value
// is not usable; build one with New.
type Scanner struct {
	defaults []defaultPattern
	extra    []*regexp.Regexp
	extraNames []string
	entropy  *regexp.Regexp
}

// builtins are the compiled default patterns. They are conservative to keep
// false positives low. Compiled once at package init.
var builtins = []defaultPattern{
	{regexp.MustCompile(`AKIA[0-9A-Z]{16}`), "aws-access-key-id"},
	{regexp.MustCompile(`gh[ps]_[A-Za-z0-9]{36}`), "github-pat"},
	{regexp.MustCompile(`glpat-[A-Za-z0-9_-]{20}`), "gitlab-pat"},
	{regexp.MustCompile(`-----BEGIN (?:RSA|EC|OPENSSH|PGP|DSA|ECDSA) PRIVATE KEY-----`), "private-key"},
}

// entropyRun matches long base64/hex-ish runs that are worth an entropy check.
var entropyRun = regexp.MustCompile(`[A-Za-z0-9+/=_-]{40,}`)

// entropyThreshold is the minimum Shannon entropy (bits/char) for a long run to
// be flagged as a generic high-entropy secret. Tuned conservatively to keep
// false positives low (random base64 ~6 bits/char; English prose ~4.0-4.5).
const entropyThreshold = 4.5

// New builds a Scanner from the built-in default patterns plus the given extra
// patterns. If any extra pattern fails to compile, New returns a non-nil error
// (and a nil scanner) so the caller can fail closed rather than silently
// dropping a configured pattern.
func New(extra []Pattern) (*Scanner, error) {
	s := &Scanner{defaults: builtins, entropy: entropyRun}
	for _, p := range extra {
		if strings.TrimSpace(p.Regex) == "" {
			continue
		}
		re, err := regexp.Compile(p.Regex)
		if err != nil {
			return nil, fmt.Errorf("secret/regex: pattern %q: %w", p.Name, err)
		}
		s.extra = append(s.extra, re)
		s.extraNames = append(s.extraNames, p.Name)
	}
	return s, nil
}

// Scan implements port.SecretScanner. It scans content line-by-line for the
// default and extra patterns plus a high-entropy heuristic. Findings carry the
// 1-based line number and a REDACTED snippet (the matched secret is masked).
//
// Binary content is skipped: a NUL byte is the standard heuristic for a binary
// file (PNGs, compiled artifacts, etc.), and binary blobs contain long
// base64-ish runs above the entropy threshold that would yield false-positive
// high-entropy findings and block legitimate binary pushes.
func (s *Scanner) Scan(path string, content []byte) []port.SecretFinding {
	if bytes.IndexByte(content, 0) >= 0 {
		return nil
	}
	var findings []port.SecretFinding
	// Iterate line-by-line so line numbers and snippets are naturally bounded
	// to the matching line.
	lines := strings.Split(string(content), "\n")
	for i, line := range lines {
		ln := i + 1
		for _, d := range s.defaults {
			loc := d.re.FindStringIndex(line)
			if loc == nil {
				continue
			}
			// Skip zero-length matches (a regex that can match the empty string,
			// e.g. "a*"): an empty match is not a secret, and redact with an empty
			// secret would emit the raw line unredacted (a leak surface if the line
			// also carries a different pattern's secret).
			if loc[0] == loc[1] {
				continue
			}
			findings = append(findings, port.SecretFinding{
				Path:    path,
				Line:    ln,
				Rule:    d.name,
				Snippet: redact(line, line[loc[0]:loc[1]]),
			})
		}
		for j, re := range s.extra {
			loc := re.FindStringIndex(line)
			if loc == nil {
				continue
			}
			if loc[0] == loc[1] {
				continue
			}
			findings = append(findings, port.SecretFinding{
				Path:    path,
				Line:    ln,
				Rule:    s.extraNames[j],
				Snippet: redact(line, line[loc[0]:loc[1]]),
			})
		}
		// High-entropy heuristic: scan the line for long base64/hex runs.
		for _, m := range s.entropy.FindAllStringIndex(line, -1) {
			run := line[m[0]:m[1]]
			if shannonEntropy(run) >= entropyThreshold {
				findings = append(findings, port.SecretFinding{
					Path:    path,
					Line:    ln,
					Rule:    "high-entropy",
					Snippet: redact(line, run),
				})
				break // one entropy finding per line is enough
			}
		}
	}
	return findings
}

// redact returns a bounded snippet of line with every occurrence of secret
// replaced by "***REDACTED***". The snippet never contains the raw secret. If
// secret is empty (a degenerate match the caller should have skipped), the
// whole line is masked: Selectively redacting an empty match is impossible, and
// returning the raw line could leak a different pattern's secret on the same
// line. Defense-in-depth — Scan skips zero-length matches, so this branch should
// be unreachable in practice.
func redact(line, secret string) string {
	if secret == "" {
		return "***REDACTED***"
	}
	masked := strings.ReplaceAll(line, secret, "***REDACTED***")
	return trimSnippet(masked)
}

// trimSnippet trims surrounding whitespace and bounds a snippet to a
// reasonable length so deny reasons stay readable.
func trimSnippet(s string) string {
	s = strings.TrimSpace(s)
	const max = 200
	if len(s) > max {
		s = s[:max] + "..."
	}
	return s
}

// shannonEntropy computes the Shannon entropy (bits per character) of s over
// its byte distribution. It is a pure computation with no I/O or randomness.
func shannonEntropy(s string) float64 {
	if len(s) == 0 {
		return 0
	}
	counts := make(map[byte]int, 64)
	for i := 0; i < len(s); i++ {
		counts[s[i]]++
	}
	n := float64(len(s))
	var h float64
	for _, c := range counts {
		p := float64(c) / n
		h -= p * (math.Log2(p))
	}
	return h
}