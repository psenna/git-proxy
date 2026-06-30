// Package pathmatch implements gitignore-style file-path matching shared by the
// push path_acl rule and the fetch read-protection path (Task 9). It is a leaf
// package with no dependencies on policy/rules so both directions can import it
// without a cycle.
//
// Semantics (gitignore-compatible, file-path oriented):
//   - `*` matches any run of characters within a single path segment (does not
//     cross `/`).
//   - `**` matches zero or more whole path segments (crosses `/`). It is only
//     special as a complete segment; `a**b` is treated as ordinary `*` globs
//     within one segment.
//   - `?` matches exactly one character within a segment.
//   - `[seq]` matches one character in seq; `[!seq]` matches one character not
//     in seq. An unclosed `[` is malformed and the pattern is dropped.
//   - A leading `/` anchors the pattern to the repository root. A pattern with
//     a `/` anywhere except a trailing `/` is also anchored (gitignore: a
//     middle slash implies root-relative). A pattern with no `/` at all matches
//     at any depth (any path segment).
//   - A trailing `/` makes the pattern directory-only: it matches the directory
//     itself and everything under it.
//   - An empty pattern set matches nothing. A malformed pattern is dropped
//     (fail-safe: it never matches and does not panic).
//
// Negation (`!`) is NOT implemented in v1 and is documented as a known
// limitation. The path_acl use case only needs positive deny patterns;
// negation adds ordering/last-match-wins complexity and risk for no current
// benefit. A pattern with a leading `!` (the gitignore negation prefix) is
// rejected as malformed (dropped by New / reported by IsMalformed) rather than
// compiled as a literal segment that would match only a file literally named
// `!foo` — for a deny list that would over-match a weirdly-named file. Task 9
// may revisit if fetch rules need allow-then-deny overrides.
package pathmatch

import "strings"

// pattern is a single compiled gitignore-style pattern.
type pattern struct {
	anchored bool // match must start at the root segment
	dirOnly  bool // match a directory and everything under it
	segs     []segment
}

// segment is one path-segment token of a pattern. When dblStar is true the
// segment matches zero or more whole path segments; otherwise lit is matched
// against a single path segment via single-segment glob rules.
type segment struct {
	dblStar bool
	lit     string
}

// Matcher matches file paths against an ordered gitignore-style pattern list.
// A nil *Matcher matches nothing.
type Matcher struct {
	patterns []pattern
}

// New builds a Matcher from patterns. Malformed patterns (empty, or containing
// an unclosed `[`) are dropped fail-safe. The resulting matcher matches a path
// if ANY surviving pattern matches.
func New(patterns []string) *Matcher {
	m := &Matcher{}
	for _, p := range patterns {
		cp, ok := compile(p)
		if !ok {
			continue
		}
		m.patterns = append(m.patterns, cp)
	}
	return m
}

// IsMalformed reports whether pattern is a non-blank pattern that New would
// drop as structurally invalid (e.g. an unclosed `[`). It lets a security
// DENY-list caller detect a config typo and fail closed rather than silently
// allowing everything through. A blank pattern (empty or whitespace-only) is
// NOT malformed — it means "nothing configured" and New drops it as a no-op
// (matches nothing), so IsMalformed returns false for it. This keeps New's
// behavior (drop malformed, never panic) unchanged; IsMalformed only exposes
// the detection.
func IsMalformed(pattern string) bool {
	if strings.TrimSpace(pattern) == "" {
		return false
	}
	_, ok := compile(pattern)
	return !ok
}

// compile parses a single pattern. It returns ok=false if the pattern is empty
// or malformed (unclosed `[`, or a leading `!` which is unsupported negation).
func compile(p string) (pattern, bool) {
	// A pattern that is empty or only whitespace matches nothing.
	if strings.TrimSpace(p) == "" {
		return pattern{}, false
	}
	// Negation (`!` prefix) is unsupported in v1. Drop it as malformed so it
	// does not compile as a literal segment that over-matches a `!`-named file.
	if strings.HasPrefix(p, "!") {
		return pattern{}, false
	}
	dirOnly := strings.HasSuffix(p, "/")
	work := strings.TrimSuffix(p, "/")
	if work == "" {
		// p was "/" or empty-ish: nothing meaningful to match.
		return pattern{}, false
	}
	// A leading `/` anchors; a `/` anywhere else (middle) also anchors per
	// gitignore. Strip a leading slash before splitting.
	anchored := strings.HasPrefix(work, "/") || strings.Contains(work, "/")
	work = strings.TrimPrefix(work, "/")

	rawSegs := strings.Split(work, "/")
	segs := make([]segment, 0, len(rawSegs))
	for _, rs := range rawSegs {
		if rs == "**" {
			segs = append(segs, segment{dblStar: true})
			continue
		}
		// Within a non-`**` segment, `**` collapses to ordinary `*` globs;
		// validate char classes here so malformed segments drop the pattern.
		if !validGlob(rs) {
			return pattern{}, false
		}
		segs = append(segs, segment{lit: rs})
	}
	return pattern{anchored: anchored, dirOnly: dirOnly, segs: segs}, true
}

// validGlob reports whether seg is a well-formed single-segment glob (every
// `[` has a matching `]`). It does not interpret other metacharacters.
func validGlob(seg string) bool {
	for i := 0; i < len(seg); i++ {
		if seg[i] == '[' {
			// Find a closing ']' (gitignore allows `[!]` negation and `[]]`
			// literal-`]` forms; we only require some ']' to exist after '[').
			j := i + 1
			// A leading ']' or '!' right after '[' is part of the class.
			if j < len(seg) && (seg[j] == ']' || seg[j] == '!') {
				j++
			}
			found := false
			for ; j < len(seg); j++ {
				if seg[j] == ']' {
					found = true
					break
				}
			}
			if !found {
				return false
			}
		}
	}
	return true
}

// Match reports whether path is matched by any pattern. A nil matcher never
// matches.
func (m *Matcher) Match(path string) bool {
	if m == nil || len(m.patterns) == 0 {
		return false
	}
	// Normalize: strip a leading "/" on the path so root-anchored patterns
	// compare against the bare relative path.
	path = strings.TrimPrefix(path, "/")
	if path == "" {
		return false
	}
	pathSegs := strings.Split(path, "/")
	for _, p := range m.patterns {
		if p.match(pathSegs) {
			return true
		}
	}
	return false
}

// match reports whether the pattern matches the given path segments.
func (p pattern) match(pathSegs []string) bool {
	if len(p.segs) == 0 {
		return false
	}
	if !p.anchored {
		// Non-anchored patterns have exactly one segment (any pattern with a
		// '/' would be anchored). Match if any path segment matches it, which
		// also covers "this name as a directory, with everything under it".
		s := p.segs[0]
		if s.dblStar {
			return true // `**` alone matches everything
		}
		for _, ps := range pathSegs {
			if singleMatch(s.lit, ps) {
				return true
			}
		}
		return false
	}
	// Anchored: match from the first segment.
	return p.matchFrom(0, 0, pathSegs)
}

// matchFrom is the backtracking matcher for anchored patterns. patI is the
// pattern-segment index; pathI is the path-segment index. dirOnly patterns may
// match a prefix of the path (everything under the matched directory); full
// patterns must consume the entire path.
func (p pattern) matchFrom(patI, pathI int, pathSegs []string) bool {
	if patI == len(p.segs) {
		if p.dirOnly {
			return true // matched the directory; anything under is included
		}
		return pathI == len(pathSegs)
	}
	s := p.segs[patI]
	if s.dblStar {
		// `**` matches zero or more whole path segments.
		remaining := len(pathSegs) - pathI
		for k := 0; k <= remaining; k++ {
			if p.matchFrom(patI+1, pathI+k, pathSegs) {
				return true
			}
		}
		return false
	}
	if pathI == len(pathSegs) {
		return false
	}
	if !singleMatch(s.lit, pathSegs[pathI]) {
		return false
	}
	return p.matchFrom(patI+1, pathI+1, pathSegs)
}

// singleMatch reports whether a single-segment glob pattern matches a single
// path segment. Supports `*` (any run within the segment), `?` (one char), and
// `[seq]` / `[!seq]` character classes. A malformed class is treated as a
// literal (validGlob already dropped truly malformed patterns at compile time,
// so a surviving `[` always has a matching `]`).
func singleMatch(pat, name string) bool {
	// Iterative backtracking glob match over one segment (no `/` handling needed
	// since both sides are single segments).
	pi, ni := 0, 0
	star := -1
	starN := 0
	for ni < len(name) {
		if pi < len(pat) {
			c := pat[pi]
			switch {
			case c == '*':
				star = pi
				starN = ni
				pi++
				continue
			case c == '?':
				pi++
				ni++
				continue
			case c == '[':
				end, ok := classEnd(pat, pi)
				if ok && classMatch(pat[pi:end], name[ni]) {
					pi = end
					ni++
					continue
				}
				// Malformed class (shouldn't happen after validGlob) or no match:
				// treat as literal '['.
			}
			if pi < len(pat) && pat[pi] == name[ni] {
				pi++
				ni++
				continue
			}
		}
		if star >= 0 {
			pi = star + 1
			starN++
			ni = starN
			continue
		}
		return false
	}
	for pi < len(pat) && pat[pi] == '*' {
		pi++
	}
	return pi == len(pat)
}

// classEnd returns the index just past the `]` that closes the class starting
// at pat[i] (`[`), and ok=true; ok=false if none closes.
func classEnd(pat string, i int) (int, bool) {
	j := i + 1
	if j < len(pat) && (pat[j] == ']' || pat[j] == '!') {
		j++
	}
	for ; j < len(pat); j++ {
		if pat[j] == ']' {
			return j + 1, true
		}
	}
	return len(pat), false
}

// classMatch reports whether the class expression cls (including the brackets)
// matches the single byte ch.
func classMatch(cls string, ch byte) bool {
	// cls[0] == '[', cls[len-1] == ']'.
	inner := cls[1 : len(cls)-1]
	negate := false
	if strings.HasPrefix(inner, "!") {
		negate = true
		inner = inner[1:]
	}
	matched := false
	for i := 0; i < len(inner); i++ {
		// Range form `a-z`.
		if i+2 < len(inner) && inner[i+1] == '-' {
			lo, hi := inner[i], inner[i+2]
			if ch >= lo && ch <= hi {
				matched = true
			}
			i += 2
			continue
		}
		if inner[i] == ch {
			matched = true
		}
	}
	if negate {
		return !matched
	}
	return matched
}