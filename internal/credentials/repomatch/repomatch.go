package repomatch

import (
	"fmt"
	"path"
	"sort"
	"strings"

	"github.com/psenna/git-proxy/internal/port"
)

// Pair associates a repository match pattern with a value of type V.
type Pair[V any] struct {
	Pattern string
	Value   V
}

type entry[V any] struct {
	pattern string
	order   int
	value   V
}

// Matcher[V] resolves a repository path to a value via a set of patterns.
// Precedence on match is: exact match first, then the longest matching
// wildcard, then the earliest-declared wildcard among equal-length patterns.
type Matcher[V any] struct {
	exact         map[string]V
	wildcards     []entry[V] // sorted by precedence: longest pattern first, then order
	wildcardOrder []string   // wildcard patterns in declaration order
}

// New builds a Matcher from pattern/value pairs. It rejects bare "*", any
// pattern containing "**", path.Match syntax errors, and duplicate patterns.
func New[V any](pairs []Pair[V]) (*Matcher[V], error) {
	m := &Matcher[V]{exact: make(map[string]V)}
	seen := make(map[string]bool)
	for i, p := range pairs {
		if err := validate(p.Pattern); err != nil {
			return nil, fmt.Errorf("repomatch: pattern %q: %w", p.Pattern, err)
		}
		if seen[p.Pattern] {
			return nil, fmt.Errorf("repomatch: duplicate repo pattern %q", p.Pattern)
		}
		seen[p.Pattern] = true
		if isWildcard(p.Pattern) {
			m.wildcards = append(m.wildcards, entry[V]{pattern: p.Pattern, order: i, value: p.Value})
			m.wildcardOrder = append(m.wildcardOrder, p.Pattern)
		} else {
			m.exact[p.Pattern] = p.Value
		}
	}
	sort.SliceStable(m.wildcards, func(i, j int) bool {
		if len(m.wildcards[i].pattern) != len(m.wildcards[j].pattern) {
			return len(m.wildcards[i].pattern) > len(m.wildcards[j].pattern) // longest first
		}
		return m.wildcards[i].order < m.wildcards[j].order // earliest declared
	})
	return m, nil
}

// Match resolves repo to its associated value. The zero value and false are
// returned when no pattern matches.
func (m *Matcher[V]) Match(repo string) (V, bool) {
	var zero V
	if v, ok := m.exact[repo]; ok {
		return v, true
	}
	for _, e := range m.wildcards {
		if ok, _ := path.Match(e.pattern, repo); ok {
			return e.value, true
		}
	}
	return zero, false
}

// WildcardPatterns returns the wildcard patterns (those containing "*") in
// declaration order.
func (m *Matcher[V]) WildcardPatterns() []string {
	out := make([]string, len(m.wildcardOrder))
	copy(out, m.wildcardOrder)
	return out
}

func isWildcard(p string) bool { return strings.Contains(p, "*") }

func validate(p string) error {
	if p == "" {
		return fmt.Errorf("empty pattern")
	}
	if p == "*" {
		return fmt.Errorf("bare * catch-all not allowed")
	}
	if strings.Contains(p, "**") {
		return fmt.Errorf("** not allowed (use single-segment *)")
	}
	if _, err := path.Match(p, ""); err != nil { // syntax check
		return err
	}
	return nil
}

// NewBoolMatcher builds a port.RepoMatcher (bool) from patterns. It is used for
// the public_repos allowlist where only a match/no-match result is needed.
func NewBoolMatcher(patterns []string) (port.RepoMatcher, error) {
	pairs := make([]Pair[struct{}], len(patterns))
	for i, p := range patterns {
		pairs[i] = Pair[struct{}]{Pattern: p}
	}
	m, err := New(pairs)
	if err != nil {
		return nil, err
	}
	return boolMatcher{m: m}, nil
}

type boolMatcher struct{ m *Matcher[struct{}] }

func (b boolMatcher) Match(repo string) bool { _, ok := b.m.Match(repo); return ok }
