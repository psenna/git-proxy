package repomatch

import (
	"testing"

	"github.com/psenna/git-proxy/internal/port"
)

func TestNewAndMatch(t *testing.T) {
	// exact beats wildcard
	m, err := New([]Pair[int]{{Pattern: "a/b.git", Value: 1}, {Pattern: "a/*", Value: 2}})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if v, ok := m.Match("a/b.git"); !ok || v != 1 {
		t.Errorf("exact beats wildcard: Match(%q) = (%v, %v), want (1, true)", "a/b.git", v, ok)
	}

	// longest wildcard wins
	m2, err := New([]Pair[int]{{Pattern: "a/*", Value: 1}, {Pattern: "a/b/*.git", Value: 2}})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if v, ok := m2.Match("a/b/x.git"); !ok || v != 2 {
		t.Errorf("longest wildcard: Match(%q) = (%v, %v), want (2, true)", "a/b/x.git", v, ok)
	}
	if v, ok := m2.Match("a/c.git"); !ok || v != 1 {
		t.Errorf("shorter wildcard fallback: Match(%q) = (%v, %v), want (1, true)", "a/c.git", v, ok)
	}

	// earliest-declared tiebreak (same-length wildcards)
	m3, err := New([]Pair[int]{{Pattern: "a/x*", Value: 1}, {Pattern: "a/y*", Value: 2}})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if v, ok := m3.Match("a/xyz.git"); !ok || v != 1 {
		t.Errorf("earliest tiebreak: Match(%q) = (%v, %v), want (1, true)", "a/xyz.git", v, ok)
	}
}

func TestStarOneSegment(t *testing.T) {
	m, err := New([]Pair[int]{{Pattern: "a/*", Value: 1}})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	cases := []struct {
		repo string
		want bool
	}{
		{"a/b.git", true},
		{"a/b/c.git", false},
		{"other/x.git", false},
	}
	for _, c := range cases {
		_, ok := m.Match(c.repo)
		if ok != c.want {
			t.Errorf("Match(%q) ok = %v, want %v", c.repo, ok, c.want)
		}
	}
}

func TestNoMatch(t *testing.T) {
	m, err := New([]Pair[int]{{Pattern: "a/*", Value: 1}})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	v, ok := m.Match("other/r.git")
	if ok || v != 0 {
		t.Errorf("Match(%q) = (%v, %v), want (0, false)", "other/r.git", v, ok)
	}
}

func TestNewErrors(t *testing.T) {
	cases := []struct {
		name    string
		pattern string
	}{
		{"bare star", "*"},
		{"double star", "a/**"},
		{"syntax error unclosed bracket", "a/["},
	}
	for _, c := range cases {
		_, err := New([]Pair[int]{{Pattern: c.pattern, Value: 1}})
		if err == nil {
			t.Errorf("%s: New(%q) err = nil, want error", c.name, c.pattern)
		}
	}
}

func TestDuplicateExactPattern(t *testing.T) {
	_, err := New([]Pair[int]{{Pattern: "a/b.git", Value: 1}, {Pattern: "a/b.git", Value: 2}})
	if err == nil {
		t.Fatal("duplicate exact pattern: expected error, got nil")
	}
}

func TestDuplicateWildcardPattern(t *testing.T) {
	_, err := New([]Pair[int]{{Pattern: "a/*", Value: 1}, {Pattern: "a/*", Value: 2}})
	if err == nil {
		t.Fatal("duplicate wildcard pattern: expected error, got nil")
	}
}

func TestWildcardPatterns(t *testing.T) {
	// Patterns deliberately ordered so declaration order differs from the
	// longest-first sort used for matching precedence.
	m, err := New([]Pair[int]{{Pattern: "a/*", Value: 1}, {Pattern: "a/b/*.git", Value: 2}})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	got := m.WildcardPatterns()
	want := []string{"a/*", "a/b/*.git"} // declaration order, not sorted
	if len(got) != len(want) {
		t.Fatalf("WildcardPatterns() = %v, want %v", got, want)
	}
	for i, p := range want {
		if got[i] != p {
			t.Errorf("WildcardPatterns()[%d] = %q, want %q (declaration order)", i, got[i], p)
		}
	}
}

func TestNewBoolMatcher(t *testing.T) {
	bm, err := NewBoolMatcher([]string{"public/*"})
	if err != nil {
		t.Fatalf("NewBoolMatcher: %v", err)
	}
	var _ port.RepoMatcher = bm
	if !bm.Match("public/r.git") {
		t.Error("Match(public/r.git) = false, want true")
	}
	if bm.Match("other/r.git") {
		t.Error("Match(other/r.git) = true, want false")
	}
	// errors on bare *, **, malformed
	for _, bad := range []string{"*", "a/**", "a/["} {
		if _, err := NewBoolMatcher([]string{bad}); err == nil {
			t.Errorf("NewBoolMatcher(%q): expected error, got nil", bad)
		}
	}
}
