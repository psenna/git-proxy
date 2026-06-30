package pathmatch_test

import (
	"testing"

	"github.com/psenna/git-proxy/internal/pathmatch"
)

func TestMatcher(t *testing.T) {
	cases := []struct {
		name     string
		patterns []string
		path     string
		want     bool
	}{
		// Empty matcher matches nothing.
		{name: "empty matcher", patterns: nil, path: "a/b.txt", want: false},

		// Single-segment `*` does not cross `/`.
		{name: "star single segment match", patterns: []string{"*.txt"}, path: "notes.txt", want: true},
		{name: "star single segment no cross", patterns: []string{"*.txt"}, path: "a/notes.txt", want: true},   // non-anchored, any segment
		{name: "star does not match dir-suffix", patterns: []string{"foo*"}, path: "foobar/baz", want: true},   // segment foobar matches foo*
		{name: "star no match", patterns: []string{"foo*"}, path: "bar/qux", want: false},

		// `**` crosses path segments.
		{name: "double-star crosses", patterns: []string{"secrets/**"}, path: "secrets/a/b/c.key", want: true},
		{name: "double-star matches one", patterns: []string{"secrets/**"}, path: "secrets/a.key", want: true},
		{name: "double-star matches zero under dir", patterns: []string{"secrets/**"}, path: "secrets", want: true},
		{name: "double-star no match outside", patterns: []string{"secrets/**"}, path: "public/a.key", want: false},

		// Leading `/` anchors to root.
		{name: "anchored root match", patterns: []string{"/top.txt"}, path: "top.txt", want: true},
		{name: "anchored root no depth", patterns: []string{"/top.txt"}, path: "dir/top.txt", want: false},
		{name: "anchored glob", patterns: []string{"/.github/workflows/*"}, path: ".github/workflows/ci.yml", want: true},
		{name: "anchored glob no cross", patterns: []string{"/.github/workflows/*"}, path: ".github/workflows/jobs/ci.yml", want: false},
		{name: "anchored glob no depth", patterns: []string{"/.github/workflows/*"}, path: "sub/.github/workflows/ci.yml", want: false},

		// Non-anchored multi-segment is anchored to root by middle slash.
		{name: "middle slash anchors", patterns: []string{"a/b"}, path: "a/b", want: true},
		{name: "middle slash no depth", patterns: []string{"a/b"}, path: "x/a/b", want: false},

		// Non-anchored no-slash matches at any depth (any segment).
		{name: "no slash any depth", patterns: []string{"config.env"}, path: "deploy/envs/config.env", want: true},
		{name: "no slash root", patterns: []string{"config.env"}, path: "config.env", want: true},
		{name: "no slash no segment match", patterns: []string{"config.env"}, path: "deploy/envs/other.env", want: false},

		// `**` in the middle.
		{name: "middle double-star zero", patterns: []string{"a/**/b"}, path: "a/b", want: true},
		{name: "middle double-star one", patterns: []string{"a/**/b"}, path: "a/x/b", want: true},
		{name: "middle double-star many", patterns: []string{"a/**/b"}, path: "a/x/y/z/b", want: true},
		{name: "middle double-star no match", patterns: []string{"a/**/b"}, path: "a/x/c", want: false},

		// Leading `**/` matches at any depth.
		{name: "leading double-star any depth", patterns: []string{"**/secrets.txt"}, path: "a/b/secrets.txt", want: true},
		{name: "leading double-star root", patterns: []string{"**/secrets.txt"}, path: "secrets.txt", want: true},

		// Trailing `/` matches a directory and everything under it.
		{name: "trailing slash dir contents", patterns: []string{"secrets/"}, path: "secrets/api.key", want: true},
		{name: "trailing slash dir itself", patterns: []string{"secrets/"}, path: "secrets", want: true},
		{name: "trailing slash no match sibling", patterns: []string{"secrets/"}, path: "public/api.key", want: false},
		{name: "trailing slash anchored root", patterns: []string{"/secrets/"}, path: "secrets/api.key", want: true},
		{name: "trailing slash anchored no depth", patterns: []string{"/secrets/"}, path: "x/secrets/api.key", want: false},
		{name: "trailing slash any depth", patterns: []string{"secrets/"}, path: "a/b/secrets/c.key", want: true},

		// `**` alone matches everything.
		{name: "double-star alone", patterns: []string{"**"}, path: "anything/here.txt", want: true},
		{name: "double-star alone root", patterns: []string{"**"}, path: "root.txt", want: true},

		// `?` single char.
		{name: "question match", patterns: []string{"a?.txt"}, path: "ab.txt", want: true},
		{name: "question no match two", patterns: []string{"a?.txt"}, path: "abc.txt", want: false},

		// Character classes.
		{name: "class match", patterns: []string{"[abc].txt"}, path: "b.txt", want: true},
		{name: "class no match", patterns: []string{"[abc].txt"}, path: "d.txt", want: false},
		{name: "negated class match", patterns: []string{"[!abc].txt"}, path: "d.txt", want: true},
		{name: "negated class no match", patterns: []string{"[!abc].txt"}, path: "a.txt", want: false},

		// Multiple patterns: any match wins.
		{name: "multi first matches", patterns: []string{"*.env", "secrets/**"}, path: "secrets/k.env", want: true},
		{name: "multi second matches", patterns: []string{"*.env", "secrets/**"}, path: "deploy/x.env", want: true},
		{name: "multi none matches", patterns: []string{"*.env", "secrets/**"}, path: "deploy/readme.md", want: false},

		// Malformed patterns are dropped (fail-safe, never match).
		{name: "malformed unclosed class dropped", patterns: []string{"[abc.txt"}, path: "[abc.txt", want: false},
		{name: "malformed does not poison good", patterns: []string{"[abc.txt", "*.env"}, path: "x.env", want: true},
		{name: "empty pattern dropped", patterns: []string{""}, path: "anything", want: false},

		// Negation (`!`) is unsupported: a `!`-prefixed pattern is dropped as
		// malformed (matches nothing, even a file literally named `!foo`).
		{name: "negation prefix dropped", patterns: []string{"!foo"}, path: "!foo", want: false},
		{name: "negation does not poison good", patterns: []string{"!foo", "*.env"}, path: "x.env", want: true},
		// A leading `/` anchors, so `/!foo` is an anchored literal `!foo` (not negation).
		{name: "anchored bang literal matches", patterns: []string{"/!foo"}, path: "!foo", want: true},
		{name: "anchored bang literal no depth", patterns: []string{"/!foo"}, path: "dir/!foo", want: false},

		// Path normalization: leading slash on the path is stripped.
		{name: "path leading slash stripped", patterns: []string{"/a/b"}, path: "/a/b", want: true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			m := pathmatch.New(c.patterns)
			if got := m.Match(c.path); got != c.want {
				t.Fatalf("Match(%q) = %v, want %v", c.path, got, c.want)
			}
		})
	}
}

func TestMatcher_NilSafe(t *testing.T) {
	var m *pathmatch.Matcher
	if m.Match("a/b") {
		t.Fatal("nil matcher should not match")
	}
}

func TestIsMalformed(t *testing.T) {
	cases := []struct {
		name    string
		pattern string
		want    bool
	}{
		// Good patterns are not malformed.
		{name: "literal", pattern: "config.env", want: false},
		{name: "star", pattern: "*.env", want: false},
		{name: "double-star dir", pattern: "secrets/**", want: false},
		{name: "anchored glob", pattern: "/.github/workflows/*", want: false},
		{name: "trailing slash dir", pattern: "secrets/", want: false},
		{name: "char class", pattern: "[abc].txt", want: false},
		{name: "negated char class", pattern: "[!abc].txt", want: false},
		{name: "double-star alone", pattern: "**", want: false},
		{name: "question", pattern: "a?.txt", want: false},

		// Blank = nothing configured, NOT malformed.
		{name: "empty", pattern: "", want: false},
		{name: "whitespace", pattern: "   ", want: false},

		// Malformed: New would drop these.
		{name: "unclosed class", pattern: "[abc.txt", want: true},
		{name: "unclosed class mid", pattern: "foo[bar", want: true},
		{name: "unbalanced class", pattern: "foo[!bar", want: true},
		{name: "root slash only", pattern: "/", want: true},
		// Negation (`!`) is unsupported: a leading `!` is malformed.
		{name: "negation prefix", pattern: "!foo", want: true},
		{name: "negation prefix dir", pattern: "!secrets/", want: true},
		// A leading `/` anchors, so `/!foo` is NOT negation (the `!` is not leading).
		{name: "anchored bang literal", pattern: "/!foo", want: false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := pathmatch.IsMalformed(c.pattern); got != c.want {
				t.Fatalf("IsMalformed(%q) = %v, want %v", c.pattern, got, c.want)
			}
		})
	}
}