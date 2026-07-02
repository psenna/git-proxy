package port

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestCoreNeverDependsOnPRSupport enforces the binding constraint that the
// proxy core NEVER depends on the optional PRSupport capability sub-interface.
// Only internal/port defines PRSupport; internal/upstream/github implements
// it. No production file in internal/gitproto, internal/transport,
// internal/policy, or cmd/git-proxy may reference the identifier "PRSupport".
// If a core package grows a PRSupport dependency, this test FAILS — keeping
// the seam truly optional so the plain adapter stays unburdened and the core
// never assumes an SCM provider.
//
// Approach: a go/parser-based AST scan of the core packages' production source
// files. We walk every non-test .go file in the guarded packages and fail if
// any identifier node named "PRSupport" is referenced (whether as
// port.PRSupport, a bare PRSupport, or in a type assertion). This is the
// cleanest form: it is a precise, real check expressed as a unit test, runs
// fast, needs no build tags, and gives a clear failure message naming the
// offending file. A grep-based test would be coarser (would match strings in
// comments); a build-tagged check would not pin the "core never" boundary as
// precisely. Test files (_test.go) are excluded — tests may reference PRSupport
// to assert the seam; the constraint is on production code only.
func TestCoreNeverDependsOnPRSupport(t *testing.T) {
	// Packages that form the proxy core and must NOT reference PRSupport.
	// internal/port is excluded (it defines the seam).
	// internal/upstream/github is excluded (it implements the seam — the only
	// non-port implementer). internal/upstream (the registry) is excluded: it
	// does not reference PRSupport and is the registry, not the core
	// enforcement path.
	guarded := []string{
		"internal/gitproto",
		"internal/transport",
		"internal/policy",
		"cmd/git-proxy",
	}
	root := repoRoot(t)

	for _, pkg := range guarded {
		dir := filepath.Join(root, pkg)
		fset := token.NewFileSet()
		pkgs, err := parser.ParseDir(fset, dir, func(fi os.FileInfo) bool {
			// Skip generated files and test files: tests may reference PRSupport
			// to assert the seam; the constraint is on production code.
			return !strings.HasSuffix(fi.Name(), "_test.go")
		}, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", pkg, err)
		}
		for _, p := range pkgs {
			for _, file := range p.Files {
				ast.Inspect(file, func(n ast.Node) bool {
					ident, ok := n.(*ast.Ident)
					if !ok {
						return true
					}
					if ident.Name == "PRSupport" {
						pos := fset.Position(ident.Pos())
						t.Errorf("%s:%d: core references PRSupport — the core must not depend on the optional PRSupport seam (only internal/port defines it; internal/upstream/github implements it)",
							filepath.Join(pkg, filepath.Base(pos.Filename)), pos.Line)
					}
					return true
				})
			}
		}
	}
}

// repoRoot returns the repository root (the directory containing go.mod).
// `go test` runs with the working directory set to the package directory
// (internal/port), so the repo root is two parents up. We confirm by checking
// for go.mod rather than assuming the depth, walking up a few levels.
func repoRoot(t *testing.T) string {
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("os.Getwd: %v", err)
	}
	for i := 0; i < 10; i++ {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		dir = filepath.Dir(dir)
	}
	t.Fatalf("could not find go.mod walking up from %s", dir)
	return ""
}