package port

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// TestPRSupport_CoreNeverDepends enforces the binding invariant (v1.md M10) that
// the proxy core NEVER depends on the optional PRSupport capability sub-interface.
// Only internal/port may define PRSupport, and an adapter package
// (internal/upstream/github) may implement it; the core (internal/gitproto,
// internal/transport, internal/policy, cmd/git-proxy) must NEVER reference
// port.PRSupport — code that wants the capability must type-assert at runtime
// (`if prs, ok := up.(PRSupport); ok { ... }`).
//
// This test parses the core packages' production source files and FAILS if any
// references the PRSupport identifier, preventing a silent regression that would
// couple the core to an SCM-specific capability. It is the enforceable form of the
// "core never depends on PRSupport" contract: the invariant currently holds (no
// core file references PRSupport), and this test keeps it held.
func TestPRSupport_CoreNeverDepends(t *testing.T) {
	// Locate the repo layout from this test file's path: internal/port -> internal -> root.
	_, here, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	portDir := filepath.Dir(here)        // .../internal/port
	internalDir := filepath.Dir(portDir)  // .../internal
	rootDir := filepath.Dir(internalDir) // repo root

	// The core packages that must stay free of any PRSupport dependency.
	// gitproto and transport are walked RECURSIVELY (their subpackages —
	// gitproto/pktline, transport/http, transport/ssh — are core protocol/transport
	// code that must also stay free of PRSupport; a top-level-only ReadDir would
	// miss the frontend files, which is exactly where a core dep would creep in).
	// policy is scanned TOP-LEVEL ONLY: its subpackage internal/policy/rules holds
	// rule implementations that MAY legitimately type-assert PRSupport in a future
	// rule (e.g. "require a PR exists before pushing to a protected branch"), so
	// scanning rules/ would create false alarms. cmd/git-proxy has no subpackages.
	recursivePkgs := []string{
		filepath.Join(internalDir, "gitproto"),
		filepath.Join(internalDir, "transport"),
		filepath.Join(rootDir, "cmd", "git-proxy"),
	}
	topLevelOnlyPkgs := []string{
		filepath.Join(internalDir, "policy"),
	}

	scanFile := func(fset *token.FileSet, path string) {
		file, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", path, err)
		}
		ast.Inspect(file, func(n ast.Node) bool {
			ident, ok := n.(*ast.Ident)
			if !ok {
				return true
			}
			if ident.Name == "PRSupport" {
				t.Errorf("%s: %s references PRSupport — the core must not depend on the optional capability sub-interface (type-assert at runtime instead)",
					fset.Position(ident.Pos()), path)
				return false
			}
			return true
		})
	}

	// isProdGo reports whether name is a production (non-test) .go source file.
	isProdGo := func(name string) bool {
		return strings.HasSuffix(name, ".go") && !strings.HasSuffix(name, "_test.go")
	}

	fset := token.NewFileSet()

	// Walk recursive core package trees (gitproto, transport, cmd).
	for _, root := range recursivePkgs {
		err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				return nil
			}
			if isProdGo(d.Name()) {
				scanFile(fset, path)
			}
			return nil
		})
		if err != nil {
			t.Fatalf("walk core pkg dir %s: %v", root, err)
		}
	}

	// Scan top-level-only core packages (policy: engine + decision, not rules/).
	for _, pkgDir := range topLevelOnlyPkgs {
		entries, err := os.ReadDir(pkgDir)
		if err != nil {
			t.Fatalf("read core pkg dir %s: %v", pkgDir, err)
		}
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			if isProdGo(e.Name()) {
				scanFile(fset, filepath.Join(pkgDir, e.Name()))
			}
		}
	}
}