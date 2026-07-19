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
// the proxy core NEVER depends on the optional SCM/issue capability sub-interfaces.
// Only internal/port may define them, and an adapter package
// (internal/upstream/github) may implement them; the core (internal/gitproto,
// internal/transport, internal/policy, cmd/git-proxy) must NEVER reference
// port.PRSupport or port.IssueSupport — code that wants a capability must
// type-assert at runtime (`if prs, ok := up.(PRSupport); ok { ... }`).
//
// This test parses the core packages' production source files and FAILS if any
// references a capability-seam identifier (PRSupport or IssueSupport), preventing a
// silent regression that would couple the core to an SCM/issue-specific capability.
// It is the enforceable form of the "core never depends on the capability seams"
// contract: the invariant currently holds (no core file references either), and
// this test keeps it held.
func TestPRSupport_CoreNeverDepends(t *testing.T) {
	// Locate the repo layout from this test file's path: internal/port -> internal -> root.
	_, here, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	portDir := filepath.Dir(here)        // .../internal/port
	internalDir := filepath.Dir(portDir)  // .../internal
	rootDir := filepath.Dir(internalDir) // repo root

	// capabilitySeams is the set of optional capability sub-interface identifiers
	// the core must never reference. Today: PRSupport (PRs / branch protection,
	// sourced from the SCM upstream) and IssueSupport (issues, sourced from a
	// separately-configured issue upstream). Adding a future capability seam means
	// adding its identifier here so the same invariant is enforced for it.
	capabilitySeams := map[string]bool{
		"PRSupport":    true,
		"IssueSupport": true,
	}

	// The core packages that must stay free of any capability-seam dependency.
	// gitproto and transport are walked RECURSIVELY (their subpackages —
	// gitproto/pktline, transport/http, transport/ssh — are core protocol/transport
	// code that must also stay free of the seams; a top-level-only ReadDir would
	// miss the frontend files, which is exactly where a core dep would creep in).
	// policy is scanned TOP-LEVEL ONLY: its subpackage internal/policy/rules holds
	// rule implementations that MAY legitimately type-assert a capability in a
	// future rule (e.g. "require a PR exists before pushing to a protected branch"),
	// so scanning rules/ would create false alarms. cmd/git-proxy has no subpackages.
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
			if capabilitySeams[ident.Name] {
				t.Errorf("%s: %s references %s — the core must not depend on the optional capability sub-interface (type-assert at runtime instead)",
					fset.Position(ident.Pos()), path, ident.Name)
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