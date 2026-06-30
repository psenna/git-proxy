package gitproto_test

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/psenna/git-proxy/internal/gitproto"
	"github.com/psenna/git-proxy/internal/gitx"
	"github.com/psenna/git-proxy/internal/policy"
	_ "github.com/psenna/git-proxy/internal/policy/rules" // register rules via init()
	"github.com/psenna/git-proxy/internal/port"
)

// enforceEngine builds a policy.Engine from a map of rule-name -> params via
// the default registry (rules self-register through init()).
func enforceEngine(t *testing.T, rules map[string]map[string]any) *policy.Engine {
	t.Helper()
	cfg := policy.PolicyConfig{Mode: policy.FirstDeny, Rules: map[string]policy.RuleConfig{}}
	for name, params := range rules {
		cfg.Rules[name] = policy.RuleConfig{Enabled: true, Params: params}
	}
	eng, err := policy.Resolve(cfg, nil)
	if err != nil {
		t.Fatalf("policy.Resolve: %v", err)
	}
	return eng
}

// enforceSourceRepo creates a non-bare repo with a linear history and returns
// (dir, tips) where tips[i] is the SHA after i+1 commits.
func enforceSourceRepo(t *testing.T, n int) (string, []string) {
	t.Helper()
	dir := t.TempDir()
	mustGit(t, "", "init", "-q", "-b", "main", dir)
	mustGit(t, dir, "config", "user.email", "test@example.com")
	mustGit(t, dir, "config", "user.name", "Test")
	tips := make([]string, 0, n)
	for i := 0; i < n; i++ {
		name := "f" + string(rune('a'+i)) + ".txt"
		if err := os.WriteFile(filepath.Join(dir, name), []byte("x\n"), 0o644); err != nil {
			t.Fatalf("write: %v", err)
		}
		mustGit(t, dir, "add", name)
		mustGit(t, dir, "commit", "-q", "-m", "c"+string(rune('a'+i)))
		tips = append(tips, revParseHead(t, dir))
	}
	return dir, tips
}

// enforceMirror builds a mirror over a bare upstream seeded from sourceDir's
// main branch, then ingests packBytes (if non-nil) and returns the mirror.
func enforceMirror(t *testing.T, sourceDir string, packBytes []byte) *gitx.Mirror {
	t.Helper()
	ctx := context.Background()
	bareRoot := t.TempDir()
	bare := filepath.Join(bareRoot, "repo.git")
	mustGit(t, "", "init", "--bare", "-q", "-b", "main", bare)
	mustGit(t, sourceDir, "push", "-q", "file://"+bare, "main")
	m, err := gitx.Open(ctx, "file://"+bareRoot, "repo.git", t.TempDir(), nil)
	if err != nil {
		t.Fatalf("gitx.Open: %v", err)
	}
	if packBytes != nil {
		if err := m.IngestPackfile(ctx, bytes.NewReader(packBytes)); err != nil {
			t.Fatalf("IngestPackfile: %v", err)
		}
	}
	return m
}

// buildReceivePackRequest encodes a receive-pack request with the given
// commands (old new ref) and an optional packfile body, returning the parsed
// request plus the raw buffer (so the test can slice the pack bytes).
func buildReceivePackRequest(t *testing.T, cmds [][3]string, pack []byte) (*gitproto.ReceivePackRequest, []byte) {
	t.Helper()
	e, buf := pktlineEnc(t)
	for i, c := range cmds {
		line := c[0] + " " + c[1] + " " + c[2]
		if i == 0 {
			line += "\x00report-status"
		}
		line += "\n"
		if err := e.EncodeString(line); err != nil {
			t.Fatalf("encode cmd: %v", err)
		}
	}
	if err := e.Flush(); err != nil {
		t.Fatalf("flush: %v", err)
	}
	raw := buf.Bytes()
	if pack != nil {
		raw = append(raw, pack...)
	}
	req, err := gitproto.ParseReceivePackRequest(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	return req, raw
}

// TestEnforceReceivePack_ForcePushDenied sets up a protected-ref rule and a
// non-fast-forward update to refs/heads/main, then asserts EnforceReceivePack
// denies with the history_protect reason.
func TestEnforceReceivePack_ForcePushDenied(t *testing.T) {
	gitBinary(t)
	ctx := context.Background()

	source, tips := enforceSourceRepo(t, 2) // A(0) -> B(1)
	A, B := tips[0], tips[1]

	// Build a divergent commit C off A (non-FF to main which is at B).
	bare := mustBare(t, source)
	div := t.TempDir()
	mustGit(t, "", "clone", "-q", "file://"+bare, div)
	mustGit(t, div, "config", "user.email", "test@example.com")
	mustGit(t, div, "config", "user.name", "Test")
	mustGit(t, div, "checkout", "-q", "-b", "topic", A)
	if err := os.WriteFile(filepath.Join(div, "div.txt"), []byte("div\n"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	mustGit(t, div, "add", "div.txt")
	mustGit(t, div, "commit", "-q", "-m", "divergent C")
	C := revParseHead(t, div)

	pack := packObjects(t, div, C)
	m := enforceMirror(t, source, pack)

	eng := enforceEngine(t, map[string]map[string]any{
		"history_protect": {"refs": []string{"refs/heads/main"}},
	})

	req, _ := buildReceivePackRequest(t, [][3]string{{B, C, "refs/heads/main"}}, pack)
	dec, err := gitproto.EnforceReceivePack(ctx, req, m, eng, "agent-1", "repo.git")
	if err != nil {
		t.Fatalf("EnforceReceivePack: %v", err)
	}
	if dec.Verdict != port.VerdictDeny {
		t.Fatalf("verdict = %v, want Deny", dec.Verdict)
	}
	if !reasonMentions(dec, "force-push") {
		t.Fatalf("deny reasons = %v, want a force-push reason", dec.Reasons)
	}
}

// TestEnforceReceivePack_FastForwardAllowed sets up a fast-forward update to a
// feat/* ref and asserts the engine allows it (Force=false).
func TestEnforceReceivePack_FastForwardAllowed(t *testing.T) {
	gitBinary(t)
	ctx := context.Background()

	source, tips := enforceSourceRepo(t, 2) // A -> B
	A, B := tips[0], tips[1]

	pack := packObjects(t, source, B)
	m := enforceMirror(t, source, pack)

	eng := enforceEngine(t, map[string]map[string]any{
		"branch_pattern": {"allow": []string{"refs/heads/feat/*"}},
	})

	req, _ := buildReceivePackRequest(t, [][3]string{{A, B, "refs/heads/feat/x"}}, pack)
	dec, err := gitproto.EnforceReceivePack(ctx, req, m, eng, "agent-1", "repo.git")
	if err != nil {
		t.Fatalf("EnforceReceivePack: %v", err)
	}
	if dec.Verdict != port.VerdictAllow {
		t.Fatalf("verdict = %v, want Allow (FF to feat/*)", dec.Verdict)
	}
}

// TestEnforceReceivePack_CreateNotForce verifies a ref creation (old=zero OID)
// normalizes to Old="" and Force=false, and is allowed for an unprotected ref.
func TestEnforceReceivePack_CreateNotForce(t *testing.T) {
	gitBinary(t)
	ctx := context.Background()

	source, tips := enforceSourceRepo(t, 1) // A
	A := tips[0]

	pack := packObjects(t, source, A)
	m := enforceMirror(t, source, pack)

	eng := enforceEngine(t, map[string]map[string]any{
		"branch_pattern": {"allow": []string{"refs/heads/feat/*"}},
	})

	zero := strings.Repeat("0", 40)
	req, _ := buildReceivePackRequest(t, [][3]string{{zero, A, "refs/heads/feat/new"}}, pack)
	dec, err := gitproto.EnforceReceivePack(ctx, req, m, eng, "agent-1", "repo.git")
	if err != nil {
		t.Fatalf("EnforceReceivePack: %v", err)
	}
	if dec.Verdict != port.VerdictAllow {
		t.Fatalf("verdict = %v, want Allow (create on feat/*)", dec.Verdict)
	}
}

// TestEnforceReceivePack_DeleteNormalized verifies a ref deletion (new=zero OID)
// normalizes to New="" (IsDelete fires) and history_protect denies it on a
// protected ref.
func TestEnforceReceivePack_DeleteNormalized(t *testing.T) {
	gitBinary(t)
	ctx := context.Background()

	source, tips := enforceSourceRepo(t, 1) // A
	A := tips[0]

	m := enforceMirror(t, source, nil) // delete-only push: no pack

	eng := enforceEngine(t, map[string]map[string]any{
		"history_protect": {"refs": []string{"refs/heads/main"}},
	})

	zero := strings.Repeat("0", 40)
	req, _ := buildReceivePackRequest(t, [][3]string{{A, zero, "refs/heads/main"}}, nil)
	dec, err := gitproto.EnforceReceivePack(ctx, req, m, eng, "agent-1", "repo.git")
	if err != nil {
		t.Fatalf("EnforceReceivePack: %v", err)
	}
	if dec.Verdict != port.VerdictDeny {
		t.Fatalf("verdict = %v, want Deny (delete on protected ref)", dec.Verdict)
	}
	if !reasonMentions(dec, "deletion") {
		t.Fatalf("deny reasons = %v, want a deletion reason", dec.Reasons)
	}
}

// TestEnforceReceivePack_AncestryErrorFailsClosed references a new SHA the
// mirror does not have, and asserts EnforceReceivePack fails closed (verdict
// Deny) rather than allowing the push.
func TestEnforceReceivePack_AncestryErrorFailsClosed(t *testing.T) {
	gitBinary(t)
	ctx := context.Background()

	source, tips := enforceSourceRepo(t, 1) // A
	A := tips[0]

	m := enforceMirror(t, source, nil)

	bogus := strings.Repeat("1", 40) // not present in mirror
	eng := enforceEngine(t, map[string]map[string]any{
		"history_protect": {"refs": []string{"refs/heads/main"}},
	})

	req, _ := buildReceivePackRequest(t, [][3]string{{A, bogus, "refs/heads/main"}}, nil)
	dec, err := gitproto.EnforceReceivePack(ctx, req, m, eng, "agent-1", "repo.git")
	// Fail-closed: verdict must be Deny regardless of whether err is set.
	if dec.Verdict != port.VerdictDeny {
		t.Fatalf("verdict = %v, want Deny (fail-closed on ancestry error); err=%v", dec.Verdict, err)
	}
}

// --- helpers ---

func reasonMentions(dec port.Decision, sub string) bool {
	for _, r := range dec.Reasons {
		if strings.Contains(r.Message, sub) {
			return true
		}
	}
	return false
}

func mustBare(t *testing.T, sourceDir string) string {
	t.Helper()
	bare := filepath.Join(t.TempDir(), "src.git")
	mustGit(t, "", "init", "--bare", "-q", "-b", "main", bare)
	mustGit(t, sourceDir, "push", "-q", "file://"+bare, "main")
	return bare
}

func packObjects(t *testing.T, dir, tip string) []byte {
	t.Helper()
	cmd := exec.Command("git", "-C", dir, "pack-objects", "--stdout")
	cmd.Stdin = strings.NewReader(tip + "\n")
	var out bytes.Buffer
	cmd.Stdout = &out
	if err := cmd.Run(); err != nil {
		t.Fatalf("pack-objects: %v", err)
	}
	if out.Len() == 0 {
		cmd = exec.Command("git", "-C", dir, "pack-objects", "--stdout", "--revs")
		cmd.Stdin = strings.NewReader("--" + tip + "\n")
		cmd.Stdout = &out
		if err := cmd.Run(); err != nil {
			t.Fatalf("pack-objects --revs: %v", err)
		}
	}
	if out.Len() == 0 {
		t.Fatalf("pack-objects produced no bytes for tip %s", tip)
	}
	return out.Bytes()
}