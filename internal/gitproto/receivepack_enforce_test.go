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
		if _, err := m.IngestPackfile(ctx, bytes.NewReader(packBytes)); err != nil {
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
	dec, err := gitproto.EnforceReceivePack(ctx, req, m, eng, "agent-1", "repo.git", "")
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

// TestEnforceReceivePack_MalformedOIDDenied proves the option-injection
// primitive is closed: a ref-update whose New field looks like a git option
// rather than a 40-hex object id must never reach a git subprocess argument.
// Before the fix, this exact shape ("--output=<path>" as New, on a create
// update) caused `git log --format=... --output=<path> --not --all` inside
// NewCommitMessages to write attacker-influenced content to an arbitrary
// filesystem path, as the proxy's own process, before any allow/deny decision
// was reached.
func TestEnforceReceivePack_MalformedOIDDenied(t *testing.T) {
	gitBinary(t)
	ctx := context.Background()

	source, tips := enforceSourceRepo(t, 1)
	m := enforceMirror(t, source, nil)
	_ = tips

	eng := enforceEngine(t, map[string]map[string]any{
		"branch_pattern": {"allow": []string{"refs/heads/**"}},
	})

	target := filepath.Join(t.TempDir(), "pwned")
	malicious := "--output=" + target

	req, _ := buildReceivePackRequest(t, [][3]string{{
		"0000000000000000000000000000000000000000", // create
		malicious,
		"refs/heads/feat/evil",
	}}, nil)

	dec, err := gitproto.EnforceReceivePack(ctx, req, m, eng, "agent-1", "repo.git", "")
	if err == nil {
		t.Fatal("EnforceReceivePack: want a non-nil inspection error for a malformed New OID, got nil " +
			"(a nil error here would let dry-run mode forward this push — see EnforceReceivePack's dry-run comment)")
	}
	if dec.Verdict != port.VerdictDeny {
		t.Fatalf("verdict = %v, want Deny", dec.Verdict)
	}
	if !reasonMentions(dec, "malformed object id") {
		t.Fatalf("deny reasons = %v, want a malformed-object-id reason", dec.Reasons)
	}
	if _, statErr := os.Stat(target); statErr == nil {
		t.Fatalf("option-injection succeeded: %s was created by the malicious New field", target)
	}
}

// TestEnforceReceivePack_MalformedOIDDenied_OldField is the same primitive via
// the Old field of an update (not create/delete), which takes the ancestry-walk
// path in the old code rather than the create/delete path.
func TestEnforceReceivePack_MalformedOIDDenied_OldField(t *testing.T) {
	gitBinary(t)
	ctx := context.Background()

	source, tips := enforceSourceRepo(t, 1)
	A := tips[0]
	pack := packObjects(t, source, A)
	m := enforceMirror(t, source, pack)

	eng := enforceEngine(t, map[string]map[string]any{
		"branch_pattern": {"allow": []string{"refs/heads/**"}},
	})

	target := filepath.Join(t.TempDir(), "pwned-old")
	malicious := "--output=" + target

	req, _ := buildReceivePackRequest(t, [][3]string{{malicious, A, "refs/heads/main"}}, pack)

	dec, err := gitproto.EnforceReceivePack(ctx, req, m, eng, "agent-1", "repo.git", "")
	if err == nil {
		t.Fatal("EnforceReceivePack: want a non-nil inspection error for a malformed Old OID, got nil")
	}
	if dec.Verdict != port.VerdictDeny {
		t.Fatalf("verdict = %v, want Deny", dec.Verdict)
	}
	if _, statErr := os.Stat(target); statErr == nil {
		t.Fatalf("option-injection succeeded: %s was created by the malicious Old field", target)
	}
}

// packObjectsWithExtra is packObjects plus one or more extra object OIDs
// appended to the rev-list input, so the resulting pack contains objects NOT
// reachable from tip. Used to simulate a client smuggling a stray object
// alongside a legitimate push (security review finding H6).
func packObjectsWithExtra(t *testing.T, dir, tip string, extraOIDs ...string) []byte {
	t.Helper()
	revList := exec.Command("git", "-C", dir, "rev-list", "--objects", tip)
	var revOut bytes.Buffer
	revList.Stdout = &revOut
	if err := revList.Run(); err != nil {
		t.Fatalf("rev-list --objects: %v", err)
	}
	for _, oid := range extraOIDs {
		revOut.WriteString(oid + "\n")
	}
	cmd := exec.Command("git", "-C", dir, "pack-objects", "--stdout")
	cmd.Stdin = &revOut
	var out bytes.Buffer
	cmd.Stdout = &out
	if err := cmd.Run(); err != nil {
		t.Fatalf("pack-objects: %v", err)
	}
	if out.Len() == 0 {
		t.Fatalf("pack-objects produced no bytes for tip %s + extras", tip)
	}
	return out.Bytes()
}

// TestEnforceReceivePack_StrayObjectDenied is the security review H6
// regression guard: a packfile containing an object NOT reachable from any
// declared ref update must be denied, even though the declared update itself
// is perfectly legitimate. Before this fix, nothing checked the pack's
// contents against the declared updates — an authorized agent could smuggle
// an extra, never-scanned blob into the upstream's object store (forwarded
// verbatim on allow), retrievable later by anyone who knows its exact SHA,
// without ever passing through secret_scan/path_acl/commit_message.
func TestEnforceReceivePack_StrayObjectDenied(t *testing.T) {
	gitBinary(t)
	ctx := context.Background()

	source, tips := enforceSourceRepo(t, 1)
	tip := tips[0]
	m := enforceMirror(t, source, nil)

	// An orphan blob unrelated to tip's history — never reachable from any
	// commit, tree, or the ref being created.
	orphan := exec.Command("git", "-C", source, "hash-object", "-w", "--stdin")
	orphan.Stdin = strings.NewReader("smuggled-content-not-part-of-any-commit\n")
	orphanOut, err := orphan.Output()
	if err != nil {
		t.Fatalf("hash-object -w: %v", err)
	}
	orphanOID := strings.TrimSpace(string(orphanOut))

	pack := packObjectsWithExtra(t, source, tip, orphanOID)
	packID, err := m.IngestPackfile(ctx, bytes.NewReader(pack))
	if err != nil {
		t.Fatalf("IngestPackfile: %v", err)
	}

	eng := enforceEngine(t, map[string]map[string]any{
		"branch_pattern": {"allow": []string{"refs/heads/**"}},
	})
	req, _ := buildReceivePackRequest(t, [][3]string{{
		"0000000000000000000000000000000000000000", // create
		tip,
		"refs/heads/feat/x",
	}}, nil)

	dec, err := gitproto.EnforceReceivePack(ctx, req, m, eng, "agent-1", "repo.git", packID)
	if err == nil {
		t.Fatal("EnforceReceivePack: want a non-nil inspection error for a stray object, got nil " +
			"(a nil error here would let dry-run mode forward this push)")
	}
	if dec.Verdict != port.VerdictDeny {
		t.Fatalf("verdict = %v, want Deny", dec.Verdict)
	}
	if !reasonMentions(dec, "not reachable from the declared ref updates") {
		t.Fatalf("deny reasons = %v, want a not-reachable reason", dec.Reasons)
	}
}

// TestEnforceReceivePack_NormalPushWithPackIDAllowed is the false-positive
// regression guard for H6: an entirely ordinary push (a fresh create,
// packed as the full object closure reachable from its tip — no stray
// content) must still be ALLOWED when packID is wired in, proving the
// pack-contents check does not spuriously deny legitimate pushes.
func TestEnforceReceivePack_NormalPushWithPackIDAllowed(t *testing.T) {
	gitBinary(t)
	ctx := context.Background()

	source, tips := enforceSourceRepo(t, 2) // A -> B
	A, B := tips[0], tips[1]
	m := enforceMirror(t, source, nil)

	pack := packObjects(t, source, B)
	packID, err := m.IngestPackfile(ctx, bytes.NewReader(pack))
	if err != nil {
		t.Fatalf("IngestPackfile: %v", err)
	}

	eng := enforceEngine(t, map[string]map[string]any{
		"branch_pattern": {"allow": []string{"refs/heads/feat/*"}},
	})
	req, _ := buildReceivePackRequest(t, [][3]string{{A, B, "refs/heads/feat/x"}}, nil)

	dec, err := gitproto.EnforceReceivePack(ctx, req, m, eng, "agent-1", "repo.git", packID)
	if err != nil {
		t.Fatalf("EnforceReceivePack: %v", err)
	}
	if dec.Verdict != port.VerdictAllow {
		t.Fatalf("verdict = %v, want Allow (ordinary push, no stray objects): reasons=%v", dec.Verdict, dec.Reasons)
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
	dec, err := gitproto.EnforceReceivePack(ctx, req, m, eng, "agent-1", "repo.git", "")
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
	dec, err := gitproto.EnforceReceivePack(ctx, req, m, eng, "agent-1", "repo.git", "")
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
	dec, err := gitproto.EnforceReceivePack(ctx, req, m, eng, "agent-1", "repo.git", "")
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
	dec, err := gitproto.EnforceReceivePack(ctx, req, m, eng, "agent-1", "repo.git", "")
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
	// Pack the full object closure reachable from tip (commits, trees, blobs) so
	// the mirror has everything the enforcement path's extraction methods need
	// (commit messages, changed-file oids, blob contents) — mirroring what a
	// real client push sends.
	revList := exec.Command("git", "-C", dir, "rev-list", "--objects", tip)
	var revOut bytes.Buffer
	revList.Stdout = &revOut
	if err := revList.Run(); err != nil {
		t.Fatalf("rev-list --objects: %v", err)
	}
	cmd := exec.Command("git", "-C", dir, "pack-objects", "--stdout")
	cmd.Stdin = &revOut
	var out bytes.Buffer
	cmd.Stdout = &out
	if err := cmd.Run(); err != nil {
		t.Fatalf("pack-objects: %v", err)
	}
	if out.Len() == 0 {
		t.Fatalf("pack-objects produced no bytes for tip %s", tip)
	}
	return out.Bytes()
}
