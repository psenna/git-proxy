package gitproto_test

import (
	"bytes"
	"os/exec"
	"strings"
	"testing"

	"github.com/psenna/git-proxy/internal/gitproto/pktline"
)

// gitBinary skips the test if git is unavailable on PATH.
func gitBinary(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skipf("git not found on PATH: %v", err)
	}
}

// mustGit runs git in dir and fails the test on error.
func mustGit(t *testing.T, dir string, args ...string) {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git %s: %v\n%s", strings.Join(args, " "), err, out)
	}
}

// revParseHead returns `git rev-parse HEAD` run in dir.
func revParseHead(t *testing.T, dir string) string {
	t.Helper()
	out, err := exec.Command("git", "-C", dir, "rev-parse", "HEAD").Output()
	if err != nil {
		t.Fatalf("rev-parse HEAD: %v", err)
	}
	return strings.TrimSpace(string(out))
}

// pktlineEnc returns a pktline encoder writing into a fresh buffer bound to t.
// The buffer is returned so the caller can read the encoded stream.
func pktlineEnc(t *testing.T) (*pktline.Encoder, *bytes.Buffer) {
	t.Helper()
	var buf bytes.Buffer
	return pktline.NewEncoder(&buf), &buf
}