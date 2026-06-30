// Package gitx shells out to the git binary for the inspection-side operations
// the push enforcement path needs: maintaining a read-only bare mirror of the
// upstream, ingesting a pushed packfile's objects, and walking ancestry. The
// mirror is never a push target and is never served to the agent; it exists
// only so the policy engine can compute fast-forward flags without giving the
// agent access to upstream credentials.
package gitx

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
)

// runGit runs `git -C dir <args...>` with ctx, returning stdout. A non-zero exit
// is surfaced as an error carrying stderr. The ctx cancellation kills the
// process (exec.CommandContext default). No secrets are passed via args;
// upstream credentials, when needed, are embedded in the upstream URL by the
// caller (see Open), never in argv.
func runGit(ctx context.Context, dir string, args ...string) ([]byte, error) {
	full := make([]string, 0, len(args)+2)
	full = append(full, "-C", dir)
	full = append(full, args...)
	cmd := exec.CommandContext(ctx, "git", full...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("git %s: %w: %s", args[0], err, bytes.TrimSpace(stderr.Bytes()))
	}
	return stdout.Bytes(), nil
}