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
	"regexp"
	"strings"
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
		return nil, fmt.Errorf("git %s: %w: %s", args[0], err, redactCreds(string(bytes.TrimSpace(stderr.Bytes()))))
	}
	return stdout.Bytes(), nil
}

// credURLRe matches the userinfo component of a URL (scheme://user:pass@ or
// scheme://user@) so it can be stripped from git stderr before an error is
// returned. Git redacts only the password in its own messages; the username and
// host can still appear, so we strip the whole userinfo as defense in depth.
var credURLRe = regexp.MustCompile(`([a-zA-Z][a-zA-Z0-9+.\-]*://)([^\s/@:]+(?::[^\s/@]+)?)@`)

// redactCreds strips URL-embedded credentials (user:pass@ or user@) from s,
// replacing the userinfo with "***". This is a defense-in-depth measure so that
// even if a caller wraps a gitx error with %v, no upstream credentials leak into
// agent-facing strings. Non-credentialed URLs (no userinfo) are returned
// unchanged.
func redactCreds(s string) string {
	return credURLRe.ReplaceAllString(s, "${1}***@")
}

// corruptionPatterns are substrings that appear in git error messages when the
// object store is corrupt or missing objects. IsCorruptionError matches these
// against the full error chain (runGit wraps git stderr into the error message).
var corruptionPatterns = []string{
	"bad object",      // git rev-list/cat-file: "fatal: bad object <sha>"
	"missing object",  // git: "fatal: missing object <sha>"
	"corrupt",          // git fsck/rev-list: "error: corrupt object"
	"loose object",    // git: "error: loose object <sha> (in ...) is corrupt"
	"unable to unpack", // git pack-objects: "fatal: unable to unpack <sha> header"
}

// IsCorruptionError reports whether err indicates a corrupt or missing object
// in a git mirror's object store. It matches git error message patterns that
// surface when the mirror's object database is damaged — the patterns that
// appear when an object the mirror believes it has (based on refs) is absent or
// unreadable. This covers rev-list, cat-file, pack-objects, and fsck failure
// modes. Designed for the mirror self-healing retry: a corruption error triggers
// a mirror Repair (re-clone) and a single retry of the enforce operation.
func IsCorruptionError(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	for _, pat := range corruptionPatterns {
		if strings.Contains(msg, pat) {
			return true
		}
	}
	return false
}
