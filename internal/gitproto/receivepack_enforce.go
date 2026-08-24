package gitproto

import (
	"context"
	"fmt"

	"github.com/psenna/git-proxy/internal/gitx"
	"github.com/psenna/git-proxy/internal/policy"
	"github.com/psenna/git-proxy/internal/port"
)

// zeroOID is the 40-zero object id git sends for a ref creation's old value
// and a ref deletion's new value. It is normalized to "" so port.RefUpdate's
// IsCreate/IsDelete fire correctly.
const zeroOID = "0000000000000000000000000000000000000000"

// normalizeOID translates the all-zero OID git sends on the wire into the empty
// string the policy contract uses to signal "no object" (ref create / delete).
// Other OIDs are returned unchanged.
func normalizeOID(oid string) string {
	if oid == zeroOID {
		return ""
	}
	return oid
}

// isHexSHA reports whether s is a well-formed 40-char lowercase-hex SHA-1
// object id. Every ref-update Old/New value MUST pass this check before it is
// allowed anywhere near a git subprocess argument (IsAncestor,
// NewCommitMessages, ChangedFiles all splice these values into "git log"/"git
// diff"/"git rev-list" argv with no "--" separator). Without this gate, a
// wire value like "--output=/home/proxy/.gitconfig" is not a revision at all
// — it is parsed by git as an OPTION, letting a ref-update command write
// attacker-influenced content (e.g. a reachable commit's message) to an
// arbitrary path on the proxy host during evaluation, before any allow/deny
// decision is reached. Strict allowlist validation (not escaping, not a "--"
// separator alone) is the fix: a value that must be exactly 40 hex digits can
// never begin with "-" or be misparsed as anything but an object id.
func isHexSHA(s string) bool {
	if len(s) != 40 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
}

// EnforceReceivePack computes the push decision for a parsed receive-pack
// request. It computes per-command Force flags by walking ancestry in the
// mirror (create/delete are never force; an update is force when new is NOT a
// descendant of old), builds a port.PushRequest, and evaluates it against the
// engine. The mirror must already have been Refreshed and, when a packfile is
// present, have ingested it via IngestPackfile so both old and new objects are
// available for the ancestry walk.
//
// Fail-closed: an ancestry error (e.g. a missing object) yields a Deny
// decision carrying the error as a reason — the push is never allowed when its
// topology could not be verified.
func EnforceReceivePack(ctx context.Context, req *ReceivePackRequest, mirror *gitx.Mirror,
	eng *policy.Engine, agent, repo string) (port.Decision, error) {

	updates := make([]port.RefUpdate, 0, len(req.Commands))
	for _, cmd := range req.Commands {
		old := normalizeOID(cmd.Old)
		new := normalizeOID(cmd.New)

		// Fail-closed on a malformed object id. This is an INSPECTION failure,
		// not a policy verdict, so it returns a non-nil error alongside the
		// Deny decision — the same posture as the ancestry-check failure
		// below. That distinction matters: the proxy's dry-run mode forwards
		// a "clean" engine deny (enErr == nil) so operators can observe
		// policy violations without enforcing them, but it must NEVER forward
		// a push the proxy could not safely inspect. A malformed old/new is
		// exactly that case — see isHexSHA's doc comment for why.
		if (old != "" && !isHexSHA(old)) || (new != "" && !isHexSHA(new)) {
			err := fmt.Errorf("malformed object id for ref %s", cmd.Ref)
			return port.Decision{
				Verdict: port.VerdictDeny,
				Reasons: []port.Reason{{
					Rule:    "enforcement",
					Message: fmt.Sprintf("push rejected: malformed object id for ref %s", cmd.Ref),
				}},
			}, err
		}

		u := port.RefUpdate{Ref: cmd.Ref, Old: old, New: new}

		switch {
		case u.IsCreate() || u.IsDelete():
			// Create/delete are not force-pushes; the engine decides per rule.
			u.Force = false
		default:
			ok, err := mirror.IsAncestor(ctx, old, new)
			if err != nil {
				// Fail-closed: topology could not be verified. Return a deny
				// decision with the error as a reason; do NOT allow.
				return port.Decision{
					Verdict: port.VerdictDeny,
					Reasons: []port.Reason{{
						Rule:    "enforcement",
						Message: fmt.Sprintf("ancestry check failed for %s: %v", cmd.Ref, err),
					}},
				}, err
			}
			u.Force = !ok // non-fast-forward when old is not an ancestor of new
		}
		updates = append(updates, u)
	}

	pushReq := port.PushRequest{
		Agent:      agent,
		Repo:       repo,
		RefUpdates: updates,
	}

	// Populate the new-commits and changed-files context the push rules need
	// (commit_message, path_acl, secret_scan). Fail-closed: ANY mirror
	// extraction error yields a Deny carrying the error as a reason — the push
	// is never allowed when its contents could not be inspected. Mirror errors
	// are already redacted of upstream credentials by gitx.redactCreds.
	//
	// Commit SHAs + messages are fetched in a SINGLE git invocation under ONE
	// lock acquisition (Mirror.NewCommitMessages) rather than one
	// NewCommits + one CommitMessage call per commit, so a push introducing
	// many commits does not churn the per-mirror mutex.
	commits, err := mirror.NewCommitMessages(ctx, updates)
	if err != nil {
		return port.Decision{
			Verdict: port.VerdictDeny,
			Reasons: []port.Reason{{
				Rule:    "enforcement",
				Message: fmt.Sprintf("commit extraction failed: %v", err),
			}},
		}, err
	}
	pushReq.Commits = commits
	files, err := mirror.ChangedFiles(ctx, updates)
	if err != nil {
		return port.Decision{
			Verdict: port.VerdictDeny,
			Reasons: []port.Reason{{
				Rule:    "enforcement",
				Message: fmt.Sprintf("changed-files extraction failed: %v", err),
			}},
		}, err
	}
	for i := range files {
		if files[i].Status == "D" || files[i].BlobOID == "" {
			continue
		}
		b, err := mirror.BlobContent(ctx, files[i].BlobOID)
		if err != nil {
			return port.Decision{
				Verdict: port.VerdictDeny,
				Reasons: []port.Reason{{
					Rule:    "enforcement",
					Message: fmt.Sprintf("blob-content extraction failed for %s: %v", files[i].Path, err),
				}},
			}, err
		}
		files[i].Content = b
	}
	pushReq.ChangedFiles = files

	dec := eng.EvaluatePush(pushReq)
	return dec, nil
}
