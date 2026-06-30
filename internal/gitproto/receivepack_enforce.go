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
	dec := eng.EvaluatePush(pushReq)
	return dec, nil
}