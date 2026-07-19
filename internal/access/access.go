package access

import "github.com/psenna/git-proxy/internal/port"

// Decision is the outcome of an access check for the git leg.
type Decision int

const (
	// DecisionAllow permits the request to proceed to the upstream. The
	// upstream path attaches Basic auth iff CredentialsFor returns ok, so a
	// profiled repo is credentialed and an anonymous-read repo attaches
	// nothing.
	DecisionAllow Decision = iota
	// DecisionDeny rejects the request with 403 and does not reach upstream.
	DecisionDeny
)

// Decide is the shared tri-state for the git leg. Allow means "proceed; the
// upstream path attaches Basic iff CredentialsFor returns ok" (so a profiled
// repo is credentialed and an anonymous-read repo attaches nothing). Deny
// means respond 403 and do not reach upstream. isWrite is true for receive-pack
// (push); pushes always require a credential, even for public_repos repos.
// Decide is fail-closed: nil creds and nil public deny both reads and writes.
func Decide(creds port.CredentialStore, public port.RepoMatcher, repo string, isWrite bool) Decision {
	if creds != nil {
		if _, ok := creds.CredentialsFor(repo); ok {
			return DecisionAllow
		}
	}
	if isWrite {
		return DecisionDeny
	}
	if public != nil && public.Match(repo) {
		return DecisionAllow
	}
	return DecisionDeny
}
