// Package github is the worked-example SCM adapter for GitHub (v1.md M10). v1
// ships a SKELETON: the git smart-HTTP protocol methods delegate to the plain
// HTTP transport — GitHub serves the standard smart-HTTP git endpoints
// (/info/refs, /git-upload-pack, /git-receive-pack), so delegation is REAL, not
// a stub — while the SCM-specific capabilities (port.PRSupport: branch
// protection and pull requests via the GitHub REST API) are stubs returning
// port.ErrNotImplemented. The real GitHub REST calls (auth via a GitHub token,
// branch-protection CRUD, PR creation) are v2; the skeleton's job is to be a
// compiling, registered, documented worked example for adding a new SCM
// provider. See docs/extensibility.md.
//
// The adapter self-registers as "github" on the upstream default registry via
// init(); config selects it with `upstream.kind: github`.
package github

import (
	"context"

	"github.com/psenna/git-proxy/internal/port"
	"github.com/psenna/git-proxy/internal/upstream"
	"github.com/psenna/git-proxy/internal/upstream/plain"
)

// Compile-time checks that the adapter satisfies both seams. The first is the
// core seam (port.Upstream); the second is the optional capability seam
// (port.PRSupport) the core never depends on — only type-asserting code does.
var (
	_ port.Upstream  = (*Adapter)(nil)
	_ port.PRSupport = (*Adapter)(nil)
)

// Adapter is the GitHub SCM adapter. It embeds a plain HTTP upstream for the
// git smart-HTTP protocol (GitHub speaks plain smart-HTTP git) and adds the
// GitHub-specific capability stubs (PRSupport). Construct with New; select via
// `upstream.kind: github` in config.
type Adapter struct {
	// *plain.Upstream promotes ListRefs, ListRefsService, UploadPack, and
	// ReceivePack — the four git-protocol methods — so the adapter satisfies
	// port.Upstream by delegating to the plain HTTP transport. GitHub serves
	// these endpoints verbatim, so delegation is correct (not a stub).
	*plain.Upstream
}

// New constructs a GitHub adapter from cfg. The git-protocol methods delegate
// to a plain HTTP upstream built from cfg.URL + cfg.CredentialsStore (GitHub
// speaks smart-HTTP git at the standard endpoints); the PRSupport methods are
// ErrNotImplemented stubs (v2). New never returns an error — delegation to
// plain cannot fail at construction; a malformed URL surfaces at first use, as
// it does for the plain adapter.
func New(cfg upstream.UpstreamConfig) *Adapter {
	return &Adapter{Upstream: plain.New(cfg.URL, cfg.CredentialsStore)}
}

// init self-registers the GitHub adapter as "github" on the upstream default
// registry, mirroring how rules self-register via policy.RegisterRule. The
// registered factory wraps New (which returns the concrete *Adapter) into the
// UpstreamFactory signature (port.Upstream, error).
func init() {
	upstream.Register("github", func(cfg upstream.UpstreamConfig) (port.Upstream, error) {
		return New(cfg), nil
	})
}

// BranchProtection fetches the branch-protection rules for branch on repo.
// GitHub REST: GET /repos/{owner}/{repo}/branches/{branch}/protection.
//
// v1 skeleton: returns the zero BranchProtection and port.ErrNotImplemented.
// The real implementation (v2) authenticates with a GitHub token and decodes the
// protection payload into port.BranchProtection.
func (a *Adapter) BranchProtection(_ context.Context, _ string, _ string) (port.BranchProtection, error) {
	return port.BranchProtection{}, port.ErrNotImplemented
}

// EnsurePR creates a pull request on repo from head into base with title.
// GitHub REST: POST /repos/{owner}/{repo}/pulls.
//
// v1 skeleton: returns the zero PR and port.ErrNotImplemented. The real
// implementation (v2) authenticates with a GitHub token, POSTs the PR payload,
// and decodes the response into port.PR (Number + URL).
func (a *Adapter) EnsurePR(_ context.Context, _ string, _ string, _ string, _ string) (port.PR, error) {
	return port.PR{}, port.ErrNotImplemented
}