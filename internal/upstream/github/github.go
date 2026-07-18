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
	"github.com/psenna/git-proxy/internal/upstream/github/rest"
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
// GitHub-specific capabilities (PRSupport) backed by the stdlib REST client
// (internal/upstream/github/rest). Construct with New; select via
// `upstream.kind: github` in config.
type Adapter struct {
	// *plain.Upstream promotes ListRefs, ListRefsService, UploadPack, and
	// ReceivePack — the four git-protocol methods — so the adapter satisfies
	// port.Upstream by delegating to the plain HTTP transport. GitHub serves
	// these endpoints verbatim, so delegation is correct (not a stub).
	*plain.Upstream

	// restBase is the GitHub REST API root derived from cfg.URL (see
	// rest.BaseURL): https://api.github.com for github.com, or
	// <scheme>://<host>/api/v3 for a GHES instance. Empty when the URL was
	// malformed, in which case baseErr is set and every PRSupport method fails
	// closed with it.
	restBase string
	// creds resolves the per-repo GitHub token the adapter attaches as a
	// Bearer header on the REST leg. nil means no vault configured: every
	// SCM REST call fails closed with port.ErrUnauthorized (never anonymous).
	creds port.CredentialStore
	// baseErr is the error from deriving restBase at construction, if any. A
	// non-nil baseErr makes every PRSupport method fail closed so a malformed
	// upstream URL surfaces at the first SCM call (mirroring the plain
	// adapter's "malformed URL surfaces at first use") without changing New's
	// no-error signature.
	baseErr error
}

// New constructs a GitHub adapter from cfg. The git-protocol methods delegate
// to a plain HTTP upstream built from cfg.URL + cfg.CredentialsStore (GitHub
// speaks smart-HTTP git at the standard endpoints); the PRSupport methods are
// backed by the REST client using the per-repo token from cfg.CredentialsStore.
// New never returns an error — delegation to plain cannot fail at construction;
// a malformed URL (for either leg) surfaces at first use, as it does for the
// plain adapter.
func New(cfg upstream.UpstreamConfig) *Adapter {
	restBase, baseErr := rest.BaseURL(cfg.URL)
	return &Adapter{
		Upstream: plain.New(cfg.URL, cfg.CredentialsStore),
		restBase: restBase,
		creds:    cfg.CredentialsStore,
		baseErr:  baseErr,
	}
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
// The v1 seam carried this as a stub; the real REST call is left to a future
// follow-up that maps GitHub's branch-protection payload to
// port.BranchProtection. It returns port.ErrNotImplemented so a caller that
// type-asserts PRSupport sees "capability present but not wired" — distinct
// from the other PR/CI methods, which ARE wired below.
func (a *Adapter) BranchProtection(_ context.Context, _ string, _ string) (port.BranchProtection, error) {
	return port.BranchProtection{}, port.ErrNotImplemented
}

// EnsurePR creates a pull request on repo from head into base with title.
// GitHub REST: POST /repos/{owner}/{repo}/pulls. It is the create-side
// counterpart of GetPR: it returns the minimal port.PR (Number + URL) the
// policy layer needs, while GetPR/ListPRs return the richer port.PRState.
func (a *Adapter) EnsurePR(ctx context.Context, repo, head, base, title string) (port.PR, error) {
	c, err := a.restClient(repo)
	if err != nil {
		return port.PR{}, err
	}
	pr, err := c.CreatePR(ctx, repo, head, base, title)
	if err != nil {
		return port.PR{}, err
	}
	return port.PR{Number: pr.Number, URL: pr.URL}, nil
}

// GetPR fetches a single pull request by number and maps the rest PR shape to
// port.PRState. GitHub REST: GET /repos/{owner}/{repo}/pulls/{number}.
func (a *Adapter) GetPR(ctx context.Context, repo string, number int) (port.PRState, error) {
	c, err := a.restClient(repo)
	if err != nil {
		return port.PRState{}, err
	}
	pr, err := c.GetPR(ctx, repo, number)
	if err != nil {
		return port.PRState{}, err
	}
	return toPRState(pr), nil
}

// ListPRs lists pull requests on repo filtered by state and maps each rest PR
// to port.PRState. GitHub REST: GET /repos/{owner}/{repo}/pulls?state={state}.
func (a *Adapter) ListPRs(ctx context.Context, repo, state string) ([]port.PRState, error) {
	c, err := a.restClient(repo)
	if err != nil {
		return nil, err
	}
	prs, err := c.ListPRs(ctx, repo, state)
	if err != nil {
		return nil, err
	}
	out := make([]port.PRState, 0, len(prs))
	for _, pr := range prs {
		out = append(out, toPRState(pr))
	}
	return out, nil
}

// MergePR merges pull request number on repo using method. GitHub REST:
// PUT /repos/{owner}/{repo}/pulls/{number}/merge. The rest client maps a 409 to
// port.ErrNotMergeable, which the broker surfaces as HTTP 409.
func (a *Adapter) MergePR(ctx context.Context, repo string, number int, method string) error {
	c, err := a.restClient(repo)
	if err != nil {
		return err
	}
	return c.MergePR(ctx, repo, number, method)
}

// CommentPR adds a line comment to pull request number. GitHub REST:
// POST /repos/{owner}/{repo}/issues/{number}/comments.
func (a *Adapter) CommentPR(ctx context.Context, repo string, number int, body string) error {
	c, err := a.restClient(repo)
	if err != nil {
		return err
	}
	return c.CommentPR(ctx, repo, number, body)
}

// ReviewPR submits a review on pull request number with event and body.
// GitHub REST: POST /repos/{owner}/{repo}/pulls/{number}/reviews.
func (a *Adapter) ReviewPR(ctx context.Context, repo string, number int, event, body string) error {
	c, err := a.restClient(repo)
	if err != nil {
		return err
	}
	return c.ReviewPR(ctx, repo, number, event, body)
}

// Checks returns the rolled-up CI state for ref. GitHub REST:
// GET /repos/{owner}/{repo}/commits/{ref}/check-runs and
// /repos/{owner}/{repo}/actions/runs. The rest CheckSummary maps directly to
// port.CheckSummary (same field names + shapes).
func (a *Adapter) Checks(ctx context.Context, repo, ref string) (port.CheckSummary, error) {
	c, err := a.restClient(repo)
	if err != nil {
		return port.CheckSummary{}, err
	}
	s, err := c.Summary(ctx, repo, ref)
	if err != nil {
		return port.CheckSummary{}, err
	}
	return toCheckSummary(s), nil
}

// restClient builds a REST client for repo's per-repo token. It fails closed
// (returns an error, never an anonymous client) when no token is configured
// for repo, and surfaces a malformed upstream URL (baseErr) the same way.
func (a *Adapter) restClient(repo string) (*rest.Client, error) {
	if a.baseErr != nil {
		return nil, a.baseErr
	}
	tok, err := a.tokenFor(repo)
	if err != nil {
		return nil, err
	}
	return rest.New(a.restBase, tok), nil
}

// tokenFor resolves the GitHub token for repo from the vault. Fail closed: a
// nil vault, an unknown repo, or an empty Token all return port.ErrUnauthorized
// — the proxy NEVER makes an anonymous SCM REST call, which could expose
// unauthenticated rate limits or surface the wrong data.
func (a *Adapter) tokenFor(repo string) (string, error) {
	if a.creds == nil {
		return "", port.ErrUnauthorized
	}
	c, ok := a.creds.CredentialsFor(repo)
	if !ok || c.Token == "" {
		return "", port.ErrUnauthorized
	}
	return c.Token, nil
}

// toPRState maps the rest-internal PR shape to port.PRState. The fields line up
// one-for-one; the mapping is explicit (rather than a shared struct) so the
// rest package stays a pure GitHub client with no port dependency for its
// response shapes, per the rest package doc.
func toPRState(pr rest.PR) port.PRState {
	return port.PRState{
		Number:    pr.Number,
		Title:     pr.Title,
		State:     pr.State,
		Mergeable: pr.Mergeable,
		Head:      pr.Head,
		Base:      pr.Base,
		URL:       pr.URL,
	}
}

// toCheckSummary maps the rest-internal CheckSummary to port.CheckSummary. The
// rest and port check/workflow shapes share field names, so the per-element
// copy is mechanical and keeps the rest package free of a port import.
func toCheckSummary(s rest.CheckSummary) port.CheckSummary {
	checks := make([]port.CheckRun, 0, len(s.Checks))
	for _, cr := range s.Checks {
		checks = append(checks, port.CheckRun{Name: cr.Name, Status: cr.Status, Conclusion: cr.Conclusion})
	}
	workflows := make([]port.WorkflowRun, 0, len(s.Workflows))
	for _, wr := range s.Workflows {
		workflows = append(workflows, port.WorkflowRun{Name: wr.Name, Status: wr.Status, Conclusion: wr.Conclusion, URL: wr.HTMLURL})
	}
	return port.CheckSummary{Overall: s.Overall, Checks: checks, Workflows: workflows}
}