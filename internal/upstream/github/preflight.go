package github

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strings"

	"github.com/psenna/git-proxy/internal/port"
	"github.com/psenna/git-proxy/internal/preflight"
	"github.com/psenna/git-proxy/internal/upstream/github/rest"
)

// Compile-time check that the GitHub prober satisfies the preflight seam.
var _ preflight.Prober = (*Prober)(nil)

// init self-registers the GitHub prober factory as "github" on the preflight
// registry, mirroring how the adapter self-registers on the upstream registry.
// Config selects it implicitly: main.go passes cfg.Upstream.Kind to
// preflight.ProberFor.
func init() {
	preflight.Register("github", func(upstreamURL string) (preflight.Prober, error) {
		base, err := rest.BaseURL(upstreamURL)
		if err != nil {
			return nil, err
		}
		return &Prober{base: base}, nil
	})
}

// Prober is the GitHub implementation of preflight.Prober. It holds only the
// REST API root (github.com or a GHES /api/v3); a fresh rest.Client is built
// per probe from the caller-supplied token (construction is I/O-free), so the
// Prober itself never holds a credential.
type Prober struct {
	base string
}

// Probe maps one permission to a bounded GitHub REST read and classifies the
// result. A plain 403 -> port.ErrForbidden ("missing"); 401 -> ErrUnauthorized;
// 429 / 403+X-RateLimit-Remaining:0 -> *RateLimitedError; anything else is
// returned as-is and the preflight treats it as inconclusive (never "missing").
func (p *Prober) Probe(ctx context.Context, token, repo string, perm preflight.Permission) error {
	rp, err := rest.RepoAPIPath(repo)
	if err != nil {
		return err
	}
	c := rest.New(p.base, token)
	switch perm {
	case preflight.PermMetadata:
		return c.Probe(ctx, rp)
	case preflight.PermContents:
		err := c.Probe(ctx, rp+"/commits?per_page=1")
		if errors.Is(err, port.ErrNotMergeable) {
			// 409 on the commits endpoint means an empty repo (no commits yet),
			// not a permission problem — mapError turns 409 into ErrNotMergeable.
			return nil
		}
		return err
	case preflight.PermChecks:
		err := c.Probe(ctx, rp+"/commits/HEAD/check-runs?per_page=1")
		if !errors.Is(err, port.ErrNotFound) {
			return err
		}
		// HEAD may 404 on an empty or unusual (GHES) repo; retry ONCE against
		// the resolved default branch before giving up. Still 404 (or the
		// lookup failed) -> return that, which the preflight treats as
		// inconclusive, never as "Checks missing".
		info, ierr := c.RepoInfo(ctx, repo)
		if ierr != nil || info.DefaultBranch == "" {
			return err
		}
		return c.Probe(ctx, rp+"/commits/"+url.PathEscape(info.DefaultBranch)+"/check-runs?per_page=1")
	case preflight.PermActions:
		return c.Probe(ctx, rp+"/actions/runs?per_page=1")
	case preflight.PermPullRequests:
		return c.Probe(ctx, rp+"/pulls?per_page=1&state=all")
	case preflight.PermIssues:
		return c.Probe(ctx, rp+"/issues?per_page=1&state=all")
	default:
		return fmt.Errorf("preflight: unknown permission %q", perm)
	}
}

// SampleRepo derives a concrete repo from a "<owner>/*" pattern by listing the
// owner's most-recently-updated repo. Any other pattern shape, an empty
// listing, or a forbidden/not-found listing yields preflight.ErrNoSample so the
// caller logs a "not probed" note and skips it. The result carries the ".git"
// suffix the proxy's repo keys use.
func (p *Prober) SampleRepo(ctx context.Context, token, pattern string) (string, error) {
	owner, ok := ownerOfWildcard(pattern)
	if !ok {
		return "", preflight.ErrNoSample
	}
	c := rest.New(p.base, token)
	names, err := c.ListOwnerRepos(ctx, owner, 1)
	if err != nil {
		if errors.Is(err, port.ErrForbidden) || errors.Is(err, port.ErrNotFound) {
			return "", preflight.ErrNoSample
		}
		return "", err
	}
	if len(names) == 0 {
		return "", preflight.ErrNoSample
	}
	return names[0] + ".git", nil
}

// ownerOfWildcard returns the owner segment of a "<owner>/*" pattern (exactly
// one slash, second segment exactly "*"), or ok=false for any other shape.
func ownerOfWildcard(pattern string) (string, bool) {
	owner, rest, found := strings.Cut(pattern, "/")
	if !found || rest != "*" || owner == "" || strings.Contains(owner, "*") {
		return "", false
	}
	return owner, true
}
