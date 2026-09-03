// Package preflight is a STARTUP DIAGNOSTIC: for each credential profile it
// probes whether the profile's token can read the upstream API families the
// enabled ops need, and logs a WARNING naming the profile, the missing
// permission, and the affected repo/pattern.
//
// Warn-only and non-fatal by construction: Run returns nothing, never blocks
// startup, and never participates in an allow/deny decision. It must never be
// assigned to or consulted by any decision path — it exists only so an
// operator sees, at boot, that (for example) a profile whose PAT can read
// Actions but not Checks will make ci.status fall back to Actions-only.
//
// No-leak: every line Run logs names only a failure class, a profile name, a
// permission label, and a repo or pattern — never a token value, never a URL
// with credentials, never an upstream response body. Tokens are fetched from
// the TokenSource immediately before a probe and never logged.
//
// The package is provider-agnostic: the actual API calls sit behind the Prober
// interface, resolved by kind through the registry (registry.go), mirroring
// internal/upstream/registry.go. Import direction:
// internal/upstream/github -> internal/preflight -> internal/port + stdlib.
package preflight

import (
	"context"
	"errors"
	"log"
	"sync"
	"time"

	"github.com/psenna/git-proxy/internal/port"
)

// Permission is one upstream API family the proxy may need to read on the
// proxy->upstream leg for an enabled op to work.
type Permission string

const (
	PermMetadata     Permission = "metadata"
	PermContents     Permission = "contents"
	PermChecks       Permission = "checks"
	PermActions      Permission = "actions"
	PermPullRequests Permission = "pull_requests"
	PermIssues       Permission = "issues"
)

// permOrder is the canonical, stable order permissions are probed and logged
// in. PermissionsFor and every per-profile result walk it so output is
// deterministic and unit-assertable.
var permOrder = []Permission{
	PermMetadata, PermContents, PermChecks, PermActions, PermPullRequests, PermIssues,
}

// Label returns the operator-facing name of the permission, e.g.
// "Checks (check-runs API)". Used verbatim in the WARNING lines.
func (p Permission) Label() string {
	switch p {
	case PermMetadata:
		return "metadata (repo API)"
	case PermContents:
		return "Contents (commits API)"
	case PermChecks:
		return "Checks (check-runs API)"
	case PermActions:
		return "Actions (workflow-runs API)"
	case PermPullRequests:
		return "Pull requests (pulls API)"
	case PermIssues:
		return "Issues (issues API)"
	default:
		return string(p)
	}
}

// consequence is the operator-facing sentence describing what breaks when the
// permission is missing. Owned by this package (not the caller) so the wording
// stays consistent.
func (p Permission) consequence() string {
	switch p {
	case PermMetadata:
		return "every credentialed op on this repo will fail closed"
	case PermContents:
		return "clone/fetch and push will fail closed"
	case PermChecks:
		return "ci.status falls back to Actions-only (checks_unavailable=true); ci.log resolves check names from Actions job names"
	case PermActions:
		return "ci.status reports check runs only; ci.log unavailable"
	case PermPullRequests:
		return "pr.* ops will fail closed"
	case PermIssues:
		return "issue.* ops will fail closed"
	default:
		return "the dependent ops will fail closed"
	}
}

// Features is the set of proxy features that are actually enabled; it decides
// which permissions the preflight probes.
type Features struct {
	Git       bool // git-protocol leg (clone/fetch/push)
	BrokerPRs bool // any broker pr.* op allowed
	CIStatus  bool // broker ci.status allowed
	CILog     bool // broker ci.log allowed (and AllowCheckLogs)
	Issues    bool // any broker issue.* op allowed (issue_upstream leg)
}

// PermissionsFor returns the permissions the preflight should probe for f, in
// permOrder. Pure and table-tested.
func PermissionsFor(f Features) []Permission {
	want := map[Permission]bool{}
	any := f.Git || f.BrokerPRs || f.CIStatus || f.CILog || f.Issues
	if any {
		want[PermMetadata] = true
	}
	if f.Git {
		want[PermContents] = true
	}
	if f.CIStatus || f.CILog {
		want[PermChecks] = true
		want[PermActions] = true
	}
	if f.BrokerPRs {
		want[PermPullRequests] = true
	}
	if f.Issues {
		want[PermIssues] = true
	}
	out := make([]Permission, 0, len(want))
	for _, p := range permOrder {
		if want[p] {
			out = append(out, p)
		}
	}
	return out
}

// Profile is the secret-free view of a credential profile the preflight needs:
// its name, its human description, its repo patterns, and whether it resolved a
// token at all. It NEVER carries the secret itself — the token is fetched from
// the TokenSource by name, immediately before a probe.
type Profile struct {
	Name        string
	Description string
	Repos       []string
	HasToken    bool
}

// TokenSource resolves a profile's token by name. The only secret-by-name
// accessor; the returned value is used for one probe and never logged.
type TokenSource interface {
	TokenForProfile(name string) (string, bool)
}

// ErrNoSample is returned by Prober.SampleRepo when no concrete repo can be
// derived from a wildcard pattern (empty listing, forbidden listing, or an
// unsupported pattern shape). The caller logs a "not probed" note and moves on.
var ErrNoSample = errors.New("preflight: no sample repo available")

// Prober performs the actual upstream reads. Probe outcomes:
//
//	nil                     the family is readable
//	port.ErrForbidden       the permission is missing -> WARNING
//	port.ErrUnauthorized    the credential is rejected -> stop probing this profile
//	port.ErrRateLimited     abort Run entirely
//	any other error         inconclusive, NOT reported as missing
type Prober interface {
	Probe(ctx context.Context, token, repo string, perm Permission) error
	SampleRepo(ctx context.Context, token, pattern string) (string, error)
}

// Default bounds. All are overridable via Options; a zero field takes the
// default.
const (
	DefaultBudget       = 30 * time.Second
	DefaultProbeTimeout = 3 * time.Second
	DefaultMaxRepos     = 20
	DefaultConcurrency  = 4
)

// Options configures one Run.
type Options struct {
	Perms              []Permission
	Prober             Prober
	Tokens             TokenSource
	Logger             *log.Logger // nil -> log.Default()
	Label              string      // "" (SCM leg) or "issue_upstream"
	Budget             time.Duration
	ProbeTimeout       time.Duration
	MaxReposPerProfile int
	Concurrency        int
}

// legTag renders the log-line leg qualifier: "" for the SCM leg, "[label] "
// otherwise.
func legTag(label string) string {
	if label == "" {
		return ""
	}
	return "[" + label + "] "
}

// probeItem is one (repo, permission) unit of work.
type probeItem struct {
	repo        string
	sampledFrom string // "" unless repo was sampled from a wildcard pattern
	perm        Permission
}

// Run probes every profile and logs findings. It never errors, never blocks
// startup, and never returns a value a decision path could consult. Safe to
// call on a nil profile slice / zero Options (it just returns).
func Run(ctx context.Context, profiles []Profile, opts Options) {
	logger := opts.Logger
	if logger == nil {
		logger = log.Default()
	}
	if opts.Prober == nil || opts.Tokens == nil || len(opts.Perms) == 0 || len(profiles) == 0 {
		return
	}
	budget := orDur(opts.Budget, DefaultBudget)
	probeTimeout := orDur(opts.ProbeTimeout, DefaultProbeTimeout)
	maxRepos := orInt(opts.MaxReposPerProfile, DefaultMaxRepos)
	conc := orInt(opts.Concurrency, DefaultConcurrency)
	perms := opts.Perms
	leg := legTag(opts.Label)

	start := time.Now()
	bctx, cancel := context.WithTimeout(ctx, budget)
	defer cancel()

	planned := 0
	for _, p := range profiles {
		planned += len(p.Repos)
	}

	var (
		probedRepos int
		handled     int
		warnings    int
		aborted     bool // rate limited
	)

	for _, p := range profiles {
		if aborted {
			break
		}
		if bctx.Err() != nil {
			break
		}
		if !p.HasToken {
			logger.Printf("git-proxy: preflight: %sprofile %q: skipped (no token; broker ops for its repos are not credentialed)", leg, p.Name)
			continue
		}
		token, ok := opts.Tokens.TokenForProfile(p.Name)
		if !ok || token == "" {
			logger.Printf("git-proxy: preflight: %sprofile %q: skipped (no token; broker ops for its repos are not credentialed)", leg, p.Name)
			continue
		}

		repos := p.Repos
		capped := 0
		if len(repos) > maxRepos {
			capped = len(repos) - maxRepos
			repos = repos[:maxRepos]
		}

		// Resolve each pattern to a concrete repo (sampling wildcards).
		type target struct {
			repo        string
			sampledFrom string
		}
		var targets []target
		for _, pat := range repos {
			if bctx.Err() != nil {
				break
			}
			if !hasWildcard(pat) {
				targets = append(targets, target{repo: pat})
				continue
			}
			if !isOwnerWildcard(pat) {
				logger.Printf("git-proxy: preflight: %sprofile %q: pattern %q not probed (wildcard, no sample available)", leg, p.Name, pat)
				handled++
				continue
			}
			sctx, scancel := context.WithTimeout(bctx, probeTimeout)
			sample, serr := opts.Prober.SampleRepo(sctx, token, pat)
			scancel()
			if serr != nil || sample == "" {
				logger.Printf("git-proxy: preflight: %sprofile %q: pattern %q not probed (wildcard, no sample available)", leg, p.Name, pat)
				handled++
				continue
			}
			targets = append(targets, target{repo: sample, sampledFrom: pat})
		}

		// Build the (repo x perm) work list in declaration order.
		var items []probeItem
		for _, tg := range targets {
			for _, perm := range perms {
				items = append(items, probeItem{repo: tg.repo, sampledFrom: tg.sampledFrom, perm: perm})
			}
		}

		results := runItems(bctx, opts.Prober, token, items, conc, probeTimeout)

		// Walk results in declaration order and log.
		unauthorized := false
		// group per repo so the combined CI line can replace the two singles.
		byRepo := map[string]map[Permission]error{}
		repoOrder := []string{}
		sampledOf := map[string]string{}
		seenRepo := map[string]bool{}
		for i, it := range items {
			if !seenRepo[it.repo] {
				seenRepo[it.repo] = true
				repoOrder = append(repoOrder, it.repo)
				byRepo[it.repo] = map[Permission]error{}
				sampledOf[it.repo] = it.sampledFrom
			}
			byRepo[it.repo][it.perm] = results[i]
			if errors.Is(results[i], port.ErrRateLimited) {
				aborted = true
			}
			if errors.Is(results[i], port.ErrUnauthorized) {
				unauthorized = true
			}
		}
		probedRepos += len(repoOrder)
		handled += len(repoOrder)

		if unauthorized {
			logger.Printf("git-proxy: WARNING: preflight: %sprofile %q: upstream rejected the token (unauthorized); every credentialed op for its repos will fail closed", leg, p.Name)
			warnings++
			if capped > 0 {
				logger.Printf("git-proxy: preflight: %sprofile %q: %d repo pattern(s) not probed (per-profile cap %d)", leg, p.Name, capped, maxRepos)
			}
			continue
		}

		for _, repo := range repoOrder {
			res := byRepo[repo]
			sampled := sampledOf[repo]
			checksMissing := errors.Is(res[PermChecks], port.ErrForbidden)
			actionsMissing := errors.Is(res[PermActions], port.ErrForbidden)
			combinedCI := checksMissing && actionsMissing
			if combinedCI {
				logger.Printf("git-proxy: WARNING: preflight: %sprofile %q: token cannot read %s or %s for %s — ci.status and ci.log will fail closed for this repo",
					leg, p.Name, PermChecks.Label(), PermActions.Label(), repo)
				warnings++
			}
			for _, perm := range permOrder {
				err, probed := res[perm]
				if !probed {
					continue
				}
				if combinedCI && (perm == PermChecks || perm == PermActions) {
					continue
				}
				switch {
				case err == nil:
					// readable
				case errors.Is(err, port.ErrForbidden):
					if sampled != "" {
						logger.Printf("git-proxy: WARNING: preflight: %sprofile %q: token cannot read %s for %s (sampled from pattern %q) — %s",
							leg, p.Name, perm.Label(), repo, sampled, perm.consequence())
					} else {
						logger.Printf("git-proxy: WARNING: preflight: %sprofile %q: token cannot read %s for %s — %s",
							leg, p.Name, perm.Label(), repo, perm.consequence())
					}
					warnings++
				default:
					// ErrNotFound / transport / decode -> inconclusive, not a verdict.
					logger.Printf("git-proxy: preflight: %sprofile %q: probe for %s inconclusive (upstream error); not a permission verdict",
						leg, p.Name, perm.Label())
				}
			}
		}

		if capped > 0 {
			logger.Printf("git-proxy: preflight: %sprofile %q: %d repo pattern(s) not probed (per-profile cap %d)", leg, p.Name, capped, maxRepos)
		}
	}

	unchecked := planned - handled
	if unchecked < 0 {
		unchecked = 0
	}
	if aborted {
		logger.Printf("git-proxy: WARNING: preflight: %saborted — upstream rate limited; %d repo(s) unchecked", leg, unchecked)
	} else if bctx.Err() == context.DeadlineExceeded && unchecked > 0 {
		logger.Printf("git-proxy: preflight: %sbudget %s exceeded; %d repo(s) unchecked", leg, budget, unchecked)
	}

	dur := time.Since(start).Round(time.Millisecond)
	if warnings == 0 {
		logger.Printf("git-proxy: preflight: %s%d profile(s), %d repo(s) probed in %s; no missing permissions", leg, len(profiles), probedRepos, dur)
	} else {
		logger.Printf("git-proxy: preflight: %s%d profile(s), %d repo(s) probed in %s; %d warning(s) — see above", leg, len(profiles), probedRepos, dur, warnings)
	}
}

// runItems runs the probes with a fixed worker pool and returns results indexed
// by input position (so the caller logs in declaration order regardless of
// completion order). A per-probe timeout bounds each call. If any probe returns
// ErrRateLimited or ErrUnauthorized the remaining not-yet-started probes are
// skipped (their result stays nil) and in-flight ones drain — ErrRateLimited
// aborts the whole Run, ErrUnauthorized only this profile (the caller decides
// from the results which happened).
func runItems(ctx context.Context, prober Prober, token string, items []probeItem, conc int, probeTimeout time.Duration) []error {
	results := make([]error, len(items))
	if len(items) == 0 {
		return results
	}
	if conc > len(items) {
		conc = len(items)
	}
	idx := make(chan int)
	var abort sync.Once
	abortCh := make(chan struct{})
	var wg sync.WaitGroup
	for w := 0; w < conc; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range idx {
				select {
				case <-abortCh:
					return
				default:
				}
				pctx, pcancel := context.WithTimeout(ctx, probeTimeout)
				err := prober.Probe(pctx, token, items[i].repo, items[i].perm)
				pcancel()
				results[i] = err
				if errors.Is(err, port.ErrRateLimited) || errors.Is(err, port.ErrUnauthorized) {
					abort.Do(func() { close(abortCh) })
				}
			}
		}()
	}
	for i := range items {
		select {
		case <-abortCh:
			close(idx)
			wg.Wait()
			return results
		case idx <- i:
		}
	}
	close(idx)
	wg.Wait()
	return results
}

func hasWildcard(p string) bool {
	for i := 0; i < len(p); i++ {
		if p[i] == '*' {
			return true
		}
	}
	return false
}

// isOwnerWildcard reports whether p is exactly "<owner>/*" (one slash, the
// second segment exactly "*"). Only this shape is sampled; every other wildcard
// shape is skipped with a note. A bare "*" cannot occur (repomatch rejects it
// at config load).
func isOwnerWildcard(p string) bool {
	slash := -1
	for i := 0; i < len(p); i++ {
		if p[i] == '/' {
			if slash != -1 {
				return false // more than one slash
			}
			slash = i
		}
	}
	if slash <= 0 {
		return false
	}
	return p[slash+1:] == "*" && !hasWildcard(p[:slash])
}

func orDur(v, d time.Duration) time.Duration {
	if v <= 0 {
		return d
	}
	return v
}

func orInt(v, d int) int {
	if v <= 0 {
		return d
	}
	return v
}
