package preflight

import (
	"bytes"
	"context"
	"errors"
	"log"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/psenna/git-proxy/internal/port"
)

// fakeProber is a no-HTTP Prober: per-repo/per-permission verdicts and per-
// pattern sample results, injected directly.
type fakeProber struct {
	verdicts  map[string]map[Permission]error
	samples   map[string]string
	sampleErr map[string]error
	delay     time.Duration

	mu         sync.Mutex
	probeCount int
}

func (f *fakeProber) Probe(ctx context.Context, _ string, repo string, perm Permission) error {
	f.mu.Lock()
	f.probeCount++
	f.mu.Unlock()
	if f.delay > 0 {
		select {
		case <-time.After(f.delay):
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	if m, ok := f.verdicts[repo]; ok {
		return m[perm]
	}
	return nil
}

func (f *fakeProber) SampleRepo(_ context.Context, _ string, pattern string) (string, error) {
	if e, ok := f.sampleErr[pattern]; ok {
		return "", e
	}
	if r, ok := f.samples[pattern]; ok {
		return r, nil
	}
	return "", ErrNoSample
}

func (f *fakeProber) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.probeCount
}

type fakeTokens map[string]string

func (f fakeTokens) TokenForProfile(name string) (string, bool) {
	t, ok := f[name]
	return t, ok
}

// runCapture drives Run against a buffer-backed logger and returns the output.
func runCapture(t *testing.T, profiles []Profile, opts Options) string {
	t.Helper()
	var buf bytes.Buffer
	opts.Logger = log.New(&buf, "", 0)
	Run(context.Background(), profiles, opts)
	return buf.String()
}

func TestPermissionsFor(t *testing.T) {
	cases := []struct {
		name string
		f    Features
		want []Permission
	}{
		{"none", Features{}, nil},
		{"git", Features{Git: true}, []Permission{PermMetadata, PermContents}},
		{"ci", Features{CIStatus: true}, []Permission{PermMetadata, PermChecks, PermActions}},
		{"cilog only", Features{CILog: true}, []Permission{PermMetadata, PermChecks, PermActions}},
		{"prs", Features{BrokerPRs: true}, []Permission{PermMetadata, PermPullRequests}},
		{"issues", Features{Issues: true}, []Permission{PermMetadata, PermIssues}},
		{"all", Features{Git: true, BrokerPRs: true, CIStatus: true, CILog: true, Issues: true},
			[]Permission{PermMetadata, PermContents, PermChecks, PermActions, PermPullRequests, PermIssues}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := PermissionsFor(tc.f)
			if len(got) != len(tc.want) {
				t.Fatalf("PermissionsFor(%+v) = %v, want %v", tc.f, got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Fatalf("PermissionsFor(%+v) = %v, want %v", tc.f, got, tc.want)
				}
			}
		})
	}
}

func baseOpts(fp *fakeProber, perms ...Permission) Options {
	return Options{
		Perms:       perms,
		Prober:      fp,
		Tokens:      fakeTokens{"p": "tok"},
		Concurrency: 1,
	}
}

func oneProfile(repos ...string) []Profile {
	return []Profile{{Name: "p", Description: "profile p", Repos: repos, HasToken: true}}
}

func TestRun_AllPermitted_NoWarnings(t *testing.T) {
	fp := &fakeProber{}
	out := runCapture(t, oneProfile("o/r.git"), baseOpts(fp, PermMetadata, PermChecks, PermActions))
	if strings.Contains(out, "WARNING") {
		t.Errorf("unexpected WARNING:\n%s", out)
	}
	if !strings.Contains(out, "no missing permissions") {
		t.Errorf("missing summary:\n%s", out)
	}
}

func TestRun_MissingChecks_WarnsWithConsequence(t *testing.T) {
	fp := &fakeProber{verdicts: map[string]map[Permission]error{
		"o/r.git": {PermChecks: port.ErrForbidden},
	}}
	out := runCapture(t, oneProfile("o/r.git"), baseOpts(fp, PermMetadata, PermChecks, PermActions))
	want := `profile "p": token cannot read Checks (check-runs API) for o/r.git — ci.status falls back to Actions-only (checks_unavailable=true); ci.log resolves check names from Actions job names`
	if !strings.Contains(out, want) {
		t.Errorf("want line %q in:\n%s", want, out)
	}
	if strings.Contains(out, "or Actions (workflow-runs API)") {
		t.Errorf("combined CI line emitted when only Checks missing:\n%s", out)
	}
}

func TestRun_MissingChecksAndActions_CombinedLine(t *testing.T) {
	fp := &fakeProber{verdicts: map[string]map[Permission]error{
		"o/r.git": {PermChecks: port.ErrForbidden, PermActions: port.ErrForbidden},
	}}
	out := runCapture(t, oneProfile("o/r.git"), baseOpts(fp, PermMetadata, PermChecks, PermActions))
	want := `profile "p": token cannot read Checks (check-runs API) or Actions (workflow-runs API) for o/r.git — ci.status and ci.log will fail closed for this repo`
	if !strings.Contains(out, want) {
		t.Errorf("want combined line %q in:\n%s", want, out)
	}
	if strings.Contains(out, "token cannot read Checks (check-runs API) for o/r.git —") {
		t.Errorf("individual Checks line emitted alongside combined line:\n%s", out)
	}
}

func TestRun_MissingContents(t *testing.T) {
	fp := &fakeProber{verdicts: map[string]map[Permission]error{
		"o/r.git": {PermContents: port.ErrForbidden},
	}}
	out := runCapture(t, oneProfile("o/r.git"), baseOpts(fp, PermMetadata, PermContents))
	if !strings.Contains(out, "clone/fetch and push will fail closed") {
		t.Errorf("want contents consequence in:\n%s", out)
	}
}

func TestRun_MissingPullRequests(t *testing.T) {
	fp := &fakeProber{verdicts: map[string]map[Permission]error{
		"o/r.git": {PermPullRequests: port.ErrForbidden},
	}}
	out := runCapture(t, oneProfile("o/r.git"), baseOpts(fp, PermMetadata, PermPullRequests))
	if !strings.Contains(out, "pr.* ops will fail closed") {
		t.Errorf("want pr consequence in:\n%s", out)
	}
}

func TestRun_MissingIssues_LabelTagged(t *testing.T) {
	fp := &fakeProber{verdicts: map[string]map[Permission]error{
		"o/r.git": {PermIssues: port.ErrForbidden},
	}}
	opts := baseOpts(fp, PermMetadata, PermIssues)
	opts.Label = "issue_upstream"
	out := runCapture(t, oneProfile("o/r.git"), opts)
	if !strings.Contains(out, "[issue_upstream] profile \"p\":") {
		t.Errorf("want leg tag in:\n%s", out)
	}
	if !strings.Contains(out, "issue.* ops will fail closed") {
		t.Errorf("want issue consequence in:\n%s", out)
	}
}

func TestRun_Unauthorized_OneLineAndStopsProfile(t *testing.T) {
	fp := &fakeProber{verdicts: map[string]map[Permission]error{
		"a/r.git": {PermMetadata: port.ErrUnauthorized},
	}}
	out := runCapture(t, oneProfile("a/r.git", "b/r.git"), baseOpts(fp, PermMetadata, PermChecks))
	if !strings.Contains(out, `profile "p": upstream rejected the token (unauthorized)`) {
		t.Errorf("want unauthorized line in:\n%s", out)
	}
	if strings.Contains(out, "b/r.git") {
		t.Errorf("second repo probed after unauthorized:\n%s", out)
	}
	if fp.count() != 1 {
		t.Errorf("probeCount = %d, want 1 (stopped after unauthorized)", fp.count())
	}
}

func TestRun_RateLimited_Aborts(t *testing.T) {
	fp := &fakeProber{verdicts: map[string]map[Permission]error{
		"a/r.git": {PermMetadata: port.ErrRateLimited},
	}}
	profiles := []Profile{
		{Name: "p", Description: "p", Repos: []string{"a/r.git"}, HasToken: true},
		{Name: "q", Description: "q", Repos: []string{"c/r.git"}, HasToken: true},
	}
	opts := baseOpts(fp, PermMetadata, PermChecks)
	opts.Tokens = fakeTokens{"p": "tok", "q": "tok"}
	out := runCapture(t, profiles, opts)
	if !strings.Contains(out, "aborted — upstream rate limited") {
		t.Errorf("want abort line in:\n%s", out)
	}
	if strings.Contains(out, `profile "q"`) {
		t.Errorf("profile q probed after rate-limit abort:\n%s", out)
	}
	if fp.count() != 1 {
		t.Errorf("probeCount = %d, want 1", fp.count())
	}
}

func TestRun_BudgetExceeded_PartialWithNote(t *testing.T) {
	fp := &fakeProber{delay: 30 * time.Millisecond}
	profiles := []Profile{
		{Name: "p", Description: "p", Repos: []string{"a/r.git"}, HasToken: true},
		{Name: "q", Description: "q", Repos: []string{"c/r.git"}, HasToken: true},
	}
	opts := baseOpts(fp, PermMetadata)
	opts.Tokens = fakeTokens{"p": "tok", "q": "tok"}
	opts.Budget = 5 * time.Millisecond
	out := runCapture(t, profiles, opts)
	if !strings.Contains(out, "budget") || !strings.Contains(out, "exceeded") || !strings.Contains(out, "unchecked") {
		t.Errorf("want budget-exceeded note in:\n%s", out)
	}
}

func TestRun_PerProfileCap(t *testing.T) {
	repos := make([]string, 25)
	for i := range repos {
		repos[i] = "o/r" + string(rune('a'+i)) + ".git"
	}
	fp := &fakeProber{}
	opts := baseOpts(fp, PermMetadata)
	opts.MaxReposPerProfile = 20
	out := runCapture(t, oneProfile(repos...), opts)
	if !strings.Contains(out, "5 repo pattern(s) not probed (per-profile cap 20)") {
		t.Errorf("want cap note in:\n%s", out)
	}
}

func TestRun_Wildcard_SampledRepoInWarning(t *testing.T) {
	fp := &fakeProber{
		samples:  map[string]string{"example-org/*": "example-org/svc.git"},
		verdicts: map[string]map[Permission]error{"example-org/svc.git": {PermChecks: port.ErrForbidden}},
	}
	out := runCapture(t, oneProfile("example-org/*"), baseOpts(fp, PermMetadata, PermChecks, PermActions))
	if !strings.Contains(out, `for example-org/svc.git (sampled from pattern "example-org/*")`) {
		t.Errorf("want sampled qualifier in:\n%s", out)
	}
}

func TestRun_Wildcard_NoSample_SkipLine(t *testing.T) {
	fp := &fakeProber{sampleErr: map[string]error{"example-org/*": ErrNoSample}}
	out := runCapture(t, oneProfile("example-org/*"), baseOpts(fp, PermMetadata))
	if !strings.Contains(out, `pattern "example-org/*" not probed (wildcard, no sample available)`) {
		t.Errorf("want skip line in:\n%s", out)
	}
	if fp.count() != 0 {
		t.Errorf("probeCount = %d, want 0", fp.count())
	}
}

func TestRun_NoToken_SkipsProfile(t *testing.T) {
	fp := &fakeProber{}
	profiles := []Profile{{Name: "p", Description: "p", Repos: []string{"o/r.git"}, HasToken: false}}
	out := runCapture(t, profiles, baseOpts(fp, PermMetadata))
	if !strings.Contains(out, `profile "p": skipped (no token`) {
		t.Errorf("want skip line in:\n%s", out)
	}
	if fp.count() != 0 {
		t.Errorf("probeCount = %d, want 0", fp.count())
	}
}

func TestRun_InconclusiveUpstreamError_NotReportedAsMissing(t *testing.T) {
	fp := &fakeProber{verdicts: map[string]map[Permission]error{
		"o/r.git": {PermMetadata: errors.New("boom")},
	}}
	out := runCapture(t, oneProfile("o/r.git"), baseOpts(fp, PermMetadata))
	if !strings.Contains(out, "inconclusive") {
		t.Errorf("want inconclusive line in:\n%s", out)
	}
	if strings.Contains(out, "WARNING") {
		t.Errorf("inconclusive must not be a WARNING:\n%s", out)
	}
	if strings.Contains(out, "cannot read") {
		t.Errorf("inconclusive must not be reported as missing:\n%s", out)
	}
}

func TestRun_DeterministicOrder(t *testing.T) {
	mk := func() string {
		fp := &fakeProber{verdicts: map[string]map[Permission]error{
			"o/a.git": {PermChecks: port.ErrForbidden},
			"o/b.git": {PermPullRequests: port.ErrForbidden},
		}}
		opts := Options{
			Perms:       []Permission{PermMetadata, PermChecks, PermActions, PermPullRequests},
			Prober:      fp,
			Tokens:      fakeTokens{"p": "tok"},
			Concurrency: 4,
		}
		return runCapture(t, oneProfile("o/a.git", "o/b.git"), opts)
	}
	a, b := mk(), mk()
	if a != b {
		t.Errorf("output not deterministic:\n--- a ---\n%s\n--- b ---\n%s", a, b)
	}
	if strings.Index(a, "o/a.git") > strings.Index(a, "for o/b.git") {
		t.Errorf("repos not logged in declaration order:\n%s", a)
	}
}

func TestRun_NoLeak_TokenNeverLogged(t *testing.T) {
	const secret = "tok-secret-value"
	fp := &fakeProber{verdicts: map[string]map[Permission]error{
		"o/r.git": {PermChecks: port.ErrForbidden, PermMetadata: port.ErrUnauthorized},
	}}
	opts := Options{
		Perms:       []Permission{PermMetadata, PermChecks},
		Prober:      fp,
		Tokens:      fakeTokens{"p": secret},
		Concurrency: 2,
	}
	out := runCapture(t, oneProfile("o/r.git", "o/s.git"), opts)
	if strings.Contains(out, secret) {
		t.Fatalf("token leaked into preflight log:\n%s", out)
	}
}

func TestRun_NeverPanicsOnNilOptions(t *testing.T) {
	Run(context.Background(), nil, Options{})
	Run(context.Background(), []Profile{{Name: "p", HasToken: true}}, Options{})
	// with a prober but nil tokens
	Run(context.Background(), []Profile{{Name: "p", HasToken: true, Repos: []string{"o/r.git"}}}, Options{
		Perms:  []Permission{PermMetadata},
		Prober: &fakeProber{},
	})
}
