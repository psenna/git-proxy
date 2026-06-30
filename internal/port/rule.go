package port

// Policy types: the request/decision contract evaluated by the policy engine.
//
// The Rule interface and the request/decision value types live in this package
// so that rules (internal/policy/rules/*), the engine (internal/policy), and
// the orchestrator share one contract. The engine is pure: it performs no I/O
// and never touches the git binary. Rules are registered by name and selected
// via config; evaluation is deterministic and fail-closed.

// Verdict is the outcome of a policy evaluation for a single request.
type Verdict int

const (
	// VerdictAllow permits the request. A request is allowed only when every
	// applicable rule allows it.
	VerdictAllow Verdict = iota
	// VerdictDeny blocks the request. Any deny from a rule denies the whole
	// request. An evaluation error is treated as a deny (fail-closed).
	VerdictDeny
)

// Reason explains why a rule produced its verdict. It carries the rule name so
// audit logs can attribute denials precisely.
type Reason struct {
	// Rule is the name of the rule that produced this reason.
	Rule string
	// Message is a human-readable explanation of the denial.
	Message string
}

// Decision is the result of evaluating a request against one rule or the full
// pipeline. An empty Reasons slice with VerdictAllow means "allowed, no
// complaints". A VerdictDeny carries at least one Reason.
type Decision struct {
	Verdict Verdict
	Reasons []Reason
}

// RefUpdate describes a single ref update in a push (git-receive-pack command).
// The fields are the structured metadata a pure rule needs to decide whether the
// update is safe; the rule must not shell out to git to walk the DAG. Fast-forward
// detection is computed by the enforcement path and passed in as the pre-computed
// Force bool.
type RefUpdate struct {
	// Ref is the full ref name, e.g. "refs/heads/main".
	Ref string
	// Old is the object id the ref pointed to; zero value ("") for a ref creation.
	Old string
	// New is the object id the ref will point to; zero value ("") for a ref deletion.
	New string
	// Force is true if the update is a non-fast-forward (rewritten/non-FF history).
	Force bool
}

// IsDelete reports whether the update deletes the ref.
func (u RefUpdate) IsDelete() bool { return u.New == "" }

// IsCreate reports whether the update creates a new ref.
func (u RefUpdate) IsCreate() bool { return u.Old == "" && u.New != "" }

// Commit is a commit introduced by a push, with the metadata the rules need.
type Commit struct {
	// SHA is the 40-char object id of the commit.
	SHA string
	// Message is the full commit message (subject + body).
	Message string
}

// ChangedFile is a file touched by a push. Content is the new blob's bytes for
// Added/Modified files; nil for Deleted. Bounded by the push's packfile size.
type ChangedFile struct {
	// Path is the repo-relative path of the file.
	Path string
	// Status is "A" (added), "M" (modified), or "D" (deleted).
	Status string
	// BlobOID is the new blob oid for A/M; "" for D.
	BlobOID string
	// Content is the new blob content for A/M; nil for D.
	Content []byte
}

// PushRequest describes a git push (git-receive-pack) operation to be evaluated
// against the push rule set. Fields are added as later milestones wire richer
// push context (commits, blobs); the engine treats the request as opaque and
// only forwards it to rules. RefUpdates carries the per-ref metadata
// (old/new ids, force flag) that push rules such as history_protect and
// branch_pattern decide over; it may be empty for callers that do not yet
// populate it. Commits and ChangedFiles carry the new commits and touched
// blobs introduced across all ref updates, populated fail-closed by the
// enforcement path from the inspection mirror; they are empty for a
// delete-only push and may be empty for callers that do not populate them.
type PushRequest struct {
	// Agent is the authenticated agent name (auth.AgentIdentity.Name).
	Agent string
	// Repo is the upstream repository path the push targets.
	Repo string
	// RefUpdates is the set of ref updates in this push. Rules iterate it to
	// decide per-ref verdicts.
	RefUpdates []RefUpdate
	// Commits is the set of new commits introduced across all ref updates
	// (deduped by SHA). commit_message and similar rules inspect it.
	Commits []Commit
	// ChangedFiles is the set of files added/modified/deleted across all ref
	// updates (deduped by path+status+oid). path_acl and secret_scan inspect it.
	ChangedFiles []ChangedFile
}

// FetchRequest describes a git fetch/clone (git-upload-pack) operation to be
// evaluated against the read rule set.
type FetchRequest struct {
	// Agent is the authenticated agent name (auth.AgentIdentity.Name).
	Agent string
	// Repo is the upstream repository path being read.
	Repo string
	// Paths is the set of repo-relative file paths the fetch is requesting.
	// Populated by the read-protection path (Task 9); empty when no path-level
	// filtering applies. path_acl.EvaluateFetch denies a fetch that requests a
	// denied path.
	Paths []string
}

// Rule evaluates a single push or fetch request and returns a Decision plus an
// error. A non-nil error is treated by the engine as a denial (fail-closed):
// the rule could not determine whether the request is safe, so it is blocked.
//
// A push-only rule returns VerdictAllow from EvaluateFetch; a fetch-only rule
// returns VerdictAllow from EvaluatePush. Rules that apply to both directions
// implement both methods.
type Rule interface {
	// Name is the rule's registered name. It is stable across instances and
	// matches the config key used to enable/disable the rule.
	Name() string
	// EvaluatePush evaluates a push request. Returning (Decision{}, nil) with
	// a nil Decision is treated as allow; returning a non-nil error is treated
	// as deny (fail-closed).
	EvaluatePush(PushRequest) (Decision, error)
	// EvaluateFetch evaluates a fetch request.
	EvaluateFetch(FetchRequest) (Decision, error)
}