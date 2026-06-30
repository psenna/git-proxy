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

// PushRequest describes a git push (git-receive-pack) operation to be evaluated
// against the push rule set. Fields are added as later milestones wire richer
// push context (refs, commits, blobs); the engine treats the request as opaque
// and only forwards it to rules.
type PushRequest struct {
	// Agent is the authenticated agent name (auth.AgentIdentity.Name).
	Agent string
	// Repo is the upstream repository path the push targets.
	Repo string
}

// FetchRequest describes a git fetch/clone (git-upload-pack) operation to be
// evaluated against the read rule set.
type FetchRequest struct {
	// Agent is the authenticated agent name (auth.AgentIdentity.Name).
	Agent string
	// Repo is the upstream repository path being read.
	Repo string
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