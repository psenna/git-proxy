package port

import "errors"

// SCM REST capability errors. These sentinels are returned by optional
// capability sub-interfaces (e.g. PRSupport via a GitHub REST adapter) so callers
// can map them to stable HTTP responses without importing the adapter package.
// They are deliberately generic and carry NO upstream response body, header, or
// credential content — the no-leak contract (see audit.go) extends to these
// errors: a capability error's message never echoes the upstream's response,
// which could otherwise leak a token fragment or secret in some deployments.
//
// The SCM REST adapter (internal/upstream/github/rest) returns these directly;
// the broker (internal/broker) maps each to an HTTP status and a generic reason.
// ErrNotImplemented (defined in upstream.go) remains the "capability present but
// not wired" signal distinct from these "the upstream said no" signals.
var (
	// ErrUnauthorized is returned when the upstream SCM rejects the proxy's
	// credentials (HTTP 401), or when no token is configured for a repo that an
	// SCM REST call targets (fail-closed: never fall back to anonymous).
	ErrUnauthorized = errors.New("git-proxy: upstream scm unauthorized")
	// ErrForbidden is returned when the upstream SCM forbids the operation
	// (HTTP 403) for a reason other than rate limiting — e.g. branch protection
	// blocks a merge, or the token lacks scope.
	ErrForbidden = errors.New("git-proxy: upstream scm forbidden")
	// ErrNotFound is returned when the upstream SCM has no such resource
	// (HTTP 404) — e.g. the repo, PR, or ref does not exist.
	ErrNotFound = errors.New("git-proxy: upstream scm resource not found")
	// ErrUnprocessable is returned when the upstream SCM rejects the request
	// payload as invalid (HTTP 422) — e.g. a PR already exists, or a merge
	// target branch is not mergeable.
	ErrUnprocessable = errors.New("git-proxy: upstream scm request unprocessable")
	// ErrNotMergeable is returned specifically when a merge cannot proceed
	// because the PR has conflicts or is not in a mergeable state (HTTP 409).
	// Distinct from ErrUnprocessable so the broker can surface 409 to the agent.
	ErrNotMergeable = errors.New("git-proxy: pull request not mergeable")
	// ErrRateLimited is returned when the upstream SCM rate-limits the proxy
	// (HTTP 429, or HTTP 403 with X-RateLimit-Remaining: 0). The caller may
	// forward the upstream's Retry-After; it must never invent one. When the
	// upstream sent a Retry-After header, the REST client wraps ErrRateLimited
	// in a *RateLimitedError carrying that value so the broker can forward it.
	ErrRateLimited = errors.New("git-proxy: upstream scm rate limited")
	// ErrUpstream is returned for any other upstream SCM failure (HTTP 5xx, or
	// a transport error talking to the SCM REST API). The message carries only
	// the status code, never the body.
	ErrUpstream = errors.New("git-proxy: upstream scm error")
)

// RateLimitedError wraps ErrRateLimited and carries the upstream's Retry-After
// header value (a number of seconds or an HTTP-date), if the upstream sent one.
// It is no-leak: Retry-After is a delay, not a credential, secret, or response
// body. Callers test for it with errors.As; a plain ErrRateLimited (no
// Retry-After available) satisfies errors.Is(ErrRateLimited) but not
// errors.As(*RateLimitedError), so the broker forwards Retry-After only when the
// upstream actually provided it — it never invents one.
type RateLimitedError struct {
	// RetryAfter is the raw value of the upstream's Retry-After response
	// header, or empty when the upstream sent none.
	RetryAfter string
}

// Error reports the underlying rate-limit sentinel's message.
func (e *RateLimitedError) Error() string { return ErrRateLimited.Error() }

// Unwrap makes errors.Is(err, ErrRateLimited) true for a *RateLimitedError.
func (e *RateLimitedError) Unwrap() error { return ErrRateLimited }