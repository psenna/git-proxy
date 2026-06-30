// Package auth defines the agent identity contract resolved by an
// Authenticator (internal/port) from a presented credential. The identity never
// carries upstream credentials: it names the agent for policy and audit, nothing
// more.
package auth

import "context"

// AgentIdentity is the authenticated identity of an agent. It is resolved by a
// port.Authenticator from a presented credential (e.g. a Bearer token) and is
// the principal later milestones gate policy on. It deliberately holds no
// upstream credentials.
type AgentIdentity struct {
	// Name is the human-readable agent identifier the token resolves to
	// (e.g. a token subject). It is non-empty for any identity returned by a
	// valid authentication.
	Name string
}

// agentCtxKey is the context key for the authenticated agent identity. It lives
// in this package so both the HTTP frontend (which stores the identity) and the
// protocol layer (which reads it for policy) share one key without an import
// cycle.
type agentCtxKey struct{}

// WithAgent stores the authenticated agent identity in ctx and returns the
// derived context.
func WithAgent(ctx context.Context, a AgentIdentity) context.Context {
	return context.WithValue(ctx, agentCtxKey{}, a)
}

// FromContext returns the authenticated agent identity stored in ctx, if any.
// Frontends store it via WithAgent after authenticating the request; the
// enforcement path reads it to attribute the push to an agent for policy.
func FromContext(ctx context.Context) (AgentIdentity, bool) {
	a, ok := ctx.Value(agentCtxKey{}).(AgentIdentity)
	return a, ok
}
