// Package auth defines the agent identity contract resolved by an
// Authenticator (internal/port) from a presented credential. The identity never
// carries upstream credentials: it names the agent for policy and audit, nothing
// more.
package auth

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
