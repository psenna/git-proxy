package port

import (
	"context"

	"github.com/psenna/git-proxy/internal/auth"
)

// Authenticator verifies an agent credential and resolves the agent's identity.
// Implementations must fail closed: an invalid, malformed, or unknown
// credential must return a non-nil error, and the caller must treat that as a
// denial (401). The credential string is the raw token extracted from the
// transport (e.g. the Bearer token); the Authenticator never sees upstream
// credentials.
type Authenticator interface {
	// Authenticate validates token and returns the agent identity on success.
	Authenticate(ctx context.Context, token string) (auth.AgentIdentity, error)
}
