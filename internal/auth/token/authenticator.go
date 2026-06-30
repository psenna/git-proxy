// Package token implements port.Authenticator against a static set of agent
// bearer tokens. A token maps to an agent name; the authenticator resolves a
// valid token to an auth.AgentIdentity and rejects anything else with a
// non-nil error (fail closed). Token comparison is constant-time to avoid
// timing side channels.
package token

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"

	"github.com/psenna/git-proxy/internal/auth"
)

// Authenticator validates Bearer tokens against a configured token->name map.
// It implements port.Authenticator.
type Authenticator struct {
	tokens map[string]string
}

// New returns an Authenticator that accepts the given tokens. Each token maps
// to the agent name returned in the resolved identity. A nil or empty map
// rejects every token (fail closed: nothing is valid).
func New(tokens map[string]string) *Authenticator {
	cp := make(map[string]string, len(tokens))
	for k, v := range tokens {
		cp[k] = v
	}
	return &Authenticator{tokens: cp}
}

// Authenticate validates token and returns the agent identity on success. An
// empty or unknown token is rejected. Comparison is constant-time across all
// configured tokens.
func (a *Authenticator) Authenticate(_ context.Context, token string) (auth.AgentIdentity, error) {
	if token == "" {
		return auth.AgentIdentity{}, errors.New("token: empty credential")
	}
	for want, name := range a.tokens {
		if subtle.ConstantTimeCompare([]byte(want), []byte(token)) == 1 {
			return auth.AgentIdentity{Name: name}, nil
		}
	}
	return auth.AgentIdentity{}, fmt.Errorf("token: invalid credential")
}
