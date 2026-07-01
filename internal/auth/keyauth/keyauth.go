// Package keyauth implements port.Authenticator against a static set of
// authorized SSH public keys mapped to agent identities. It resolves a
// presented SSH public key (by its fingerprint) to an auth.AgentIdentity and
// rejects unknown keys with a non-nil error (fail closed). This is the SSH
// counterpart of internal/auth/token (HTTP Bearer): both implement
// port.Authenticator and resolve to the same auth.AgentIdentity so the
// protocol/enforcement layers are transport-agnostic.
//
// v1.md open question #3 (forced-command token vs key→identity) is resolved
// as key→identity: the config maps agent-name → authorized public key string
// (the form found in authorized_keys), and the authenticator builds a
// reverse map fingerprint → agent name. The SSH frontend's PublicKeyCallback
// computes ssh.FingerprintSHA256(clientKey) and calls Authenticate.
package keyauth

import (
	"context"
	"errors"
	"fmt"

	"github.com/psenna/git-proxy/internal/auth"
	"golang.org/x/crypto/ssh"
)

// Authenticator maps an SSH public key (by its fingerprint) to an agent
// identity. It implements port.Authenticator: Authenticate is called with the
// key's fingerprint as the "token" (the port.Authenticator seam is
// credential-shape-agnostic). Fail-closed: an unknown or empty fingerprint
// returns an error.
type Authenticator struct {
	// fpToAgent maps SSH public-key fingerprint → agent name.
	fpToAgent map[string]string
}

// New builds an Authenticator from the authorized map (agent-name → authorized
// public key string in authorized_keys form, e.g.
// "ssh-ed25519 AAAAC3Nz... comment"). It parses each key via
// ssh.ParseAuthorizedKey, computes ssh.FingerprintSHA256, and builds a reverse
// map fingerprint → agent name. A duplicate key authorized for more than one
// agent is rejected (ambiguous → fail closed at construction). A malformed
// authorized-key string is rejected. A nil/empty map yields an Authenticator
// that rejects every key (fail closed: nothing is valid).
func New(authorized map[string]string) (*Authenticator, error) {
	a := &Authenticator{fpToAgent: make(map[string]string, len(authorized))}
	for name, keyStr := range authorized {
		if keyStr == "" {
			return nil, fmt.Errorf("keyauth: agent %q has empty authorized key", name)
		}
		pk, _, _, _, err := ssh.ParseAuthorizedKey([]byte(keyStr))
		if err != nil {
			return nil, fmt.Errorf("keyauth: agent %q: parse authorized key: %w", name, err)
		}
		fp := ssh.FingerprintSHA256(pk)
		if existing, ok := a.fpToAgent[fp]; ok && existing != name {
			return nil, fmt.Errorf("keyauth: duplicate authorized key (fingerprint %s) for agents %q and %q", fp, existing, name)
		}
		a.fpToAgent[fp] = name
	}
	return a, nil
}

// Authenticate resolves the SSH key fingerprint to an agent identity. An empty
// or unknown fingerprint returns an error (fail closed). The fingerprint is
// expected to be ssh.FingerprintSHA256(clientKey) as computed by the SSH
// frontend's PublicKeyCallback.
func (a *Authenticator) Authenticate(_ context.Context, fingerprint string) (auth.AgentIdentity, error) {
	if fingerprint == "" {
		return auth.AgentIdentity{}, errors.New("keyauth: empty fingerprint")
	}
	name, ok := a.fpToAgent[fingerprint]
	if !ok {
		return auth.AgentIdentity{}, errors.New("keyauth: unknown public key")
	}
	return auth.AgentIdentity{Name: name}, nil
}

// FingerprintForAgent returns the fingerprint of the authorized key configured
// for the named agent, or "" when the agent has no key configured. The SSH
// frontend may use it for logging/audit. It is optional and not on the hot
// path.
func (a *Authenticator) FingerprintForAgent(name string) string {
	for fp, n := range a.fpToAgent {
		if n == name {
			return fp
		}
	}
	return ""
}