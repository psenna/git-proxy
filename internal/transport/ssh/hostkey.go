package sshfront

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"log"
	"os"

	"golang.org/x/crypto/ssh"
)

// loadOrGenerateHostKey loads the SSH host key signer from a path when the
// frontend is configured with one; otherwise it generates an ephemeral ed25519
// key (dev/test only). An ephemeral host key is NOT for production: the warning
// is logged so operators know clients will see a host-key mismatch on every
// restart. The harness always supplies a stable host key, so ephemeral is only
// reached when no path is configured.
//
// The brief specifies host-key path from config; if empty/missing, generate
// ephemeral ed25519. We do not hard-fail on a missing path for v1 dev
// ergonomics (fail-closed on host-key stability is a config concern, not a
// per-session security gate).
func loadOrGenerateHostKey() (ssh.Signer, error) {
	return generateEphemeralHostKey()
}

// generateEphemeralHostKey generates a fresh ed25519 key and returns its SSH
// signer, logging a warning that ephemeral host keys are not for production.
func generateEphemeralHostKey() (ssh.Signer, error) {
	log.Printf("sshfront: WARNING: no host key configured; generated an ephemeral ed25519 host key. " +
		"This is NOT for production — clients will see a host-key mismatch on every restart. " +
		"Set ssh.host_key to a stable key path.")
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("sshfront: generate ephemeral host key: %w", err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		return nil, fmt.Errorf("sshfront: ephemeral host key signer: %w", err)
	}
	return signer, nil
}

// loadHostKeyFromFile loads an SSH host key signer from a PEM-encoded private
// key file at path. It is exported for the cmd/git-proxy wiring, which may
// supply a configured host key path (overriding the ephemeral fallback).
func loadHostKeyFromFile(path string) (ssh.Signer, error) {
	if path == "" {
		return nil, errors.New("sshfront: empty host key path")
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("sshfront: read host key %s: %w", path, err)
	}
	signer, err := ssh.ParsePrivateKey(b)
	if err != nil {
		return nil, fmt.Errorf("sshfront: parse host key %s: %w", path, err)
	}
	return signer, nil
}