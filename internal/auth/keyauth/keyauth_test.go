// Package keyauth implements port.Authenticator against a static set of
// authorized SSH public keys mapped to agent identities. It resolves a
// presented SSH public key (by its fingerprint) to an auth.AgentIdentity and
// rejects unknown keys with a non-nil error (fail closed). This is the SSH
// counterpart of internal/auth/token (HTTP Bearer): both implement
// port.Authenticator and resolve to the same auth.AgentIdentity so the
// protocol/enforcement layers are transport-agnostic.
package keyauth

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

// generateAuthorizedKey generates an ed25519 SSH key pair and returns the
// authorized-key string for the public key (the form that goes in
// authorized_keys / config).
func generateAuthorizedKey(t *testing.T) (authorizedKey string, signer ssh.Signer) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate ed25519: %v", err)
	}
	signer, err = ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("new signer: %v", err)
	}
	// Marshal the public key in authorized_keys form.
	pubKey, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatalf("new public key: %v", err)
	}
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pubKey))), signer
}

func TestAuthenticator_KnownKeyResolvesIdentity(t *testing.T) {
	agent1Key, _ := generateAuthorizedKey(t)
	authn, err := New(map[string]string{"agent-1": agent1Key})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	fp := ssh.FingerprintSHA256(pubKeyFromAuthorized(t, agent1Key))
	id, err := authn.Authenticate(context.Background(), fp)
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if id.Name != "agent-1" {
		t.Errorf("identity name = %q, want agent-1", id.Name)
	}
}

func TestAuthenticator_UnknownKeyRejected(t *testing.T) {
	knownKey, _ := generateAuthorizedKey(t)
	authn, err := New(map[string]string{"agent-1": knownKey})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	// A different, unknown key.
	unknownKey, _ := generateAuthorizedKey(t)
	fp := ssh.FingerprintSHA256(pubKeyFromAuthorized(t, unknownKey))
	if _, err := authn.Authenticate(context.Background(), fp); err == nil {
		t.Fatal("expected error for unknown key, got nil (fail closed)")
	}
}

func TestAuthenticate_EmptyFingerprintRejected(t *testing.T) {
	knownKey, _ := generateAuthorizedKey(t)
	authn, err := New(map[string]string{"agent-1": knownKey})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := authn.Authenticate(context.Background(), ""); err == nil {
		t.Fatal("expected error for empty fingerprint, got nil")
	}
}

func TestNew_DuplicateKeyAcrossAgentsRejected(t *testing.T) {
	dupKey, _ := generateAuthorizedKey(t)
	// Same key authorized for two agents → must fail closed at construction
	// (a duplicate key is ambiguous and a config error).
	_, err := New(map[string]string{
		"agent-1": dupKey,
		"agent-2": dupKey,
	})
	if err == nil {
		t.Fatal("expected error for duplicate key across agents, got nil")
	}
}

func TestNew_MalformedAuthorizedKeyRejected(t *testing.T) {
	_, err := New(map[string]string{"agent-1": "not-a-valid-key"})
	if err == nil {
		t.Fatal("expected error for malformed authorized key, got nil")
	}
}

func TestAuthenticator_FingerprintStable(t *testing.T) {
	// The same public key must produce the same fingerprint across calls
	// (so the reverse map lookup is reliable).
	agent1Key, _ := generateAuthorizedKey(t)
	authn, err := New(map[string]string{"agent-1": agent1Key})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	fp1 := ssh.FingerprintSHA256(pubKeyFromAuthorized(t, agent1Key))
	fp2 := ssh.FingerprintSHA256(pubKeyFromAuthorized(t, agent1Key))
	if fp1 != fp2 {
		t.Fatalf("fingerprint not stable: %q vs %q", fp1, fp2)
	}
	if _, err := authn.Authenticate(context.Background(), fp1); err != nil {
		t.Fatalf("Authenticate stable fp: %v", err)
	}
}

// TestNew_FromPEMBlock accepts an OpenSSH private-key PEM block as the
// authorized key (some configs paste the private key by mistake); we only
// accept authorized_keys-formatted public keys. This guards fail-closed on
// the wrong key shape.
func TestNew_RejectsPEMPrivateKey(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	// Encode as an OpenSSH private key PEM (NOT an authorized public key).
	pemBlock, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		t.Fatalf("marshal private key: %v", err)
	}
	pemBytes := pem.EncodeToMemory(pemBlock)
	_, err = New(map[string]string{"agent-1": string(pemBytes)})
	if err == nil {
		t.Fatal("expected error when a private key PEM is given as authorized key, got nil")
	}
}

// pubKeyFromAuthorized parses an authorized_keys string and returns the
// ssh.PublicKey for fingerprinting.
func pubKeyFromAuthorized(t *testing.T, s string) ssh.PublicKey {
	t.Helper()
	pk, _, _, _, err := ssh.ParseAuthorizedKey([]byte(s))
	if err != nil {
		t.Fatalf("parse authorized key: %v", err)
	}
	return pk
}