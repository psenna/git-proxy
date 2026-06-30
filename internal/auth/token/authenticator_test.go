package token

import (
	"context"
	"testing"

	"github.com/psenna/git-proxy/internal/auth"
)

func TestAuthenticator_ValidToken(t *testing.T) {
	a := New(map[string]string{"agent-token-1": "agent-1"})

	id, err := a.Authenticate(context.Background(), "agent-token-1")
	if err != nil {
		t.Fatalf("Authenticate: unexpected error: %v", err)
	}
	if id.Name != "agent-1" {
		t.Errorf("identity name = %q, want agent-1", id.Name)
	}
	if id == (auth.AgentIdentity{}) {
		t.Error("returned zero identity for a valid token")
	}
}

func TestAuthenticator_UnknownToken(t *testing.T) {
	a := New(map[string]string{"agent-token-1": "agent-1"})

	if _, err := a.Authenticate(context.Background(), "not-a-known-token"); err == nil {
		t.Fatal("expected error for unknown token, got nil")
	}
}

func TestAuthenticator_EmptyToken(t *testing.T) {
	a := New(map[string]string{"agent-token-1": "agent-1"})

	if _, err := a.Authenticate(context.Background(), ""); err == nil {
		t.Fatal("expected error for empty token, got nil")
	}
}

func TestAuthenticator_EmptyStoreRejectsAll(t *testing.T) {
	a := New(nil)

	if _, err := a.Authenticate(context.Background(), "any-token"); err == nil {
		t.Fatal("expected error with empty token store, got nil")
	}
}

func TestAuthenticator_DoesNotMutateInput(t *testing.T) {
	in := map[string]string{"t": "n"}
	a := New(in)
	in["injected"] = "evil"
	if _, ok := a.tokens["injected"]; ok {
		t.Fatal("Authenticator copied input map by reference; New must defensive-copy")
	}
}
