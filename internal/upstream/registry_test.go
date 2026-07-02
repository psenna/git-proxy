package upstream

import (
	"context"
	"io"
	"testing"

	"github.com/psenna/git-proxy/internal/port"
)

// stubUpstream is a test-only port.Upstream. Real adapters (plain, github)
// self-register via init() and are exercised in their own package tests; stubs
// exercise the registry in isolation here, mirroring how the rule registry
// tests (internal/policy/engine_test.go) use a stubRule on an isolated
// Registry rather than the real rules.
type stubUpstream struct{ name string }

func (s *stubUpstream) ListRefs(context.Context, string) (port.Refs, error) { return port.Refs{}, nil }
func (s *stubUpstream) ListRefsService(context.Context, string, string) (port.Refs, error) {
	return port.Refs{}, nil
}
func (s *stubUpstream) UploadPack(context.Context, string, io.Reader) (io.ReadCloser, error) {
	return nil, nil
}
func (s *stubUpstream) ReceivePack(context.Context, string, io.Reader) (io.ReadCloser, error) {
	return nil, nil
}

// stubFactory builds a stubUpstream from its config. It is the upstream
// counterpart of the policy test's allow/deny stub rules.
func stubFactory(cfg UpstreamConfig) (port.Upstream, error) {
	return &stubUpstream{name: cfg.Kind}, nil
}

func TestRegistry_RegisterAndLookup(t *testing.T) {
	// Use an isolated registry to avoid cross-test pollution with the global
	// registry used by Build (and self-registered by plain via init()). Mirrors
	// TestRegistry_RegisterAndLookup in the rule registry.
	reg := NewRegistry()
	reg.Register("stub", stubFactory)
	f, ok := reg.Lookup("stub")
	if !ok {
		t.Fatal("Lookup stub: not found")
	}
	up, err := f(UpstreamConfig{Kind: "stub"})
	if err != nil {
		t.Fatalf("factory error: %v", err)
	}
	if up == nil {
		t.Fatal("factory returned nil Upstream")
	}
	if _, ok := reg.Lookup("nope"); ok {
		t.Fatal("Lookup nope: want not found")
	}
}

func TestRegistry_DuplicateRegisterPanics(t *testing.T) {
	// Duplicate registration panics (fail-fast on conflicting init() blocks),
	// mirroring the rule registry's duplicate-register panic.
	reg := NewRegistry()
	reg.Register("dup", stubFactory)
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("Register dup: want panic, got none")
		}
	}()
	reg.Register("dup", stubFactory)
}

func TestBuild_UnknownKindFailClosed(t *testing.T) {
	// An unknown Kind fails closed: Build returns an error rather than silently
	// falling back to plain. Mirrors Resolve's unknown-rule error.
	reg := NewRegistry()
	_, err := reg.Build(UpstreamConfig{Kind: "ghost"})
	if err == nil {
		t.Fatal("Build unknown kind: want error, got nil")
	}
}

func TestBuild_EmptyKindDefaultsToPlainIsolated(t *testing.T) {
	// On an isolated registry the empty-Kind default still resolves to "plain";
	// with no "plain" factory registered, Build fails closed — proving the
	// default is "plain" (not "skip" / not the empty string). The plain package
	// self-registers "plain" via init(); that is asserted in plain_test.go
	// (which can import upstream without a cycle).
	reg := NewRegistry()
	_, err := reg.Build(UpstreamConfig{URL: "http://example.git"})
	if err == nil {
		t.Fatal("Build empty kind on isolated registry: want error (no plain registered), got nil")
	}
}

func TestBuild_FactoryErrorPropagates(t *testing.T) {
	// A factory error propagates from Build (fail-fast at startup).
	reg := NewRegistry()
	reg.Register("boom", func(UpstreamConfig) (port.Upstream, error) {
		return nil, io.ErrUnexpectedEOF
	})
	_, err := reg.Build(UpstreamConfig{Kind: "boom"})
	if err == nil {
		t.Fatal("Build boom: want factory error, got nil")
	}
}