package preflight

import (
	"context"
	"testing"
)

type nopProber struct{}

func (nopProber) Probe(context.Context, string, string, Permission) error { return nil }
func (nopProber) SampleRepo(context.Context, string, string) (string, error) {
	return "", ErrNoSample
}

func TestRegistry_RoundTrip(t *testing.T) {
	var gotURL string
	Register("prtest-roundtrip", func(u string) (Prober, error) {
		gotURL = u
		return nopProber{}, nil
	})
	p, ok, err := ProberFor("prtest-roundtrip", "https://ghes.example.com")
	if err != nil {
		t.Fatalf("ProberFor: %v", err)
	}
	if !ok || p == nil {
		t.Fatalf("ProberFor ok=%v p=%v, want true / non-nil", ok, p)
	}
	if gotURL != "https://ghes.example.com" {
		t.Errorf("factory got url %q", gotURL)
	}
}

func TestRegistry_UnknownKind(t *testing.T) {
	p, ok, err := ProberFor("prtest-nope", "")
	if p != nil || ok || err != nil {
		t.Errorf("ProberFor(unknown) = (%v, %v, %v), want (nil, false, nil)", p, ok, err)
	}
}

func TestRegistry_DuplicateRegistrationPanics(t *testing.T) {
	Register("prtest-dup", func(string) (Prober, error) { return nopProber{}, nil })
	defer func() {
		if recover() == nil {
			t.Error("duplicate Register did not panic")
		}
	}()
	Register("prtest-dup", func(string) (Prober, error) { return nopProber{}, nil })
}
