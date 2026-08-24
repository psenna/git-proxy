package config

import "testing"

// TestAuthConfig_RequiresExplicitOptOut is the security review H9 regression
// guard: an empty auth.tokens map requires UnsafeAllowNoAuth to be true, or
// RequiresExplicitOptOut reports true (meaning main.go must refuse to start).
func TestAuthConfig_RequiresExplicitOptOut(t *testing.T) {
	cases := []struct {
		name string
		auth AuthConfig
		want bool
	}{
		{"empty tokens, no opt-out -> requires opt-out", AuthConfig{}, true},
		{"empty tokens, explicit opt-out -> does not require it", AuthConfig{UnsafeAllowNoAuth: true}, false},
		{"tokens configured, no opt-out -> does not require it", AuthConfig{Tokens: map[string]string{"tok": "agent-1"}}, false},
		{"tokens configured AND opt-out set -> still does not require it (tokens take precedence)", AuthConfig{Tokens: map[string]string{"tok": "agent-1"}, UnsafeAllowNoAuth: true}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.auth.RequiresExplicitOptOut(); got != tc.want {
				t.Errorf("RequiresExplicitOptOut() = %v, want %v", got, tc.want)
			}
		})
	}
}
