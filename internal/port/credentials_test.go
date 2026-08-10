package port_test

import (
	"testing"

	"github.com/psenna/git-proxy/internal/port"
)

// TestBasicUserPassword covers the git-protocol leg's Basic-auth resolution,
// including the token-only synthesis (GitHub PAT form x-access-token:<token>)
// that lets a token-only credential profile authenticate the git leg as well as
// the broker leg. Precedence is password-first so a token is only synthesized
// when no password is set.
func TestBasicUserPassword(t *testing.T) {
	cases := []struct {
		name     string
		creds    port.Credentials
		wantUser string
		wantPass string
		wantOK   bool
	}{
		{
			name:     "full profile uses username/password as-is",
			creds:    port.Credentials{Username: "x-access-token", Password: "ghp_full", Token: "ghp_full"},
			wantUser: "x-access-token",
			wantPass: "ghp_full",
			wantOK:   true,
		},
		{
			name:     "token-only synthesizes x-access-token Basic",
			creds:    port.Credentials{Username: "", Password: "", Token: "ghp_broker_only"},
			wantUser: "x-access-token",
			wantPass: "ghp_broker_only",
			wantOK:   true,
		},
		{
			name:     "password-only (git-only) uses username/password",
			creds:    port.Credentials{Username: "ci-bot", Password: "hunter2"},
			wantUser: "ci-bot",
			wantPass: "hunter2",
			wantOK:   true,
		},
		{
			name:     "username-only with empty password uses username and empty password",
			creds:    port.Credentials{Username: "ci-bot"},
			wantUser: "ci-bot",
			wantPass: "",
			wantOK:   true,
		},
		{
			name:     "username set but password empty and token set synthesizes PAT Basic",
			creds:    port.Credentials{Username: "x-access-token", Password: "", Token: "ghp_pat"},
			wantUser: "x-access-token",
			wantPass: "ghp_pat",
			wantOK:   true,
		},
		{
			name:     "all empty returns ok=false (anonymous)",
			creds:    port.Credentials{},
			wantUser: "",
			wantPass: "",
			wantOK:   false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			gotUser, gotPass, gotOK := tc.creds.BasicUserPassword()
			if gotUser != tc.wantUser || gotPass != tc.wantPass || gotOK != tc.wantOK {
				t.Fatalf("BasicUserPassword() = (%q, %q, %v), want (%q, %q, %v)",
					gotUser, gotPass, gotOK, tc.wantUser, tc.wantPass, tc.wantOK)
			}
		})
	}
}
