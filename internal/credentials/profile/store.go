// Package profile implements port.CredentialStore as a profile-based vault:
// a YAML file of named profiles, each mapping a set of repository patterns to
// the upstream credentials the proxy uses when it talks to those upstreams.
// The agent never sees this file or its contents; the proxy loads it at
// startup, resolves each profile's secret from env-or-file, and attaches the
// credentials to upstream requests only.
//
// Resolution rule: env > file > empty. The env-var name is derived from the
// profile name uppercased (e.g. profile "company_abc" reads COMPANY_ABC_TOKEN,
// COMPANY_ABC_PASSWORD, COMPANY_ABC_USERNAME). A profile whose resolved
// password AND token are both empty is "secretless": it matches in the
// matcher but CredentialsFor returns (zero, false) so the deny decision falls
// through to the public_repos allowlist (deny-by-default).
package profile

import (
	"fmt"
	"log"
	"os"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/psenna/git-proxy/internal/credentials/repomatch"
	"github.com/psenna/git-proxy/internal/port"
)

// rawProfile is the YAML schema for one credential profile.
type rawProfile struct {
	Name        string   `yaml:"name"`
	Description string   `yaml:"description"`
	Username    string   `yaml:"username"`
	Password    string   `yaml:"password"`
	Token       string   `yaml:"token"`
	Repos       []string `yaml:"repos"`
}

// vaultFile is the YAML schema of the credentials file:
//
//	credentials:
//	  - name: company_abc
//	    description: "Main org token"
//	    username: ci-bot
//	    password: hunter2
//	    token: ghp_broker_token
//	    repos: ["mycompany/*"]
type vaultFile struct {
	Credentials []rawProfile `yaml:"credentials"`
}

// profileWildcard is a wildcard pattern tagged with the profile that declared
// it, for the aggregated startup warning. It carries only the pattern, the
// profile name, and the description — never the resolved secret.
type profileWildcard struct {
	Pattern     string
	Name        string
	Description string
}

// Store is a profile-backed credential vault. It implements port.CredentialStore.
// The matcher resolves a repo to a *resolved; CredentialsFor then applies the
// secretless tri-state.
type Store struct {
	matcher   *repomatch.Matcher[*resolved]
	wildcards []profileWildcard
}

// resolved holds the resolved credentials for a profile, snapshotted at New
// time (env is read once, at startup).
type resolved struct {
	creds port.Credentials
}

var nameRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// New loads the credential vault at path. If path is empty, New returns an
// empty store (no credentials for any repo) rather than erroring, so the proxy
// can run without a vault in passthrough configurations.
//
// Startup fatal (returns an error): the file cannot be read or parsed; a
// profile name is empty or does not match ^[A-Za-z_][A-Za-z0-9_]*$; a profile
// name duplicates another case-insensitively; a profile has no repos; a
// pattern is malformed (bare *, **, path.Match syntax error); or the same
// exact repo or same wildcard pattern appears in two profiles. Pattern
// validation and cross-profile dup-pattern detection are delegated to
// repomatch.New.
//
// Startup non-fatal (logs a warning, returns nil error): a profile with no
// usable credential (password and token both empty after env resolution), or
// a one-legged profile (token set, password empty, or vice versa). Warnings
// name the env-var NAMES (uppercased) and the profile description — never the
// resolved secret values (no-leak binding).
func New(path string) (*Store, error) {
	s := &Store{}
	if path == "" {
		return s, nil // no credentials file → empty store
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("profile: read %s: %w", path, err)
	}
	var vf vaultFile
	if err := yaml.Unmarshal(data, &vf); err != nil {
		return nil, fmt.Errorf("profile: parse %s: %w", path, err)
	}
	seenNames := make(map[string]bool)
	pairs := make([]repomatch.Pair[*resolved], 0)
	for _, rp := range vf.Credentials {
		if rp.Name == "" || !nameRe.MatchString(rp.Name) {
			return nil, fmt.Errorf("profile: invalid name %q (must match ^[A-Za-z_][A-Za-z0-9_]*$)", rp.Name)
		}
		up := strings.ToUpper(rp.Name)
		if seenNames[up] {
			return nil, fmt.Errorf("profile: duplicate name %q (case-insensitive)", rp.Name)
		}
		seenNames[up] = true
		if len(rp.Repos) == 0 {
			return nil, fmt.Errorf("profile %q: repos is empty", rp.Name)
		}
		c := port.Credentials{
			Username: envOr(up+"_USERNAME", rp.Username),
			Password: envOr(up+"_PASSWORD", rp.Password),
			Token:    envOr(up+"_TOKEN", rp.Token),
		}
		r := &resolved{creds: c}
		for _, pat := range rp.Repos {
			// repomatch.New validates each pattern (bare *, **, syntax) and
			// detects duplicate exact and duplicate wildcard patterns across
			// the whole set — collect then build once below.
			pairs = append(pairs, repomatch.Pair[*resolved]{Pattern: pat, Value: r})
			if strings.Contains(pat, "*") {
				s.wildcards = append(s.wildcards, profileWildcard{Pattern: pat, Name: rp.Name, Description: rp.Description})
			}
		}
		// non-functional / one-legged warnings. These name env-var NAMES and
		// the description only — never the resolved secret values (no-leak
		// binding). Naming the missing env var tells the operator exactly what
		// to set without ever echoing the value that IS present.
		switch {
		case c.Password == "" && c.Token == "":
			log.Printf("profile %q (%s) has no usable credential; set %s_PASSWORD/%s_TOKEN (or a file value); repos under it will not be credentialed",
				rp.Name, rp.Description, up, up)
		case c.Password == "":
			log.Printf("profile %q (%s) has token but no password — broker-only; git-HTTP clone will not be credentialed; set %s_PASSWORD (or a file value) to enable it",
				rp.Name, rp.Description, up)
		case c.Token == "":
			log.Printf("profile %q (%s) has password but no token — git-only; broker ops will not be credentialed; set %s_TOKEN (or a file value) to enable it",
				rp.Name, rp.Description, up)
		}
	}
	m, err := repomatch.New(pairs) // enforces dup-exact / dup-wildcard across profiles + per-pattern syntax
	if err != nil {
		return nil, err
	}
	s.matcher = m
	return s, nil
}

// envOr returns the env var when it is set and non-empty, else the file
// fallback. An empty env value is treated the same as unset so an operator can
// blank out a file secret by setting the env var to "".
func envOr(name, fallback string) string {
	if v, ok := os.LookupEnv(name); ok && v != "" {
		return v
	}
	return fallback
}

// CredentialsFor returns the upstream credentials for repo, or false if no
// credentials are configured for that repo. A secretless profile (resolved
// password and token both empty) returns (zero, false) so the deny decision
// falls through to the public_repos allowlist. Fail closed: unknown repos
// return (zero, false).
func (s *Store) CredentialsFor(repo string) (port.Credentials, bool) {
	if s.matcher == nil {
		return port.Credentials{}, false
	}
	r, ok := s.matcher.Match(repo)
	if !ok {
		return port.Credentials{}, false
	}
	if r.creds.Password == "" && r.creds.Token == "" {
		return port.Credentials{}, false // secretless profile → no creds (deny falls through to public_repos)
	}
	return r.creds, true
}

// WildcardPatterns returns each wildcard pattern tagged with the profile name
// and description that declared it, in declaration order. It carries no
// secret material.
func (s *Store) WildcardPatterns() []profileWildcard {
	out := make([]profileWildcard, len(s.wildcards))
	copy(out, s.wildcards)
	return out
}
