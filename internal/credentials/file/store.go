// Package file implements port.CredentialStore as a file-based vault: a YAML
// file mapping upstream repository paths to the credentials the proxy uses when
// it talks to that upstream. The agent never sees this file or its contents;
// the proxy loads it at startup and attaches the credentials to upstream
// requests only.
package file

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"

	"github.com/psenna/git-proxy/internal/port"
)

// Store is a file-backed credential vault. It maps upstream repository paths to
// port.Credentials. It implements port.CredentialStore.
type Store struct {
	creds map[string]port.Credentials
}

// vaultFile is the YAML schema of the credentials file:
//
//	credentials:
//	  "owner/repo.git":
//	    username: ci-bot
//	    password: hunter2
//	    token: ghp_broker_token   # optional Bearer token for the SCM REST API
type vaultFile struct {
	Credentials map[string]port.Credentials `yaml:"credentials"`
}

// New loads the credential vault at path. If path is empty, New returns an
// empty store (no credentials for any repo) rather than erroring, so the proxy
// can run without a vault in passthrough configurations. A non-empty path that
// cannot be read or parsed is an error: fail closed on a malformed vault
// rather than silently running without credentials.
func New(path string) (*Store, error) {
	s := &Store{creds: map[string]port.Credentials{}}
	if path == "" {
		return s, nil
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("credentials: read %s: %w", path, err)
	}
	var vf vaultFile
	if err := yaml.Unmarshal(b, &vf); err != nil {
		return nil, fmt.Errorf("credentials: parse %s: %w", path, err)
	}
	if vf.Credentials != nil {
		s.creds = vf.Credentials
	}
	return s, nil
}

// CredentialsFor returns the upstream credentials for repo, or false if no
// credentials are configured for that repo. Fail closed: unknown repos return
// (zero, false).
func (s *Store) CredentialsFor(repo string) (port.Credentials, bool) {
	c, ok := s.creds[repo]
	return c, ok
}
