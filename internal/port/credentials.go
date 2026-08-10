package port

// Credentials are upstream credentials held by the proxy's vault. The proxy
// attaches these when it talks to the upstream git server; the agent never
// receives them. Only HTTP Basic auth fields are modeled today (the current
// upstream is smart-HTTP); SSH key material will be added with the SSH frontend
// (M8).
type Credentials struct {
	// Username is the username for upstream HTTP Basic auth.
	Username string
	// Password is the password or personal access token for upstream HTTP
	// Basic auth.
	Password string
	// Token is a Bearer token for the upstream SCM REST API (GitHub PAT, a
	// GitHub App installation token, or a GHES token). It is used by the
	// SCM-specific adapter (e.g. the GitHub broker) on the proxy→upstream
	// REST leg, distinct from Username/Password which the git-protocol leg
	// uses for HTTP Basic auth. When Username/Password are empty but a Token
	// is set, the git-protocol leg synthesizes a GitHub PAT Basic credential
	// (username "x-access-token", password the token) via BasicUserPassword,
	// so a token-only profile authenticates both legs rather than leaving the
	// git leg anonymous. Empty means no token is configured; an SCM REST call
	// for that repo MUST fail closed rather than fall back to anonymous. Both
	// Basic and Bearer may be set for the same repo: the git protocol uses
	// Basic, the SCM REST API uses Bearer. The agent never receives this token.
	Token string
}

// gitPATAuthUser is the well-known username for using a GitHub PAT as the
// password over git HTTPS HTTP Basic auth (canonical for classic and
// fine-grained PATs).
const gitPATAuthUser = "x-access-token"

// BasicUserPassword returns the HTTP Basic auth username and password the
// git-protocol leg attaches to an upstream request. When Username/Password are
// set they are used as-is. Otherwise, when a Token is set, it is synthesized as
// a GitHub PAT Basic credential (username "x-access-token", password the token)
// so a token-only profile authenticates the git leg as well as the broker leg
// (which sends Token as a Bearer header). Returns ok=false when no usable
// credential is present: the caller must leave the request anonymous (subject to
// deny-by-default / public_repos upstream of here). The agent never receives
// these values.
//
// Precedence is password-first: a profile with a Password always uses it, and a
// token-only profile (or one with Username set but Password empty and a Token
// set) synthesizes the PAT Basic form rather than sending an empty-password
// Basic that GitHub would reject.
func (c Credentials) BasicUserPassword() (user, pass string, ok bool) {
	switch {
	case c.Password != "":
		return c.Username, c.Password, true
	case c.Token != "":
		return gitPATAuthUser, c.Token, true
	case c.Username != "":
		return c.Username, "", true
	}
	return "", "", false
}

// CredentialStore resolves upstream credentials for a repository. Credentials
// are looked up per upstream repository path so a single proxy can front
// multiple upstream repos with distinct credentials. Implementations must fail
// closed on a missing repo: return (zero, false) rather than a default or
// fallback credential. A nil/empty store means no credentials are configured.
type CredentialStore interface {
	// CredentialsFor returns the upstream credentials for repo, or false if no
	// credentials are configured for that repo.
	CredentialsFor(repo string) (Credentials, bool)
}

// RepoMatcher tests whether a repository path matches an allowlist (e.g. the
// public_repos config). A nil RepoMatcher matches nothing.
type RepoMatcher interface {
	Match(repo string) bool
}
