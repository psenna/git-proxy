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
	// uses for HTTP Basic auth. Empty means no token is configured; an SCM
	// REST call for that repo MUST fail closed rather than fall back to
	// anonymous. Both Basic and Bearer may be set for the same repo: the git
	// protocol uses Basic, the SCM REST API uses Bearer. The agent never
	// receives this token.
	Token string
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
