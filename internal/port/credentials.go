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
