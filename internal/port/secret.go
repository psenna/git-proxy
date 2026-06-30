package port

// Secret-finding contract: the push secret_scan rule scans changed blob
// contents for secrets via a pure, deterministic SecretScanner. The scanner
// performs no I/O; the caller provides the bytes. Implementations must redact
// the matched secret value from any snippet they emit so the secret never
// reaches agent-facing deny reasons.

// SecretFinding is one detected secret in a scanned blob.
type SecretFinding struct {
	// Path is the repo-relative path of the blob.
	Path string
	// Line is the 1-based line number of the finding within the blob.
	Line int
	// Rule is the name of the detecting pattern (e.g. "aws-access-key-id").
	Rule string
	// Snippet is a REDACTED context snippet — never the full secret value.
	// The scanner masks the matched secret before emitting the snippet.
	Snippet string
}

// SecretScanner scans blob contents for secrets. Implementations must be pure
// (no I/O) and deterministic; the caller provides the bytes. Snippets in the
// returned findings must be redacted so the secret value is not exposed.
type SecretScanner interface {
	Scan(path string, content []byte) []SecretFinding
}