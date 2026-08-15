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
	// Suppressed is true when the raw matched value exactly matched the scan
	// allowlist. Suppressed findings do NOT deny the push; the rule records
	// them in the audit MASKED (a generic reason built from Path/Line/Rule,
	// never the raw secret). The raw secret is never carried on a finding.
	Suppressed bool
}

// SecretScanner scans blob contents for secrets. Implementations must be pure
// (no I/O) and deterministic; the caller provides the bytes. Snippets in the
// returned findings must be redacted so the secret value is not exposed.
//
// allowlist is a set of exact secret strings that are exempt from enforcement:
// a finding whose raw matched value exactly equals an allowlist entry is
// returned with Suppressed=true (and a redacted Snippet) instead of a live
// finding. nil or empty disables suppression (today's behavior). The raw-value
// comparison happens BEFORE redaction; the raw secret is never carried on the
// finding.
type SecretScanner interface {
	Scan(path string, content []byte, allowlist []string) []SecretFinding
}
