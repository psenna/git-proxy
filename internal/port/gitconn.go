package port

import "io"

// GitConn models a single agent-facing git operation. It is the unit of work
// that the orchestrator inspects and gates. The SSH frontend (a later
// milestone) builds a GitConn from the SSH channel's stdio; the HTTP frontend
// builds one from the HTTP request/response pair.
type GitConn interface {
	// Agent identifies the authenticated agent. Empty until auth is wired.
	Agent() string
	// Repo is the repository path the operation targets (e.g. "test.git").
	Repo() string
	// Service is "git-upload-pack" (read) or "git-receive-pack" (write).
	Service() string
	// Stdio returns the git protocol streams: stdin from the agent, stdout
	// to the agent, and a closer for stdout.
	Stdio() (io.Reader, io.Writer, io.WriteCloser)
}