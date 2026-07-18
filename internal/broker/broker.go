// Package broker is the agent-facing GitHub broker: a separate HTTP server
// (separate mux, separate listen port from the git-protocol frontend) through
// which an already-authenticated AI agent asks the proxy to manipulate PRs and
// query CI/pipeline state. The proxy attaches its OWN held GitHub token and
// forwards to the upstream SCM REST API; the agent never receives the token
// (same fail-closed, no-leak security model as the git-protocol path).
//
// The broker type-asserts port.PRSupport off the port.Upstream main.go built
// via the upstream registry, and fails closed at startup if the upstream does
// not implement it (the broker requires an SCM adapter — set upstream.kind:
// github). It deliberately lives OUTSIDE the core isolation set
// (internal/gitproto, internal/transport, internal/policy, cmd/git-proxy):
// those packages must never reference PRSupport, and the broker is the one place
// the type-assert happens. main.go passes the already-built port.Upstream and
// never mentions PRSupport.
package broker

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/psenna/git-proxy/internal/auth"
	"github.com/psenna/git-proxy/internal/port"
)

// Config is the broker's config, mapped from config.BrokerConfig in main.go.
// It mirrors the upstream.UpstreamConfig-vs-config.UpstreamConfig split: config
// is a pure YAML leaf with no broker import, so main.go translates the YAML
// shape into this type. This struct carries only the broker's runtime fields.
type Config struct {
	// Listen is the broker HTTP listen address. Empty means disabled; main.go
	// does not call New when Listen is empty, so this is informational here.
	Listen string
	// AllowedAgents is the allowlist of agent names permitted to use broker
	// ops. Empty means "all authenticated agents" (authentication still gates).
	AllowedAgents []string
	// AllowedOps optionally restricts which op kinds are permitted. Empty
	// means all ops are allowed. Values: "pr.create", "pr.get", "pr.list",
	// "pr.merge", "pr.comment", "pr.review", "ci.status".
	AllowedOps []string
	// MergeMethod is the default GitHub merge method when a merge request does
	// not specify one. Empty defaults to "merge".
	MergeMethod string
}

// Broker is the agent-facing broker HTTP server. It implements port.Transport
// so main.go's serveTransports fan-out runs it alongside the git frontends.
type Broker struct {
	ln   net.Listener
	prs  port.PRSupport // type-asserted from port.Upstream at New
	repos map[string]string // agent-facing repo path → upstream repo key
	auth      port.Authenticator // agent Bearer authenticator; nil → fail closed
	auditSink port.AuditSink     // best-effort; nil → no audit

	mergeMethod   string
	allowedAgents map[string]bool // empty-set means "all authenticated agents"
	allowedOps    map[string]bool // empty-set means "all ops"

	server *http.Server
}

// New constructs a broker. It type-asserts port.PRSupport off up and fails
// closed (returns an error) when up does not implement it — the broker is
// meaningless without an SCM adapter, and main.go treats the error as a startup
// failure rather than silently running a broker that 501s every op.
func New(ln net.Listener, up port.Upstream, repos map[string]string, a port.Authenticator, audit port.AuditSink, cfg Config) (*Broker, error) {
	prs, ok := up.(port.PRSupport)
	if !ok {
		// Fail closed: name the type so an operator sees *why* (e.g. they set
		// upstream.kind: plain, which has no SCM API). No secret content.
		return nil, fmt.Errorf("broker: upstream %T does not implement port.PRSupport; the broker requires an SCM adapter (set upstream.kind: github)", up)
	}
	mergeMethod := cfg.MergeMethod
	if mergeMethod == "" {
		mergeMethod = "merge"
	}
	b := &Broker{
		ln:            ln,
		prs:           prs,
		repos:         repos,
		auth:          a,
		auditSink:      audit,
		mergeMethod:   mergeMethod,
		allowedAgents: toSet(cfg.AllowedAgents),
		allowedOps:    toSet(cfg.AllowedOps),
	}
	mux := b.routes()
	b.server = &http.Server{Handler: mux}
	return b, nil
}

// Serve runs the broker until ctx is canceled, then gracefully shuts down. It
// implements port.Transport so main.go's serveTransports runs it concurrently
// with the git frontends; a broker fatal error (other than a clean shutdown)
// is surfaced through serveTransports.
func (b *Broker) Serve(ctx context.Context) error {
	errCh := make(chan error, 1)
	go func() { errCh <- b.server.Serve(b.ln) }()
	select {
	case <-ctx.Done():
		_ = b.ln.Close()
		return b.server.Shutdown(context.Background())
	case err := <-errCh:
		if err != nil && err != http.ErrServerClosed {
			return err
		}
		return nil
	}
}

// authenticate extracts the Bearer token from the Authorization header and
// validates it via the shared port.Authenticator. This ~10-line extraction is
// intentionally duplicated from the HTTP git frontend to keep the core frontend
// untouched (the broker is a separate surface). Fail closed: a missing header,
// a non-Bearer scheme, an empty/unknown token, OR a nil authenticator all
// return an error the handler maps to 401. The broker NEVER runs unauthenticated
// (unlike the git frontend, which may run open with a warning): an unauthenticated
// broker would let any client drive PR/merge ops on the proxy's behalf.
func (b *Broker) authenticate(r *http.Request) (auth.AgentIdentity, error) {
	if b.auth == nil {
		return auth.AgentIdentity{}, fmt.Errorf("broker: no authenticator configured")
	}
	h := r.Header.Get("Authorization")
	if h == "" {
		return auth.AgentIdentity{}, fmt.Errorf("missing Authorization header")
	}
	const prefix = "Bearer "
	if !strings.HasPrefix(h, prefix) {
		return auth.AgentIdentity{}, fmt.Errorf("authorization scheme is not Bearer")
	}
	return b.auth.Authenticate(r.Context(), strings.TrimPrefix(h, prefix))
}

// authorize reports whether agent is permitted to perform op. An empty
// allowedAgents set means "all authenticated agents" (authentication already
// gated entry); an empty allowedOps set means "all ops". Otherwise both the
// agent name and the op must be in their respective allowlists.
func (b *Broker) authorize(agent auth.AgentIdentity, op string) bool {
	if len(b.allowedAgents) > 0 && !b.allowedAgents[agent.Name] {
		return false
	}
	if len(b.allowedOps) > 0 && !b.allowedOps[op] {
		return false
	}
	return true
}

// resolveRepo maps an agent-facing repo path to the upstream repo key the
// SCM adapter expects, using the same repos map the git frontends use so
// operator aliases work identically on both legs. An unknown repo passes
// through unchanged (the adapter will fail closed if no token is configured).
func (b *Broker) resolveRepo(repo string) string {
	if p, ok := b.repos[repo]; ok && p != "" {
		return p
	}
	return repo
}

// audit records one broker op as an AuditEvent. It is best-effort: a write
// failure is logged and never changes the op outcome (audit is observability,
// not a gate, matching the git-protocol audit contract). The event carries ONLY
// generic reason strings — no token, no upstream response body, no OIDs beyond
// what the agent already knows. Service is the op kind (e.g. "pr.merge");
// Verdict is "allow" or "deny".
func (b *Broker) audit(ctx context.Context, agent, repo, op, verdict string, reasons []string) {
	if b.auditSink == nil {
		return
	}
	err := b.auditSink.Record(ctx, port.AuditEvent{
		Time:     time.Now(),
		Transport: "broker",
		Agent:    agent,
		Repo:     repo,
		Service:  op,
		Verdict:  verdict,
		Reasons:  reasons,
	})
	if err != nil {
		// Best-effort: log and proceed. The op outcome stands regardless.
		// (Mirrors the git-protocol audit path.)
		fmt.Printf("broker: audit record failed: %v\n", err)
	}
}

// toSet converts a slice to a set for O(1) allowlist lookups. A nil or empty
// input yields a nil (empty) map, which authorize treats as "no restriction".
func toSet(items []string) map[string]bool {
	if len(items) == 0 {
		return nil
	}
	m := make(map[string]bool, len(items))
	for _, s := range items {
		m[s] = true
	}
	return m
}