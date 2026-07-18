package broker

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"

	"github.com/psenna/git-proxy/internal/auth"
	"github.com/psenna/git-proxy/internal/port"
)

// routes builds the broker's mux. The agent URL-encodes the repo key's slash
// (e.g. POST /owner%2Frepo.git/prs) so the {repo} wildcard — a single path
// segment — captures the full owner/repo.git key (decoded by ServeMux). The
// {ref...} wildcard on the checks route captures a SHA or a branch that itself
// contains slashes, with no encoding required.
//
// healthz is unauthenticated (a liveness probe must not 401); the op routes
// all require a valid agent Bearer token (authenticate) and pass the allowlist
// (authorize) before they touch PRSupport.
func (b *Broker) routes() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", b.handleHealthz)
	mux.HandleFunc("POST /{repo}/prs", b.handleCreate)
	mux.HandleFunc("GET /{repo}/prs", b.handleList)
	mux.HandleFunc("GET /{repo}/prs/{number}", b.handleGet)
	mux.HandleFunc("POST /{repo}/prs/{number}/merge", b.handleMerge)
	mux.HandleFunc("POST /{repo}/prs/{number}/comments", b.handleComment)
	mux.HandleFunc("POST /{repo}/prs/{number}/reviews", b.handleReview)
	mux.HandleFunc("GET /{repo}/checks/{ref...}", b.handleChecks)
	return mux
}

// handleHealthz is an unauthenticated liveness probe. It carries no upstream
// data and never calls PRSupport — it only confirms the broker's mux is up.
func (b *Broker) handleHealthz(w http.ResponseWriter, _ *http.Request) {
	respondJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// handleCreate implements POST /{repo}/prs (op pr.create).
func (b *Broker) handleCreate(w http.ResponseWriter, r *http.Request) {
	const op = "pr.create"
	repo := b.resolveRepo(r.PathValue("repo"))
	agent, ok := b.authOK(w, r, repo, op)
	if !ok {
		return
	}
	var req createPRReq
	if err := decodeJSON(r, &req); err != nil {
		b.opFail(w, r, agent.Name, repo, op, err)
		return
	}
	pr, err := b.prs.EnsurePR(r.Context(), repo, req.Head, req.Base, req.Title)
	if err != nil {
		b.opFail(w, r, agent.Name, repo, op, err)
		return
	}
	b.audit(r.Context(), agent.Name, repo, op, "allow", nil)
	respondJSON(w, http.StatusCreated, pr)
}

// handleList implements GET /{repo}/prs (op pr.list). state is taken from the
// ?state= query (empty defaults to "open" inside the adapter).
func (b *Broker) handleList(w http.ResponseWriter, r *http.Request) {
	const op = "pr.list"
	repo := b.resolveRepo(r.PathValue("repo"))
	agent, ok := b.authOK(w, r, repo, op)
	if !ok {
		return
	}
	state := r.URL.Query().Get("state")
	prs, err := b.prs.ListPRs(r.Context(), repo, state)
	if err != nil {
		b.opFail(w, r, agent.Name, repo, op, err)
		return
	}
	b.audit(r.Context(), agent.Name, repo, op, "allow", nil)
	respondJSON(w, http.StatusOK, prs)
}

// handleGet implements GET /{repo}/prs/{number} (op pr.get).
func (b *Broker) handleGet(w http.ResponseWriter, r *http.Request) {
	const op = "pr.get"
	repo := b.resolveRepo(r.PathValue("repo"))
	agent, ok := b.authOK(w, r, repo, op)
	if !ok {
		return
	}
	number, err := strconv.Atoi(r.PathValue("number"))
	if err != nil {
		b.opFail(w, r, agent.Name, repo, op, fmt.Errorf("invalid pr number"))
		return
	}
	pr, err := b.prs.GetPR(r.Context(), repo, number)
	if err != nil {
		b.opFail(w, r, agent.Name, repo, op, err)
		return
	}
	b.audit(r.Context(), agent.Name, repo, op, "allow", nil)
	respondJSON(w, http.StatusOK, pr)
}

// handleMerge implements POST /{repo}/prs/{number}/merge (op pr.merge). The
// optional ?method= / body method overrides the broker's configured default.
func (b *Broker) handleMerge(w http.ResponseWriter, r *http.Request) {
	const op = "pr.merge"
	repo := b.resolveRepo(r.PathValue("repo"))
	agent, ok := b.authOK(w, r, repo, op)
	if !ok {
		return
	}
	number, err := strconv.Atoi(r.PathValue("number"))
	if err != nil {
		b.opFail(w, r, agent.Name, repo, op, fmt.Errorf("invalid pr number"))
		return
	}
	var req mergePRReq
	// decodeJSON returns nil for an empty body (the common "no body → default
	// method" path) and an error only for a malformed body, which we surface as
	// 400 — never silently fall back to the default merge method on a bad body,
	// since a truncated {"method":"squash" would otherwise merge with the wrong
	// (hard-to-reverse) method.
	if err := decodeJSON(r, &req); err != nil {
		b.opFail(w, r, agent.Name, repo, op, err)
		return
	}
	method := req.Method
	if method == "" {
		method = r.URL.Query().Get("method")
	}
	if method == "" {
		method = b.mergeMethod
	}
	if err := b.prs.MergePR(r.Context(), repo, number, method); err != nil {
		b.opFail(w, r, agent.Name, repo, op, err)
		return
	}
	b.audit(r.Context(), agent.Name, repo, op, "allow", nil)
	w.WriteHeader(http.StatusNoContent)
}

// handleComment implements POST /{repo}/prs/{number}/comments (op pr.comment).
func (b *Broker) handleComment(w http.ResponseWriter, r *http.Request) {
	const op = "pr.comment"
	repo := b.resolveRepo(r.PathValue("repo"))
	agent, ok := b.authOK(w, r, repo, op)
	if !ok {
		return
	}
	number, err := strconv.Atoi(r.PathValue("number"))
	if err != nil {
		b.opFail(w, r, agent.Name, repo, op, fmt.Errorf("invalid pr number"))
		return
	}
	var req commentReq
	if err := decodeJSON(r, &req); err != nil {
		b.opFail(w, r, agent.Name, repo, op, err)
		return
	}
	if err := b.prs.CommentPR(r.Context(), repo, number, req.Body); err != nil {
		b.opFail(w, r, agent.Name, repo, op, err)
		return
	}
	b.audit(r.Context(), agent.Name, repo, op, "allow", nil)
	w.WriteHeader(http.StatusNoContent)
}

// handleReview implements POST /{repo}/prs/{number}/reviews (op pr.review).
func (b *Broker) handleReview(w http.ResponseWriter, r *http.Request) {
	const op = "pr.review"
	repo := b.resolveRepo(r.PathValue("repo"))
	agent, ok := b.authOK(w, r, repo, op)
	if !ok {
		return
	}
	number, err := strconv.Atoi(r.PathValue("number"))
	if err != nil {
		b.opFail(w, r, agent.Name, repo, op, fmt.Errorf("invalid pr number"))
		return
	}
	var req reviewReq
	if err := decodeJSON(r, &req); err != nil {
		b.opFail(w, r, agent.Name, repo, op, err)
		return
	}
	if err := b.prs.ReviewPR(r.Context(), repo, number, req.Event, req.Body); err != nil {
		b.opFail(w, r, agent.Name, repo, op, err)
		return
	}
	b.audit(r.Context(), agent.Name, repo, op, "allow", nil)
	w.WriteHeader(http.StatusNoContent)
}

// handleChecks implements GET /{repo}/checks/{ref...} (op ci.status). ref may be
// a SHA or a branch (the {ref...} wildcard captures the remainder verbatim,
// slashes included).
func (b *Broker) handleChecks(w http.ResponseWriter, r *http.Request) {
	const op = "ci.status"
	repo := b.resolveRepo(r.PathValue("repo"))
	agent, ok := b.authOK(w, r, repo, op)
	if !ok {
		return
	}
	ref := r.PathValue("ref")
	summary, err := b.prs.Checks(r.Context(), repo, ref)
	if err != nil {
		b.opFail(w, r, agent.Name, repo, op, err)
		return
	}
	b.audit(r.Context(), agent.Name, repo, op, "allow", nil)
	respondJSON(w, http.StatusOK, summary)
}

// authOK performs authentication + authorization for op. On either failure it
// writes the failure response, audits the deny, and returns ok=false so the
// handler returns immediately. On success it returns the agent identity; the
// handler then performs the op and audits the allow itself.
func (b *Broker) authOK(w http.ResponseWriter, r *http.Request, repo, op string) (auth.AgentIdentity, bool) {
	agent, err := b.authenticate(r)
	if err != nil {
		w.Header().Set("WWW-Authenticate", "Bearer")
		respondError(w, http.StatusUnauthorized, "unauthorized")
		b.audit(r.Context(), "", repo, op, "deny", []string{"unauthorized"})
		return auth.AgentIdentity{}, false
	}
	if !b.authorize(agent, op) {
		respondError(w, http.StatusForbidden, "forbidden")
		b.audit(r.Context(), agent.Name, repo, op, "deny", []string{"forbidden"})
		return agent, false
	}
	return agent, true
}

// opFail writes the error response for a failed op (mapping the sentinel to its
// HTTP status) and audits a deny with the generic reason. It centralizes the
// no-leak writeError + audit-deny pair every op handler uses on failure.
func (b *Broker) opFail(w http.ResponseWriter, r *http.Request, agent, repo, op string, err error) {
	_, reason := writeError(w, err)
	b.audit(r.Context(), agent, repo, op, "deny", []string{reason})
}

// writeError maps a port sentinel (or any error) to an HTTP status and a
// generic, no-leak reason, writes the JSON error body, and returns the status
// and reason so the caller can audit. The reason names only the failure class
// — never the upstream response body, a credential, or a token.
//
// ErrUnauthorized maps to 502 "upstream auth" rather than 401: a 401 would tell
// the agent the proxy's token is bad, leaking a proxy misconfiguration; the
// agent's own auth is checked separately in authOK. ErrRateLimited forwards
// the upstream's Retry-After when the REST client surfaced one (via
// *port.RateLimitedError) and never invents one.
func writeError(w http.ResponseWriter, err error) (int, string) {
	var status int
	var reason string
	switch {
	case errors.Is(err, port.ErrNotFound):
		status, reason = http.StatusNotFound, "not found"
	case errors.Is(err, port.ErrUnauthorized):
		status, reason = http.StatusBadGateway, "upstream auth"
	case errors.Is(err, port.ErrForbidden):
		status, reason = http.StatusForbidden, "upstream denied"
	case errors.Is(err, port.ErrNotMergeable):
		status, reason = http.StatusConflict, "not mergeable"
	case errors.Is(err, port.ErrUnprocessable):
		status, reason = http.StatusUnprocessableEntity, "request unprocessable"
	case errors.Is(err, port.ErrRateLimited):
		status, reason = http.StatusTooManyRequests, "rate limited"
		var rle *port.RateLimitedError
		if errors.As(err, &rle) && rle.RetryAfter != "" {
			w.Header().Set("Retry-After", rle.RetryAfter)
		}
	case errors.Is(err, port.ErrNotImplemented):
		status, reason = http.StatusNotImplemented, "not implemented"
	case errors.Is(err, port.ErrUpstream):
		status, reason = http.StatusBadGateway, "upstream error"
	default:
		status, reason = http.StatusBadRequest, "bad request"
	}
	respondError(w, status, reason)
	return status, reason
}

// decodeJSON decodes the request body into dst. An empty body is allowed (dst
// stays zero) so handlers like merge can be called with no body; a malformed
// body is an error the handler surfaces as 400.
func decodeJSON(r *http.Request, dst any) error {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return fmt.Errorf("read body: %w", err)
	}
	if len(body) == 0 {
		return nil
	}
	if err := json.Unmarshal(body, dst); err != nil {
		return fmt.Errorf("decode body: %w", err)
	}
	return nil
}

// respondJSON writes status and a JSON body. A nil v writes only the status
// (used for 204-style responses that have no body, though callers use
// WriteHeader directly for those).
func respondJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if v != nil {
		_ = json.NewEncoder(w).Encode(v)
	}
}

// respondError writes a JSON {"error": reason} body. It is the single shape of
// every broker error response (the no-leak contract: reason is a generic
// class string, never upstream content).
func respondError(w http.ResponseWriter, status int, reason string) {
	respondJSON(w, status, errorResp{Error: reason})
}