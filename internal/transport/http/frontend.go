// Package httpfront is the HTTPS smart-HTTP frontend: it terminates the
// agent's git traffic and routes the three smart-HTTP endpoints to an
// upstream. Passthrough: no policy, no protocol parsing beyond routing.
package httpfront

import (
	"bytes"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"

	"github.com/psenna/git-proxy/internal/access"
	"github.com/psenna/git-proxy/internal/auth"
	"github.com/psenna/git-proxy/internal/gitproto"
	"github.com/psenna/git-proxy/internal/pathmatch"
	"github.com/psenna/git-proxy/internal/policy"
	"github.com/psenna/git-proxy/internal/port"
)

// Frontend is the smart-HTTP transport. It implements port.Transport.
type Frontend struct {
	ln          net.Listener
	upstreamURL string
	proxy       *gitproto.Proxy
	repos       map[string]string
	client      *http.Client
	server      *http.Server
	creds       port.CredentialStore
	auth        port.Authenticator
	publicRepos port.RepoMatcher   // nil → no anonymous-read allowlist (deny-by-default)
	readDeny    *pathmatch.Matcher // nil → info/refs passthrough (read protection off)
}

// New returns a Frontend that listens on ln, forwards POST streams through up,
// and reverse-proxies info/refs to upstreamURL. repos maps agent-facing repo
// paths to upstream repo paths.
//
// auth gates every request with Bearer token authentication: a missing or
// invalid token is rejected with 401 (fail closed). Pass a nil Authenticator
// only for unauthenticated passthrough (e.g. local tests). creds, if non-nil,
// is the vault of upstream credentials the proxy attaches when it talks to the
// upstream; the agent never receives these.
func New(ln net.Listener, up port.Upstream, upstreamURL string, repos map[string]string, a port.Authenticator, creds port.CredentialStore, publicRepos port.RepoMatcher) *Frontend {
	f := &Frontend{
		ln:          ln,
		upstreamURL: strings.TrimRight(upstreamURL, "/"),
		proxy:       gitproto.New(up),
		repos:       repos,
		client:      &http.Client{},
		auth:        a,
		creds:       creds,
		publicRepos: publicRepos,
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/", f.handle)
	f.server = &http.Server{Handler: mux}
	return f
}

// Serve serves the frontend until ctx is canceled, then gracefully shuts down.
// It implements port.Transport.
func (f *Frontend) Serve(ctx context.Context) error {
	errCh := make(chan error, 1)
	go func() { errCh <- f.server.Serve(f.ln) }()
	select {
	case <-ctx.Done():
		_ = f.ln.Close()
		return f.server.Shutdown(context.Background())
	case err := <-errCh:
		if err != nil && err != http.ErrServerClosed {
			return err
		}
		return nil
	}
}

// SetEnforcement wires push enforcement into the frontend's proxy: the policy
// engine, a mirror opener for inspection, and the max receive-pack request body
// size in bytes. With engine == nil or opener == nil the proxy stays
// passthrough (policy off). Call before Serve. maxBytes <= 0 uses the proxy
// default (256 MiB).
func (f *Frontend) SetEnforcement(engine *policy.Engine, opener gitproto.MirrorOpener, maxBytes int64) {
	f.proxy.SetEnforcement(engine, opener, maxBytes)
}

// SetReadDeny wires read-protection into the frontend and its proxy. When
// matcher is non-nil, info/refs for git-upload-pack is re-emitted as v0 with the
// filter capability (the client falls back to v0 and may request a partial
// clone), and the proxy's UploadPack assembles a filtered packfile. When nil,
// read protection is OFF and info/refs stays reverse-proxied (passthrough) —
// existing fetch/clone behavior is preserved. Call before Serve.
func (f *Frontend) SetReadDeny(matcher *pathmatch.Matcher) {
	f.readDeny = matcher
	f.proxy.SetReadDeny(matcher)
}

// SetAuditSink wires an optional audit sink + transport tag into the frontend's
// proxy. A nil sink means audit off (the proxy skips recording — existing
// behavior). transport ("http"/"ssh") is stamped into each audit event. Call
// before Serve. Best-effort: a Record error is logged by the proxy and does
// NOT change the verdict or block the op.
func (f *Frontend) SetAuditSink(s port.AuditSink, transport string) {
	f.proxy.SetAuditSink(s)
	f.proxy.SetTransport(transport)
}

// SetDryRun enables/disables dry-run mode on the frontend's proxy. When on, the
// proxy forwards a clean engine push-deny (instead of writing the deny
// response) and records the TRUE verdict with DryRun=true. Call before Serve.
// Mirrors sshfront.Frontend. See gitproto.Proxy.SetDryRun for the full
// semantics (policy denies only, NOT inspection errors; read-protection out of
// v1 scope).
func (f *Frontend) SetDryRun(on bool) { f.proxy.SetDryRun(on) }

// SetAlertSink wires an optional alert sink into the frontend's proxy. A nil
// sink means alerts off (the proxy never fires an Alert). Call before Serve.
// Best-effort: an Alert error is logged by the proxy and does NOT change the
// verdict or block the op. Mirrors sshfront.Frontend.
func (f *Frontend) SetAlertSink(s port.AlertSink) { f.proxy.SetAlertSink(s) }

// handle routes a single smart-HTTP request to one of the three endpoints.
func (f *Frontend) handle(w http.ResponseWriter, r *http.Request) {
	if f.auth != nil {
		agent, err := f.authenticate(r)
		if err != nil {
			log.Printf("httpfront: auth denied: %v", err)
			w.Header().Set("WWW-Authenticate", "Bearer")
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		// Make the authenticated identity available to later milestones
		// (policy, audit) via the request context. Stored via the shared
		// auth.WithAgent helper so the protocol layer can read it without
		// importing this package (no import cycle).
		r = r.WithContext(auth.WithAgent(r.Context(), agent))
	}
	repo, endpoint, ok := parsePath(r.URL.Path)
	if !ok {
		http.NotFound(w, r)
		return
	}
	mapped := f.repoPath(repo)
	switch endpoint {
	case "/info/refs":
		f.handleInfoRefs(w, r, mapped)
	case "/git-upload-pack":
		f.handleService(w, r, mapped, "git-upload-pack",
			"application/x-git-upload-pack-result")
	case "/git-receive-pack":
		f.handleService(w, r, mapped, "git-receive-pack",
			"application/x-git-receive-pack-result")
	default:
		http.NotFound(w, r)
	}
}

// handleInfoRefs handles ref discovery. With read protection OFF
// (f.readDeny == nil) it reverse-proxies the upstream advertisement untouched
// (both upload-pack and receive-pack). With read protection ON and the service
// is git-upload-pack, the proxy CONTROLS the advertisement: it fetches the
// upstream advertisement WITHOUT forwarding the client's Git-Protocol header
// (so the upstream returns v0), parses it, and re-emits it as v0 with the filter
// capability so the client may request a partial clone and negotiates v0 (the
// read-protected upload-pack response is v0-only in v1). git-receive-pack
// advertisements are always passthrough (push is enforced separately).
func (f *Frontend) handleInfoRefs(w http.ResponseWriter, r *http.Request, repo string) {
	isWrite := r.URL.Query().Get("service") == "git-receive-pack"
	if access.Decide(f.creds, f.publicRepos, repo, isWrite) == access.DecisionDeny {
		f.denyRepo(w, r)
		return
	}
	if f.readDeny != nil && r.URL.Query().Get("service") == "git-upload-pack" {
		f.handleInfoRefsReadProtected(w, r, repo)
		return
	}
	url := f.upstreamURL + "/" + repo + "/info/refs"
	if r.URL.RawQuery != "" {
		url += "?" + r.URL.RawQuery
	}
	req, err := http.NewRequestWithContext(r.Context(), http.MethodGet, url, nil)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	f.applyUpstreamCreds(req, repo)
	resp, err := f.client.Do(req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	defer func() { _ = resp.Body.Close() }()
	copyHeaders(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)
	if _, err := io.Copy(w, resp.Body); err != nil {
		log.Printf("httpfront: info/refs stream: %v", err)
	}
}

// handleInfoRefsReadProtected fetches the upstream git-upload-pack advertisement
// as v0 (dropping the client's Git-Protocol header so the upstream does not
// return v2), parses it, and re-emits it as v0 with the filter capability.
// Fail-closed: any upstream/parse/encode error yields a 502 (the agent never sees
// a usable advertisement that would let it fetch unprotected objects).
func (f *Frontend) handleInfoRefsReadProtected(w http.ResponseWriter, r *http.Request, repo string) {
	// Defensive: handleInfoRefs already gated on the deny-check and delegated
	// here only for git-upload-pack. Re-check (always read) so this stays
	// fail-closed even if a future caller routes here directly.
	if access.Decide(f.creds, f.publicRepos, repo, false) == access.DecisionDeny {
		f.denyRepo(w, r)
		return
	}
	url := f.upstreamURL + "/" + repo + "/info/refs?service=git-upload-pack"
	req, err := http.NewRequestWithContext(r.Context(), http.MethodGet, url, nil)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	f.applyUpstreamCreds(req, repo)
	// Deliberately do NOT forward the client's Git-Protocol header: without it
	// the upstream returns a v0 advertisement, which the proxy can parse and
	// re-emit as v0 + filter cap. Forwarding version=2 would force the upstream
	// into v2 format and break the v0 downgrade.
	resp, err := f.client.Do(req)
	if err != nil {
		log.Printf("httpfront: read-protected info/refs upstream fetch for repo %q: %v", repo, err)
		http.Error(w, "upstream unavailable", http.StatusBadGateway)
		return
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		log.Printf("httpfront: read-protected info/refs upstream status %s for repo %q", resp.Status, repo)
		http.Error(w, "upstream unavailable", http.StatusBadGateway)
		return
	}
	adv, err := gitproto.ParseRefAdvertisement(resp.Body)
	if err != nil {
		log.Printf("httpfront: read-protected info/refs parse for repo %q: %v", repo, err)
		http.Error(w, "advertisement parse failed", http.StatusBadGateway)
		return
	}
	// Buffer the re-emitted advertisement and only commit headers (status +
	// Content-Type) + body on a successful emit. Writing Content-Type before
	// EmitRefAdvertisementV0 and only logging an emit error would send a 200
	// with a truncated/partial v0 advertisement; buffer + 502-on-error so the
	// client sees a real failure instead of a malformed advertisement.
	var buf bytes.Buffer
	if err := gitproto.EmitRefAdvertisementV0(&buf, adv, []string{"filter", "allow-reachable-sha1-in-want"}); err != nil {
		log.Printf("httpfront: read-protected info/refs emit for repo %q: %v", repo, err)
		http.Error(w, "advertisement emit failed", http.StatusBadGateway)
		return
	}
	w.Header().Set("Content-Type", "application/x-git-upload-pack-advertisement")
	w.WriteHeader(http.StatusOK)
	if _, err := w.Write(buf.Bytes()); err != nil {
		log.Printf("httpfront: read-protected info/refs write for repo %q: %v", repo, err)
	}
}

// handleService streams a POST service (upload-pack / receive-pack) through the
// gitproto proxy. gzip request bodies are decompressed first so the upstream
// receives raw git protocol.
func (f *Frontend) handleService(w http.ResponseWriter, r *http.Request, repo, service, resultContentType string) {
	// Deny BEFORE consuming the request body: a denied push must not read the
	// (potentially large) receive-pack stream. isWrite is true for push.
	if access.Decide(f.creds, f.publicRepos, repo, service == "git-receive-pack") == access.DecisionDeny {
		f.denyRepo(w, r)
		return
	}
	body, err := requestBody(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	defer func() { _ = body.Close() }()

	w.Header().Set("Content-Type", resultContentType)
	fw := &flushWriter{w: w}
	if fl, ok := w.(http.Flusher); ok {
		fw.f = fl
	}
	var streamErr error
	switch service {
	case "git-upload-pack":
		streamErr = f.proxy.UploadPack(r.Context(), repo, body, fw)
	case "git-receive-pack":
		streamErr = f.proxy.ReceivePack(r.Context(), repo, body, fw)
	}
	if streamErr != nil {
		// If no bytes were written yet, we can still set a proper status.
		// Once streaming has begun, the status is already committed; the
		// best we can do is end the response (the agent will see a truncated
		// stream).
		if !fw.wrote {
			http.Error(w, streamErr.Error(), http.StatusInternalServerError)
		} else {
			log.Printf("httpfront: %s stream error after partial write: %v", service, streamErr)
		}
	}
}

// authenticate extracts the Bearer token from the Authorization header and
// validates it. A missing header, a non-Bearer scheme, an empty token, or an
// unknown token all return an error (fail closed → 401).
func (f *Frontend) authenticate(r *http.Request) (auth.AgentIdentity, error) {
	h := r.Header.Get("Authorization")
	if h == "" {
		return auth.AgentIdentity{}, fmt.Errorf("missing Authorization header")
	}
	const prefix = "Bearer "
	if !strings.HasPrefix(h, prefix) {
		return auth.AgentIdentity{}, fmt.Errorf("authorization scheme is not Bearer")
	}
	token := strings.TrimSpace(h[len(prefix):])
	return f.auth.Authenticate(r.Context(), token)
}

// applyUpstreamCreds attaches vault credentials for repo to an upstream request,
// if any are configured. The agent never sees these: they live only on the
// proxy→upstream leg. A token-only profile (Token set, Username and Password
// both empty) is broker-only: the Token is consumed by the SCM adapter, not by
// Basic auth, so the git leg skips SetBasicAuth entirely rather than emitting a
// meaningless "Basic Og==" header (the request stays anonymous on this leg,
// subject to deny-by-default / public_repos upstream of here).
func (f *Frontend) applyUpstreamCreds(req *http.Request, repo string) {
	if f.creds == nil {
		return
	}
	if c, ok := f.creds.CredentialsFor(repo); ok {
		if c.Username == "" && c.Password == "" {
			return
		}
		req.SetBasicAuth(c.Username, c.Password)
	}
}

// denyRepo rejects a request for a repo not served by this proxy with a fixed
// generic 403. It emits a single, constant reason string — no repo path, no OID,
// no credential — so an unconfigured/unauthorized repo is not leaked to the
// agent (no-leak). Called after authenticate, so an unauthenticated caller gets
// 401 before reaching here (401 before 403).
func (f *Frontend) denyRepo(w http.ResponseWriter, r *http.Request) {
	http.Error(w, `{"error":"repository not served by this proxy"}`, http.StatusForbidden)
}

// parsePath splits a smart-HTTP path into the repo and the endpoint suffix.
// The repo may contain slashes (e.g. "org/team/repo.git"). The endpoint is always
// a SUFFIX of the path (smart-HTTP URLs are <base>/<repo>/<endpoint>); matching
// on a substring would mis-route a repo whose path contains an endpoint token
// (e.g. "/git-upload-pack.git/git-upload-pack" → empty repo), so HasSuffix is
// used, not strings.Index.
func parsePath(path string) (repo, endpoint string, ok bool) {
	for _, ep := range []string{"/info/refs", "/git-upload-pack", "/git-receive-pack"} {
		if strings.HasSuffix(path, ep) {
			return strings.TrimPrefix(path[:len(path)-len(ep)], "/"), ep, true
		}
	}
	return "", "", false
}

func (f *Frontend) repoPath(repo string) string {
	if p, ok := f.repos[repo]; ok && p != "" {
		return p
	}
	return repo
}

// requestBody returns the request body, decompressing gzip transfer encoding so
// the upstream receives raw git protocol.
func requestBody(r *http.Request) (io.ReadCloser, error) {
	if !strings.EqualFold(r.Header.Get("Content-Encoding"), "gzip") {
		return r.Body, nil
	}
	zr, err := gzip.NewReader(r.Body)
	if err != nil {
		return nil, fmt.Errorf("gzip decode: %w", err)
	}
	return zr, nil
}

func copyHeaders(dst, src http.Header) {
	for k, vs := range src {
		for _, v := range vs {
			dst.Add(k, v)
		}
	}
}

// flushWriter flushes after every write so streamed progress reaches the agent
// promptly. wrote reports whether any bytes have been written, so the caller can
// decide whether an error can still set the HTTP status.
type flushWriter struct {
	w     io.Writer
	f     http.Flusher
	wrote bool
}

func (fw *flushWriter) Write(p []byte) (int, error) {
	n, err := fw.w.Write(p)
	if n > 0 {
		fw.wrote = true
	}
	if fw.f != nil {
		fw.f.Flush()
	}
	return n, err
}

// AgentFromContext returns the authenticated agent identity stored in ctx, if
// any. It delegates to the shared auth.FromContext helper so the protocol layer
// and the frontend read the same context key.
func AgentFromContext(ctx context.Context) (auth.AgentIdentity, bool) {
	return auth.FromContext(ctx)
}
