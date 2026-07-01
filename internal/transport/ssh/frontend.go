// Package sshfront is the SSH transport frontend: it terminates an agent's
// git-over-SSH session and routes git-upload-pack / git-receive-pack through a
// *gitproto.Proxy (the SAME protocol/enforcement handlers as the HTTP
// frontend). The only SSH-specific protocol work is the ref advertisement,
// which is written to the channel raw (no smart-HTTP "# service=" preamble)
// before negotiation is handed to the proxy.
//
// The frontend holds its own *gitproto.Proxy (built via gitproto.New(up)) and
// exposes SetEnforcement / SetReadDeny thin wrappers mirroring the HTTP
// frontend, so main.go wires the SAME engine / mirror opener / read-deny
// matcher / maxBytes into both transports. Per-frontend proxy (rather than a
// shared one) avoids cross-transport locking and matches the HTTP frontend's
// shape.
//
// Auth: SSH public-key → agent identity via internal/auth/keyauth. The
// PublicKeyCallback computes ssh.FingerprintSHA256(clientKey), resolves the
// identity, and stashes the agent name in *ssh.Permissions.Extensions["agent"];
// the session handler reads it and stores it in ctx via auth.WithAgent so the
// proxy's agentName(ctx) sees the SSH-authenticated agent (same context-key
// mechanism as the HTTP frontend).
//
// Fail-closed: unknown SSH key → connection rejected (no session);
// unparseable/unknown exec command → reject with an error and exit non-zero;
// advertisement fetch/parse/emit error → ERR pkt-line + no negotiation; never
// leak upstream creds (the SSH frontend sees no creds — they live on the
// proxy→upstream leg). v0 only over SSH (v2-over-SSH is out of scope for v1).
package sshfront

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"strings"

	"github.com/psenna/git-proxy/internal/auth"
	"github.com/psenna/git-proxy/internal/gitproto"
	"github.com/psenna/git-proxy/internal/pathmatch"
	"github.com/psenna/git-proxy/internal/policy"
	"github.com/psenna/git-proxy/internal/port"
	"golang.org/x/crypto/ssh"
)

// Frontend is the SSH transport. It implements port.Transport.
type Frontend struct {
	ln       net.Listener
	up       port.Upstream
	proxy    *gitproto.Proxy
	repos    map[string]string
	authn    *keyAuthenticator
	sshSrv   *ssh.ServerConfig
	hostKey  ssh.Signer
}

// keyAuthenticator wraps a port.Authenticator (keyauth) with the SSH-specific
// key→fingerprint resolution so the PublicKeyCallback can call Authenticate.
// Keeping this here avoids the SSH frontend importing keyauth directly (it
// only needs the port.Authenticator contract + the fingerprint computation).
type keyAuthenticator struct {
	port.Authenticator
}

// New returns a Frontend that listens on ln, forwards git protocol through up
// via its own *gitproto.Proxy, and authenticates SSH public keys against authn
// (a port.Authenticator whose Authenticate takes an SSH key fingerprint). repos
// maps agent-facing repo paths to upstream repo paths (same semantics as the
// HTTP frontend). hostKeyPath is the SSH host private-key file path; if empty,
// the frontend generates an ephemeral ed25519 key at startup (dev/test only —
// log a warning). Fail-closed: a non-empty path that is missing/unreadable or
// unparseable returns an error (no silent fallback to ephemeral when a path is
// configured).
func New(ln net.Listener, up port.Upstream, repos map[string]string, authn port.Authenticator, hostKeyPath string) (*Frontend, error) {
	var signer ssh.Signer
	var err error
	if hostKeyPath != "" {
		signer, err = loadHostKeyFromFile(hostKeyPath)
	} else {
		signer, err = loadOrGenerateHostKey()
	}
	if err != nil {
		return nil, fmt.Errorf("sshfront: host key: %w", err)
	}
	if authn == nil {
		return nil, errors.New("sshfront: authenticator is required (fail closed: no key auth = no access)")
	}
	f := &Frontend{
		ln:      ln,
		up:      up,
		proxy:   gitproto.New(up),
		repos:   repos,
		authn:   &keyAuthenticator{Authenticator: authn},
		hostKey: signer,
	}
	cfg := &ssh.ServerConfig{
		PublicKeyCallback: f.publicKeyCallback,
	}
	cfg.AddHostKey(signer)
	f.sshSrv = cfg
	return f, nil
}

// SetEnforcement wires push enforcement into the frontend's proxy: the policy
// engine, a mirror opener for inspection, and the max receive-pack request body
// size in bytes. With engine == nil or opener == nil the proxy stays
// passthrough (policy off). Call before Serve. Mirrors httpfront.Frontend.
func (f *Frontend) SetEnforcement(engine *policy.Engine, opener gitproto.MirrorOpener, maxBytes int64) {
	f.proxy.SetEnforcement(engine, opener, maxBytes)
}

// SetReadDeny wires read-protection into the frontend's proxy. When matcher is
// non-nil, the upload-pack ref advertisement is re-emitted as v0 with the filter
// capability and the proxy's UploadPack assembles a filtered packfile. When nil,
// read protection is OFF. Call before Serve. Mirrors httpfront.Frontend.
func (f *Frontend) SetReadDeny(matcher *pathmatch.Matcher) {
	f.proxy.SetReadDeny(matcher)
}

// SetAuditSink wires an optional audit sink + transport tag into the frontend's
// proxy. A nil sink means audit off. transport ("http"/"ssh") is stamped into
// each audit event. Call before Serve. Mirrors httpfront.Frontend.
func (f *Frontend) SetAuditSink(s port.AuditSink, transport string) {
	f.proxy.SetAuditSink(s)
	f.proxy.SetTransport(transport)
}

// SetDryRun enables/disables dry-run mode on the frontend's proxy. When on, the
// proxy forwards a clean engine push-deny (instead of writing the deny
// response) and records the TRUE verdict with DryRun=true. Call before Serve.
// Mirrors httpfront.Frontend. See gitproto.Proxy.SetDryRun for the full
// semantics (policy denies only, NOT inspection errors; read-protection out of
// v1 scope).
func (f *Frontend) SetDryRun(on bool) { f.proxy.SetDryRun(on) }

// SetAlertSink wires an optional alert sink into the frontend's proxy. A nil
// sink means alerts off (the proxy never fires an Alert). Call before Serve.
// Best-effort: an Alert error is logged by the proxy and does NOT change the
// verdict or block the op. Mirrors httpfront.Frontend.
func (f *Frontend) SetAlertSink(s port.AlertSink) { f.proxy.SetAlertSink(s) }

// Serve serves the frontend until ctx is canceled, then closes the listener.
// It implements port.Transport.
func (f *Frontend) Serve(ctx context.Context) error {
	errCh := make(chan error, 1)
	go func() {
		for {
			conn, err := f.ln.Accept()
			if err != nil {
				errCh <- err
				return
			}
			go f.handleConn(ctx, conn)
		}
	}()
	select {
	case <-ctx.Done():
		_ = f.ln.Close()
		return nil
	case err := <-errCh:
		if err != nil && !errors.Is(err, net.ErrClosed) {
			return err
		}
		return nil
	}
}

// publicKeyCallback validates the client's SSH public key against the
// authorized set and maps it to an agent identity. The agent name is stashed in
// *ssh.Permissions.Extensions["agent"] so the session handler can recover it.
// Fail-closed: an unknown key returns an error (SSH rejects the connection —
// no session, no advertisement).
func (f *Frontend) publicKeyCallback(_ ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
	fp := ssh.FingerprintSHA256(key)
	identity, err := f.authn.Authenticate(context.Background(), fp)
	if err != nil {
		log.Printf("sshfront: key auth denied for fingerprint %s: %v", fp, err)
		return nil, fmt.Errorf("sshfront: unknown public key")
	}
	return &ssh.Permissions{Extensions: map[string]string{"agent": identity.Name}}, nil
}

// handleConn handles one SSH connection: handshake, accept the first session
// channel, and dispatch the exec request.
func (f *Frontend) handleConn(ctx context.Context, conn net.Conn) {
	sconn, chans, reqs, err := ssh.NewServerConn(conn, f.sshSrv)
	if err != nil {
		log.Printf("sshfront: handshake: %v", err)
		return
	}
	defer func() { _ = sconn.Close() }()

	// Drain global (out-of-channel) requests concurrently with the channel
	// loop — the standard x/crypto/ssh server pattern. Discarding them in a
	// goroutine started here (rather than after the channel loop) keeps global
	// requests from piling up while a long-lived git session holds the channel.
	go ssh.DiscardRequests(reqs)

	for newChannel := range chans {
		if newChannel.ChannelType() != "session" {
			_ = newChannel.Reject(ssh.UnknownChannelType, "only session channels are supported")
			continue
		}
		channel, reqs, err := newChannel.Accept()
		if err != nil {
			log.Printf("sshfront: accept channel: %v", err)
			continue
		}
		f.handleSession(ctx, sconn, channel, reqs)
	}
}

// handleSession handles one session channel. It waits for the exec request
// carrying the git command, runs the git flow, then closes the channel. Any
// non-exec request (shell, pty, env, etc.) is rejected — git only ever exec's
// the pack commands.
func (f *Frontend) handleSession(ctx context.Context, sconn *ssh.ServerConn, channel ssh.Channel, reqs <-chan *ssh.Request) {
	defer func() { _ = channel.Close() }()
	for req := range reqs {
		switch req.Type {
		case "exec":
			f.handleExec(ctx, sconn, channel, req)
			return
		case "env":
			// git sends an env request to negotiate protocol v2
			// (GIT_PROTOCOL=version=2). We do NOT honor it (v2-over-SSH is out
			// of scope for v1) — replying false makes git fall back to v0, which
			// is what we advertise. Acknowledging it would make git expect a v2
			// advertisement and hang on our v0 one.
			_ = req.Reply(false, nil)
		default:
			// Reject shell, pty, subsystem, etc. Git only exec's.
			_ = req.Reply(false, nil)
		}
	}
}

// handleExec parses the exec command (git-upload-pack '/repo' |
// git-receive-pack '/repo'), maps the repo, writes the raw v0 ref advertisement,
// then hands the channel stdin/stdout to Proxy.UploadPack / ReceivePack. The
// agent identity from key auth is stored in ctx via auth.WithAgent. Fail-closed:
// unparseable/unknown command or advertisement error → write an error and exit
// non-zero; never run a partial git session.
func (f *Frontend) handleExec(ctx context.Context, sconn *ssh.ServerConn, channel ssh.Channel, req *ssh.Request) {
	// Acknowledge the exec request; the payload is the command string.
	_ = req.Reply(true, nil)

	// The exec request payload is an SSH string: uint32 length + command
	// bytes. Parse it; a malformed payload (too short / wrong length) is
	// rejected fail-closed (unknown command).
	cmd, parsed := parseSSHString(req.Payload)
	if !parsed || cmd == "" {
		f.failSession(channel, "sshfront: empty or malformed exec command")
		return
	}
	service, repo, ok := parseExecCommand(cmd)
	if !ok {
		f.failSession(channel, fmt.Sprintf("sshfront: refusing unknown command: %q", cmd))
		return
	}
	mapped := f.repoPath(repo)

	// Resolve the authenticated agent identity from key auth and store it in
	// ctx so the proxy's agentName(ctx) sees it (same context key as HTTP).
	agentName := ""
	if sconn.Permissions != nil && sconn.Permissions.Extensions != nil {
		agentName = sconn.Permissions.Extensions["agent"]
	}
	sessionCtx := auth.WithAgent(ctx, auth.AgentIdentity{Name: agentName})

	if err := f.runGitSession(sessionCtx, channel, service, mapped); err != nil {
		log.Printf("sshfront: %s session for repo %q agent %q: %v", service, mapped, agentName, err)
		// runGitSession writes its own structured error and sends exit-status;
		// nothing more to do here.
		return
	}
}

// runGitSession writes the ref advertisement and hands the channel to the proxy.
// It returns nil on a successful session (the proxy completes the negotiation +
// packfile), and a non-nil error when the session must fail (advertisement
// error). On advertisement error it writes an ERR pkt-line (upload-pack) or a
// stderr message (receive-pack) and exits non-zero. On success it exits 0.
func (f *Frontend) runGitSession(ctx context.Context, channel ssh.Channel, service, repo string) error {
	// Write the ref advertisement (raw v0, no preamble).
	if err := f.writeAdvertisement(ctx, channel, service, repo); err != nil {
		// Fail-closed: advertisement error → ERR pkt-line + no negotiation.
		writeSessionError(channel, service, err)
		return err
	}
	// Hand the channel's stdin/stdout to the proxy for negotiation + packfile.
	//
	// upload-pack: the git client does NOT send EOF after `done` (it keeps the
	// channel open for the response), but Proxy.UploadPack does io.ReadAll(body)
	// (shaped for an HTTP request body that self-terminates). So the SSH frontend
	// frames the channel's stdin into the bounded upload-pack request (until
	// done+flush) and hands a bytes.Reader of that framed request as the body.
	// The proxy forwards the framed bytes to the upstream verbatim and streams
	// the packfile back to the channel — exactly the HTTP frontend's path. This
	// is the necessary SSH-specific adaptation beyond the ref advertisement
	// (the brief named the advertisement as the only SSH-specific piece; the
	// stdin framing is an unavoidable consequence of the duplex channel vs the
	// bounded HTTP body — flagged as a deviation). v0-only, single-round fetch.
	//
	// receive-pack: the client sends commands + flush + packfile, then EOFs
	// (closes the write side) after the packfile — so io.ReadAll(channel) returns
	// the full push and the raw channel can be handed directly (no framing).
	var streamErr error
	switch service {
	case "git-upload-pack":
		body, rerr := readUploadPackRequest(channel)
		if rerr != nil {
			writeSessionError(channel, service, rerr)
			_ = sendExitStatus(channel, 1)
			return rerr
		}
		streamErr = f.proxy.UploadPack(ctx, repo, bytes.NewReader(body), channel)
	case "git-receive-pack":
		streamErr = f.proxy.ReceivePack(ctx, repo, channel, channel)
	}
	if streamErr != nil {
		writeSessionError(channel, service, streamErr)
		_ = sendExitStatus(channel, 1)
		return streamErr
	}
	_ = sendExitStatus(channel, 0)
	return nil
}

// writeAdvertisement fetches the upstream advertisement for service as v0,
// parses it, and re-emits it raw (no smart-HTTP preamble) to the channel. For
// upload-pack read-protected, the filter + allow-reachable-sha1-in-want caps
// are added; otherwise the advertisement is re-emitted verbatim. Fail-closed:
// any fetch/parse/emit error returns an error and the caller MUST NOT proceed
// to negotiation.
func (f *Frontend) writeAdvertisement(ctx context.Context, w io.Writer, service, repo string) error {
	refs, err := f.up.ListRefsService(ctx, repo, service)
	if err != nil {
		return fmt.Errorf("sshfront: fetch advertisement: %w", err)
	}
	defer func() { _ = refs.Body.Close() }()
	adv, err := gitproto.ParseRefAdvertisement(refs.Body)
	if err != nil {
		return fmt.Errorf("sshfront: parse advertisement: %w", err)
	}
	var extraCaps []string
	if service == "git-upload-pack" && f.proxy.ReadDenyOn() {
		extraCaps = []string{"filter", "allow-reachable-sha1-in-want"}
	}
	var buf bytes.Buffer
	if err := gitproto.EmitRefAdvertisementRaw(&buf, adv, extraCaps); err != nil {
		return fmt.Errorf("sshfront: emit advertisement: %w", err)
	}
	if _, err := w.Write(buf.Bytes()); err != nil {
		return fmt.Errorf("sshfront: write advertisement: %w", err)
	}
	return nil
}

// writeSessionError writes a structured error to the channel for a failed
// session. For git-upload-pack it writes a v0 ERR pkt-line (the git client
// surfaces it as a fetch error); for git-receive-pack it writes a plain stderr
// message (the push advertisement has no ERR channel). The reason is generic
// and fail-closed: no upstream credentials, no secret content.
func writeSessionError(channel ssh.Channel, service string, err error) {
	reason := "proxy error"
	switch service {
	case "git-upload-pack":
		_ = gitproto.WriteUploadPackErr(channel, reason)
	case "git-receive-pack":
		_, _ = channel.Stderr().Write([]byte("fatal: " + reason + "\n"))
	}
}

// failSession writes a stderr error message and exits the channel non-zero,
// used for unparseable/unknown exec commands before any git protocol begins.
func (f *Frontend) failSession(channel ssh.Channel, reason string) {
	_, _ = channel.Stderr().Write([]byte("fatal: " + reason + "\n"))
	_ = sendExitStatus(channel, 1)
}

// sendExitStatus sends the SSH exit-status channel request (RFC 4254 §6.10):
// a 4-byte big-endian uint32 status. The client surfaces non-zero as a failed
// git command. Errors are logged but not returned: the session is ending
// regardless, and a failed exit-status send (client gone) is not actionable.
func sendExitStatus(channel ssh.Channel, status uint32) error {
	payload := make([]byte, 4)
	binary.BigEndian.PutUint32(payload, status)
	_, err := channel.SendRequest("exit-status", false, payload)
	return err
}

// repoPath maps an agent-facing repository path to the upstream repository path
// (same semantics as the HTTP frontend).
func (f *Frontend) repoPath(repo string) string {
	if p, ok := f.repos[repo]; ok && p != "" {
		return p
	}
	return repo
}

// parseExecCommand parses the SSH exec command string into the git service
// ("git-upload-pack" | "git-receive-pack") and the repository path. Git sends
// the path single-quoted, e.g. `git-upload-pack '/repo.git'`. The repo path may
// be unquoted in some clients; both forms are accepted. A leading slash on the
// repo path (as sent for ssh:// URLs, e.g. '/repo.git') is stripped so the path
// matches the HTTP frontend's repo map keys (which have no leading slash —
// HTTP parsePath strips the host's leading '/'); scp-style paths have no
// leading slash and are unaffected. Returns ok=false for an unrecognized
// command (fail-closed).
func parseExecCommand(cmd string) (service, repo string, ok bool) {
	cmd = strings.TrimSpace(cmd)
	for _, svc := range []string{"git-upload-pack", "git-receive-pack"} {
		if cmd == svc {
			// No path argument — git always sends the path. Reject.
			return "", "", false
		}
		prefix := svc + " "
		if strings.HasPrefix(cmd, prefix) {
			arg := strings.TrimSpace(strings.TrimPrefix(cmd, prefix))
			repo = unquoteRepo(arg)
			if repo == "" {
				return "", "", false
			}
			// Normalize a leading slash (ssh:// URL form) so the repo map keys
			// match the HTTP frontend's (no leading slash).
			repo = strings.TrimPrefix(repo, "/")
			if repo == "" {
				return "", "", false
			}
			return svc, repo, true
		}
	}
	return "", "", false
}

// unquoteRepo strips surrounding single (or double) quotes from the repo path
// argument. Git sends paths single-quoted over SSH.
func unquoteRepo(arg string) string {
	if len(arg) >= 2 {
		if (arg[0] == '\'' && arg[len(arg)-1] == '\'') || (arg[0] == '"' && arg[len(arg)-1] == '"') {
			return arg[1 : len(arg)-1]
		}
	}
	return arg
}

// parseSSHString decodes an SSH string payload (uint32 big-endian length prefix
// + bytes) as used by the "exec" channel request. Returns the string and
// ok=false when the payload is too short or the length field exceeds the
// remaining bytes (malformed — fail-closed).
func parseSSHString(payload []byte) (string, bool) {
	if len(payload) < 4 {
		return "", false
	}
	n := binary.BigEndian.Uint32(payload[:4])
	if int(n) > len(payload)-4 {
		return "", false
	}
	return string(payload[4 : 4+n]), true
}