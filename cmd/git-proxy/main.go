// Command git-proxy is a policy-enforcing gateway between AI coding agents and
// upstream Git repositories. It terminates the agent's git traffic and
// reverse-proxies upload-pack byte streams to a configured upstream git server
// (passthrough), while inspecting receive-pack (push) streams against a policy
// engine: allowed pushes are forwarded verbatim, denied pushes are rejected via
// a report-status response and the upstream is left unchanged. With no policy
// rules configured it runs as a pure passthrough proxy.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"sync"
	"syscall"

	"github.com/psenna/git-proxy/internal/alert"
	logalert "github.com/psenna/git-proxy/internal/alert/log"
	"github.com/psenna/git-proxy/internal/alert/webhook"
	"github.com/psenna/git-proxy/internal/audit/file"
	"github.com/psenna/git-proxy/internal/auth/keyauth"
	"github.com/psenna/git-proxy/internal/auth/token"
	"github.com/psenna/git-proxy/internal/config"
	credfile "github.com/psenna/git-proxy/internal/credentials/file"
	"github.com/psenna/git-proxy/internal/gitproto"
	"github.com/psenna/git-proxy/internal/gitx"
	"github.com/psenna/git-proxy/internal/policy"
	_ "github.com/psenna/git-proxy/internal/policy/rules" // register rules via init()
	"github.com/psenna/git-proxy/internal/port"
	httpfront "github.com/psenna/git-proxy/internal/transport/http"
	sshfront "github.com/psenna/git-proxy/internal/transport/ssh"
	"github.com/psenna/git-proxy/internal/upstream"
	_ "github.com/psenna/git-proxy/internal/upstream/github" // register the github adapter via init()
	"github.com/psenna/git-proxy/internal/version"
)

func main() {
	configPath := flag.String("config", "config.yaml", "path to git-proxy config file")
	flag.Parse()
	if err := run(*configPath); err != nil {
		log.Fatalf("git-proxy: %v", err)
	}
}

func run(configPath string) error {
	cfg, err := config.Load(configPath)
	if err != nil {
		return err
	}
	log.Printf("git-proxy %s starting: listen=%s upstream=%s", version.Version, cfg.Listen, cfg.Upstream.URL)

	ln, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}

	// Upstream credential vault: holds per-repo upstream credentials the proxy
	// attaches on the proxy→upstream leg. The agent never sees these. A missing
	// credentials_file is allowed (passthrough); a malformed one fails closed at
	// startup.
	var creds port.CredentialStore
	if cfg.Upstream.CredentialsFile != "" {
		store, err := credfile.New(cfg.Upstream.CredentialsFile)
		if err != nil {
			return fmt.Errorf("load credentials: %w", err)
		}
		creds = store
	}

	// Agent authenticator: Bearer tokens. If no tokens are configured the proxy
	// runs unauthenticated (fail open at the config level); production must
	// configure at least one token. With tokens configured, every request must
	// present a valid token or receive 401 (fail closed at the request level).
	var auth port.Authenticator
	if len(cfg.Auth.Tokens) > 0 {
		auth = token.New(cfg.Auth.Tokens)
	}

	// Upstream/SCM adapter: built via the upstream registry (v1.md M10), selected
	// by upstream.kind (default "plain" — backward compatible). Fail-closed on
	// an unknown kind: upstream.Build returns an error rather than silently
	// falling back. config is a YAML leaf; it does NOT import the registry, so
	// main.go maps the YAML shape into upstream.UpstreamConfig here (carrying
	// the already-loaded creds so every adapter shares one store).
	up, err := upstream.Build(upstream.UpstreamConfig{
		Kind:            cfg.Upstream.Kind,
		URL:             cfg.Upstream.URL,
		CredentialsStore: creds,
	})
	if err != nil {
		return fmt.Errorf("upstream: build kind %q: %w", cfg.Upstream.Kind, err)
	}
	httpFrontend := httpfront.New(ln, up, cfg.Upstream.URL, cfg.Repos, auth, creds)

	// Audit sink: append-only JSONL file. Built once and wired into BOTH
	// frontends' proxies (each owns its own *gitproto.Proxy). Empty
	// audit.file → disabled (nil sink, the proxy skips recording — existing
	// behavior). When set, fail fast at startup if the file cannot be opened
	// (fail-closed at startup, NOT per-op: a misconfigured audit path is a
	// startup error, not a silent gap). The sink is closed on shutdown.
	var auditSink *file.Sink
	if cfg.Audit.File != "" {
		s, err := file.New(cfg.Audit.File)
		if err != nil {
			return fmt.Errorf("audit: open %s: %w", cfg.Audit.File, err)
		}
		auditSink = s
		httpFrontend.SetAuditSink(auditSink, "http")
		log.Printf("git-proxy: audit enabled (file=%s)", cfg.Audit.File)
	} else {
		log.Printf("git-proxy: audit off (no audit.file) — audit disabled")
	}

	// Alert sink: a webhook that POSTs violation Alerts as JSON, plus a log
	// (stderr) sink, fanned out via a MultiAlertSink so operators see
	// violations both in real time (webhook) and in the proxy log. Empty
	// alerts.webhook → disabled (nil sink, the proxy never fires an Alert —
	// existing behavior). When set, fail fast at startup ONLY if the webhook
	// URL is malformed (a config error; config.validate already rejects this,
	// so webhook.New should not error here — but guard regardless). An
	// unreachable webhook at runtime is best-effort (the sink returns a
	// delivery error the proxy logs; the op proceeds regardless). The sink is
	// closed on shutdown (frees idle HTTP connections).
	var alertSink port.AlertSink
	var webhookSink *webhook.Sink
	if cfg.Alerts.Webhook != "" {
		ws, err := webhook.New(cfg.Alerts.Webhook)
		if err != nil {
			return fmt.Errorf("alerts: webhook: %w", err)
		}
		webhookSink = ws
		alertSink = alert.Multi(ws, logalert.NewSink(nil))
		httpFrontend.SetAlertSink(alertSink)
		log.Printf("git-proxy: alerts enabled (webhook=%s)", cfg.Alerts.Webhook)
	} else {
		log.Printf("git-proxy: alerts off (no alerts.webhook) — alert disabled")
	}

	// Dry-run mode: when policy.dry_run is on, the proxy FORWARDS a clean
	// engine push-deny (instead of writing the deny response) and records the
	// TRUE verdict (deny) with DryRun=true. The engine stays pure — it returns
	// the true verdict; dry-run is a proxy-level concern. Default false
	// (enforce-on-deny — today's behavior). Wired into BOTH frontends so policy
	// applies identically across HTTP and SSH.
	if cfg.Policy.DryRun {
		httpFrontend.SetDryRun(true)
		log.Printf("git-proxy: dry-run enabled (policy denies are forwarded, not enforced; mode=%s)", cfg.Policy.Mode)
	}

	// Enforcement state, built once and wired into BOTH the HTTP and SSH
	// frontends so policy applies identically across transports. The engine is
	// pure (no I/O); the inspection mirror (git binary) is owned by the mirror
	// opener. With no enabled rules and no read-deny, enforcement is off
	// (passthrough) and the SSH frontend (if enabled) shares the same
	// passthrough behavior.
	var (
		eng      *policy.Engine
		opener   gitproto.MirrorOpener
		readDeny = cfg.Policy.ReadDenyMatcher()
		maxBytes = cfg.Policy.MaxPackfileBytesOrDefault()
	)

	// Push enforcement: build the policy engine from config when any rule is
	// enabled. With no enabled rules the proxy stays passthrough (no mirror,
	// no inspection) — preserving the unauthenticated/passthrough behavior when
	// policy is unconfigured.
	if cfg.Policy.HasEnabledRules() {
		e, err := policy.Resolve(cfg.Policy.ToPolicy(), nil)
		if err != nil {
			return fmt.Errorf("load policy: %w", err)
		}
		eng = e
		mirrorDir := cfg.Policy.Mirror.Dir
		if mirrorDir == "" {
			return fmt.Errorf("config: policy.mirror.dir is required when policy rules are enabled")
		}
		opener = newMirrorOpener(cfg.Upstream.URL, mirrorDir, creds)
		httpFrontend.SetEnforcement(eng, opener, maxBytes)
		log.Printf("git-proxy: push enforcement enabled (rules=%d, mirror=%s, max_packfile_bytes=%d)",
			len(cfg.Policy.Rules), mirrorDir, maxBytes)
	} else {
		log.Printf("git-proxy: push enforcement off (no policy rules enabled) — passthrough")
	}

	// Read protection: build the proxy-level fetch path matcher from
	// policy.read.deny. With no deny patterns read protection is OFF. When set,
	// the proxy assembles the packfile and withholds blobs whose path matches.
	// Fail closed at startup on a malformed deny pattern. Read protection needs
	// a mirror opener; if push enforcement is also off, wire one.
	if cfg.Policy.ReadDenyEnabled() {
		if bad := cfg.Policy.MalformedReadDenyPatterns(); len(bad) > 0 {
			return fmt.Errorf("config: policy.read.deny has malformed pattern(s): %q", bad)
		}
		mirrorDir := cfg.Policy.Mirror.Dir
		if mirrorDir == "" {
			return fmt.Errorf("config: policy.mirror.dir is required when read protection is enabled")
		}
		// If push enforcement is off, no mirror opener has been wired yet; build
		// one for the read-protection fetch path. When push enforcement is on,
		// the opener from SetEnforcement is reused (the proxy already holds it).
		if !cfg.Policy.HasEnabledRules() {
			opener = newMirrorOpener(cfg.Upstream.URL, mirrorDir, creds)
			httpFrontend.SetEnforcement(nil, opener, maxBytes)
		}
		httpFrontend.SetReadDeny(readDeny)
		log.Printf("git-proxy: read protection enabled (deny patterns=%d, mirror=%s)",
			len(cfg.Policy.Read.Deny), mirrorDir)
	} else {
		log.Printf("git-proxy: read protection off (no policy.read.deny) — passthrough")
	}

	// SSH frontend: enabled only when ssh.listen is configured. It holds its
	// own *gitproto.Proxy (built via gitproto.New(up)) and is wired with the
	// SAME engine / opener / readDeny / maxBytes as the HTTP frontend so policy
	// applies identically over SSH. Auth is SSH public key → agent identity via
	// keyauth (the HTTP Bearer authenticator is unchanged). SSH disabled when
	// ssh.listen is empty (today's HTTP-only behavior).
	var transports []port.Transport
	transports = append(transports, httpFrontend)
	if cfg.SSH.Listen != "" {
		sshAuthn, err := keyauth.New(cfg.SSH.AuthorizedKeys)
		if err != nil {
			return fmt.Errorf("load ssh authorized keys: %w", err)
		}
		sshLn, err := net.Listen("tcp", cfg.SSH.Listen)
		if err != nil {
			return fmt.Errorf("ssh listen: %w", err)
		}
		sshFE, err := sshfront.New(sshLn, up, cfg.Repos, sshAuthn, cfg.SSH.HostKey)
		if err != nil {
			return fmt.Errorf("ssh frontend: %w", err)
		}
		sshFE.SetEnforcement(eng, opener, maxBytes)
		sshFE.SetReadDeny(readDeny)
		// Audit the SSH frontend with its own transport tag (the sink is shared
		// with HTTP; each frontend stamps its tag into its events).
		if auditSink != nil {
			sshFE.SetAuditSink(auditSink, "ssh")
		}
		// Dry-run + alerts apply identically over SSH (same engine, same proxy
		// semantics). Each frontend owns its own *gitproto.Proxy, so the sinks /
		// dry-run flag are wired into the SSH frontend's proxy separately.
		if cfg.Policy.DryRun {
			sshFE.SetDryRun(true)
		}
		if alertSink != nil {
			sshFE.SetAlertSink(alertSink)
		}
		transports = append(transports, sshFE)
		log.Printf("git-proxy: SSH frontend enabled: listen=%s", cfg.SSH.Listen)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	err = serveTransports(ctx, stop, transports)
	// Graceful shutdown: close the audit sink (flush-safe; the file is
	// append-only so close never loses already-written lines) and the webhook
	// alert sink (frees idle HTTP connections). Both best-effort.
	if auditSink != nil {
		if cerr := auditSink.Close(); cerr != nil {
			log.Printf("git-proxy: close audit sink: %v", cerr)
		}
	}
	if webhookSink != nil {
		if cerr := webhookSink.Close(); cerr != nil {
			log.Printf("git-proxy: close alert webhook sink: %v", cerr)
		}
	}
	return err
}

// serveTransports runs all wired transports concurrently and returns when ctx
// is canceled (graceful shutdown) or any transport returns a fatal error. On a
// fatal error from any transport, stop is called so the others shut down; the
// first non-nil error is surfaced. A transport returning nil (e.g. listener
// closed) does not by itself shut down the others — only ctx cancel or a fatal
// error does.
func serveTransports(ctx context.Context, stop context.CancelFunc, transports []port.Transport) error {
	if len(transports) == 0 {
		<-ctx.Done()
		return nil
	}
	errCh := make(chan error, len(transports))
	for _, t := range transports {
		go func(tt port.Transport) { errCh <- tt.Serve(ctx) }(t)
	}
	var firstErr error
	for i := 0; i < len(transports); i++ {
		if err := <-errCh; err != nil && firstErr == nil {
			firstErr = err
			stop() // cancel ctx so the remaining transports shut down
		}
	}
	return firstErr
}

// newMirrorOpener returns a gitproto.MirrorOpener that caches one bare mirror
// per upstream repo under root, cloning from upstreamURL on first open. The
// upstream credentials (for the fetch leg) are attached when non-nil; the agent
// never sees them — they live only inside the mirror's remote config. The cache
// is safe for concurrent use.
func newMirrorOpener(upstreamURL, root string, creds port.CredentialStore) gitproto.MirrorOpener {
	var mu sync.Mutex
	cache := map[string]*gitx.Mirror{}
	return func(ctx context.Context, repo string) (*gitx.Mirror, error) {
		mu.Lock()
		if m, ok := cache[repo]; ok {
			mu.Unlock()
			return m, nil
		}
		mu.Unlock()
		m, err := gitx.Open(ctx, upstreamURL, repo, root, creds)
		if err != nil {
			return nil, err
		}
		mu.Lock()
		cache[repo] = m
		mu.Unlock()
		return m, nil
	}
}
