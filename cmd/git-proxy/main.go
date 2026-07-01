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

	"github.com/psenna/git-proxy/internal/auth/token"
	"github.com/psenna/git-proxy/internal/config"
	"github.com/psenna/git-proxy/internal/credentials/file"
	"github.com/psenna/git-proxy/internal/gitproto"
	"github.com/psenna/git-proxy/internal/gitx"
	"github.com/psenna/git-proxy/internal/policy"
	_ "github.com/psenna/git-proxy/internal/policy/rules" // register rules via init()
	"github.com/psenna/git-proxy/internal/port"
	httpfront "github.com/psenna/git-proxy/internal/transport/http"
	"github.com/psenna/git-proxy/internal/upstream/plain"
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
		store, err := file.New(cfg.Upstream.CredentialsFile)
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

	up := plain.New(cfg.Upstream.URL, creds)
	frontend := httpfront.New(ln, up, cfg.Upstream.URL, cfg.Repos, auth, creds)

	// Push enforcement: build the policy engine from config when any rule is
	// enabled. With no enabled rules the proxy stays passthrough (no mirror,
	// no inspection) — preserving the unauthenticated/passthrough behavior when
	// policy is unconfigured. The engine is pure (no I/O); the inspection
	// mirror (git binary) is owned by the mirror opener wired below.
	if cfg.Policy.HasEnabledRules() {
		eng, err := policy.Resolve(cfg.Policy.ToPolicy(), nil)
		if err != nil {
			return fmt.Errorf("load policy: %w", err)
		}
		mirrorDir := cfg.Policy.Mirror.Dir
		if mirrorDir == "" {
			return fmt.Errorf("config: policy.mirror.dir is required when policy rules are enabled")
		}
		opener := newMirrorOpener(cfg.Upstream.URL, mirrorDir, creds)
		frontend.SetEnforcement(eng, opener, cfg.Policy.MaxPackfileBytesOrDefault())
		log.Printf("git-proxy: push enforcement enabled (rules=%d, mirror=%s, max_packfile_bytes=%d)",
			len(cfg.Policy.Rules), mirrorDir, cfg.Policy.MaxPackfileBytesOrDefault())
	} else {
		log.Printf("git-proxy: push enforcement off (no policy rules enabled) — passthrough")
	}

	// Read protection: build the proxy-level fetch path matcher from
	// policy.read.deny. With no deny patterns read protection is OFF (the proxy
	// forwards fetch/clone to the upstream, which speaks whatever the client
	// negotiated). When set, the proxy assembles the packfile and withholds
	// blobs whose path matches. Fail closed at startup on a malformed deny
	// pattern (a typo must not become "deny nothing"). Read protection needs a
	// mirror opener to compute the object set; if push enforcement is also off
	// (no mirror wired yet), wire one from policy.mirror.dir (required).
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
			opener := newMirrorOpener(cfg.Upstream.URL, mirrorDir, creds)
			frontend.SetEnforcement(nil, opener, cfg.Policy.MaxPackfileBytesOrDefault())
		}
		frontend.SetReadDeny(cfg.Policy.ReadDenyMatcher())
		log.Printf("git-proxy: read protection enabled (deny patterns=%d, mirror=%s)",
			len(cfg.Policy.Read.Deny), mirrorDir)
	} else {
		log.Printf("git-proxy: read protection off (no policy.read.deny) — passthrough")
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	return frontend.Serve(ctx)
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
