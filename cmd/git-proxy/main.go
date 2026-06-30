// Command git-proxy is a policy-enforcing gateway between AI coding agents and
// upstream Git repositories. This M1 build is a passthrough smart-HTTP proxy:
// it terminates the agent's git traffic and reverse-proxies upload-pack and
// receive-pack byte streams to a configured upstream git server, with no policy
// yet.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/psenna/git-proxy/internal/auth/token"
	"github.com/psenna/git-proxy/internal/config"
	"github.com/psenna/git-proxy/internal/credentials/file"
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

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	return frontend.Serve(ctx)
}
