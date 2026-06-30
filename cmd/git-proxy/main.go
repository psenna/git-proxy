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

	"github.com/psenna/git-proxy/internal/config"
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

	up := plain.New(cfg.Upstream.URL)
	frontend := httpfront.New(ln, up, cfg.Upstream.URL, cfg.Repos)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	return frontend.Serve(ctx)
}