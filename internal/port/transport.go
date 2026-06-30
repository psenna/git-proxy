// Package port defines the extensibility seams for git-proxy.
//
// All integration points (transports, upstreams, authentication, policy) are
// expressed as interfaces in this package. New implementations register against
// these interfaces; the core orchestrator never imports a concrete
// implementation directly.
package port

import "context"

// Transport serves git clients over a single wire protocol (HTTP, SSH, ...).
// Serve blocks until ctx is canceled or a fatal error occurs.
type Transport interface {
	Serve(ctx context.Context) error
}
