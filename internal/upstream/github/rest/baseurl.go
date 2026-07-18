package rest

import (
	"fmt"
	"net/url"
)

// publicGithubHost is the host of public GitHub, for which the REST API lives at
// the well-known https://api.github.com root rather than under the web host.
const publicGithubHost = "github.com"

// BaseURL derives the GitHub REST API root from the proxy's upstream URL (the
// same value configured as upstream.url, which also drives the git smart-HTTP
// leg). For public GitHub (github.com, or an empty URL meaning "default") it
// returns the fixed https://api.github.com root. For any other host it assumes a
// GitHub Enterprise Server instance and returns <scheme>://<host>/api/v3, the
// documented GHES REST root.
//
// The upstream URL for a GHES deployment is the instance root (e.g.
// https://ghes.example.com), NOT the API root (https://ghes.example.com/api/v3):
// the same upstream.url drives both legs, and this function computes the REST
// root from it. A malformed upstream URL is an error (fail closed).
//
// Note: a non-GitHub host (e.g. a Gitea server) cannot be reliably distinguished
// from a GHES instance by hostname alone. The operator opts into the GitHub
// adapter by setting upstream.kind: github; the SCM REST path additionally fails
// closed at call time when no token is configured for the repo (tokenFor), so a
// misconfigured Gitea upstream never makes an authenticated SCM call. A future
// enhancement may probe /api/v3/version to distinguish GHES from other SCMs.
func BaseURL(upstreamURL string) (string, error) {
	if upstreamURL == "" {
		return "https://api.github.com", nil
	}
	parsed, err := url.Parse(upstreamURL)
	if err != nil {
		return "", fmt.Errorf("rest: derive base url: %w", err)
	}
	host := parsed.Hostname() // no port
	if host == "" || host == publicGithubHost {
		return "https://api.github.com", nil
	}
	scheme := parsed.Scheme
	if scheme == "" {
		scheme = "https"
	}
	// parsed.Host keeps the port (GHES on a non-default port); /api/v3 is the
	// documented GHES REST root.
	return fmt.Sprintf("%s://%s/api/v3", scheme, parsed.Host), nil
}