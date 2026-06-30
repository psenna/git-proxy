// Package plain implements port.Upstream against a plain git HTTP server
// (git http-backend or any smart-HTTP server). It forwards protocol byte
// streams verbatim; no inspection happens here. Later milestones wrap or
// replace this to enforce policy on the forwarded streams.
package plain

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/psenna/git-proxy/internal/port"
)

// Upstream talks to a single plain git HTTP server at BaseURL.
type Upstream struct {
	BaseURL string
	client  *http.Client
	creds   port.CredentialStore
}

// New returns an Upstream that forwards to the git server at baseURL. creds, if
// non-nil, is the vault of upstream credentials the proxy attaches to its
// upstream requests (HTTP Basic auth). The agent never receives these; they
// live only on the proxy→upstream leg. A nil creds means no credentials are
// attached (passthrough).
func New(baseURL string, creds port.CredentialStore) *Upstream {
	return &Upstream{
		BaseURL: strings.TrimRight(baseURL, "/"),
		client:  &http.Client{},
		creds:   creds,
	}
}

// ListRefs performs ref discovery for repo. Passthrough uses the upload-pack
// service advertisement; the seam is reserved for later milestones that
// inspect refs.
func (u *Upstream) ListRefs(ctx context.Context, repo string) (port.Refs, error) {
	url := u.BaseURL + "/" + repo + "/info/refs?service=git-upload-pack"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return port.Refs{}, err
	}
	u.applyCreds(req, repo)
	resp, err := u.client.Do(req)
	if err != nil {
		return port.Refs{}, fmt.Errorf("plain: list refs: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		defer func() { _ = resp.Body.Close() }()
		return port.Refs{}, fmt.Errorf("plain: list refs: upstream returned %s", resp.Status)
	}
	return port.Refs{Body: resp.Body, ContentType: resp.Header.Get("Content-Type")}, nil
}

// UploadPack forwards a git-upload-pack request body to the upstream and
// returns the server's response stream.
func (u *Upstream) UploadPack(ctx context.Context, repo string, body io.Reader) (io.ReadCloser, error) {
	return u.post(ctx, repo, "git-upload-pack", "application/x-git-upload-pack-request", body)
}

// ReceivePack forwards a git-receive-pack request body to the upstream and
// returns the server's response stream.
func (u *Upstream) ReceivePack(ctx context.Context, repo string, body io.Reader) (io.ReadCloser, error) {
	return u.post(ctx, repo, "git-receive-pack", "application/x-git-receive-pack-request", body)
}

// post forwards a service POST to the upstream. The body is buffered so the
// upstream request carries an explicit Content-Length: git http-backend over
// CGI rejects chunked request bodies, and buffering guarantees a valid
// content-length regardless of the agent's transfer encoding.
func (u *Upstream) post(ctx context.Context, repo, service, contentType string, body io.Reader) (io.ReadCloser, error) {
	buf, err := io.ReadAll(body)
	if err != nil {
		return nil, fmt.Errorf("plain: read %s body: %w", service, err)
	}
	url := u.BaseURL + "/" + repo + "/" + service
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(buf))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", contentType)
	u.applyCreds(req, repo)
	resp, err := u.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("plain: %s: %w", service, err)
	}
	if resp.StatusCode != http.StatusOK {
		defer func() { _ = resp.Body.Close() }()
		return nil, fmt.Errorf("plain: %s: upstream returned %s", service, resp.Status)
	}
	return resp.Body, nil
}

// applyCreds attaches vault credentials for repo to req, if any are configured.
func (u *Upstream) applyCreds(req *http.Request, repo string) {
	if u.creds == nil {
		return
	}
	if c, ok := u.creds.CredentialsFor(repo); ok {
		req.SetBasicAuth(c.Username, c.Password)
	}
}
