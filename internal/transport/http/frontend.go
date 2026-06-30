// Package httpfront is the HTTPS smart-HTTP frontend: it terminates the
// agent's git traffic and routes the three smart-HTTP endpoints to an
// upstream. Passthrough: no policy, no protocol parsing beyond routing.
package httpfront

import (
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"

	"github.com/psenna/git-proxy/internal/gitproto"
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
}

// New returns a Frontend that listens on ln, forwards POST streams through up,
// and reverse-proxies info/refs to upstreamURL. repos maps agent-facing repo
// paths to upstream repo paths.
func New(ln net.Listener, up port.Upstream, upstreamURL string, repos map[string]string) *Frontend {
	f := &Frontend{
		ln:          ln,
		upstreamURL: strings.TrimRight(upstreamURL, "/"),
		proxy:       gitproto.New(up),
		repos:       repos,
		client:      &http.Client{},
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

// handle routes a single smart-HTTP request to one of the three endpoints.
func (f *Frontend) handle(w http.ResponseWriter, r *http.Request) {
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

// handleInfoRefs reverse-proxies ref discovery to the upstream, preserving the
// service query parameter. Both upload-pack and receive-pack advertisements
// flow through untouched.
func (f *Frontend) handleInfoRefs(w http.ResponseWriter, r *http.Request, repo string) {
	url := f.upstreamURL + "/" + repo + "/info/refs"
	if r.URL.RawQuery != "" {
		url += "?" + r.URL.RawQuery
	}
	req, err := http.NewRequestWithContext(r.Context(), http.MethodGet, url, nil)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	resp, err := f.client.Do(req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	defer func() { _ = resp.Body.Close() }()
	copyHeaders(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body)
}

// handleService streams a POST service (upload-pack / receive-pack) through the
// gitproto proxy. gzip request bodies are decompressed first so the upstream
// receives raw git protocol.
func (f *Frontend) handleService(w http.ResponseWriter, r *http.Request, repo, service, resultContentType string) {
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

// parsePath splits a smart-HTTP path into the repo and the endpoint suffix.
// The repo may contain slashes (e.g. "org/team/repo.git").
func parsePath(path string) (repo, endpoint string, ok bool) {
	for _, ep := range []string{"/info/refs", "/git-upload-pack", "/git-receive-pack"} {
		if i := strings.Index(path, ep); i >= 0 {
			return strings.TrimPrefix(path[:i], "/"), ep, true
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