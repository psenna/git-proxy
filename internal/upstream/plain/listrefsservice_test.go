package plain

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/psenna/git-proxy/internal/port"
)

// TestUpstream_ListRefsService_UploadPack asserts ListRefsService fetches
// info/refs with service=git-upload-pack and returns the smart-HTTP stream
// (no Git-Protocol header → v0), attaching vault creds.
func TestUpstream_ListRefsService_UploadPack(t *testing.T) {
	var gotPath, gotQuery, gotProto, gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotQuery = r.URL.RawQuery
		gotProto = r.Header.Get("Git-Protocol")
		gotAuth = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/x-git-upload-pack-advertisement")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "0000")
	}))
	defer srv.Close()

	up := New(srv.URL, memStore{creds: map[string]port.Credentials{
		"test.git": {Username: "ci-bot", Password: "upstream-secret"},
	}})
	refs, err := up.ListRefsService(context.Background(), "test.git", "git-upload-pack")
	if err != nil {
		t.Fatalf("ListRefsService: %v", err)
	}
	defer func() { _ = refs.Body.Close() }()
	if gotPath != "/test.git/info/refs" {
		t.Errorf("path = %q, want /test.git/info/refs", gotPath)
	}
	if gotQuery != "service=git-upload-pack" {
		t.Errorf("query = %q, want service=git-upload-pack", gotQuery)
	}
	if gotProto != "" {
		t.Errorf("Git-Protocol = %q, want empty (v0; no version=2)", gotProto)
	}
	if gotAuth == "" {
		t.Error("vault creds not attached")
	}
	if refs.ContentType != "application/x-git-upload-pack-advertisement" {
		t.Errorf("ContentType = %q", refs.ContentType)
	}
}

// TestUpstream_ListRefsService_ReceivePack asserts the receive-pack service
// path is fetched with the right service query parameter.
func TestUpstream_ListRefsService_ReceivePack(t *testing.T) {
	var gotQuery string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotQuery = r.URL.RawQuery
		w.Header().Set("Content-Type", "application/x-git-receive-pack-advertisement")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "0000")
	}))
	defer srv.Close()

	up := New(srv.URL, nil)
	refs, err := up.ListRefsService(context.Background(), "test.git", "git-receive-pack")
	if err != nil {
		t.Fatalf("ListRefsService: %v", err)
	}
	defer func() { _ = refs.Body.Close() }()
	if gotQuery != "service=git-receive-pack" {
		t.Errorf("query = %q, want service=git-receive-pack", gotQuery)
	}
	if refs.ContentType != "application/x-git-receive-pack-advertisement" {
		t.Errorf("ContentType = %q", refs.ContentType)
	}
}

// TestUpstream_ListRefs_DelegatesToListRefsService asserts ListRefs delegates
// to ListRefsService with the git-upload-pack service (preserving the existing
// ListRefs contract).
func TestUpstream_ListRefs_DelegatesToListRefsService(t *testing.T) {
	var gotQuery string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotQuery = r.URL.RawQuery
		w.Header().Set("Content-Type", "application/x-git-upload-pack-advertisement")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "0000")
	}))
	defer srv.Close()

	up := New(srv.URL, nil)
	if _, err := up.ListRefs(context.Background(), "test.git"); err != nil {
		t.Fatalf("ListRefs: %v", err)
	}
	if gotQuery != "service=git-upload-pack" {
		t.Errorf("ListRefs query = %q, want service=git-upload-pack", gotQuery)
	}
}

// TestUpstream_ListRefsService_NonOK asserts a non-200 upstream response yields
// an error (fail closed — no usable advertisement).
func TestUpstream_ListRefsService_NonOK(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	up := New(srv.URL, nil)
	if _, err := up.ListRefsService(context.Background(), "test.git", "git-upload-pack"); err == nil {
		t.Fatal("expected error for non-200 upstream, got nil")
	}
}