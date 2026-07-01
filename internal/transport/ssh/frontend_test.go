package sshfront

import (
	"encoding/binary"
	"testing"
)

func TestParseExecCommand_UploadPackQuoted(t *testing.T) {
	svc, repo, ok := parseExecCommand("git-upload-pack '/repo.git'")
	if !ok {
		t.Fatal("expected ok, got false")
	}
	if svc != "git-upload-pack" {
		t.Errorf("service = %q, want git-upload-pack", svc)
	}
	// A leading slash (ssh:// URL form) is stripped so the repo map keys match
	// the HTTP frontend's (no leading slash).
	if repo != "repo.git" {
		t.Errorf("repo = %q, want repo.git", repo)
	}
}

func TestParseExecCommand_ReceivePackQuoted(t *testing.T) {
	svc, repo, ok := parseExecCommand("git-receive-pack '/repo.git'")
	if !ok {
		t.Fatal("expected ok, got false")
	}
	if svc != "git-receive-pack" {
		t.Errorf("service = %q, want git-receive-pack", svc)
	}
	if repo != "repo.git" {
		t.Errorf("repo = %q, want repo.git", repo)
	}
}

func TestParseExecCommand_Unquoted(t *testing.T) {
	// Some clients send the path unquoted.
	svc, repo, ok := parseExecCommand("git-upload-pack repo.git")
	if !ok {
		t.Fatal("expected ok, got false")
	}
	if svc != "git-upload-pack" || repo != "repo.git" {
		t.Errorf("svc=%q repo=%q", svc, repo)
	}
}

func TestParseExecCommand_NestedPath(t *testing.T) {
	svc, repo, ok := parseExecCommand("git-upload-pack 'org/team/repo.git'")
	if !ok {
		t.Fatal("expected ok, got false")
	}
	if svc != "git-upload-pack" || repo != "org/team/repo.git" {
		t.Errorf("svc=%q repo=%q", svc, repo)
	}
}

func TestParseExecCommand_StripsLeadingSlash(t *testing.T) {
	// ssh:// URLs send the path with a leading slash; it is stripped so the
	// repo map keys match the HTTP frontend's (no leading slash).
	svc, repo, ok := parseExecCommand("git-upload-pack '/repo.git'")
	if !ok {
		t.Fatal("expected ok, got false")
	}
	if svc != "git-upload-pack" {
		t.Errorf("service = %q", svc)
	}
	if repo != "repo.git" {
		t.Errorf("repo = %q, want repo.git (leading slash stripped)", repo)
	}
}

func TestParseExecCommand_UnknownCommand(t *testing.T) {
	// A shell command or unknown service must be rejected (fail closed).
	if _, _, ok := parseExecCommand("/bin/bash -c 'rm -rf /'"); ok {
		t.Fatal("expected ok=false for arbitrary shell command")
	}
}

func TestParseExecCommand_NoPath(t *testing.T) {
	// git-upload-pack with no path argument must be rejected (git always
	// sends the path; a bare command is malformed).
	if _, _, ok := parseExecCommand("git-upload-pack"); ok {
		t.Fatal("expected ok=false for command with no path")
	}
	if _, _, ok := parseExecCommand("git-receive-pack"); ok {
		t.Fatal("expected ok=false for command with no path")
	}
}

func TestParseExecCommand_Empty(t *testing.T) {
	if _, _, ok := parseExecCommand(""); ok {
		t.Fatal("expected ok=false for empty command")
	}
}

func TestRepoPath_Mapped(t *testing.T) {
	f := &Frontend{repos: map[string]string{"agent/repo.git": "internal/repo.git"}}
	if got := f.repoPath("agent/repo.git"); got != "internal/repo.git" {
		t.Errorf("mapped repo = %q, want internal/repo.git", got)
	}
}

func TestRepoPath_Passthrough(t *testing.T) {
	f := &Frontend{repos: map[string]string{}}
	if got := f.repoPath("other.git"); got != "other.git" {
		t.Errorf("unknown repo = %q, want other.git (passthrough)", got)
	}
}

// TestParseSSHString verifies the exec-request payload is decoded as an SSH
// string (uint32 BE length + bytes), matching what git sends.
func TestParseSSHString(t *testing.T) {
	cmd := "git-upload-pack '/repo.git'"
	payload := make([]byte, 4+len(cmd))
	binary.BigEndian.PutUint32(payload[:4], uint32(len(cmd)))
	copy(payload[4:], cmd)
	got, ok := parseSSHString(payload)
	if !ok {
		t.Fatal("expected ok, got false")
	}
	if got != cmd {
		t.Errorf("decoded = %q, want %q", got, cmd)
	}
}

func TestParseSSHString_Malformed(t *testing.T) {
	if _, ok := parseSSHString(nil); ok {
		t.Error("nil payload should be malformed")
	}
	if _, ok := parseSSHString([]byte{0, 0, 0}); ok {
		t.Error("short payload should be malformed")
	}
	// Length field exceeds remaining bytes.
	bad := []byte{0, 0, 0, 10, 'a', 'b'}
	if _, ok := parseSSHString(bad); ok {
		t.Error("overlong length should be malformed")
	}
}