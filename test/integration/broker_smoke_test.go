package integration

import (
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// freePort returns a TCP port that is currently free (it briefly listens and
// closes). The caller races other binders, but for tests this is reliable
// enough; a collision fails the test loudly rather than silently.
func freePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = ln.Close() }()
	addr, ok := ln.Addr().(*net.TCPAddr)
	if !ok {
		t.Fatalf("listen addr %T is not *net.TCPAddr", ln.Addr())
	}
	return addr.Port
}

// buildBinary builds the git-proxy binary into a temp dir and returns its path.
// It is the smoke-test stand-in for "go build ./cmd/git-proxy".
func buildBinary(t *testing.T) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "git-proxy")
	out, err := exec.Command("go", "build", "-o", bin, "github.com/psenna/git-proxy/cmd/git-proxy").CombinedOutput()
	if err != nil {
		t.Fatalf("go build: %v\n%s", err, out)
	}
	return bin
}

// writeSmokeConfig writes a minimal config that enables the broker over a
// github-kind upstream (the broker type-asserts PRSupport, which the github
// adapter implements). The upstream URL is never contacted by /healthz, so a
// placeholder github.com URL is fine.
func writeSmokeConfig(t *testing.T, gitPort, brokerPort int, upstreamKind string) string {
	t.Helper()
	yaml := fmt.Sprintf(`
listen: "127.0.0.1:%d"
upstream:
  kind: %s
  url: "https://github.com/owner/repo.git"
auth:
  tokens:
    agent-token-1: agent-1
broker:
  listen: "127.0.0.1:%d"
`, gitPort, upstreamKind, brokerPort)
	p := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(p, []byte(yaml), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return p
}

// waitForHealthy polls the broker /healthz until it returns 200 or the deadline
// passes, returning the response on success and failing the test on timeout.
func waitForHealthy(t *testing.T, brokerAddr string, deadline time.Duration) *http.Response {
	t.Helper()
	client := &http.Client{Timeout: time.Second}
	deadlineAt := time.Now().Add(deadline)
	for time.Now().Before(deadlineAt) {
		resp, err := client.Get("http://" + brokerAddr + "/healthz")
		if err == nil {
			return resp
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("broker /healthz never became healthy at %s", brokerAddr)
	return nil
}

// TestBrokerSmoke_Healthz is the PR10 smoke test: build the real git-proxy
// binary, start it with a broker-enabled config, and confirm the broker's
// /healthz endpoint responds 200 — proving the main.go wiring brings the
// broker up alongside the git frontend and serveTransports runs it.
func TestBrokerSmoke_Healthz(t *testing.T) {
	if testing.Short() {
		t.Skip("smoke test builds + runs the binary")
	}
	bin := buildBinary(t)
	gitPort := freePort(t)
	brokerPort := freePort(t)
	cfgPath := writeSmokeConfig(t, gitPort, brokerPort, "github")
	brokerAddr := fmt.Sprintf("127.0.0.1:%d", brokerPort)

	cmd := exec.Command(bin, "-config", cfgPath)
	if err := cmd.Start(); err != nil {
		t.Fatalf("start git-proxy: %v", err)
	}
	t.Cleanup(func() {
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
			_, _ = cmd.Process.Wait()
		}
	})

	resp := waitForHealthy(t, brokerAddr, 5*time.Second)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("/healthz status = %d, want 200", resp.StatusCode)
	}
}

// TestBrokerSmoke_FailsClosedOnPlainUpstream asserts the main.go wiring fails
// closed at startup when the broker is enabled but the upstream is NOT an SCM
// adapter (upstream.kind: plain has no PRSupport). The binary must exit non-zero
// with an actionable error naming the missing capability — never silently run a
// broker that 501s every op.
func TestBrokerSmoke_FailsClosedOnPlainUpstream(t *testing.T) {
	if testing.Short() {
		t.Skip("smoke test builds + runs the binary")
	}
	bin := buildBinary(t)
	gitPort := freePort(t)
	brokerPort := freePort(t)
	cfgPath := writeSmokeConfig(t, gitPort, brokerPort, "plain")

	cmd := exec.Command(bin, "-config", cfgPath)
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatal("git-proxy exited 0 with broker enabled on a plain upstream; want a fail-closed startup error")
	}
	if !contains(string(out), "does not implement port.PRSupport") {
		t.Errorf("stderr/stdout = %q, want an error mentioning port.PRSupport", string(out))
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

// writeSmokeConfigWithIssues is writeSmokeConfig plus a separately-configured
// issue_upstream (github kind, same placeholder URL — never contacted by
// /healthz). It exercises the main.go path that builds a SECOND port.Upstream
// and passes it to the broker as the issue upstream.
func writeSmokeConfigWithIssues(t *testing.T, gitPort, brokerPort int) string {
	t.Helper()
	yaml := fmt.Sprintf(`
listen: "127.0.0.1:%d"
upstream:
  kind: github
  url: "https://github.com/owner/repo.git"
auth:
  tokens:
    agent-token-1: agent-1
broker:
  listen: "127.0.0.1:%d"
issue_upstream:
  kind: github
  url: "https://github.com/owner/repo.git"
`, gitPort, brokerPort)
	p := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(p, []byte(yaml), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return p
}

// TestBrokerSmoke_IssueUpstreamStarts is the PR6 smoke test: with an
// issue_upstream configured, main.go builds the second upstream and passes it
// to the broker; the broker must still come up (/healthz 200). Proves the
// issue-upstream wiring does not break broker startup. (Issue routes are
// exercised end-to-end in the broker integration test.)
func TestBrokerSmoke_IssueUpstreamStarts(t *testing.T) {
	if testing.Short() {
		t.Skip("smoke test builds + runs the binary")
	}
	bin := buildBinary(t)
	gitPort := freePort(t)
	brokerPort := freePort(t)
	cfgPath := writeSmokeConfigWithIssues(t, gitPort, brokerPort)
	brokerAddr := fmt.Sprintf("127.0.0.1:%d", brokerPort)

	cmd := exec.Command(bin, "-config", cfgPath)
	if err := cmd.Start(); err != nil {
		t.Fatalf("start git-proxy: %v", err)
	}
	t.Cleanup(func() {
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
			_, _ = cmd.Process.Wait()
		}
	})

	resp := waitForHealthy(t, brokerAddr, 5*time.Second)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("/healthz status = %d, want 200 (broker must start with issue_upstream wired)", resp.StatusCode)
	}
}

// TestBrokerSmoke_IssueRoutes501WhenNoIssueUpstream asserts the end-to-end
// wiring: with a broker enabled and NO issue_upstream, an issue route returns
// 501 per-op (issues opt-in) while the broker is up and PR routes are
// unaffected. The agent's auth still gates first (a missing Bearer → 401).
func TestBrokerSmoke_IssueRoutes501WhenNoIssueUpstream(t *testing.T) {
	if testing.Short() {
		t.Skip("smoke test builds + runs the binary")
	}
	bin := buildBinary(t)
	gitPort := freePort(t)
	brokerPort := freePort(t)
	// No issue_upstream → issues disabled.
	cfgPath := writeSmokeConfig(t, gitPort, brokerPort, "github")
	brokerAddr := fmt.Sprintf("127.0.0.1:%d", brokerPort)

	cmd := exec.Command(bin, "-config", cfgPath)
	if err := cmd.Start(); err != nil {
		t.Fatalf("start git-proxy: %v", err)
	}
	t.Cleanup(func() {
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
			_, _ = cmd.Process.Wait()
		}
	})

	// Wait for the broker to come up.
	resp := waitForHealthy(t, brokerAddr, 5*time.Second)
	_ = resp.Body.Close()

	// POST an issue create with a valid bearer → 501 (issues not configured).
	req, err := http.NewRequest(http.MethodPost, "http://"+brokerAddr+"/owner%2Frepo.git/issues", stringReader(`{"title":"t"}`))
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("Authorization", "Bearer agent-token-1")
	req.Header.Set("Content-Type", "application/json")
	iresp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	defer func() { _ = iresp.Body.Close() }()
	if iresp.StatusCode != http.StatusNotImplemented {
		t.Fatalf("issue create status = %d, want 501 (no issue_upstream → issues opt-in 501)", iresp.StatusCode)
	}
}

// stringReader returns a non-nil reader for a body so the smoke test can POST.
func stringReader(s string) *strings.Reader { return strings.NewReader(s) }