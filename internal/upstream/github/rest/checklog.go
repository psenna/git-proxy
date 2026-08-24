package rest

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/psenna/git-proxy/internal/port"
)

// minHardCeiling is the read-time bound tailRead enforces on top of maxBytes: a
// hostile or huge log response stops being read once this many bytes (or
// maxBytes, if larger) have been consumed, regardless of how much more the
// server tries to send. It bounds worst-case time independently of the memory
// bound (which is always exactly maxBytes, via the circular buffer).
const minHardCeiling = 64 * 1024 * 1024 // 64 MiB

// tailRead reads all of r (up to a bounded ceiling — see minHardCeiling) and
// returns the TAIL of it: at most maxBytes of the most-recently-read bytes,
// verbatim. It uses a fixed-size circular buffer of exactly maxBytes bytes, so
// memory use is O(maxBytes) regardless of how large r's stream is (the common
// case: a multi-megabyte CI job log, of which only the failing tail matters).
// truncated is true iff more than maxBytes bytes were read (the returned text
// is strictly shorter than the input). maxBytes<=0 yields an empty text and
// truncated=true whenever r produced any bytes at all.
func tailRead(r io.Reader, maxBytes int64) (text string, truncated bool, err error) {
	if maxBytes < 0 {
		maxBytes = 0
	}
	buf := make([]byte, maxBytes)
	var total int64
	var pos int64 // next circular write position in buf (only meaningful when maxBytes > 0)
	hardCeiling := int64(minHardCeiling)
	if maxBytes > hardCeiling {
		hardCeiling = maxBytes
	}
	readBuf := make([]byte, 32*1024)
	for {
		n, rerr := r.Read(readBuf)
		if n > 0 {
			data := readBuf[:n]
			total += int64(n)
			if maxBytes > 0 {
				for len(data) > 0 {
					space := maxBytes - pos
					k := int64(len(data))
					if k > space {
						k = space
					}
					copy(buf[pos:pos+k], data[:k])
					pos += k
					if pos == maxBytes {
						pos = 0
					}
					data = data[k:]
				}
			}
		}
		if rerr == io.EOF {
			break
		}
		if rerr != nil {
			return "", false, rerr
		}
		if total >= hardCeiling {
			break
		}
	}
	truncated = total > maxBytes
	if !truncated {
		return string(buf[:total]), false, nil
	}
	if maxBytes == 0 {
		return "", true, nil
	}
	// buf is circular; the oldest retained byte sits at pos (the next write
	// position wraps around to the oldest data), so the tail in order is
	// buf[pos:] followed by buf[:pos].
	out := make([]byte, maxBytes)
	copy(out, buf[pos:])
	copy(out[maxBytes-pos:], buf[:pos])
	return string(out), true, nil
}

// parseJobIDFromDetailsURL extracts the Actions run_id/job_id from a check
// run's details_url. It scans the URL path for the segment shape
// .../actions/runs/{run_id}/job/{job_id} (GitHub-Actions-backed checks only) —
// host-agnostic (works for github.com and GHES). Any other shape, including a
// third-party check app's arbitrary URL (e.g. a Socket or pkg.pr.new
// dashboard link), yields ok=false: that check simply has no fetchable Actions
// job log, which is the expected case, not a parse bug.
func parseJobIDFromDetailsURL(detailsURL string) (runID, jobID int64, ok bool) {
	u, err := url.Parse(detailsURL)
	if err != nil {
		return 0, 0, false
	}
	segs := strings.Split(strings.Trim(u.Path, "/"), "/")
	for i := 0; i+4 < len(segs); i++ {
		if segs[i] != "actions" || segs[i+1] != "runs" || segs[i+3] != "job" {
			continue
		}
		rid, errR := strconv.ParseInt(segs[i+2], 10, 64)
		jid, errJ := strconv.ParseInt(segs[i+4], 10, 64)
		if errR == nil && errJ == nil {
			return rid, jid, true
		}
	}
	return 0, 0, false
}

// JobLog fetches the raw log text for Actions job jobID on repo, tail-bounded
// to maxBytes (see tailRead). GitHub REST:
// GET /repos/{owner}/{repo}/actions/jobs/{job_id}/logs, which responds with a
// 302 redirect to a time-limited, pre-signed log-archive URL that needs (and
// must never receive) the proxy's GitHub token.
//
// This does NOT reuse Client.do(): do() always attaches the Authorization
// header and always buffers the whole response body, neither of which is safe
// here — the signed redirect target must not see the token, and a job log can
// be many megabytes. Instead this uses a DEDICATED http.Client whose
// CheckRedirect strips Authorization before the redirect hop is followed, and
// reads the body through tailRead so memory stays bounded regardless of the
// log's real size.
func (c *Client) JobLog(ctx context.Context, repo string, jobID int64, maxBytes int64) (text string, truncated bool, err error) {
	p, err := repoPath(repo)
	if err != nil {
		return "", false, err
	}
	path := fmt.Sprintf("%s/actions/jobs/%d/logs", p, jobID)
	u := c.baseURL + "/" + strings.TrimLeft(path, "/")
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return "", false, err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")

	client := &http.Client{
		CheckRedirect: func(req *http.Request, _ []*http.Request) error {
			// The redirect target is a pre-signed log-archive URL (Azure
			// Blob / S3-style); it needs no proxy credential and MUST never
			// receive the proxy's GitHub token.
			req.Header.Del("Authorization")
			return nil
		},
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", false, fmt.Errorf("rest: GET %s: %w", path, err)
	}
	defer func() {
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", false, c.mapError(resp)
	}
	return tailRead(resp.Body, maxBytes)
}

// CheckLogForCheck resolves checkName on ref to its backing Actions job and
// returns the job's (tail-bounded) log text. It is the glue between the
// already-called ListCheckRuns (also used by Summary/ci.status — no extra
// upstream call beyond what checks/{ref} already makes) and JobLog:
//  1. List check runs for ref and filter to Name == checkName. Zero matches →
//     ErrNotFound. Multiple matches (reruns) are tiebroken by highest ID (the
//     most recent check-run wins).
//  2. Parse the matched check-run's DetailsURL for an Actions run_id/job_id.
//     A non-Actions-shaped URL (third-party check) → ErrNotFound: there is no
//     log to fetch for that check type, which from the caller's perspective
//     is indistinguishable from "no log found".
//  3. Fetch the job's log by ID via JobLog.
func (c *Client) CheckLogForCheck(ctx context.Context, repo, ref, checkName string, maxBytes int64) (text string, truncated bool, err error) {
	runs, err := c.ListCheckRuns(ctx, repo, ref)
	if err != nil {
		return "", false, err
	}
	var match *CheckRun
	for i := range runs {
		cr := &runs[i]
		if cr.Name != checkName {
			continue
		}
		if match == nil || cr.ID > match.ID {
			match = cr
		}
	}
	if match == nil {
		return "", false, port.ErrNotFound
	}
	_, jobID, ok := parseJobIDFromDetailsURL(match.DetailsURL)
	if !ok {
		return "", false, port.ErrNotFound
	}
	return c.JobLog(ctx, repo, jobID, maxBytes)
}
