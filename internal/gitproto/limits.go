package gitproto

// MaxUploadPackRequestBytes is the size cap on a git-upload-pack REQUEST body
// read by the proxy (the wants/haves/caps frame — NOT the packfile, which is in
// the upload-pack *response*). A real upload-pack request is tiny (a handful of
// ref SHAs + capabilities + haves), so 1 MiB is a generous ceiling. This caps
// both transports' upload-pack request reads against an unbounded-accumulation
// DoS (a rogue authorized agent streaming `want` lines without `done`):
//
//   - The SSH framer (internal/transport/ssh/uploadpack_body.go) accumulates
//     pkt-lines into a bytes.Buffer before handing a bounded body to
//     Proxy.UploadPack; it checks MaxUploadPackRequestBytes inside the scan
//     loop and returns a fail-closed error on overflow.
//   - Proxy.UploadPack (internal/gitproto/proxy.go) wraps the body read in an
//     io.LimitReader{N: MaxUploadPackRequestBytes+1} on BOTH the passthrough and
//     read-protected branches and denies an oversized/truncated request
//     fail-closed (no forward, no assembly).
//
// This is DISTINCT from the 256 MiB push packfile cap (push.max_packfile_bytes
// on the receive-pack path) — upload-pack requests never carry a packfile.
const MaxUploadPackRequestBytes int64 = 1 << 20 // 1 MiB