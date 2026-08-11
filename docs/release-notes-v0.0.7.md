# git-proxy v0.0.7

Release date: 2026-08-11 · Base: `v0.0.6` · Head: `fc3331e`

Two fixes since v0.0.6.

## 🐛 fix(gitx): tolerate unknown client haves in `WantedObjects`/`ShallowObjects` (#76, closes #75)

A git client whose advertised **haves** include a commit unknown to the inspection
mirror (e.g. a stale local branch tip no longer reachable upstream) previously
broke the fetch with **HTTP 502** — `git rev-list --not <missing>` fails with
`fatal: bad object`, and the self-heal wrapper then wasted a full mirror
re-clone that could never help.

Now the mirror filters client haves to those **present** in its object store
(`git cat-file --batch-check`) before building `--not` — an unknown have is
treated as non-common ground, exactly like a real `git upload-pack`, and the
fetch succeeds with a superset pack. Fail-closed on probe errors; **missing
wants still self-heal** (the #69/#71 corruption path is unchanged); no more
wasted re-clones for client-local objects.

## 🐛 fix(broker): forward the PR body on create (#79, closes #78)

Pull requests created via the broker's `POST /{repo}/prs` landed on GitHub with a
**blank description** — the handler accepted a `body` field but never read it
(`createPRReq`, `port.EnsurePR`, the GitHub adapter's `CreatePR`, and the REST
`createPRRequest` all omitted it). The markdown description is now threaded
end-to-end and included in `POST /repos/{owner}/{repo}/pulls`, so PRs opened
through the proxy carry their full description.

## Full changelog (`v0.0.6..main`)

- `e888b78` fix(gitx): tolerate unknown client haves in WantedObjects/ShallowObjects (issue #75) (#76)
- `fc3331e` fix(broker): forward the PR body on create (issue #78) (#79)
