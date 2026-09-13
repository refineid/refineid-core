# Agent Worktrees

Status: Active

Date: 2026-09-12

## Context

Several agents (and the owner) work on this repository at the same time.
One task, one worktree, one branch, one pull request keeps that work from
colliding and keeps the main checkout pristine for integration.

## Topology and naming

- The main checkout is never edited directly. It integrates and releases.
- Each task gets a worktree strictly under `~/src/wt/`, never beside repositories or under `/tmp/`:
  `~/src/wt/refineid-core-<topic>` on branch `agent/<topic>`.
- One branch carries one pull request. Never stack unrelated work onto a
  branch that already has an open pull request.

## Starting a task

1. Update local main: `git checkout main && git pull --ff-only`.
2. Create the worktree under `~/src/wt/`: `git worktree add ~/src/wt/refineid-core-<topic> -b agent/<topic>`.
3. Write `WHATSUP.md` in the worktree root (see below).
4. Run `scripts/agent-housekeeping.sh` and act on what it reports.

## WHATSUP.md

Every worktree carries a `WHATSUP.md` work log in its root: plain Markdown
so owners and agents can both read it. It records why the worktree was
born, where the work stopped, and whether it is worth resuming. Work gets
diverted to another focus at random; that is normal, and the log is what
makes a diverted worktree evaluable later instead of mysterious.

```markdown
# WHATSUP

branch: agent/resilient-pcsc
purpose: Add connect_resilient and single-protocol reconnect to crates/pcsc.
started: 2026-09-12T17:05+03:00 by Antigravity
heartbeat: 2026-09-12T17:05+03:00
status: in-progress
```

Fields (each value stays on its own single line so tooling can read it):

- `purpose`: why this worktree exists, one or two sentences on one line.
- `started`: timestamp and owner (session name plus human or agent).
- `heartbeat`: last time the owner touched the work; refresh it when
  starting, pausing, or finishing.
- `status`: `in-progress`, `paused-diverted` (with a note saying what
  diverted it and how to resume), or `done-pending-merge`.

## Housekeeping

`scripts/agent-housekeeping.sh` reports every worktree with its branch,
merge state, dirty files, unpushed commits, claim freshness, and disk use.
With `--clean` it removes only what is provably done:

- The branch is merged into main, the tree is clean, and nothing is
  unpushed. The work is fully preserved in main, so deleting the worktree
  loses nothing. The branch goes with it.

Everything else is reported, never destroyed, with the `WHATSUP.md`
purpose and status quoted so the evaluator — owner or agent — can decide
in seconds whether to resume work or clean up. In particular:

- A fresh claim is hands off, unconditionally.
- Uncommitted changes or unpushed commits are never auto-deleted.
- Non-compliant worktrees not under `~/src/wt/` are flagged explicitly.

## Finishing a task

1. Run the quality gates (`cargo fmt --check`, `cargo test`, `cargo clippy --all-targets`, etc.) in the worktree.
2. Run `./scripts/verify-push.sh` to ensure all pre-push gates pass.
3. Commit on the task branch (imperative subject and explanatory body only; no attribution trailers) and push.
4. Open one pull request for the branch.
5. Squash-merge once CI is green, so the `main` history stays linear. The pull request preserves the branch history.
6. Remove the worktree (`git worktree remove`), delete the branch, and
   fast-forward local main.
