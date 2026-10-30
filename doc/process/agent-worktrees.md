# Agent Worktrees

Status: Active

Date: 2026-09-12

## Context

Several agents (and the owner) work on this repository at the same time.
One task, one worktree, one branch, one pull request keeps that work from
colliding and keeps the main checkout pristine for integration.

## Topology and naming

- Reading does not require a worktree; writing does. The main checkout is never edited directly. It integrates and releases.
- Each task gets a worktree strictly under `../wt/`, never beside repositories or under `/tmp/`:
  `../wt/refineid-core-<topic>` on branch `<topic>`.
- One branch carries one pull request. Never stack unrelated work onto a
  branch that already has an open pull request.

## Starting a task

1. Update local main: `git checkout main && git pull --ff-only`.
2. Create the worktree under `../wt/`: `git worktree add ../wt/refineid-core-<topic> -b <topic>`.
3. Run `./scripts/agent-housekeeping.sh` (a bash script) and act on what it reports.

## Housekeeping

`./scripts/agent-housekeeping.sh` reports every worktree with its branch,
merge state, dirty files, unpushed commits, activity freshness, and disk use.
With `--clean` it removes only what is provably done:

- The branch is merged into main, the tree is clean, and nothing is
  unpushed. The work is fully preserved in main, so deleting the worktree
  loses nothing. The branch goes with it.
- Merged means main contains the branch by ancestry, or contains all of
  its changes by patch: each commit on its own (`git cherry`), or the
  branch's whole diff as one squash commit, which is how pull requests
  merge here. A branch without an upstream whose content is in main has
  nothing unpushed. A probe that fails counts as not merged.

Everything else is reported, never destroyed, with the latest commit headline
quoted so the evaluator — owner or agent — can decide in seconds whether to
resume work or clean up. In particular:

- Fresh activity (or dirty working tree) is hands off, unconditionally.
- Uncommitted changes or unpushed commits are never auto-deleted.
- Non-compliant worktrees not under `../wt/`, beside the main checkout, are
  flagged explicitly.

## Finishing a task

1. Run the quality gates (`cargo fmt --check`, `cargo test`, `cargo clippy --all-targets`, etc.) in the worktree.
2. Run `./scripts/verify-push.sh` to ensure all pre-push gates pass.
3. Commit on the task branch (imperative subject and explanatory body only; no attribution trailers) and push.
4. Open one pull request for the branch.
5. Squash-merge after local gates pass and review is complete, so the `main` history stays linear. The pull request preserves the branch history; the manual Ubuntu workflow is an optional portability check, not a merge gate.
6. Remove the worktree (`git worktree remove`), delete the branch, and
   fast-forward local main.
