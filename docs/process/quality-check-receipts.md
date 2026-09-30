# Local source-check receipts

The commit and push gates share the source checks in
[`../../scripts/run-source-checks.sh`](../../scripts/run-source-checks.sh):
formatting, the magic-number policy, repository hygiene, and receipt self-tests.
After one successful run, a later invocation may reuse a local receipt for the
same indexed tree, check code, tools, Cargo configuration, and supported build
environment.

Staged changes are included through the Git index tree. Before checking or
reusing a receipt, tracked worktree files must match the index, and the raw
tracked-file content is hashed. This rejects partial staging and file flags
that tell Git to skip worktree checks. Untracked files and ignored files
outside the root Cargo build directory disable receipt reuse. Checks still
run, but the result is not recorded. If indexed files or tool inputs change
while a check runs or while a receipt is read, the gate fails without reusing
or recording a result.

The key includes the selected Rust toolchain binaries and versions, the
receipt runner's Python interpreter, Git and grep, the check command, applicable
Cargo configuration files and referenced environment values, and a digest of
stable build environment inputs. Receipt files contain only a format version,
an input digest, and a success marker. They live under the current user's cache
directory with private permissions and are replaced atomically. Concurrent
checks may both run; neither can observe a partially written receipt.

Receipts are a local speed hint, not a trusted attestation. A user who controls
the machine can change the cache or skip local hooks. The mandatory local push
gate still runs build, tests, Clippy, rustdoc, and supply-chain checks; only its
identical source-check group may be reused locally. The Ubuntu quality workflow
is manual-only and supplies optional platform portability evidence without
blocking pull-request merges.
