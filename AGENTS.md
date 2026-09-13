# Working in this repository

This is the protocol core for a national electronic identity card. Work
as if a wrong byte locks a citizen's card or leaks a citizen's PIN,
because it can. The code is small on purpose: every crate is expected to
be read whole, understood whole, and held to the policy whole.

## Read before writing

Three documents are normative. Read them in full before designing or
editing anything, and do not infer the rules from existing code -- code
may predate its own review:

- [docs/architecture/core-migration.md](docs/architecture/core-migration.md)
  -- slice admission, trust by construction, the numeric policy.
- [docs/architecture/refinement-types.md](docs/architecture/refinement-types.md)
  -- the type discipline: predicates, borders, the three states of bytes,
  dependence with reason, no ducks at the border.
- [docs/security/credential-custody.md](docs/security/credential-custody.md)
  -- how secrets move.
- [docs/architecture/case-study-refinement-types-vec-insert.md](docs/architecture/case-study-refinement-types-vec-insert.md)
  -- case study: why `<alloc::vec::Vec>::insert` is bad code, progress and preservation,
  and refinement typing across collections.

## Rule #1: PIN codes NEVER travel over any network

PIN codes (PIN1 and PIN2) NEVER leave the mobile phone when accessed via RAPP:
- **Zero PIN transport**: RAPP must absolutely deny and preclude all attempts to transport PIN codes anywhere. No wire format, message, or API shall ever accept, serialize, or transmit PIN codes over the network.
- **PIN1 stays local**: PIN1 is cached or entered strictly on the mobile device and verified locally with the card over NFC. The client receives only cryptographic proof (e.g. signature bytes or TLS client auth).
- **PIN2 stays local**: PIN2 (qualified electronic signature) prompts appear exclusively on the mobile device's screen and are entered directly by the cardholder into the phone's protected UI.
- **Host computer protected path**: The host computer and browsers never prompt for, receive, cache, or handle PIN codes when using remote readers (`CKF_PROTECTED_AUTHENTICATION_PATH`).

## Rule #2: Zero PIN data and candidate PIN-length logging across all environments

Never log PIN codes (PIN1, PIN2), PUK, or CAN in any development, test, staging, or production context:
- **Zero PIN data logging**: Diagnostic macros (`diag!`), tracing, event logs, and error messages must never contain PIN bytes, non-digit character bytes, character offsets, or role-identifying secrets.
- **Zero candidate PIN-length logging**: Never log or format candidate PIN lengths or candidate digit counts. Disclosing candidate lengths leaks entropy and reduces keyspace security.
- **Errors**: Display implementations of credential/PIN errors must state expected specification policy boundaries without echoing candidate digit counts or offsets.
- **Debugging**: If specialized debugging is ever needed, it is done via temporary, uncommitted private test harnesses and removed immediately.

## Design before code

Every slice starts as a short design, not as code. Before writing, answer
in your own working notes:

1. **Trust origins.** For every input, where do the bytes come from --
   card, host, specification constant? Each external origin gets one
   border and one constructor.
2. **Predicates.** Which specification sentences state the invariants?
   List them with citations. The constructor will check all of them,
   because downstream trusts totally.
3. **Shape of the meaning.** What does downstream actually consult?
   Deconstruct to that depth: typed parts for what is consulted, a
   length-checked container for what merely travels through.
4. **Static or dynamic.** Which values does the specification fix at
   design time -- lift those into the type -- and which does the world
   choose at runtime -- check those at the border.
5. **The failure story.** For each way the input can be malformed, which
   typed error names it, and what does the caller safely do next?

If any answer is missing, the slice is not ready; read the specification
section again. The design questions in the refinement-types policy's
"Review questions" are the checklist for both writing and review.

## The floor

The floor is enforced, not suggested: tracked git hooks (enable once per
clone with `scripts/install-hooks.sh`) run the fast gates at commit and
the full floor at push, and GitHub Actions reruns the full floor on
every push and pull request. Never commit or push with `--no-verify`,
never disable, weaken, or work around a gate, and never leave the hooks
uninstalled. This binds every contributor, human and AI agent alike:
fix the finding, or raise the policy question openly instead of dodging
it.

Mechanical requirements, all of them, before any commit:

- `cargo fmt --check`, `cargo build`, `cargo test`, and
  `cargo clippy --all-targets` -- zero warnings, warnings are denied;
- `cargo doc --no-deps` with rustdoc warnings denied;
- `cargo run -q -p xtask -- check-magic-numbers` -- clean;
- no anonymous numeric literals and no hand-typed hexadecimal arrays
  anywhere, tests included; wire fixtures are assembled from the same
  named constants the serializer uses; the admitted-as-is subtrees in
  the xtask `POLICY_EXEMPT_SUBTREES` list (the RAPP bridge and its
  pinned protocol corpus) are the sole, temporary exception;
- new dependencies are exceptional and justified; nothing that drags a
  second DER stack or duplicates what a crate here already does;
- safe Rust only; protocol, parsing, and secret handling never in
  `unsafe`.

## The floor is not the goal

The gates catch mechanical failures; none of them can tell a
predicate-carrying type from a costume. Your job is the part the tools
cannot check: types whose existence proves their invariants, borders
where all validation concentrates, secrets that cannot leak by
construction. When a rule seems to block a sensible design, re-derive the
design from the specification and the trust topology. Never resolve the
tension with a rename, wrapper, encoding, or attribute that quiets a
check while keeping the design -- that is a defect with better camouflage.
If the policy itself seems wrong, say so openly in the commit body or the
review instead of engineering around it; the policy has been corrected
before and the correction made the core better.

## Commits and publication

- Imperative subject, explanatory body; no attribution trailers of any
  kind.
- This is a public repository. No private paths, no unpublished project
  context, no personal data, and no secrets -- test PINs and card
  numbers included -- in any file, fixture, comment, or commit message.
- Nothing card-mutating or retry-consuming is described as working until
  it has been observed on real hardware; scripted tests earn the words
  "covered by scripted tests", not "works".
- Claims about card behaviour, cryptography, or platform interfaces are
  verified against a primary source -- the FINEID specifications, ISO,
  the RFCs -- not assumed from memory.

## Worktree policy

- All agent worktrees MUST live strictly under `~/src/wt/` (e.g., `~/src/wt/refineid-core-<topic>`).
- Worktrees must NEVER be created loose beside repositories in `~/src/` or under `/tmp/`.
- One task, one worktree, one branch (`agent/<topic>`), one pull request.
- Every worktree must have a `WHATSUP.md` in its root recording its purpose, owner, heartbeat, and status (see [docs/process/agent-worktrees.md](docs/process/agent-worktrees.md)).
- Run `scripts/agent-housekeeping.sh` to monitor worktrees and verify compliance.

## Working discipline

- Never poll background commands or set rapid check timers (e.g. 10s-30s). When running builds, tests, or async tasks, execute asynchronously and wait strictly for system completion notifications.

## Source comments

- Comments explain what the code does now and the constraints it honors.
  Past bugs, previous implementations, and explanations of what a fix changed
  belong in commit messages, not source comments.

## Commits and integration

- Commits are cheap backups. Make small, focused commits often, without
  asking for permission, once the required commit checks pass.
- Complete the integration without waiting for another instruction: push
  the task branch, open a pull request, and merge it into `main` once the
  required checks pass. Sync local `main` with the merged remote.
  Use squash merges to keep the `main` history linear; do not use merge commits.

