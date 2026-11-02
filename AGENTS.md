# Working in this repository

This is the protocol core for a national electronic identity card. Work
as if a wrong byte locks a citizen's card or leaks a citizen's PIN,
because it can. The code is small on purpose: every crate is expected to
be read whole, understood whole, and held to the policy whole.

## Read before writing

Three documents are normative. Read them in full before designing or
editing anything, and do not infer the rules from existing code -- code
may predate its own review:

- [doc/architecture/core-migration.md](doc/architecture/core-migration.md)
  -- slice admission, trust by construction, the numeric policy.
- [doc/architecture/refinement-types.md](doc/architecture/refinement-types.md)
  -- the type discipline: predicates, borders, the three states of bytes,
  dependence with reason, no ducks at the border.
- [doc/security/credential-custody.md](doc/security/credential-custody.md)
  -- how secrets move.
- [doc/architecture/case-study-refinement-types-vec-insert.md](doc/architecture/case-study-refinement-types-vec-insert.md)
  -- case study: why `<alloc::vec::Vec>::insert` is bad code, progress and preservation,
  and refinement typing across collections.

## Rule #1: PIN codes and the CAN NEVER travel over any network

PIN codes (PIN1 and PIN2) and the CAN NEVER leave the mobile phone when accessed via RAPP:
- **Zero PIN transport**: RAPP must absolutely deny and preclude all attempts to transport PIN codes anywhere. No wire format, message, or API shall ever accept, serialize, or transmit PIN codes over the network.
- **PIN1 stays local**: PIN1 is cached or entered strictly on the mobile device and verified locally with the card over NFC. The client receives only cryptographic proof (e.g. signature bytes or TLS client auth).
- **PIN2 stays local**: PIN2 (qualified electronic signature) prompts appear exclusively on the mobile device's screen and are entered directly by the cardholder into the phone's protected UI.
- **Host computer protected path**: The host computer and browsers never prompt for, receive, cache, or handle PIN codes when using remote readers (`CKF_PROTECTED_AUTHENTICATION_PATH`).
- **The CAN is a secret**: The CAN is handled like the PINs. No RAPP message, diagnostic report or export carries it; it is never displayed back, logged, or read from argv or the environment; entry fields hide it by default. A personal card's CAN may be stored only in the platform's secure credential store. See `doc/security/credential-custody.md`.

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

## STPA in design

Every design includes a short System-Theoretic Process Analysis (STPA),
sized to the change. [doc/stpa.md](doc/stpa.md) explains the method and
its literature; [stpa-rapp.md](doc/security/stpa-rapp.md) is the worked
example and the record for RAPP and its applications.

- Ground the analysis in the losses (L-n) and hazards (H-n) the record
  already names. Add a loss only when a real stakeholder could suffer it
  and no recorded loss covers it, and a hazard only for a real system
  state that leads to a loss.
- Do not invent imaginary losses, hazards or threats to fill the method.
  A few real ones beat a long list.
- Describe the control structure the change touches: the controllers,
  their control actions, and the feedback each gets. Look first for
  missing, late or misleading feedback; a controller acting on a stale
  process model is the usual cause of an unsafe control action.
- List the unsafe control actions (UCA-n) the affected controllers could
  issue or fail to issue, the hazards each leads to, and the controller
  constraints (CC-n) the design enforces against them.
- A small change records its analysis in the pull request, and a change
  with no control action or feedback to analyse says so in one line. A
  change to the control structure updates the STPA record that covers it.

## The floor

The floor is enforced, not suggested: tracked git hooks (enable once per
clone with `scripts/install-hooks.sh`) run the fast gates at commit and
the full floor at push. The Ubuntu quality workflow is available by
manual dispatch for platform portability checks and does not gate
pull-request merges. Never commit or push with `--no-verify`,
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

- Reading does not require a worktree; writing does. The main checkout is
  never edited directly. Before writing code or modifying files for any task,
  create a dedicated git worktree strictly under `../wt/`
  (e.g., `../wt/refineid-core-<topic>`) on a `<topic>` branch. Never
  work directly on `main` or modify files in the main checkout.
- All worktrees MUST live strictly under `../wt/`, never loose beside
  repositories or in parent directories.
- Never put a git worktree under `/tmp`. It is cleared on reboot and takes the
  branch's only checkout with it.
- One task, one worktree, one branch, one pull request (see [doc/process/agent-worktrees.md](doc/process/agent-worktrees.md)).
- Run `./scripts/agent-housekeeping.sh` to monitor worktrees and verify compliance.

## Working discipline

- Never poll background commands or set rapid check timers (e.g. 10s-30s). When running builds, tests, or async tasks, execute asynchronously and wait strictly for system completion notifications.

## Protocol specifications

- A specification under `doc/protocols/` states the protocol as it is at
  its stamped version: rules, schemas, and bytes. It carries no change
  history -- no "changes from" sections, no "supersedes" lines, no prose
  about what a revision altered. History belongs in commit messages and
  pull requests.
- Document and protocol versions are stamped by the project owner; never
  invent one.

## Rules live here, not in an agent's memory

Every rule, decision and finding an agent should remember lives in this
repository, never only in an agent's memory: a design rule in `doc/`, a
defect in an issue, a working rule in this file. This file states each
rule in a line and points to the reading behind it; the readings live in
`doc/`, not here.

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


## Record deferred findings

- While working, file a GitHub issue in the owning repository for each
  confirmed, actionable defect or quality gap that cannot reasonably be
  fixed within the current task. Filing these issues is authorized; do not
  wait for a separate instruction for each finding.
- Search existing open issues first. Reuse the matching issue and add only
  new, useful evidence instead of creating a duplicate. Group findings only
  when they share a cause and can be resolved by one focused change.
- State the observed behavior, expected behavior, affected repository-relative
  paths, reproduction or inspection evidence, impact, and acceptance checks.
  Distinguish observations from hypotheses and specification requirements.
  Never claim an unexecuted test or hardware operation was verified.
- Keep speculative improvements in working notes until they have a concrete
  problem and useful acceptance criteria. Avoid issue spam and severity claims
  unsupported by evidence.
- Never put credentials, PIN data or candidate lengths, card secrets,
  personal data, private workspace paths, or persistent device identifiers
  in issue text, logs, screenshots, attachments, or reproduction fixtures.
  Security-sensitive findings may go to a public issue; this repository
  has no embargo policy. Use the private reporting process only when a
  reporter offers working exploit detail for an unfixed flaw and publishing
  it would be gratuitous. Otherwise report and fix.
- An issue does not excuse a broken gate or incomplete work needed to make
  the current task correct. Fix findings required for the task before handing
  it over; file independently deferred work with a clear scope.
- Link newly filed or reused issues in the task handoff. If issue creation is
  unavailable, preserve a sanitized finding locally and report that it was
  not filed; never silently discard it.

## No backwards compatibility

- When code, a script, a command, an API, a file format or a setting is
  replaced, remove the old one in the same change. Do not leave
  compatibility wrappers, deprecated aliases, forwarding shims, fallback
  readers or migration paths behind.
- Update every caller, hook, CI job and document to the replacement in that
  same change instead of keeping the old entry point alive for them.

## Certificates and trust

- Certificates come from the card, which carries its own, or, for external
  ones (EU eIDAS), from trusted lists at runtime. No certificates or
  fingerprints are shipped in the software.
- No pinning or other trust policy is added without the owner's decision.

## Independent review

- Before a pull request merges, have its diff reviewed by a model from a
  different family than the one that wrote it. Any CLI that runs a model
  headless will do; take the strongest model it offers that day, and add a
  second one for protocol, cryptography or state-machine changes.
- Run the reviewer in a sandbox and plan mode, from an empty directory,
  with the diff pasted into the prompt and no tool use. Frame the request as
  a code review from the project's author.
- Check every finding against the code. Fix the real ones and list the
  rejected ones, with the reason, in the pull request description.

## Working method

Read [doc/process/working-method.md](doc/process/working-method.md) before starting: the roles (front agent, implementation agents), what a brief contains, the feedback loops, and which documentation is kept. The same file is in every RefineID repository.
