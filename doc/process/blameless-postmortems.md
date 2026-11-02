# Blameless postmortems

Proven failures, written down so the next design does not repeat them.
Each entry is blameless: it names what happened, how it showed in
practice, the cause in the system or the design, and the rule that
prevents it, never a person. Read this before designing a protocol, a
card path or a state that two parties share. Add an entry whenever
something fails on real hardware or in real use; a lesson that only lives
in one session's memory is lost.

## Protocol design (RAPP)

### A teardown is a statement, not a fault

- **What failed:** turning Card Remote Access off on the phone did not reach
  the computer. The computer kept the phone's card as available, then after
  about a minute showed "Connecting to the phone…" and kept dialing.
- **Why:** the protocol had messages but no defined life cycle. The
  computer knew two cases, connected and lost, so an active teardown fell
  into "lost" and triggered reconnection.
- **Rule:** every session end carries a reason, and the reasons are typed
  so that reconnect logic cannot consume a deliberate end as a network
  error. A peer that stops serving says so before closing the transport;
  the other side accepts it at once and waits for the next announcement.

### Define the whole state machine, both roles, every event

- **What failed:** four further bugs in one morning: the computer not
  noticing the phone come back, the phone still serving a pairing the
  computer had forgotten, a stale nameless duplicate after re-pairing, and
  a computer dialing a pairing the phone had turned off without getting a
  refusal.
- **Why:** each was a state × event cell nobody had defined. Messages were
  specified; their effect on the other side's state was not.
- **Rule:** a protocol between two parties is specified as a state machine
  for both roles, TCP style, with every state × event cell filled in,
  "cannot happen" stated with its reason, closing states included. The
  table is machine readable and every implementation is tested against
  vectors generated from it.

### Feedback must be symmetric

- **What failed:** forgetting a pairing on one side left the other side
  believing in it, in both directions.
- **Why:** notifications were designed for one direction at a time.
- **Rule:** whatever one side forgets, revokes or stops, it tells the other
  side; if the notice cannot be delivered, the next contact from either
  side resolves it with a defined refusal. Check every lifecycle message
  for its mirror.

### Identify a peer by its key, never by its name

- **What failed:** re-pairing the same computer added a second record
  instead of replacing the first.
- **Why:** the custodian had no rule that one computer has one pairing.
- **Rule:** a peer's identity is its long-term key; a new pairing from the
  same key replaces the old record. Display names are labels only.

### A failed write must never be silent

- **What failed:** with the computer's disk full, pairing failed without a
  word, and the user only learned it from the agent session.
- **Why:** keychain and file write statuses were dropped or folded into a
  generic failure.
- **Rule:** every persistent write returns its status to a place the user
  sees; out-of-space has its own message. Keep a list of writes that have
  no user-visible error place and treat that list as debt.

### Apply STPA to the life cycle, not only to the messages

- **What we learned:** every bug above is a controller acting on a stale
  process model (the other side's state). STPA finds these before
  hardware does when the analysis covers the life cycle: who believes
  what about the peer, and what feedback keeps that belief true.

## Cards and transports

### Never decide by ATR bytes one transport omits

- **What failed:** the iPhone reports the organisation card's answer to
  reset as `3B 80 11 81 10`, without historical bytes, while PC/SC readers
  include them. Code keyed the stored organisation identity on historical
  bytes, and decided whether a PIN operation needs PACE by the ATR; both
  failed on the phone.
- **Rule:** decide by the card's answers to commands (for example `6985`
  before PACE), not by ATR bytes. Where an ATR must be a key, define what
  happens when part of it is missing.

### A fallback command can end the session

- **What failed:** after the organisation card refused the main file with
  `6985`, a select-by-name fallback made the iPhone's NFC slot report a
  malformed response and end the session before PACE.
- **Rule:** after a card refuses before PACE, send only what PACE needs.
  Every fallback is tested on every transport, the phone's NFC slot
  included, before it ships.

### An aborted PACE with a PIN costs a try

- **What failed:** on the organisation card the PIN try is taken at the
  first GENERAL AUTHENTICATE and only returned when the handshake
  completes. A parsing error after the card's first answer (a two-block
  nonce the code did not accept) cost a try, and a remembered PIN 1 could
  be resent after a refusal.
- **Rule:** check the retry floor on the MSE:Set AT answer before any
  GENERAL AUTHENTICATE; never resend a remembered PIN after a refusal;
  accept what the specification allows (any whole number of cipher
  blocks), not what the first card happened to send.

### One stuck card session must not block the others

- **What failed:** a card session another program held made the token
  driver wait 60 s, retry, and block every later card event; the app told
  the user to remove the card.
- **Rule:** waits end when the card leaves, are bounded, and are per slot.

### Probe the card before trusting a specification's silence

- **What we learned:** the published organisational specification did not
  say which PACE password reference each PIN uses or that PACE with a PIN
  counts as the PIN verified. A counter-safe probe (MSE:Set AT without a
  password) answered the first question without spending a try; one
  traced handshake answered the second.

## Working method

- **Parallel builds filled the disk twice.** Several agents building in
  separate worktrees at once ran a 460 GB disk out of space and stopped
  every tool. Run one heavy build per platform at a time and delete build
  output of merged work.
- **A test harness shares the card with the product.** Running the
  hardware harness on a slot while the token driver read it wedged the
  driver. Use the harness only when the app does not need the card.
- **Merge policy.** Pull requests are squash merged; GitHub CI reports
  afterwards and does not gate a merge. Rebasing onto main before merging
  is churn.
