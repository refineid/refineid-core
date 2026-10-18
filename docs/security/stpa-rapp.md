# STPA of the Remote Authorization Proxy Protocol

**Status:** Draft for owner review
**Date:** 2026-10-18
**Applies to:** RAPP v26.10.10 (`docs/protocols/rapp-v26.10.10.md`), the
transport and discovery hierarchy, and the requester and custodian
applications built on them

---

## 1. Purpose and method

This document applies System-Theoretic Process Analysis (STPA) to RAPP.
STPA rests on the STAMP accident model: losses are not caused only by
component failures but by inadequate control, and control is inadequate
when a controller's model of the process it controls is wrong. A
controller keeps its model right through feedback. Where feedback is
missing, late, or ambiguous, the controller acts on a stale model, and the
action is unsafe even though every component worked as built.

The analysis follows the four STPA steps:

1. Define the losses the system must not cause, the hazards that lead to
   them, and the safety constraints that negate the hazards.
2. Draw the control structure: controllers, controlled processes, control
   actions, and feedback.
3. Identify unsafe control actions (UCAs).
4. Identify loss scenarios: how a UCA comes to be issued, or how a safe
   control action fails to take effect, with emphasis on missing or
   misleading feedback.

The scope is the whole socio-technical system: the cardholder, the
requester (the computer that wants a card operation), the custodian (the
phone holding the card), the phone's operating system, the local consumer
on the computer (browser, CryptoTokenKit, PKCS#11), the discovery layer,
and the card. The protocol is one part of the control structure, not the
whole of it. Spec references are to RAPP v26.10.10 unless stated.

Sections 2 to 6 are the analysis. Section 7 lists candidate requirements
for the owner to accept, reject, or reshape; none of them is a protocol
change until it is stamped into a specification.

## 2. Losses

| ID | Loss |
| :--- | :--- |
| L-1 | A card operation (authentication or qualified signature) is executed without the cardholder's current, informed consent. |
| L-2 | The card's PIN retry budget is consumed, or the card is blocked, by operations the cardholder did not intend. |
| L-3 | The cardholder cannot authenticate or sign when they legitimately want to, and cannot tell why. |
| L-4 | The cardholder's presence, activity, or identity is disclosed to a third party. |
| L-5 | A document other than the one the cardholder approved is signed. |

## 3. System-level hazards and safety constraints

| ID | Hazard | Losses |
| :--- | :--- | :--- |
| H-1 | A card command that consumes a PIN try or uses a private key is dispatched without a consent given for that command. | L-1, L-2, L-5 |
| H-2 | The same authorized operation is executed on the card more than once. | L-1, L-2 |
| H-3 | The requester offers a card identity to local consumers that the custodian cannot serve now (card gone, phone gone, pairing gone). | L-3 |
| H-4 | The two endpoints of a pairing hold different beliefs about whether the pairing exists or what it grants. | L-3, L-1 |
| H-5 | A human is shown a state that is not the system's state, or is given no way to tell between states that need different actions. | L-1, L-2, L-3 |
| H-6 | A message or record observable by a third party reveals a pairing, a card event, or a person. | L-4 |
| H-7 | The requester withholds or withdraws a card identity that the custodian can serve. | L-3 |

Each hazard has a safety constraint, its negation, which the design must
enforce:

| ID | Safety constraint |
| :--- | :--- |
| SC-1 | The custodian dispatches a PIN-consuming or key-using command only under a consent given for that command's frozen content, and only while that consent is current. |
| SC-2 | One authorization executes on the card at most once, whatever the transport does. |
| SC-3 | The requester offers an identity to local consumers only while the custodian can serve it. |
| SC-4 | Both endpoints of a pairing agree on its existence and grants, and a change on one side reaches the other. |
| SC-5 | What a human is shown is the system's state, and states that need different remedies are shown differently. |
| SC-6 | Nothing observable by a third party is derivable from a stable identifier of a pairing, a card, or a person. |
| SC-7 | The requester withdraws an identity only on evidence that the custodian cannot serve it. |

The protocol already addresses H-1, H-2, and H-6 in depth: consent on the
custodian screen (section 11), write-ahead journaling and durable
tombstones (section 8), and keyed, rotating discovery and withdrawal hints
(sections 2.2.1, 4.3, 4.5). The findings below concentrate on H-3, H-4,
H-5, and H-7, where the control structure has the fewest feedback paths.

## 4. Control structure

```
                      +-----------------------------+
                      |         Cardholder          |
                      +--+-----^-----------+-----^--+
      code entry,        |     |           |     |       consent, PIN,
      forget pairing,    |     | screen    |     | screen tap card,
      start login/sign   |     |           |     |        pair, forget,
                         v     |           v     |        toggle, quit
 +------------------+   +------+---+   +------+----+   +-------------+
 | Local consumer   |-->| Requester|<=>| Custodian |-->| Phone OS    |
 | browser, CTK,    |<--| (desktop)|   | (phone)   |<--| NFC, BLE,   |
 | PKCS#11          |   +----+-----+   +--+-----+--+   | scheduler   |
 +------------------+        ^            |     ^       +-------------+
   sign/login requests,      |  records   |     |  advertise
   identity offered,         |            |     +----------+
   identity withdrawn        |            |                |
                      +------+------------v-+        +-----v-----+
                      |      Discovery       |        |   Card    |
                      |   mDNS/DNS-SD, BLE   |        | APDU in,  |
                      +----------------------+        | SW out    |
                                                      +-----------+
```

The double line between requester and custodian is the RAPP session; the
single lines are platform interfaces. Downward arrows are control
actions; upward or returning arrows are feedback. Each link is listed
below with its control actions, the feedback that exists, and the
feedback that is absent. "Absent" means no authenticated signal carries
the fact; a timeout or an inference from silence is not feedback.

### 4.1 Cardholder <-> custodian

| Control action | Feedback present | Feedback absent |
| :--- | :--- | :--- |
| Approve or decline an operation (section 8.2 item 3) | Result on the phone screen | Whether the requester received the result |
| Enter PIN on the phone | Card status word, retries remaining (section 9.1) | Nothing on the requester side; see 4.3 |
| Tap or insert the card | Card read on the phone | Nothing on the requester side until an operation runs |
| Turn remote access off, quit the app (section 4.5) | Withdrawal hint published for up to 8 pairings | Which requesters observed it |
| Forget a pairing on the phone | Local list updates | The requester is never told (UCA-9) |

### 4.2 Cardholder <-> requester

| Control action | Feedback present | Feedback absent |
| :--- | :--- | :--- |
| Type the pairing code | "connecting", then success or one failure string | Which of wrong code, lockout, wrong network, phone not offering (section 3.3 withholds some of this on purpose) |
| Forget a pairing on the computer | Local list updates | The custodian is never told |
| Start a browser login or a signature | The consumer's own progress | Whether the phone has shown the prompt (4.4) |

### 4.3 Requester <-> custodian (RAPP)

| Control action | Feedback present | Feedback absent |
| :--- | :--- | :--- |
| `pairing.hello`, `pairing.confirm` (section 7.1) | Mutual echo, `grants_hash` | That the peer durably stored the pair (section 2.1 phase 4 is local on each side) |
| `operation.request` (section 8.2) | `operation.result`, `operation.progress` (advisory), `operation.status` | That the custodian is awake and has rendered the consent view; the deadline is enforced only by a running custodian |
| `operation.result` with `rejected` or `credential_rejected` | None | `operation.result_ack` exists only for `completed`; the custodian cannot know the requester learned the retries left |
| `session.close` with a reason (section 7.1) | The reason itself | The requester's user interface does not distinguish reasons |
| `liveness.ping` / `liveness.pong` | Within a session | Nothing between sessions; the stream transport opens a session per transaction |
| Noise_KK handshake failure (section 7.2) | Class 2 transport loss | Whether the peer has revoked the pairing; a revoked peer and an absent peer look the same |

### 4.4 Custodian <-> phone OS and card

| Control action | Feedback present | Feedback absent |
| :--- | :--- | :--- |
| Show the consent view | View shown while the app is foreground or notified | Whether the OS delivered the notification or suspended the app |
| Dispatch an APDU over NFC | Status word, field loss | Thermal throttling of the NFC controller, which lengthens or breaks the exchange without a distinct error |
| Advertise presence (discovery record, BLE advertisement) | None from the network | Whether any requester sees the advertisement |
| Card inserted or removed on the phone | Local card presence | No protocol message; the requester learns through `inspect_card` polling or an operation failure |

### 4.5 Requester <-> discovery and local consumer

| Control action | Feedback present | Feedback absent |
| :--- | :--- | :--- |
| Local consumer asks for a signature or a login (CryptoTokenKit, PKCS#11 `C_Sign`) | The requester's own completion or error to the consumer | Whether the consumer will retry or cache the outcome |
| Watch the custodian's advertisement | Record seen or not seen, with a hold against multicast loss | Authenticated liveness; a seen record is not a serving custodian, and an unseen one may be serving |
| Publish or withdraw the borrowed card identity (CryptoTokenKit) | Keychain queries that sometimes answer "no identity" for a token the browser is using | A reliable "published and visible to consumers" signal |
| Offer the identity to the browser | The browser's own chooser | Whether the browser cached the identity after it was withdrawn |

## 5. Unsafe control actions

Each UCA follows the form "controller provides or omits control action
in context", and is one of: not provided when needed (N), provided when
unsafe (P), or provided too early, too late, or out of order (T). No
control action in this system is a continuous one, so the duration type
does not apply. Physical degradation of an actuator is not a UCA; it is a
loss scenario (6.6).

| ID | Controller | Control action | Type | Context | Hazard |
| :--- | :--- | :--- | :--- | :--- | :--- |
| UCA-1 | Custodian | Dispatch a PIN-consuming or key-using APDU | P | When the consent shown was for a different frozen snapshot, or the deadline passed while the custodian was suspended and did not expire the operation. | H-1 |
| UCA-2 | Custodian | Dispatch an APDU | P | When a journal entry for the same `(pair_id, operation_id)` exists in any state. Already prevented by section 8.2; listed to keep the chain visible. | H-2 |
| UCA-3 | Requester | Publish the borrowed identity to local consumers | P | When the custodian is not serving: card removed, remote access off, app quit, phone on another network, or pairing revoked on the phone. | H-3 |
| UCA-4 | Requester | Withdraw the borrowed identity | P | When the only evidence is a keychain answer that is wrong (identity in use but reported absent). | H-7 |
| UCA-5 | Requester | Withdraw the borrowed identity | T | More than the hold after the card actually left the phone, so a consumer keeps offering a card that cannot sign. | H-3 |
| UCA-6 | Requester | Dial the custodian for an operation | P | When the custodian is suspended but its advertisement is still seen, so the dial hangs with nothing to tell the user. | H-3, H-5 |
| UCA-7 | Requester | Show "phone not reachable" | P | When any of five causes applies and the text names none, so the user cannot pick the right remedy. | H-5 |
| UCA-8 | Requester | Store the pairing | P | When the custodian did not store its side (storage failure, abort race), so the requester holds a pairing with no peer. | H-4 |
| UCA-9 | Custodian or requester | Tell the peer that a pairing was forgotten | N | When the user forgets a pairing locally; the peer keeps the pairing and treats every later handshake failure as a transient outage. | H-4, H-3 |
| UCA-10 | Custodian | Send `operation.result` for a rejection | P | When delivery cannot be confirmed, because no acknowledgement is defined for a rejection; a lost result leaves the requester without the retries-remaining count and the user may retry into a block. | H-5 |
| UCA-11 | Custodian | Render the consent view | N | When the OS suspended the app or did not deliver the notification; the operation expires silently after the local deadline, if the deadline runs at all. | H-5 |
| UCA-12 | Requester | Accept a typed pairing code | T | When the custodian's offer has lapsed (60 s) or is locked out; the requester reports only "no device offering this code". | H-5 |
| UCA-13 | Custodian | Advertise as serving | P | When primed NFC data exists but no card is in the field, so the requester publishes an identity that cannot sign. | H-3 |
| UCA-14 | Custodian | Publish a discovery record or withdrawal hint | P | When any value in it is derivable from a stable identifier of the pairing or the phone. Already prevented by sections 4.1, 4.3 and 4.5; listed to keep the chain visible. | H-6 |
| UCA-15 | Requester | Send `operation.request` carrying a document hash | P | When the hash is not of the document the user chose on the computer; the custodian can show only the name and hash summary it was given (section 11 item 3). | H-1 |

## 6. Loss scenarios

Scenarios are grouped by the feedback gap that produces them. Each names
the UCAs it explains and the spec sections involved.

### 6.1 Pairing state diverges (UCA-8, UCA-9)

Phase 4 of the lifecycle stores the trust record on each side without a
confirmation from the other (section 2.1). A custodian that fails its
durable write, or a requester that aborts after `pairing.confirm`, leaves
one side with a pairing the other does not have. Later, a user forgets a
pairing in one application's settings; the other application has no
message for this and keeps the record (section 4.5 states that withdrawal
changes no stored pairing, and nothing else addresses revocation).

The surviving side then dials, fails Noise_KK, and classifies the failure
as a Class 2 transport loss (section 7.2 item 1). The requester shows the
phone as unreachable indefinitely. In an observed case the surviving
record also lacked a peer name, so the requester showed a generic label
and offered no way to pair another phone.

### 6.2 Presence is inferred, not fed back (UCA-3, UCA-5, UCA-6, UCA-13)

Between operations the stream transport holds no session, so the only
signal of a serving custodian is its discovery record, and the requester
applies a hold of tens of seconds against multicast loss. The record is
unauthenticated and the custodian keeps publishing it while primed NFC
data exists but no card is present. The requester's process model "phone
here, card here" can therefore be wrong in both directions: a seen record
for a phone that cannot serve, and a lost record for a phone that can.

The card departure plan (requester repository) proposes a keyed, private
card-status signal. Until a message like it is in the protocol, UCA-3 and
UCA-5 are structural, not implementation bugs.

### 6.3 Consent delivery has no acknowledgement (UCA-1, UCA-6, UCA-11)

`operation.request` has no "prompt displayed" feedback, and
`operation.progress` is advisory. The local deadline (section 8.2 item 1)
is derived from a monotonic clock. On the platforms in use that clock
does not advance while the process is suspended, so a suspended custodian
neither shows the prompt nor expires the operation; the requester waits
on its own timer with nothing to tell its user. When the custodian
resumes, its deadline has not moved, and it shows a prompt the user no
longer expects. The deadline must be measured against time that keeps
running through suspension, and an operation found past it on resume
must expire without a prompt.

### 6.4 Rejections are unacknowledged (UCA-10)

`operation.result_ack` covers `completed` only (section 8.2 item 5). A
`credential_rejected` result lost to a dropped link is recoverable through
`operation.status_request`, but only if the requester knows to ask. The
retries-remaining count, which is what stops a user from retrying into a
block, is the payload most worth confirming.

### 6.5 The requester's user is shown one state for many (UCA-7, UCA-12)

Close reasons (section 7.1 item 5), withdrawal (section 4.5), lockout
(section 3.3), offer expiry (60 s), and handshake failure after revocation
all reach the requester, but its user interface collapses them into one
line. Section 3.3 withholds "wrong code" versus "other failure" on purpose
to deny a disconnect oracle; that is a security trade-off, and it should
be stated as one so that the other causes, which the oracle argument does
not cover, can be shown.

### 6.6 Platform feedback is wrong or absent (UCA-4; actuator degradation)

Two observed incidents on the Apple requester and custodian:

- The requester withdrew a published identity because a keychain query
  answered that no identity existed, while the browser was using it. The
  automatic withdrawal was removed; the query is not evidence. (UCA-4)
- NFC signing failed on a warm phone. The controller was being throttled
  by temperature, which the application could not see; the failure was
  attributed to software for days. This is not a UCA: the custodian
  issued a safe control action and the actuator executed it inadequately.
  The gap is the missing feedback that would have let the custodian
  report a degraded field instead of a card or software fault.

Both are controllers acting on inadequate feedback from the platform. The
remedy in each case was to stop treating a platform answer as truth; the
analysis asks what feedback would have made the state visible.

### 6.7 The document shown is the document signed (UCA-15)

Document secrecy (section 11 item 3) keeps raw bytes off the wire, so
the custodian can show only a name and a hash summary. The binding
between the file the user chose on the computer and the hash in
`operation.request` rests entirely on the requester. A requester that
hashes the wrong file, or a consumer that hands it the wrong digest,
produces a consent screen that looks right for a document the user did
not choose. The protocol cannot close this; the requester's own path from
chosen file to digest must be the subject of its own analysis.

## 7. Candidate requirements

Protocol-level candidates, for the owner to stamp or reject:

| ID | Candidate | Closes |
| :--- | :--- | :--- |
| R-1 | A `pairing.stored` message from each side after Phase 4, so a pairing exists only when both confirmations have been exchanged; an unconfirmed pairing is revoked locally. | UCA-8 |
| R-2 | An authenticated `pairing.revoke` message, sent on the next session or carried as a keyed hint like withdrawal, so a peer that forgets a pairing tells the other. | UCA-9 |
| R-3 | A distinct close or handshake outcome for "pairing unknown" so the requester can show "this phone forgot this computer" instead of "not reachable". It must not become a probe for pairing existence; section 2.2.1's constant-time routing already shapes this. | UCA-7, UCA-9 |
| R-4 | A card-status message or keyed discovery hint carrying card presence, per the departure plan, so the requester's identity publication follows the card. | UCA-3, UCA-5, UCA-13 |
| R-5 | `operation.result_ack` for every terminal status, not only `completed`. | UCA-10 |
| R-6 | An `operation.progress` state `consent_shown`, and a deadline measured against a clock that keeps running through suspension, so that an operation found past its deadline on resume expires without a prompt. | UCA-1, UCA-11 |

Implementation-level candidates:

| ID | Candidate | Closes |
| :--- | :--- | :--- |
| R-7 | The requester shows the custodian by name and names the cause when it can: withdrawn, closed with reason, locked out, offer lapsed. | UCA-7, UCA-12 |
| R-8 | The custodian stops advertising as serving when no card can answer, prime data or not. | UCA-13 |
| R-9 | The custodian reads the platform's thermal and NFC availability state where the platform exposes it, and reports a distinct error when the field is degraded. | Scenario 6.6 |
| R-10 | The requester treats keychain and token queries as hints and never withdraws an identity on their answer alone. Already in force on the Apple requester. | UCA-4 |
| R-11 | The requester bounds every dial and every operation with its own deadline, and when it lapses tells the user that the phone did not answer rather than leaving the consumer to hang. | UCA-6 |
| R-12 | The requester's path from the file the user chose to the digest it sends is analysed and tested as its own control loop, with the consumer's digest checked against the file where the consumer supplies one. | UCA-15 |

## 8. Incidents for CAST

Causal Analysis using System Theory (CAST) applies the same control
structure to events that have already happened. Three candidates, each
with a known outcome and a feedback gap at its centre:

1. A requester held a pairing without a peer name and showed a generic
   device label; the user could not pair another phone from the main
   window. Gap: 6.1.
2. NFC signing on a warm phone failed for days and was attributed to the
   operating system and then to the application. Gap: 6.6.
3. A requester withdrew a live browser identity twice on a wrong keychain
   answer. Gap: 6.6.

Each CAST should produce: the control structure at the time, the
controllers' process models, the feedback each lacked, and the
recommendation that generalises beyond the one incident.

## 9. CAST: a browser login through the phone, 2026-10-18

**Status:** preliminary. The phone's own per-command timings have not
been read yet; the timeline below comes from the requester's log and
the phone's system log, which show when each command left, not when the
card answered.

### 9.1 What happened

A browser login on the requester, with the card on the phone, failed
twice and succeeded on the third attempt. Each attempt opened a fresh
NFC session on the phone and ran the full card choreography.

| Step | Failed attempt | Successful attempt |
| :--- | :--- | :--- |
| Browser asks, requester opens the session to the phone | 0.3 s | 0.3 s |
| Phone opens the NFC session, finds the card, selects the application | 1.4 s | 0.25 s |
| First commands to the card | 5 in 0.2 s | 6 in 0.3 s |
| No command to the card | 2.6 s | 1.3 s |
| Next command | RF error ("Tag Error"), card reported removed | 1 command, then 1.1 s with no command |
| Remaining commands and the signature | - | 9 commands in 1.4 s |
| NFC field left on after the result was delivered | - | 3.6 s |

The requester then refused the browser's immediate retries for 15
seconds under its back-off, so the user's own retry inside that window
was refused silently.

### 9.2 Control structure at the time

Browser -> CryptoTokenKit token (requester) -> requester app -> RAPP
session -> phone app -> CryptoTokenKit NFC slot daemon -> NFC daemon ->
card, with the holder above the phone app. Three feedback paths were
missing or wrong:

- The requester offered the identity to the browser on the strength of
  the phone's discovery record, with no word from the phone about the
  card (UCA-3, scenario 6.2).
- The requester's back-off hid the state from the holder: a refusal
  looked like nothing happening (UCA-7, scenario 6.5).
- The phone app's own timeline is private in the system log, so neither
  the requester nor an observer could see what the phone was waiting
  for during the silent stretch; only the phone's diagnostics report
  carries per-command timings.

### 9.3 Causal analysis

- The phone ran a new NFC session and the full PACE handshake for every
  browser request. On the contactless interface the card computes two
  brainpoolP384r1 point multiplications during PACE, each on the order
  of a second under the field, and a signing request needs PACE, the
  PIN and the signature in one session.
- The silent stretch before the RF error is where the card was most
  likely computing or waiting; a card that answers late under a weak
  coupling loses the link, and the phone reports the card removed. The
  requester's engine math is not the cause: the phone's package is
  compiled optimised, and the handshake arithmetic measures tens of
  milliseconds.
- The field stayed on for 3.6 s after the result left, which costs
  nothing for that request and everything for the next: the phone's
  NFC controller warms about 7 C per second under the field.
- The controller temperature itself was examined and ruled out as a
  cause: the failure came at 45 C, the success at 82 C.

### 9.4 Recommendations

| ID | Recommendation | Closes |
| :--- | :--- | :--- |
| R-13 | While the card stays on the phone, keep the NFC session and the PACE secure channel open across requests, and run PACE when the card is first seen rather than when a request arrives, so a browser request costs the PIN and the signature only. | 9.3, UCA-6 |
| R-14 | End the NFC session as soon as the result has left, or at an idle limit measured in seconds, never later. | 9.3 |
| R-15 | Read the phone's diagnostics report, which carries per-command round-trip times, before touching the handshake code, and record the command that took the time in this section. | 9.3 |
| R-16 | Implemented in the 26.10.18 adoption: the requester offers the identity only while a session reports a card, and the phone reports absence as soon as an operation ends without the card answering, so a retrying browser finds nothing to retry; the back-off is gone. | UCA-3, UCA-7 |

## 10. STPA of the browser slot on a Unix requester

**Status:** prospective. This section analyses a design before it is
built: the paired phone offered to browsers on a Unix computer as a
PKCS#11 slot. Section 4 drew the local consumer as one box; here the
box is opened, because the design puts a requester inside the browser's
process, beside the requester the user sees.

### 10.1 The design

The PKCS#11 module that Firefox loads through p11-kit gains one slot
for the one phone paired with the computer. The slot's token is present
while the module holds an open session to the phone and the phone
reports a card in the field (specification §8.4); the module dials when
the phone's record carries a card-present hint (§4.5) and ends the
session when the card leaves. The token's
certificate objects are answered from the pairing record on disk, which
the GUI fills after pairing, so that enumeration never dials the phone.
`C_Login` succeeds without reading a PIN: the token declares a
protected authentication path, and the phone verifies PIN 1 when the
operation arrives, as it does for every requester (§9.2 carries no
credential). `C_Sign` becomes one `operation.request` on the held
session, bounded by a deadline the module sends as the operation's
lifetime. A lock file per pairing keeps the module, the GUI and the CLI
from opening two sessions under one static key.

### 10.2 Control structure

Two requester processes now share one pairing on one computer. Each is
a controller with its own process model of the phone, the card and the
pairing record; the record on disk is the only channel between them.

| Control action | Controller | Feedback present | Feedback absent |
| :--- | :--- | :--- | :--- |
| Offer the slot and token | Module | Session open or closed; `card.status` on the session | Whether the cached certificate is the card now on the phone |
| Answer certificate attributes | Module | None needed: the answer is local | Whether the browser cached a certificate the token no longer offers |
| Accept `C_Login` | Module | The slot's own token state: session open and `card.status` present | Whether the phone will ask for a PIN or has one cached |
| Dispatch `C_Sign` to the phone | Module | `operation.progress`, `operation.result`, the close reason, the deadline | Whether the browser's own handshake deadline passed while the phone was asking |
| Send the operation context with `C_Sign` | Module | None | Which relying party asked; PKCS#11 does not carry it |
| Hold the session: dial, ping, reconnect | Module | Ping replies; discovery records; the close reason | A phone that is suspended but still advertised (UCA-6) |
| Take and release the pairing lock | Module, GUI, CLI | The lock call's own result | Whether the holder is alive, if the lock is not released by the kernel on exit |
| Write the pairing record (certificate, tombstone, journal) | Module, GUI, CLI | The file system | Whether the other process read a record that is being rewritten |
| Withdraw the token | Module | The browser's next `C_GetSlotList` | Whether a login already in flight used the withdrawn token |
| Show the state of the phone | GUI | The GUI's own session or lock result | The module's session state, which lives in another process |

### 10.3 Unsafe control actions

| ID | Controller | Control action | Type | Context | Hazard |
| :--- | :--- | :--- | :--- | :--- | :--- |
| UCA-16 | Module | Offer the token with the cached certificate | P | When the card on the phone is not the card the certificate was read from: the cardholder swapped cards, or a new card was issued, so the browser offers one identity and the phone signs with another. | H-3, H-5 |
| UCA-17 | Module | Hold the session | P | When no login is wanted for hours, so the phone keeps a stream and its advertisement alive for a browser that merely runs; the cost is battery and the phone's "connected" state, and a reconnect storm on a flapping network. | H-6, H-7 |
| UCA-18 | Module | Dial the phone again | P | After a close with reason `pairing_revoked`, a verified revocation hint, or a Class 4 refusal, when the record on disk is not yet marked revoked, so the module re-dials a pairing the phone has forgotten and lists it as paired. | H-4 |
| UCA-19 | Module | Hold the lock while a record lacks a certificate | P | When the GUI is the only writer of the certificate and the module holds the session, so the certificate is never fetched, the token never appears, and the user sees a paired phone that no browser can use. | H-7, H-5 |
| UCA-20 | Module | Dispatch `C_Sign` | P | When the browser or the relying party will give up before the phone can answer, so the phone asks for a PIN whose signature arrives at a closed connection, and the user is left to guess whether to enter the PIN again. | H-5, H-2 |
| UCA-21 | Module | Dispatch `C_Sign` again | P | After an outcome the module could not classify (transport lost after the request left), so the same login is executed twice on the card. Already constrained by the journal of §8.3. | H-2 |
| UCA-22 | Module | Dial the phone again after the session was lost | N | When the phone's record is in sight again after a transient loss, a lost ping or a Wi-Fi roam, so the slot stays empty although the phone is back within seconds. | H-7 |
| UCA-23 | Module or GUI | Rewrite the pairing store | P | While the other process holds a record in memory, or when the store's open sweeps superseded and keyless records, so two processes on one computer hold different beliefs about the pairing. | H-4 |
| UCA-24 | Module | Send the operation context | P | When the context names a relying party the module cannot know: PKCS#11 carries no origin, so a context that claims one would be fabricated. The phone's PIN prompt can name only the computer. | H-1, H-5 |
| UCA-25 | Module | Accept `C_Login` | P | When the token is not present, no session or no card, so the browser enters the logged-in state, dispatches a sign that cannot succeed, and reports the failure as a PIN problem. | H-5 |
| UCA-26 | Module | Answer certificate attributes | P | From the record on disk after the token appeared with other objects, so a browser session holds handles to objects that no longer exist, and a swapped record is served under old handles. | H-3, H-5 |
| UCA-27 | Module | Withdraw the token | N | When the session closed or `card.status` reports no card, so the browser keeps offering an identity the phone cannot serve. | H-3 |
| UCA-28 | Module | Withdraw the token | P | While an operation is in flight on the session, so the signature the user is approving on the phone returns to a handle that is gone, the browser reports an error, and a retry asks the card again. | H-5, H-2 |
| UCA-29 | GUI or CLI | Forget the pairing | P | While another process on the computer holds the session, without that process learning of it, so the session stays open under a pairing the record calls revoked and the phone is never told. | H-4 |
| UCA-30 | Module | Dial the phone again after the session was lost | P | As a loop while the phone's record is not in sight, so the computer dials into nothing and a phone that reappears is met by a burst. | H-6 |
| UCA-31 | Module, GUI or CLI | Open a session | P | Without holding the pairing's lock, so two processes on one computer hold sessions under one static key and journal, revoke and rewrite the same record on different evidence. | H-4, H-2 |

### 10.4 Loss scenarios

**The certificate is not the card (UCA-16).** The record holds the
certificate the GUI read at pairing time. The phone later serves another
card: the holder has two cards, or a replacement arrived. Enumeration
answers from the record, the browser shows the old identity, the TLS
server sends a challenge, the phone signs it with the key of the card
in the field, and the server rejects the signature with a message that
names nothing. Every component worked; the module's process model of
"the card" was a photograph. The feedback that would correct it exists
on the session, `card.status`, but carries presence, not identity.

**The lock starves the fetch (UCA-19).** The user pairs in the GUI
while the browser runs. The record is written without a certificate,
since the GUI's fetcher runs on its own interval. The module sees a
usable pairing, opens its offering session, and holds the lock. The
fetcher dials, meets the lock, and reports busy on every round. The
Phone tab shows the phone paired and the browser shows nothing,
forever, and nothing on either screen says why. The control structure
has two controllers that each need the session and one channel between
them that neither reads for this purpose.

**The phone answers a dead connection (UCA-20).** The relying party's
TLS handshake timeout is typically 30 to 60 seconds. The module waits
90. The user picks up the phone at 40 seconds, enters PIN 1, and the
signature returns to a browser whose connection the server already
closed. The browser shows an error, the user retries, the phone asks
again, and the user concludes the PIN was wrong. No PIN try was lost,
but L-3 occurred, and a user who now types the PIN hastily is on the
path to L-2.

**Two sessions, one key (UCA-31, UCA-23, UCA-7).** Without the lock, the
module and the GUI each open a session under the same static key. The
specification allows one live operation per session, not one session
per pairing, so the phone serves both; but the two processes then
revoke, journal and rewrite the same record on different evidence. With
the lock, the loser must say so: a GUI that cannot dial because the
browser holds the phone is in a different state from one whose phone is
away, and showing both as "not reachable" is UCA-7 again.

**The phone said no and the module dials again (UCA-18).** The phone
closes with `pairing_revoked`: its user forgot the computer. The
module's session ends and the token goes with it, as §8.4 requires. But
the record on disk still reads usable, so the module's next refresh
dials again under a key the phone has destroyed and meets a refusal,
and again at every refresh until the record is rewritten: each dial is
a handshake the phone must refuse, and the user at the computer sees a
phone listed as paired that never answers. The write of the record and
the next dial are a race, and the order of the two is the whole
defence.

### 10.5 Requirements for the design

| ID | Requirement | Closes |
| :--- | :--- | :--- |
| R-18 | Whichever requester process holds the session fetches the certificate when the record lacks one, and writes it to the record; the module is not a reader only. The read is a safe operation and consumes no PIN try. | UCA-19 |
| R-19 | Before the token is offered on a session, the module reads the certificate over that session, a safe read that consumes no PIN try, and compares it with the record's; on a mismatch it rewrites the record and offers the new identity, and while the phone reports no card it offers nothing. No signature is requested under a certificate that was not read on the current session. | UCA-16 |
| R-20 | The module's operation deadline is one named constant chosen below the browsers' and relying parties' handshake timeouts, sent to the phone as the operation lifetime, and a result that arrives after it is reconciled through the journal and never resent. | UCA-20, UCA-21 |
| R-21 | The token follows the session, as §8.4 requires: it is withdrawn when the session closes or `card.status` reports no card, with no hold beyond an operation in flight (R-28); the module dials again when the phone's record with a card-present hint is in sight, at a bounded interval, and not at all while no record is in sight. | UCA-27, UCA-22, UCA-30 |
| R-22 | A close carrying `pairing_revoked`, a verified revocation hint, or a Class 4 refusal marks the record revoked before any new dial, so no dial follows the close and the slot goes with the pairing. | UCA-18 |
| R-23 | The pairing lock is a session lock, not a store lock: it is released by the kernel when its holder exits, and record rewrites are atomic renames any process makes after re-reading the record, so the GUI forgets or revokes while the browser holds the session. The session holder re-reads the record at every ping of its own session thread, independent of the browser's calls; a record it finds revoked ends its session with the `pairing_revoked` close of §4.6 item 1, which the session holder is placed to deliver, and withdraws the token. The module's open never deletes records; sweeping is the GUI's. | UCA-23, UCA-29 |
| R-24 | The GUI tells apart "the browser holds the phone session" from "the phone is away", from the lock result, and shows the phone as paired and in use rather than unreachable. | UCA-7 |
| R-25 | The operation context names the computer and nothing it cannot know; the phone's PIN prompt shows that name and the operation kind. The module never fabricates an origin. | UCA-24 |
| R-26 | The module dials only when the phone's record carries a card-present hint (§4.5) and holds the session only while `card.status` reports a card, closing it when the card leaves and no operation is in flight (R-28), so a browser that merely runs costs the phone nothing while no card lies on it; `C_Finalize` ends any session. | UCA-17 |
| R-27 | `C_Login` succeeds only while the token is present and otherwise returns the token-absent error, and the token's objects are fixed when the token appears: a changed record withdraws the token and offers a new one, so a handle never outlives its object. | UCA-25, UCA-26 |
| R-28 | A withdrawal that arrives while an operation is in flight waits for that operation's own result or deadline, which the browser receives as the answer to its `C_Sign`; the token is withdrawn after, and the operation is never resent. | UCA-28 |
| R-29 | Every session under a pairing is opened under that pairing's lock, by the module, the GUI and the CLI alike; a process that cannot take the lock opens nothing and reports the holder. | UCA-31 |

## 11. STPA of the Android custodian

**Status:** first pass, prompted by an incident on the phone alone: a
tap that was lost during the flow that takes the card into use was
reported as "card not found", and the next attempt asked for PIN 1
again. Section 4 drew the custodian as one box with the card and the
operating system around it; here the box is opened for the Android
application, whose controllers are the preparation state machine, the
reader controller, the dialogs, and the person holding the phone.

### 11.1 Scope

The Android application as custodian, on the phone alone and while
serving a paired computer: the preparation that takes the card into use
(the CAN when the card needs one, PIN 1, a tap, PACE, the PIN's
verification, and the verified PIN retained for its purpose), the
reader controller that arms NFC reader mode and reports what the tag
does, the prompt a computer's request raises, and the card session kept
while the card lies on the phone.

### 11.2 Control structure

| Control action | Controller | Feedback present | Feedback absent |
| :--- | :--- | :--- | :--- |
| Ask for PIN 1 | Preparation | The typed PIN; whether the cache holds a verified PIN | Whether the person counts this as the same attempt as the last one |
| Arm reader mode and wait for a tap | Reader controller | Tag discovered; status: checking, recognised, connecting, ready, transport error | Why no tag came: card not placed, placed off the antenna, field dropped, reader mode not delivered by the OS, controller throttled |
| Connect: PACE with the CAN | Backend | PACE accepted or rejected; transport error | Whether the field will hold for the next command |
| Verify PIN 1 | Backend | Status word: verified, wrong with the tries left, locked, a safety refusal below the floor | Nothing when the field drops mid-command: whether the card counted a try is unknown |
| Retain the verified PIN | Preparation | The cache's state | How long the person may rely on it |
| End the attempt and offer Retry | Dialog | The person's tap on Retry or Cancel | That Retry starts from the credentials step, not from the tap |
| Time out the attempt | Preparation | Its own timer | Whether the person was still trying |
| Show a computer's request and ask its PIN | Remote dialog | The typed PIN; approve or decline | Whether the person is inside a local flow at that moment |
| Report the card present to a computer | Custodian | `card.status` on the session; the last tag event | A field that dropped since the last command |

### 11.3 Unsafe control actions

| ID | Controller | Control action | Type | Context | Hazard |
| :--- | :--- | :--- | :--- | :--- | :--- |
| UCA-32 | Preparation | Discard the entered PIN | P | When the attempt ended for a reason the PIN had no part in: no tap came, the field dropped, PACE lost the transport, or the attempt timed out; the next attempt asks again for a PIN the system never tested. | H-5 |
| UCA-33 | Dialog | End the attempt and offer Retry | P | When no card answered at all, so the person is told a card is missing while holding it against the phone, nothing says what to change, and Retry starts from the credentials step rather than from the tap. | H-5 |
| UCA-34 | Preparation | Time out the attempt | T | Too early against the person's handling of the card, so a slow tap becomes a failure whose Retry asks the PIN again. | H-5 |
| UCA-35 | Backend | Verify PIN 1 | P | Again with the held PIN after a field loss left the last command's outcome unknown, without reading the tries left first, so a wrong PIN the card did count is sent once more and the person never saw the count fall. | H-5 |
| UCA-36 | Preparation | Ask for PIN 1 again after a wrong PIN | P | Without the tries left shown, so the person cannot judge whether to continue or stop. | H-5 |
| UCA-37 | Reader controller | Keep reader mode armed | N | After the activity paused or the OS dropped reader mode, so the dialog waits for a tap that cannot arrive and says only "hold the card". | H-5 |
| UCA-38 | Remote dialog | Show a computer's request and ask its PIN | P | While the person is inside the local preparation dialog, so two PIN prompts compete and a PIN typed for one lands in the other. | H-1, H-5 |
| UCA-39 | Custodian | Report the card present to a computer | P | From the last tag event when the field has since dropped, so the computer offers an identity the phone cannot serve. UCA-13 and R-8 state this for priming; this is the live-tag case. | H-3 |
| UCA-40 | Backend | Connect: PACE with the CAN | P | Again with a CAN the card already rejected, without a new entry, so the attempt fails the same way at every tap and the person is told the card is missing. | H-5 |
| UCA-41 | Preparation | Retain the verified PIN | P | After the purpose ended, or for a card other than the one that verified it, so a later operation runs under a PIN meant for another moment or another card, and a wrong one costs a try. | H-1, H-5 |

### 11.4 Loss scenarios

**The lost tap and the second PIN (UCA-32, UCA-33).** The person types
PIN 1 and holds the card to the phone. The attempt moves to waiting for
the card; the tag is not read, or the field drops during PACE, and the
attempt ends as card unavailable. The preparation zeroes the PIN it was
holding, since only a verified PIN is kept, and shows "card not found"
with Retry. Retry starts the preparation over, finds no verified PIN,
and asks for the PIN again. The state machine's model of an attempt is
one PIN with one tap, and a PIN the card never saw is worth nothing to
it; the person's model is one PIN for the card, and a tap that failed
is a tap to repeat. The person retypes, now hurried; a wrong digit
costs a try the card does count, and a second lost tap repeats the
cycle. L-3 is immediate, and L-2 is two slips away.

**The unknown count (UCA-35).** The PIN command leaves the phone and the
field drops before the status word returns. The card may have verified
the PIN, counted a wrong one, or never received it. The application
classifies the loss as a missing card, which is a belief, not a fact,
and the next attempt sends the held PIN again. With the right PIN the
card's counter resets, so nothing is lost; with a wrong one the person
is one try nearer to lockout than the last count they saw, and nothing
on the screen says so. The card reports its tries left without
counting one, so the count can be read before the PIN is sent.

**Two prompts (UCA-38).** A computer sends a request while the person is
in the middle of taking the card into use. The remote dialog appears
over the local one. The person types the PIN into whichever prompt is
on top, and the other keeps waiting; whichever operation that PIN
serves, the person did not choose it at that moment. The consent model
of §8.2 assumes one prompt at a time.

**The reader that is not listening (UCA-37, UCA-34).** The person
answers a notification, returns to the application, and holds the card
to the phone. Reader mode was dropped with the activity and is not
re-armed, or the controller is throttled. The dialog says "hold the
card" until the attempt times out, then "card not found", then asks
the PIN again. Every component acted as built; the dialog's model of
"waiting for a tap" had no input that said the reader was not armed.

### 11.5 Requirements

| ID | Requirement | Closes |
| :--- | :--- | :--- |
| R-30 | The entered PIN lives for the whole preparation: an attempt that ends without an answer from the card (no tap, field lost, PACE transport lost) returns to waiting for the card with the PIN held, and the reader is re-armed. PIN 1 is asked again when the card rejected it, when the tries left read after an unknown outcome are fewer than the last count (R-33), when the person cancels or leaves the dialog, or when the purpose ends. The PIN is zeroed when the dialog ends. | UCA-32 |
| R-31 | A tap that did not happen is not a failure: the dialog keeps waiting with the hold-card text. A card that answered and is not a supported card is reported as not supported; "card not found" is shown for nothing. Retry, where it is offered, starts from the tap, not from the credentials. | UCA-33 |
| R-32 | The attempt's timeout is measured from the last reader status change, not from the PIN entry; its expiry ends the attempt and offers Retry with the PIN still held. The dialog itself ends, zeroing the PIN, when the person cancels, when the application leaves the foreground, or after an idle limit. | UCA-34 |
| R-33 | A field loss during the PIN command is reported as contact lost during the PIN check. The next attempt reads the tries left before sending the PIN, which the card reports without counting a try; a count lower than the last one the card reported means the PIN was counted wrong, so the held PIN is not sent, the count is shown and the PIN is asked again. | UCA-35 |
| R-34 | Every PIN prompt shows the tries left whenever the card has told them. | UCA-36 |
| R-35 | While a local preparation dialog is open, a computer's request waits behind it with a line saying a computer is waiting, and the request's own deadline is honoured; one PIN prompt is on screen at a time. | UCA-38 |
| R-36 | The reader controller re-arms reader mode when the activity resumes and tells the dialog when reader mode is not active; the dialog says so instead of waiting. | UCA-37 |
| R-37 | `card.status` reports the card present only while the tag answers, and a dropped field reports absent at once, as R-8 and R-16 say for the Apple custodian. | UCA-39 |
| R-38 | A CAN the card rejected is asked again before the next PACE; the backend never repeats PACE with a CAN that failed. | UCA-40 |
| R-39 | The retained PIN is bound to the card that verified it, by the identity read in the same session, and to its purpose: a different card asks again, and the end of the purpose zeroes it. | UCA-41 |

## 12. Open questions

- Which of R-1 to R-6 are worth a protocol version, and which are better
  served by application behaviour over the existing messages?
- Should discovery carry any authenticated liveness at all, or should the
  requester hold a long-lived session instead of inferring presence?
- How much of the one-line failure text in 6.5 is a deliberate oracle
  defence, and how much is an omission?
