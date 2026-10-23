# STPA of the Remote Authorization Proxy Protocol

**Status:** Reviewed by the owner on 2026-10-22 with RAPP v26.10.22
**Date:** 2026-10-18
**Applies to:** RAPP v26.10.22 (`docs/protocols/rapp-v26.10.22.md`), the
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
custodian screen (section 11), one operation at a time on the card,
forgotten with its session (section 8), and keyed, rotating discovery and withdrawal hints
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
| Noise_KK handshake failure (section 7.2) | session close | Whether the peer has revoked the pairing; a revoked peer and an absent peer look the same |

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
as a session close (section 7.2 item 1). The requester shows the
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

## 7. Controller constraints

Protocol-level constraints, for the owner to stamp or reject:

| ID | Constraint | Closes |
| :--- | :--- | :--- |
| CC-1 | A `pairing.stored` message from each side after Phase 4, so a pairing exists only when both confirmations have been exchanged; an unconfirmed pairing is revoked locally. | UCA-8 |
| CC-2 | An authenticated `pairing.revoke` message, sent on the next session or carried as a keyed hint like withdrawal, so a peer that forgets a pairing tells the other. | UCA-9 |
| CC-3 | A distinct close or handshake outcome for "pairing unknown" so the requester can show "this phone forgot this computer" instead of "not reachable". It must not become a probe for pairing existence; section 2.2.1's constant-time routing already shapes this. | UCA-7, UCA-9 |
| CC-4 | A card-status message or keyed discovery hint carrying card presence, per the departure plan, so the requester's identity publication follows the card. | UCA-3, UCA-5, UCA-13 |
| CC-5 | `operation.result_ack` for every terminal status, not only `completed`. | UCA-10 |
| CC-6 | An `operation.progress` state `consent_shown`, and a deadline measured against a clock that keeps running through suspension, so that an operation found past its deadline on resume expires without a prompt. | UCA-1, UCA-11 |

Implementation-level constraints:

| ID | Constraint | Closes |
| :--- | :--- | :--- |
| CC-7 | The requester shows the custodian by name and names the cause when it can: withdrawn, closed with reason, locked out, offer lapsed. | UCA-7, UCA-12 |
| CC-8 | The custodian stops advertising as serving when no card can answer, prime data or not. | UCA-13 |
| CC-9 | The custodian reads the platform's thermal and NFC availability state where the platform exposes it, and reports a distinct error when the field is degraded. | Scenario 6.6 |
| CC-10 | The requester treats keychain and token queries as hints and never withdraws an identity on their answer alone. Already in force on the Apple requester. | UCA-4 |
| CC-11 | The requester bounds every dial and every operation with its own deadline, and when it lapses tells the user that the phone did not answer rather than leaving the consumer to hang. | UCA-6 |
| CC-12 | The requester's path from the file the user chose to the digest it sends is analysed and tested as its own control loop, with the consumer's digest checked against the file where the consumer supplies one. | UCA-15 |

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
| CC-13 | While the card stays on the phone, keep the NFC session and the PACE secure channel open across requests, and run PACE when the card is first seen rather than when a request arrives, so a browser request costs the PIN and the signature only. | 9.3, UCA-6 |
| CC-14 | End the NFC session as soon as the result has left, or at an idle limit measured in seconds, never later. | 9.3 |
| CC-15 | Read the phone's diagnostics report, which carries per-command round-trip times, before touching the handshake code, and record the command that took the time in this section. | 9.3 |
| CC-16 | Implemented in the 26.10.18 adoption: the requester offers the identity only while a session reports a card, and the phone reports absence as soon as an operation ends without the card answering, so a retrying browser finds nothing to retry; the back-off is gone. | UCA-3, UCA-7 |
| CC-17 | A requester that forgets a pairing without a session open had no feedback path to the phone: the specification let it dial once or not at all, and the Unix requester did neither, so the phone kept listing and serving a pairing that no longer existed until its own user forgot it too. Section 4.6 item 1 now requires the requester to deliver the `pairing_revoked` close itself whenever the phone's session record names the pairing, at most six dials per instance and epoch at least ten seconds apart, from the moment the user forgot the pairing and for up to 30 days, keeping the static key for that close alone until the phone closes the transport after the close or the phone's own revocation hint names the pairing. The retained key is the new hazard this introduces: for up to 30 days a forgotten pairing's key stays on the computer, usable for nothing but a close on a session the requester itself opens, at rest as it was before the user forgot the pairing. | UCA-9 |

## 10. STPA of the browser slot on a Unix requester

**Status:** prospective. This section analyses a design before it is
built: the paired phone offered to browsers on a Unix computer as a
PKCS#11 slot. Section 4 drew the local consumer as one box; here the
box is opened, because the design puts a requester inside the browser's
process, beside the requester the user sees.

### 10.1 The design

The PKCS#11 module that Firefox loads through p11-kit gains one slot
for the one phone paired with the computer. The slot's token stands on
the certificate the pairing record caches, while the pairing does: the
module dials the phone for a session (§4.5 says when), ends the session
when the card leaves, and keeps the token through both, so a browser
that asks before the session is open is given the identity and its
signature waits for the phone. The token's certificate objects are
answered from the pairing record on disk, which whichever requester
first held a session fills, so that enumeration never dials the phone.
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
| UCA-50 | Module | Offer the token | N | Not before the session to the phone is open, when the browser's first page load at a site that asks for a certificate comes earlier: the browser answers the request with no certificate, and a browser given none at a handshake keeps resuming that handshake for the rest of its run and never asks again, so every later login at that site fails at once while the identity is present and the phone would serve. Seen on 2026-10-19 with Firefox and a site whose server asks for a certificate but admits a client without one. | H-7, H-5 |
| UCA-18 | Module | Dial the phone again | P | After a close with reason `pairing_revoked`, when the record on disk is not yet marked revoked, so the module re-dials a pairing the phone has forgotten and lists it as paired. | H-4 |
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
| UCA-42 | GUI | Show the phone as paired | P | After the phone forgot the computer, when the GUI holds no session and reads the record only at its own events, so the phone's hint (§4.6 item 3) and a revocation another process recorded reach the screen never; the person keeps a phone that is gone and pairs nothing new. As UCA-7, a shown state that is not the system's. | H-5 |

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

**The handshake the browser remembers (UCA-50).** Firefox starts, loads
the module, and the module's thread starts dialing the phone; the user
opens the login page within the same seconds. The server asks for a
certificate, the browser looks at the slot, finds a token without one
or no token, and completes the handshake without a certificate. The
server admits the connection and answers that no card was presented.
The user waits for the module, which holds the session a few seconds
later and offers the identity, and loads the page again: the browser
resumes the TLS session it already has with that server, in which no
certificate was ever asked for, and the server answers as before. Every
reload does the same, with the identity visible in the browser's own
list of certificates, until the browser is restarted. The requester's
process model says the identity should be offered only when it can be
served; the browser's process model says a server that once asked for
nothing more will not ask again. L-3 and H-5, and nothing on the
requester's side can clear the browser's memory.

### 10.5 Requirements for the design

| ID | Requirement | Closes |
| :--- | :--- | :--- |
| CC-18 | Whichever requester process holds the session fetches the certificate when the record lacks one, and writes it to the record; the module is not a reader only. The read is a safe operation and consumes no PIN try. | UCA-19 |
| CC-19 | The token's certificate is the one the pairing record caches, read from the card once when no program has cached it yet; a session asks the phone for nothing but its pings, and the phone's one task is the signature. The computer checks every signature against the cached certificate's public key before handing it to the browser, which it can do alone: a signature that does not verify is reported as a device error, never handed on, and the cached certificate is dropped so the next session reads the card again. Residual risk, accepted: a card other than the cached one that shares the access number signs one TLS challenge the browser never receives, and a renewed card costs one failed login before the record is refreshed; a card whose access number differs fails PACE at the signature, which the card does not count, and is reported the same way. | UCA-16 |
| CC-20 | The module's operation deadline is one named constant chosen below the browsers' and relying parties' handshake timeouts, sent to the phone as the operation lifetime, and a result that arrives after it is reconciled through the journal and never resent. | UCA-20, UCA-21 |
| CC-21 | The token follows the session, as §8.4 requires: it is withdrawn when the session closes or `card.status` reports no card, with no hold beyond an operation in flight (CC-28); the module dials again when the phone's record with a card-present hint is in sight, at a bounded interval, and not at all while no record is in sight. | UCA-27, UCA-22, UCA-30 |
| CC-22 | A close carrying `pairing_revoked` marks the record revoked before any new dial, so no dial follows the close and the slot goes with the pairing. | UCA-18 |
| CC-23 | The pairing lock is a session lock, not a store lock: it is released by the kernel when its holder exits, and record rewrites are atomic renames any process makes after re-reading the record, so the GUI forgets or revokes while the browser holds the session. The session holder re-reads the record at every ping of its own session thread, independent of the browser's calls; a record it finds revoked ends its session with the `pairing_revoked` close of §4.6 item 1, which the session holder is placed to deliver, and withdraws the token. The module's open never deletes records; sweeping is the GUI's. | UCA-23, UCA-29 |
| CC-24 | The GUI tells apart "the browser holds the phone session" from "the phone is away", from the lock result, and shows the phone as paired and in use rather than unreachable. | UCA-7 |
| CC-25 | The operation context names the computer and nothing it cannot know; the phone's PIN prompt shows that name and the operation kind. The module never fabricates an origin. | UCA-24 |
| CC-26 | The module dials when the phone's record carries a card-present hint (§4.5) and when a signature is asked (CC-46), and holds the session only while `card.status` reports a card, closing it when the card leaves and no operation is in flight (CC-28), so a browser that merely runs costs the phone nothing while no card lies on it; `C_Finalize` ends any session. | UCA-17 |
| CC-46 | The token's presence is the pairing record's, not the session's: the token stands on the cached certificate from the module's load, before and between sessions, and goes only when the pairing goes or the certificate proved not to be the card's (CC-19). A signature asked while no session is held waits for one within the browser's deadline and wakes the dial out of any pause at once; a request the browser has stopped waiting for is never sent to the card. The phone prompts for the card when none lies on it (section 12). Residual, accepted: with the phone unreachable the browser's handshake fails after the deadline, which the user sees as a failed login rather than a missing identity. | UCA-50 |
| CC-27 | `C_Login` succeeds only while the token is present and otherwise returns the token-absent error, and the token's objects are fixed when the token appears: a changed record withdraws the token and offers a new one, so a handle never outlives its object. | UCA-25, UCA-26 |
| CC-28 | A withdrawal that arrives while an operation is in flight waits for that operation's own result or deadline, which the browser receives as the answer to its `C_Sign`; the token is withdrawn after, and the operation is never resent. | UCA-28 |
| CC-29 | Every session under a pairing is opened under that pairing's lock, by the module, the GUI and the CLI alike; a process that cannot take the lock opens nothing and reports the holder. | UCA-31 |
| CC-40 | The GUI closes its own feedback loop while it holds no session: at an interval it re-reads the pairing record, which any process that held a session or dialed may have marked revoked, and it listens to the phone's announcements on the local network, which costs no connection; a revocation hint it verifies (§4.6 item 3) it records under the pairing's lock (CC-29), and while the lock is held it records nothing, since the holder is told in its session by the close of §4.6 item 1 and the hint stays announced for the GUI's next round after the lock is free. A phone that forgot the computer leaves the screen within one interval, and the GUI dials for none of this. | UCA-42 |

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
| UCA-32 | Preparation | Ask for PIN 1 | P | Again after an attempt that ended for a reason the PIN had no part in: no tap came, the field dropped, PACE lost the transport, or the attempt timed out; the entered PIN is discarded untested and the person is asked for it once more. | H-5 |
| UCA-33 | Dialog | End the attempt and offer Retry | P | When no card answered at all, so the person is told a card is missing while holding it against the phone, nothing says what to change, and Retry starts from the credentials step rather than from the tap. | H-5 |
| UCA-34 | Preparation | Time out the attempt | T | Too early against the person's handling of the card, so a slow tap becomes a failure whose Retry asks the PIN again. | H-5 |
| UCA-35 | Backend | Verify PIN 1 | P | Again with the held PIN after a field loss left the last command's outcome unknown, without reading the tries left first, so a wrong PIN the card did count is sent once more and the person never saw the count fall. | H-5 |
| UCA-36 | Preparation | Ask for PIN 1 | P | Again after a wrong PIN, without the tries left shown, so the person cannot judge whether to continue or stop. | H-5 |
| UCA-37 | Reader controller | Arm reader mode and wait for a tap | N | When the activity resumes after the OS dropped reader mode with it, so the dialog waits for a tap that cannot arrive and says only "hold the card". | H-5 |
| UCA-38 | Remote dialog | Show a computer's request and ask its PIN | P | While the person is inside the local preparation dialog, so two PIN prompts compete and a PIN typed for one lands in the other. | H-1, H-5 |
| UCA-39 | Custodian | Report the card present to a computer | P | From the last tag event when the field has since dropped, so the computer offers an identity the phone cannot serve. UCA-13 and CC-8 state this for priming; this is the live-tag case. | H-3 |
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
| CC-30 | The entered PIN lives for the whole preparation: an attempt that ends without an answer from the card (no tap, field lost, PACE transport lost) returns to waiting for the card with the PIN held, and the reader is re-armed. The held PIN is sent only to the card first seen in this preparation, by the serial read before the PIN command; another card asks again. PIN 1 is asked again when the card rejected it, when the tries left read after an unknown outcome are fewer than the last count (CC-33), when the person cancels, or when the dialog ends on its idle limit (CC-32). An entered PIN the card never verified is zeroed when the dialog ends; a verified PIN is retained as CC-39 says. | UCA-32 |
| CC-31 | A tap that did not happen is not a failure: the dialog keeps waiting with the hold-card text. A card that answered and is not a supported card is reported as not supported; "card not found" is shown for nothing. Retry, where it is offered, starts from the tap, not from the credentials. | UCA-33 |
| CC-32 | The attempt's timeout is measured from the last reader status change, not from the PIN entry, and counts only while the application is in the foreground with reader mode armed; its expiry ends the attempt and offers Retry with the PIN still held. The dialog itself ends, zeroing the PIN, when the person cancels or after an idle limit that counts in the background too; leaving the foreground alone ends nothing, so a person who answers a notification returns to the same attempt (CC-36). | UCA-34 |
| CC-33 | The tries left are read before the first PIN command of a preparation and before every PIN command that follows an unknown outcome; the card reports them without counting a try. A field loss during the PIN command is reported as contact lost during the PIN check. A count lower than the last one read means the PIN was counted wrong, so the held PIN is not sent, the count is shown and the PIN is asked again; with no count to compare, the held PIN is not sent either. | UCA-35 |
| CC-34 | Every PIN prompt shows the tries left whenever the card has told them. | UCA-36 |
| CC-35 | While a local preparation dialog is open, a computer's request waits behind it with a line saying a computer is waiting, and the request's own deadline is honoured; one PIN prompt is on screen at a time. | UCA-38 |
| CC-36 | The reader controller re-arms reader mode when the activity resumes and tells the dialog when reader mode is not active; the dialog says so instead of waiting. | UCA-37 |
| CC-37 | `card.status` claims the card present only on the strength of a command the card answered, never from a tag event alone; a command that ends without the card answering reports absence at once, as CC-16 says. A field that drops between commands is learned of at the next command, which is why the computer offers the identity only while a session reports a card (§8.4). | UCA-39 |
| CC-38 | A CAN the card rejected is asked again before the next PACE; the backend never repeats PACE with a CAN that failed. | UCA-40 |
| CC-39 | The retained PIN is bound to the card that verified it, by the identity read in the same session, and to its purpose: a different card asks again, and the end of the purpose zeroes it. | UCA-41 |

## 12. STPA of the iOS custodian's held card session

**Status:** prompted by an incident on 2026-10-18. A browser on a Unix
computer logged in through the paired iPhone to a site that needs one
signature, and failed or took tens of seconds on a site that needs
several signatures in one login. The phone's trace: the first
`browser_authenticate` completed in 4.7 s, of which PACE took 3.4 s; the
next request, 14 s later, found the slot without a valid card, ended the
near-field session and opened a new one within 10 ms, and `nfcd` refused
the slot (`Reader mode temporarily disabled`); the request was answered
as card unavailable, and the login failed. The request after that, some
20 s later, succeeded, and the pattern repeated. A measurement on
2026-10-19 with requests 3 s apart showed the other half: when the
field had not idled off and the channel was reused, the holder skipped
VERIFY on the strength of its own memory that PIN 1 was verified, the
card refused the signature command with security status not satisfied,
and the request was answered as ambiguous. A login that asks for two
signatures failed on the second one either way.

### 12.1 Scope

The iOS application as custodian serving a paired computer over the
near field: the system NFC slot it opens for a request, the card session
and PACE channel it prepares on that slot, the hold that keeps the
session for the next request, and the operations it runs. The contact
reader path of a desktop custodian is out of scope; its field does not
idle off.

### 12.2 Control structure

The holder is one controller with one process model, the hold: whether
a session is open, whether its channel is prepared, whether an operation
is running, when the session opened and when it last went idle. Its
actuators are the system slot (open, end), the card session (open, PACE,
command), and the sheet. Its sensors are the slot's state, the card's
answers, and its own clock. Around it, the operating system keeps its
own policy for the field and the reader, and says nothing of it: the
field idles off within seconds of the last exchange, a session has an
upper life, and ending a session starts a pause before the reader opens
again.

| Control action | Controller | Feedback present | Feedback absent |
| :--- | :--- | :--- | :--- |
| Open the slot | Holder | A slot, or the system's refusal with its code | How long the reader's pause after the last session lasts |
| Prepare the channel (PACE) | Holder | The card's answers | Whether the field will hold for the next command |
| Run the operation | Holder | The card's answer or its loss | Whether the field will hold through it |
| Skip VERIFY, trusting the remembered verification | Holder | None | Whether the card still holds the security status |
| Keep the session after an operation | Holder | Nothing until the next request looks at the slot | That the field idled off and the card lost its state |
| End the session | Holder | None | That a pause follows, during which no slot opens |
| Answer the request | Holder | None | How the requester's user reads "card unavailable" |

### 12.3 Unsafe control actions

| ID | Controller | Control action | Type | Context | Hazard |
| :--- | :--- | :--- | :--- | :--- | :--- |
| UCA-43 | Holder | Keep the session after an operation | P | For a hold measured in tens of seconds, when the field idles off within seconds of the last exchange, so the hold's model says a prepared channel and a present card while the card has lost its state; the next request pays an end and a fresh open, and meets the reader's pause. | H-3 |
| UCA-44 | Holder | Open the slot | T | Within the reader's pause after the session it has just ended, so the system refuses the slot and the request is refused with the card lying on the phone. | H-3 |
| UCA-45 | Holder | Answer the request | P | As card unavailable for a refusal the holder caused (UCA-44), so the requester's user is told to present a card that is present, and nothing says that waiting would have served. | H-5 |
| UCA-46 | Holder | End the session | N | Not when the card leaves the field during the hold's idle time, but only when the next request looks at the slot, so the reader's pause runs inside that request's deadline instead of during the idle time. | H-3 |
| UCA-51 | Custodian | Accept a second computer's session | N | Not while one computer's session is held, although the two are different pairings: the second computer's dial is closed before its preamble is read, its requester retries behind its pauses and shows its user "connected" or nothing, and whichever computer dialed last cannot log in for as long as the other holds its session, which a browser slot holds for as long as the browser runs. Seen on 2026-10-19 with a Mac and a FreeBSD computer paired with one phone. The specification limits concurrent pre-authentication handshakes to one, not established sessions. | H-7, H-5 |
| UCA-47 | Holder | Skip VERIFY, trusting the remembered verification | P | For the second operation on a held channel, when the card does not keep PIN 1's security status from one signature to the next, so the signature command is refused and the request is answered as ambiguous: the requester cannot tell a refused command from a lost one, and nothing was signed. | H-3, H-5 |

### 12.4 Loss scenarios

Measured on 2026-10-19 on an iPhone 15 Pro Max: left idle, the slot's
state went from valid card to missing 6 s to 8 s after the last command;
kept up by one SELECT every 2 s, the slot still went away 11 s to 22 s
after it was given, once in the middle of a signature command; and the
system refused a new slot for 8 s to 11 s after each ending. With the
keep-alive and the retry, six of seven logins 0 s to 20 s apart
completed, the ones that met the pause in 16 s to 17 s; without them,
two of six. The slot's life is the platform's, and a request that meets
its end pays the pause: a residual the holder cannot remove, only keep
out of the request's path where the slot lets it.

**The second signature of a login (UCA-43, UCA-44, UCA-45, UCA-46).**
A login to a site that fetches several resources under client
authentication, or renegotiates, asks the browser's slot for a signature
more than once within some seconds. The first request opens the slot,
runs PACE and signs, and the holder keeps the session for 25 s so that
the next request reuses the channel. The process model was built for a
contact reader, where a card in the reader keeps its state until it is
pulled; on the near field the operating system idles the field off
within seconds, and with it the card's PACE state. The hold's only
feedback is the slot's state, and the holder reads it only when a
request arrives. The second request arrives, finds the slot without a
valid card, ends the session and opens a new one at once; the system's
pause after a session is still running, the slot is refused, and the
holder answers card unavailable. The browser's handshake fails, the
user sees the login fail or hang, and holds the card more firmly. The
third request, after the pause, succeeds, which is why one-signature
sites work and the failure looks like slowness. L-3.

**The remembered PIN (UCA-47).** When the second request arrives while
the field still holds, the channel is reused as designed, and the
holder's credential state says PIN 1 was verified in this session. The
card's security status does not survive the first signature, and the
holder has no feedback on it: the first sign it gets is the refusal of
the signature command, which the executor reports as ambiguous, the
word for a command whose outcome is unknown. The requester tells its
user the operation ended ambiguously; nothing says that a fresh VERIFY
would have served. L-3.

**Two computers, one phone (UCA-51).** The person's Mac and laptop are
both paired with the phone; the laptop's browser slot holds a session
from the moment the browser starts, as section 10 designed it. The Mac
asks for a login; its requester dials, the phone closes the connection
before reading the preamble, and the requester, which cannot tell a
refusal from a lost packet, pauses and dials again. The Mac shows the
phone connected and no identity; the laptop, idle, holds the phone. When
the laptop's browser is closed, the Mac logs in. The person, who paired
both on purpose, has no model in which pairing one computer locks out
another, and nothing on either screen names the other computer. L-3,
H-5.

### 12.5 Requirements

| ID | Requirement | Closes |
| :--- | :--- | :--- |
| CC-41 | The hold's process model follows the slot: while the session is idle the holder watches the slot's state, and a slot that no longer holds a valid card ends the session at once, so that the reader's pause after a session runs during the idle time and not inside the next request. The system takes an idle slot away some six seconds after the last exchange, so a holder that keeps a session sends one harmless command on the channel every few seconds for as long as it holds it, and a request that arrives while that command is in flight waits for the card's answer. | UCA-43, UCA-46 |
| CC-42 | Opening the slot retries through the reader's pause, for a bounded time within the request's deadline, before the request is refused; the refusal the system gives for the pause is known by its code and never answered as card unavailable while a retry remains. | UCA-44, UCA-45 |
| CC-43 | The holder keeps no belief about the card's security status between operations: PIN 1 is verified for every signature, after the tries-left probe CC-33 describes. A command the card refused is reported as refused, never as ambiguous. | UCA-47 |
| CC-47 | The custodian holds one session per pairing, not one session: a second computer's dial is read, routed by its preamble to its own pairing, and served; the card is one and operations from all sessions join one queue at the holder (section 12.2). A dial that names a pairing whose session is already held replaces that session, so a requester that restarts does not wait for its own stale session to expire. A refusal the custodian does give is a close with a reason the requester can show, never a silent drop. | UCA-51 |

## 13. STPA of discovery over a wireless network

**Status:** prompted by a measurement on 2026-10-19, made while
reproducing the incident of section 12. A FreeBSD laptop on Wi-Fi and
an iPhone on the same network: of nine identical mDNS queries the
laptop sent to the group, four were answered; the loss came in bursts
long enough that the requester reported "no phone found on the local
network" six times in a row over four minutes, while the phone
advertised and Avahi on the same laptop listed it. The same query sent
to the phone's own address was answered every time.

### 13.1 Scope

The requester's search for the phone of one stored pairing over the
local network: the query it sends, the answers it reads, the addresses
it keeps, and the word it gives its user when nothing answers. The
pairing ceremony, which searches for a phone it does not know yet, is
in scope only as the case that has no address to ask.

### 13.2 Control structure

Finding the phone is one control action of the requester (section 4.5):
a multicast query, answered by unicast. The requester's process model
holds that a query reaches every phone on the link, so that no answer
within the window means no phone. A wireless network gives no feedback
on whether a multicast frame was delivered; a phone in power save
receives multicast only at intervals, and an access point may not
forward a client's multicast at all.

| Control action | Controller | Feedback present | Feedback absent |
| :--- | :--- | :--- | :--- |
| Ask the network for the phone | Requester | Answers | Whether the query reached the phone |
| Report no phone | Requester | None | That the phone was reachable by its address |

### 13.3 Unsafe control actions

| ID | Controller | Control action | Type | Context | Hazard |
| :--- | :--- | :--- | :--- | :--- | :--- |
| UCA-48 | Requester | Ask the network for the phone | P | By multicast alone, for a pairing whose phone answered from a known address before, so a network that drops the multicast hides a phone that would answer at its address. | H-3, H-7 |
| UCA-49 | Requester | Report no phone | P | After a window in which no query reached the phone, so the user is told the phone is absent and looks at the phone, which is present and serving. | H-5 |

### 13.4 Loss scenarios

**The phone that was there (UCA-48, UCA-49).** The computer joins the
phone's wireless network and the requester asks for the phone the way
it always has, by a query to the multicast group. A wireless link
acknowledges and retransmits unicast frames; multicast frames go out
once, at the base rate, and a phone in power save receives them only at
its listen interval, when the access point forwards them at all. The
query is lost; the requester's model of the network says a lost query
means no phone, so after its window it reports none. The user looks at
the phone, which is on, paired and advertising, and can make nothing of
the report. Each retry sends the same query the same way, and the loss
comes in bursts longer than the window. The login does not happen,
L-3, and the user is shown a state that is not the system's, H-5. The
address the phone answered from last time was in the pairing's own
record all along, and a query sent there would have been answered.

### 13.5 Requirements

| ID | Requirement | Closes |
| :--- | :--- | :--- |
| CC-44 | The requester remembers the addresses a paired phone answered from, beside the pairing record, and every browse for that pairing sends the query to them directly as well as to the group. The addresses are a cache: losing them costs a slower discovery, never a pairing, and a pairing's removal drops them. The pairing ceremony, which knows no address, browses the group alone. | UCA-48 |
| CC-45 | "No phone found" is reported only after the remembered addresses were asked directly and did not answer. | UCA-49 |

## 14. CAST: a signature refused as a mismatch, 2026-10-19

### 14.1 What happened

A browser login through the phone at kortti.tunnistautuminen.suomi.fi
from a Unix requester failed every time, while the same login at a site
negotiating TLS 1.3 succeeded. The phone's trace showed the card
signing and the result sent; the browser showed a handshake failure
two seconds later, and the phone's trace showed a new session with a
certificate read right after. The requester's local check of the
signature (CC-19) had refused it as a mismatch, dropped the cached
certificate, and closed the session. The server had asked for
ECDSA with SHA-384 over a P-256 key, which TLS 1.2 allows; the check
demanded a P-384 key for a SHA-384 digest.

### 14.2 The control structure at the time

Three controllers handled one value, each with its own model of what
it meant:

- NSS, in the browser, asked the module for `CKM_ECDSA` over 48 bytes.
  The mechanism names no hash; the bytes are a digest and nothing says
  of what.
- The module's token named the request `EcdsaSha384` from the digest's
  length: a hash inferred, not told, and the name then carried it as a
  fact.
- The requester's verifier took `EcdsaSha384Raw` to mean the document
  signature profile of that name, in which the hash and the curve are
  one choice, and required the key's curve to be P-384.

The card signed the 48 bytes under its P-256 key as ECDSA says, taking
the digest's leftmost 256 bits. The signature was right; the model of
it was not.

### 14.3 Why the control structure allowed it

- **No refinement in the type.** One enum value stood for "ECDSA with
  SHA-384" in the sense of a fixed profile and for "ECDSA over a 48-byte
  digest" in the sense of a TLS request. The type carried a curve it
  had no right to carry. A digest's length is the hash's; a coordinate's
  width is the key's; a type that holds both as one name invites the
  reader to assume they agree.
- **A fact inferred and then asserted.** The token turned a length into
  a hash name because the request type demanded a hash. The inference
  was harmless until a consumer read the name as more than a length.
- **A check added without its vectors.** The local verification was
  added for the mismatch case (CC-19) with a test that a certificate
  parsing as nothing verifies nothing. No test ran a real signature for
  each pairing of curve and hash the requester would meet; the one
  field test, a TLS 1.3 site, pairs P-256 with SHA-256 and passed.
- **The failure wore another failure's clothes.** A refused signature
  was reported to the browser as ambiguous and to the record as a
  certificate that was not the card's, so the first symptoms, a dropped
  cache and a fresh certificate read, pointed at the card and the
  phone, not at the verifier.

### 14.4 Recommendations

| ID | Requirement | Closes |
| :--- | :--- | :--- |
| CC-48 | A signature request names the hash of its digest and nothing about the key; the key's curve is read from the key. No type in the request path carries a hash and a curve as one value. Where the hash is not told, as under `CKM_ECDSA`, the request carries the digest's length as a length, and the verifier takes the leftmost bits as the curve's order allows, as the card does. | 14.3 |
| CC-49 | Every local check of a signature ships with a vector for each pairing of curve and hash a browser can ask for (P-256 and P-384 with SHA-256, SHA-384 and SHA-512 at least), and a refusal by the check is reported as the check's refusal, distinguishable from a lost signature and from a card that is not the cached one. | 14.3 |

## 15. Open questions

- Which of CC-1 to CC-6 are worth a protocol version, and which are better
  served by application behaviour over the existing messages?
- Should discovery carry any authenticated liveness at all, or should the
  requester hold a long-lived session instead of inferring presence?
- How much of the one-line failure text in 6.5 is a deliberate oracle
  defence, and how much is an omission?

## 16. STPA of a browser login over Bluetooth alone

**Status:** prospective, reviewed by the owner on 2026-10-20. This
section analyses a
design before it is built: a browser on a Windows computer logs in to
kortti.tunnistautuminen.suomi.fi with the card of a paired iPhone,
while the iPhone has Wi-Fi and cellular data turned off, so the only
bearer is BLE (`"fi.refineid.rapp.ble"`, RAPP v26.10.18 §5). On the
first run the card sits in a contact reader wired to the iPhone, so the
near-field behaviour of section 12 is out of the path. The Windows
computer's own controllers, the browser, CNG, the key storage provider
and the agent that holds the session, are analysed in the Windows
repository's platform STPA (`docs/stpa-windows-ble-requester.md`),
which refines this section and keeps its identifiers.

### 16.1 What the bearer changes

Sections 4 to 13 assume a network on which discovery records, hints
and announcements reach the requester. Over BLE alone that layer is
gone, and four feedback paths change:

- **Discovery is the advertisement.** It carries the RAPP Service UUID
  and nothing else (§4.1). No discovery, withdrawal or revocation hint
  travels over BLE (§4.5 item 5), so a requester cannot tell its own
  phone from any other phone advertising RAPP without connecting and
  routing a preamble (§2.2.1), and it learns of withdrawal and
  revocation only on an open session.
- **The advertisement depends on the phone's foreground.** For an
  application advertising in the background, iOS ignores the local
  name and places the service UUIDs in an overflow area that "can be
  discovered only by an iOS device that is explicitly scanning for
  them" (Apple, Core Bluetooth Programming Guide, background processing
  for iOS apps). A Windows computer therefore sees nothing of a phone
  whose RefineID application is in the background or whose screen is
  locked, even though the application could serve.
- **A held link is the only presence left.** Under the
  `bluetooth-peripheral` background mode the system wakes a
  backgrounded application to process reads, writes and subscriptions
  from a connected central (same source), so a session on a link
  established in the foreground can keep serving; that the link itself
  survives the phone's lock is to be observed on the first run's
  hardware, not assumed. Once the link drops, the phone can be found
  again only after its user brings the application to the foreground.
- **The link has a size the requester does not choose alone.** Both
  ends require an ATT MTU of at least 512 (§5.2). The value is
  negotiated by the two operating systems, and each application learns
  it only after the connection is up.

| Control action | Controller | Feedback present | Feedback absent |
| :--- | :--- | :--- | :--- |
| Scan for RAPP advertisers | Requester | Advertisements with the Service UUID and their RSSI | Which advertiser is this pairing's phone; whether a phone that is not seen is backgrounded or gone |
| Connect and route a session preamble | Requester | Connection, negotiated MTU, routing accepted or the link closed (§2.2.1) | Why a link closed before Noise_KK: another person's phone, a revoked pairing, or a replayed nonce look the same |
| Hold the link between operations | Requester | Liveness on the session (§7.1), `card.status` (§8.4) | Whether the phone could be found again if the link dropped now |
| Release the link | Requester | None needed | That the phone may not be discoverable again until its user acts |
| Advertise | Custodian | None from the requester | Whether the advertisement is readable by a non-Apple scanner |
| Ask the operating system to bond | Requester | The OS pairing dialog | Nothing RAPP needs: the link is untrusted (§13.2) |

### 16.2 Unsafe control actions

| ID | Controller | Control action | Type | Context | Hazard |
| :--- | :--- | :--- | :--- | :--- | :--- |
| UCA-52 | Requester | Release the held BLE link | P | While the pairing exists and nothing ended it but idleness, when the phone's application is in the background, so the next login finds no advertisement and the phone cannot be reached until its user opens the application. | H-7, H-5 |
| UCA-53 | Requester | Report that the phone is not found | P | When no advertisement is seen because the phone's application is in the background or the phone is locked, so the user is told the phone is absent while it lies on the desk, and nothing names the remedy. | H-5 |
| UCA-54 | Requester | Close the link for a small MTU | P | Without naming the cause, so a negotiation below 512 on one computer reads as "phone not reachable" (UCA-7) and nothing says that this computer's Bluetooth stack is the limit. | H-5 |
| UCA-55 | Requester | Connect to an advertiser and route a preamble | P | Repeatedly to the same strangers' phones in a crowded room, in the order the scan returns them, so a login waits behind a sequence of refused routings and a phone's own requester is starved of the single-flight slot (§3.3 item 8) of each phone it dials. | H-7 |
| UCA-56 | Requester | Ask the operating system to bond with the phone | P | In any context, because RAPP authenticates on the application layer alone (§13.2): the bond adds an operating-system pairing dialog the user cannot relate to the RAPP pairing, stores a link key RAPP never relies on, and lists the phone by its device name in the computer's Bluetooth settings. | H-5, H-6 |
| UCA-57 | Custodian | Execute `browser_authenticate` without a prompt | P | Under a stored PIN 1, as section 3 of the usability consensus intends, when a program on the computer other than the browser the user is using drives the key storage provider; the phone cannot tell a login the user clicked from one a program started, and over BLE the phone may be face down in a pocket. | H-1 |
| UCA-58 | Requester | Name a relying party in the operation context | P | When the key storage provider cannot know it: CNG tells a provider nothing of the site, so an origin built from a process name or an environment variable is shown on the phone as if it were the site. As UCA-24 for the Unix slot. | H-1, H-5 |
| UCA-59 | Custodian | Admit a session on the BLE peripheral | N | When the routing preamble's purpose is `"session"`, because the peripheral admits only pairing; every login fails after a successful pairing, and the requester shows the phone as paired. | H-7, H-5 |

### 16.3 Loss scenarios

**The phone in the pocket (UCA-52, UCA-53).** The user pairs the
computer with the phone, both in the foreground, and logs in. Later the
phone is locked and put away. The requester, built on the stream
transport's model, closes the idle session after a while to save the
phone's battery, as CC-26 asks for a stream. Over the stream the phone's
discovery record would bring it back within seconds; over BLE the
locked phone advertises nothing a Windows computer can read. The next
click on "log in with identity card" finds no phone, the login fails,
and the requester says "phone not found" while the phone lies within
reach, paired and able to serve. L-3, H-5. The requester's process
model held that a phone not seen is a phone not there; on this bearer
that is false whenever the phone is not in the user's hand.

**The silent login (UCA-57, UCA-58).** PIN 1 is stored on the phone,
the card is in the reader on the phone, and the usability consensus
makes a browser login unattended: the click on the computer is the
intent. The key storage provider on Windows runs inside whichever
program asks CNG to sign; the agent that holds the session serves every
program of the user's that reaches it. A program that is not the
browser asks for a signature with the card's authentication key; the
phone signs without a prompt and shows the request under whatever
origin the computer sent. The private key never left the card, but an
authentication was made that the cardholder did not intend. L-1. The
consensus accepts this for a card that lies in a reader or on a phone
(section 2.1 of that document: code on the host can use a connected
card in milliseconds); BLE changes only that the phone need not be in
sight. What it must not add is a false origin on the phone's screen,
which would turn an accepted residual risk into a misleading one.

**The pairing that cannot log in (UCA-59).** The pairing ceremony over
BLE completes and both ends store the pairing. The first operational
connection sends a `"session"` preamble; the custodian's peripheral
admits only pairing and refuses the preamble; an iOS peripheral has no
call that ends a central's connection, so it stops serving it and the
requester's own deadline ends the link. The requester, which cannot
tell this refusal from a stranger's phone or a revoked pairing, reports
the phone unreachable. L-3, H-5.

**The small link (UCA-54).** A Windows computer's Bluetooth stack
negotiates an ATT MTU below 512 with the phone. The custodian learns
the capacity when the requester subscribes to the Channel
Characteristic, refuses it, and stops serving the connection, which it
cannot end; the requester, which never read the value it negotiated,
waits out its deadline and reports nothing more specific than a lost
connection. The user retries, moves the phone closer, restarts both,
and nothing changes, because nothing in the radio path is at fault.
L-3, H-5.

**The crowded room (UCA-55).** In a lecture hall a dozen phones
advertise the RAPP Service UUID, and the computer cannot tell its own
phone from the others without routing a preamble to each (§2.2.1). The
phones rotate their resolvable private addresses (§4.1), and RAPP
forbids a link-layer bond that would let the computer resolve them
(UCA-56), so the address it dialed last time is gone. The computer
dials the advertisers in the order the scan returned them; each refuses
the routing, and each of those phones' own computers finds the single
pre-authentication slot (§3.3 item 8) taken while it is refused. The
login waits behind the queue and may miss the browser's deadline. L-3,
H-7.

**The bond nobody asked for (UCA-56).** The requester's first GATT
access asks for an encrypted link, or calls the operating system's
pairing. Windows shows its own pairing dialog with a numeric
comparison; the user, who has just typed the RAPP code, cannot tell
which of the two pairings this is and accepts or cancels at random. If
accepted, Windows stores a link key and an identity resolving key that
RAPP never relies on, and lists the phone by its personal device name in
the computer's Bluetooth settings, where any user of the computer can
read it. H-5, H-6.

### 16.4 Requirements

| ID | Requirement | Closes |
| :--- | :--- | :--- |
| CC-50 | Over BLE the requester holds the link and its session for as long as the pairing is usable and the user has not turned the remote reader off, and re-establishes it as soon as the phone's advertisement is seen; it never releases a BLE session for idleness. The cost is the phone's radio, which the custodian may end by withdrawal (§4.5) or by its user. CC-26's release on idleness applies to the stream transport, where discovery can find the phone again. | UCA-52 |
| CC-51 | When no session is held and no advertisement is seen, the requester tells its user that the phone must have RefineID open to be found over Bluetooth, and never that the phone is absent. | UCA-53 |
| CC-52 | The requester reads the negotiated ATT MTU as soon as the connection is up and before its first write. Below 512, it closes the link itself and names the cause with the value, distinct from every other close. The custodian reads the capacity when the requester subscribes, which precedes the requester's first frame, refuses a capacity below the minimum before any authentication, and sends nothing (§10.1 item 1); on iOS it cannot end the connection, so the requester's own reading is the feedback that matters. | UCA-54 |
| CC-53 | The requester remembers, per pairing, the advertiser address that last routed its preamble, and dials it first while that address is still advertised; the phone rotates its resolvable private address, and without a bond (CC-54) the computer cannot follow it, so the memory lasts until the address changes. Other advertisers are dialed in descending filtered RSSI above the proximity gate (§4.4), each at most once per scan window, and a refused routing is not retried within that window. | UCA-55 |
| CC-54 | The requester never asks the operating system to bond or pair with the phone at the link layer, and the custodian's characteristics require no link-layer encryption, so no operating-system pairing dialog can appear. | UCA-56 |
| CC-55 | The operation context names the computer and the program that asked, and never a relying party it cannot know; the phone shows the computer's name and the program, labelled as such, never as a site. As CC-25 for the Unix slot. | UCA-58 |
| CC-56 | Residual, accepted by the usability consensus (section 3): with PIN 1 stored, a program on the computer that reaches the requester can make the card sign for authentication without a prompt. The requester narrows who can reach it to the user's own processes (Windows platform STPA), shows every authentication it relays in its own notification, and the phone records each one in its history with the computer and program that asked. | UCA-57 |
| CC-57 | The custodian's BLE peripheral admits `"session"` preambles and routes them as on the stream transport (§2.2.1), with one session per pairing (CC-47). | UCA-59 |

## 17. STPA of serving many computers from one card

### 17.1 Scope

A person pairs a card's phone with the computers they use -- a desktop,
a laptop, a work machine -- and expects the card to work from any of
them. The phone is the card's server; the computers are its clients.
One phone serves many computers; each computer is bound to one phone. A
computer paired to several phones is complexity we do not need and do
not build. A computer runs more than one program that needs the card: on
macOS the app that shows the identity and the extension that signs are
separate processes. The card is one, and physical: the security boundary
is that the holder takes it away. Within that, a paired computer is
trusted; the protocol secures the channel and the consent, not an
arbitrary quota of who may ask. This section covers the custodian
serving several such clients over the stream transport. BLE, where a
computer is a single central whose programs share one GATT link, is out
of scope here; CC-57 stands.

### 17.2 The governing principle

Never assume; always feed back. Every fact one controller needs about
another -- the card is present, the card changed, the operation is
queued, the prompt is shown, the result arrived -- is communicated, not
inferred. Where a controller cannot know, it asks. Every state that is
distinct in the implementation is distinct on the wire and to the user;
none is collapsed, and none is hidden, because a vague state neither
lets a human act nor lets an engineer debug. The incidents below are all
one failure of this principle: a controller acted on a guess.

### 17.3 Control structure

The earlier model had one serving slot: the custodian served a single
requester, and a second dialer was refused. Several computers, and the
two programs of one computer, then raced for the slot, and the loser
inferred from a dropped connection whether the phone, or the card, was
there at all.

The model here is one authenticated control loop per client session. The
custodian is the controller of the card; each client holds its own
session and its own feedback edge. The card is the single controlled
process behind them, and operations on it are serialized by a queue and
by the one consent prompt the holder answers.

| Control action | Feedback that must be present |
| :--- | :--- |
| Client opens a session (any number per pairing) | Session established, and the card's presence and fingerprint at once (`card.status`, fingerprint proposed in §17.7) |
| Card present / removed / replaced on the phone | `card.status` on **every** open session on change, carrying the authentication certificate's SHA-256 fingerprint |
| Client requests an operation while the card is busy | That it is queued, not silence |
| Holder is shown the consent prompt | `consent_shown` to the requesting client |
| Operation completes, is rejected, or expires | The terminal result to the client |

### 17.4 Unsafe control actions

- **UCA-60** The custodian serves one client and drops a competing
  dialer with no feedback, so the loser cannot tell "busy" from "gone"
  and re-dials at once; several clients then thrash and none is served.
- **UCA-61** The custodian reports the card gone only on the session it
  is serving, so other clients keep offering a card that has left.
- **UCA-62** A requester keeps offering a cached certificate after its
  session has closed, against the offering rule (§8.4 item 2), so a
  consumer that re-queries is handed an identity the phone is no longer
  serving.
- **UCA-63** `card.status` carries presence as one bit and no identity,
  so a requester cannot tell a replaced card from the same card and
  offers the old card's certificate for the new card in the reader.
- **UCA-64** A requester, and its user, is shown one state -- "phone
  connected" -- for many distinct situations (card ready, card gone,
  phone asleep, busy serving another, waiting on consent), so the human
  cannot act and the behaviour cannot be diagnosed.
- **UCA-65** A contact-reader card still in its slot is reported absent
  because one exchange glitched, so the identity is withdrawn -- on the
  wire to every client and on the phone's own screen -- in the middle of
  a signature.

### 17.5 Loss scenarios (observed 2026-10-21)

All five were seen in one session serving a FreeBSD box, a Mac and a
Windows machine from one iPhone with a reader card.

- **The locked-out computer (UCA-60).** The Mac's session was refused
  every two seconds while the phone served another peer; its log was an
  unbroken run of `transportClosed`, and it showed "iPhone yhdistetty"
  with no identity. Freeing the phone let it in at once -- proof it was
  contention, not a dead phone. L-3.
- **The stale certificate across a swap (UCA-61, UCA-63).** A login
  failed with a non-revoked card after the card was changed on the
  phone: the Mac offered the previous card's certificate, the extension
  signed with the new card's key, and the signatures did not match the
  offered certificate. L-1 for the user, who cannot log in.
- **The offer that outlived its session (UCA-62).** Grace timers and a
  cached certificate kept the Mac's offer published after its session
  dropped, so Safari was handed an identity with no serving session
  behind it.
- **The collapsed state (UCA-64).** "iPhone yhdistetty," without even a
  trailing stop, stood for every way the card was unavailable; the user
  had nothing to act on. L-3.
- **The identity that vanished at PIN entry (UCA-65).** On the iPhone's
  own screen, entering PIN 1 for a remote signature blanked the holder's
  identity, because a glitched exchange while the card sat in the reader
  was read as the card being gone.

### 17.6 Controller constraints

| ID | Constraint | Closes |
| :--- | :--- | :--- |
| CC-58 | The custodian serves every paired client concurrently: one authenticated session per client connection, as many under a pairing as the programs that need the card. This supersedes CC-47's "one session per pairing" (never adopted -- UCA-60 is the single slot still in force) and keeps CC-47's clause that a refusal is a close with a reason, never a silent drop. A paired client is trusted within the channel; there is no quota on sessions or operations. Stream transport; CC-57 (BLE) stands. | UCA-60 |
| CC-59 | The card serves one whole request at a time: a request's card commands run start to finish before another request's begin, and commands from different sessions are never interleaved. Concurrent requests queue first-come-first-served, serialized by the one consent prompt, each bounded by a deadline that runs through suspension (CC-6). A waiting client is told it is queued (no position), never left silent. Restates CC-47's single-queue clause. | UCA-60 |
| CC-60 | `card.status` always carries the SHA-256 fingerprint of the card's authentication certificate (the X.509 certificate fingerprint), zeroed when no card is present so the message is one fixed size. A requester caches the certificate with its fingerprint, reuses it while the fingerprint matches, and re-reads (`read_certificate`) when it changes. | UCA-63 |
| CC-61 | Card presence and every change to it are sent on **every** open session, not only the one being served, so a removed or replaced card reaches all clients at once; `card.status` is sent on change, not polled, with the liveness heartbeat standing in between. A requester whose consumer re-queries (CryptoTokenKit, a browser chooser) offers the card only while a session is open and withdraws the instant the session closes, `card.status` reports absence, or the fingerprint changes. The PKCS#11 slot keeps CC-46: its token stands on the cached certificate between sessions, because Firefox never re-asks once handed none. | UCA-61, UCA-62 |
| CC-62 | Every state distinct in the implementation is distinct on the wire and to the user: card ready, waiting on consent, queued, no card, phone unreachable. "Busy" and "gone" are never the same state, and no state is collapsed or hidden. Amends CC-7. | UCA-64 |
| CC-63 | Presence is whether the custodian can serve the card on request, not whether the card is electrically connected at that instant, applied the same way to `card.status` on every session and to the custodian's own on-device display. A reader card is present while it is in the reader; a near-field card is present while it is primed and the holder can present it on request, the card summoned per operation. A glitched exchange, or a tap that did not complete, is a failed operation, not absence -- the identity stays. The card is absent only when the holder can no longer serve it: the reader card removed, or the near-field prime cleared. This supersedes section 8.4 item 1's marking the card absent on an unanswered operation. | UCA-65 |

### 17.7 Wire changes these require

For the owner to stamp as the next RAPP version, over the stream
transport:

- **Concurrent sessions.** The custodian accepts and keeps a session per
  client connection; the single-session gate is removed. Pair keys are
  unchanged; each session is its own Noise_KK handshake. A stale session
  left by a crashed program ends by liveness (§7.1), not by a new dial
  replacing "the" session, of which there is now no single one.
- **Fingerprint in `card.status`.** Add `cert_fingerprint` (32-byte
  SHA-256 of the DER authentication certificate) to the `card.status`
  payload, always present, zeroed when `card_present` is false.
- **`queued` feedback.** An `operation.progress` value `queued`, for a
  request waiting on the card, alongside the existing `consent_shown`. No
  position.

No new identifiers are invented: the fingerprint is the standard X.509
certificate fingerprint, the session is the client's identity, and an
operation lives inside its session.

## 18. Constraints at 26.10.21

The specification stamped 26.10.21 adopts CC-1, CC-2 (as the `pairing_revoked` close delivered in session or on the next one, in both directions), CC-4, CC-6 and CC-58 to CC-63. Three constraints and the hazards behind them are closed differently:

- **CC-5 is withdrawn.** There are no acknowledgements: an operation lives inside its session and is forgotten when the session ends (specification §8.1). A requester that lacks a result starts a new operation.
- **CC-47 is superseded** by CC-58, as section 17.6 says.
- **CC-20's journal clause is withdrawn.** A result that arrives after the module's deadline ends with its session; the module starts a new operation (specification §8.1 item 3).
- **CC-26 is superseded** by specification §8.3 and CC-61: a requester keeps a session open to every paired custodian whose discovery hint is in sight, card or no card, and no record carries a card-present hint.
- **CC-40's hint path is withdrawn.** No record carries a revocation hint. A phone that forgot the computer tells it as the first message of the next session (specification §4.6 item 2), and the requester dials whenever the phone's discovery hint is in sight (§8.3), so the GUI learns of the forget on that session.
- **The at-most-once machinery behind UCA-2 and UCA-21 is withdrawn.** Nothing RAPP does mutates the card: a repeated signature or read changes nothing on it, and a PIN is typed by the holder on the phone, bounded by the retry floor (specification §10.2), so a retransmitted request cannot spend a try. The write-ahead journal, the durable tombstones and the reconciliation messages that guarded against a repeated card command are gone; the hazard they addressed does not exist for these operations.

The offer in UCA-12 now lasts 5 minutes, and a wrong PIN is re-prompted on the phone, so the retries-remaining count of section 6 never reaches the requester.

## 19. Constraints at 26.10.22

The specification stamped 26.10.22 chooses software that works with real browsers and real NFC over a stricter reading, and keeps the state eventually consistent: a card that is really gone leaves every client within a bounded time.

| ID | Constraint | UCA |
| :--- | :--- | :--- |
| CC-64 | A requester offers an identity on a certificate the custodian confirmed by fingerprint on a session, before and between sessions, on every consumer alike. A request that arrives with no session open wakes the dial and waits within the consumer's own deadline. The offer goes when the custodian has been out of reach, or has reported absence, for 120 seconds with no later report of the card present; at once when the pairing is forgotten or revoked; and at once when a session confirms a different card. This supersedes CC-46, CC-61's instant withdrawal on a closed session or an absence report, and the Mac's session-loss grace. Residual, accepted: for up to 120 seconds a consumer can be offered an identity whose phone has left, and a login then fails after the consumer's deadline. | UCA-50, UCA-62 |
| CC-65 | Presence is the card the custodian holds: a reader card from insertion until removal, and an NFC card from the holder adding it to the custodian until the holder removes it there. An operation the card did not answer ends with `card_error` and never changes presence; the next operation asks the holder to present the card again. This narrows CC-63 and supersedes CC-8 and CC-37 where they inferred absence from a missing answer. | UCA-13, UCA-39, UCA-65 |
| CC-66 | PIN 1 is asked once and held only in the custodian's memory, never in storage; it ends when the card is removed, the card rejects it, the custodian's process ends or the device restarts. While it is held a browser authentication runs with no screen. PIN 2 is asked for every signature or batch and kept no longer. The PIN prompt is the holder's authorization; there is no separate consent view. Residual, accepted: while PIN 1 is held, a paired computer can obtain authentication signatures with no prompt, with a tap per operation for an NFC card and none for a card left in the reader. | UCA-1, UCA-36 |

`inspect_card` no longer carries `supported_profiles`; nothing consumed the list, so no control action changes.

## 20. Serving over Bluetooth in the background

### 20.1 Scope

iOS suspends a custodian app soon after it leaves the screen; its stream
listener stops, and a paired computer cannot reach the phone. The
custodian therefore also serves the BLE transport profile with the
pairings it already has (a stored pairing serves any registered
transport, specification §2.1 phase 4), as a GATT peripheral that iOS
keeps serving and relaunches for Bluetooth events. A Mac requester dials
the stream while the phone is on the local network and Bluetooth
otherwise; its programs share one GATT link to the phone, so the
extension that signs hands its operation to the app that holds the
session. Losses and hazards are this record's: L-1, L-3; H-1, H-3, H-5,
H-7.

### 20.2 Control structure

```
Mac: token extension --handoff--> Mac app (held session, stream | BLE) <=RAPP=> phone relay
Phone relay: stream listener + GATT server --one session--> coordinator
Phone OS: suspends the app; wakes it for BLE events; relaunches it
Phone relay --notification--> cardholder --tap--> app in front --> NFC
```

New control actions: the custodian admits a session on a second
transport and displaces the open one; it unpublishes its stream listener
in the background; it summons the holder; the requester picks a
transport per dial; the extension hands an operation to the app. New
feedback: a BLE link routed, refused or closed with its cause, and
`waiting_for_card` while the holder is summoned.

### 20.3 Unsafe control actions

| ID | Controller | Control action | Type | Context | Hazard |
| :--- | :--- | :--- | :--- | :--- | :--- |
| UCA-66 | Custodian | Admit a session on the second transport | P | While a session on the other transport carries an operation, so the operation is cut and its card command's answer is lost. | H-5, H-7 |
| UCA-67 | Custodian | Keep the stream listener published | P | While the app is suspended in the background, so the Mac dials a phone that cannot answer and never tries Bluetooth (UCA-6). | H-7, H-5 |
| UCA-68 | Custodian | Command the near-field card | P | While the app is in the background: Core NFC refuses, the operation ends as `card_error`, and the holder never learned a card was wanted. | H-7, H-5 |
| UCA-69 | Custodian | Report `card.status` absent | P | While the phone is locked and the primed card is unreadable only because protected data is unavailable, so the Mac withdraws an identity the phone can serve once the holder unlocks it. | H-7 |
| UCA-70 | Requester | Open a second GATT link from the extension | P | While the app holds one: both share the phone's single link and channel, SAR fragments interleave, and both sessions fail. | H-7, H-5 |
| UCA-71 | Requester | Dial the stream again | P | When the last stream dial failed while Bonjour still shows the phone (cached record of a suspended app), so Bluetooth is never tried. | H-7 |
| UCA-72 | Custodian | Answer a refused preamble with an authentication or encryption error | P | Any context: the central's OS starts bonding and shows a pairing dialog the user cannot relate to RAPP. | H-5 |

### 20.4 Controller constraints

| ID | Constraint | Closes |
| :--- | :--- | :--- |
| CC-67 | One session at a time across all transports; a session with an operation in flight or a handshake under way is never displaced from any transport; the main actor re-decides admission before displacing. | UCA-66 |
| CC-68 | On entering the background with Bluetooth serving, the custodian closes an idle stream session and unpublishes the stream listener (a busy one when it ends), and publishes it again on foreground. Not a withdrawal (§4.5). | UCA-67 |
| CC-69 | A near-field card command from the background first summons the holder: a time-sensitive notification, `waiting_for_card`, and a wait bounded by a named limit and by the session; the card is commanded only once the app is active, otherwise the operation ends `card_error` with `card_wait_ended`. | UCA-68 |
| CC-70 | While protected data is unavailable the custodian keeps the card status it last read with protected data available. | UCA-69 |
| CC-71 | On a Mac only the app holds a GATT link to the phone; the extension hands its operation to the app, which carries it on its session or tells the extension to dial the stream. | UCA-70 |
| CC-72 | A stream dial that fails while Bonjour still shows the phone sends the next dial over Bluetooth, until the phone is seen on Bonjour again after an absence. | UCA-71 |
| CC-73 | A refused or closed link answers writes with `writeNotPermitted`; the characteristics need no link-layer security (CC-54). | UCA-72 |

Residuals, accepted: a Mac reaches the phone over Bluetooth only while
its app runs; right after the phone leaves the screen, a Mac may spend
one stream discovery window before it dials Bluetooth; Core NFC needs
the app in front, so an NFC card operation from the background needs the
holder to answer the notification.

## 21. Serving every computer at once

### 21.1 Scope

Under CC-67 the custodian served one session at a time across its
transports and refused a dial while that session was busy. A Mac whose
token extension dialed the stream while the app's Bluetooth session
carried an operation was refused that way, and so was a second computer:
each saw its connection close and its login fail, the lockout of UCA-60
across transports. The custodian now serves every routed connection as its
own session on either transport, and the card's one-operation queue
(CC-59) is the only serialization left. On a Mac the app holds the
computer's one session and keeps running without its window. Losses and
hazards are this record's: L-1, L-3; H-1, H-5, H-7.

### 21.2 Control structure

```
Mac: token extension --handoff--> Mac app (one session, stream | BLE) --+
other computers (one session each per connection) ----------------------+
                                                                        v
Phone: session 1..n, each with its own coordinator and dispatcher
       card.status to every open session
                 |
                 v
       card queue (first come first served, one whole operation)
                 |                       \--queued--> a waiting session
                 v
       PIN prompt / holder summons (the operation holding the card only)
                 |
                 v
                card
```

New control actions: the custodian admits a session per routed connection;
the card queue grants the card's turn and releases it. New feedback:
`queued` to a waiting session, once; an operation cancelled for its
deadline is reported to its dispatcher as answered, so its prompt comes
down and the queue moves on.

### 21.3 Unsafe control actions

| ID | Controller | Control action | Type | Context | Hazard |
| :--- | :--- | :--- | :--- | :--- | :--- |
| UCA-73 | Custodian | Show the PIN prompt or summons naming a computer | P | Naming a computer other than the one whose operation holds the card, so the holder consents for the wrong computer. | H-1, H-5 |
| UCA-74 | Custodian | Release the card's turn | N, late | Not when the operation expired or its session ended while its prompt was up, so every other computer's operation waits behind a prompt nobody will answer. | H-7, H-5 |
| UCA-75 | Custodian | Take down a prompt or summons | P | Another session's, because one session ended, so the holder's consent in progress for a computer still waiting is withdrawn. | H-7, H-5 |
| UCA-76 | Requester | Open a session to the phone | P | While its own session is open or being established, by the extension beside the app or by a fixed short redial, so the phone holds sessions nobody needs and a refused dial repeats without end. | H-7 |
| UCA-77 | Requester | End the Mac app | P | When its window closes, while the app holds the computer's one session: the extension falls back to dialing the stream per operation, and a phone reachable only over Bluetooth is unreachable. | H-7 |
| UCA-78 | Custodian | Hold a connection that has not routed | P | Without a bound, so dialers on the local network that never authenticate hold the phone's connections and paired computers cannot reach it. | H-7 |

### 21.4 Controller constraints

| ID | Constraint | Closes |
| :--- | :--- | :--- |
| CC-74 | No session is displaced or refused for being busy, on any transport. The custodian serves every routed stream connection and every subscribed Bluetooth central as its own session, concurrently, and the card serves one whole operation at a time across all of them (CC-59). No other session cuts an admitted operation: it ends by its answer, its own session's end or its deadline, and a card command already under way runs to the card's answer. Over Bluetooth a computer is one central with one link, so it holds one session there. This supersedes CC-67 and CC-57's one session per pairing, and carries CC-58 to both transports. | UCA-66, UCA-60 |
| CC-75 | The PIN prompt and the holder summons name the computer of the session whose operation holds the card. | UCA-73 |
| CC-76 | An operation that expires, or whose session ends, releases the card's turn as soon as no card exchange of it is under way, and its prompt and summons come down at once. A waiting operation whose session ends or whose deadline passes leaves the queue at once. | UCA-74 |
| CC-77 | Ending one session takes down only that session's prompt and summons. | UCA-75 |
| CC-78 | A requester holds at most one session to its phone across its transports, and a Mac across its processes too: only the app holds it, on either transport, and the extension hands its operation to the app whenever the app runs and dials itself only when no app answers the handoff port. An iPad, whose extension has no handoff port, is the accepted exception below. Operations on that session wait their turn instead of failing busy. A failed or refused dial is followed by a wait that doubles from 2 to 32 seconds and starts over when a session comes up or the phone newly appears. This supersedes CC-71. | UCA-76, UCA-70 |
| CC-79 | The Mac app keeps running when its window closes and starts at login, without a window; only quitting ends it. It registers itself as a login item once, and a removal by the user stands. | UCA-77 |
| CC-80 | A connection on the custodian's session listener that has not sent its first whole frame within 5 seconds is closed, and at most 8 such connections wait at once. Routed, authenticated sessions have no quota (CC-58). | UCA-78 |

Residuals, accepted:

- The phone's own preparation of a reader card (opening the reader session
  and reading the authentication certificate for `card.status`) runs on the
  reader's exchange chain, not in the operation queue. It never splits one
  card exchange and sends no PIN command, but it may run between two
  exchanges of one operation, such as before a re-prompt after a refused PIN.
- A Mac whose app is not running lets the extension dial a session per
  operation; the phone serves it beside any other.
- An iPad requester's extension dials its own stream session beside the
  app's, since iOS gives it no handoff port, an exception to CC-78; the
  phone serves them all.
- `queued` reaches the requester on the wire, but no requester shows it as a
  state of its own yet, so CC-62's display half is open.

## 22. Reporting the custodian's card reader

### 22.1 Scope

A requester that needs the card tells its user how to supply it: into the
phone's card reader, or to the phone over NFC. `card.status` carried the
card and its fingerprint but nothing about the reader, so the requester
chose the instruction from a reader it had assumed. A Mac paired with an
Android phone told its user to insert the card into the phone's card
reader after the reader had been unplugged from the phone. Seen on
2026-10-22. The custodian now reports in `card.status` whether a contact
card reader is connected to it, and the requester names the reader only
while one is reported. Losses and hazards are this record's: L-3; H-5,
H-6.

### 22.2 Control structure

```
Phone OS --reader attached / detached (built in, USB, Lightning)--> custodian
custodian --card.status {card_present, reader_attached, fingerprint}--> every open session
requester --"insert the card into the phone's reader" | "present the card to the phone"--> user
```

New feedback: the reader's attachment, in `card.status` right after
`session.ready` and on every attachment or detachment. The control action
it informs is the requester's instruction to its user; presence and the
identity offer (CC-64, CC-65) do not change.

### 22.3 Unsafe control actions

| ID | Controller | Control action | Type | Context | Hazard |
| :--- | :--- | :--- | :--- | :--- | :--- |
| UCA-79 | Requester | Tell the user to insert the card into the custodian's reader | P | When the custodian has no reader connected, because it was unplugged or the phone reads cards only over NFC, so the user looks for a reader that is not there and does not tap the card. | H-5 |
| UCA-80 | Requester | Tell the user to attach a reader or present the card | N | When the card is absent and the custodian's reader is gone, so the user is left with an instruction that cannot be followed and nothing that can. | H-5 |

### 22.4 Controller constraints

| ID | Constraint | Closes |
| :--- | :--- | :--- |
| CC-81 | The custodian reports in `card.status` whether a contact card reader is connected to it, built in or attached to a port, once right after `session.ready` and again on every attachment or detachment, on every open session. Attaching or detaching a reader leaves presence as CC-65 defines it, except that detaching a reader removes the card in it; an NFC card the holder added stays present. Specification §8.4 item 1. | UCA-79, UCA-80 |
| CC-82 | A requester that asks its user for the card names the custodian's reader only while the latest `card.status` on an open session reports the card absent and a reader attached; otherwise it asks the user to present the card to the custodian. The reader changes no offer: CC-64 alone governs offering and withdrawal. Specification §8.4 item 6. | UCA-79, UCA-80 |

Privacy: `reader_attached` travels only inside the encrypted session, and
no discovery record or advertisement carries it.

## 23. Trying every phone in pairing mode

### 23.1 Scope

Two phones on one network, an iPhone and an Android phone, were both in
pairing mode. The Mac took the code shown on one, dialed the other, and
that phone's CPace key confirmation failed; the Mac reported that the code
was not accepted, although it was right. Seen on 2026-10-22. A
`mode=pairing` record and a BLE advertisement carry nothing derived from
the code or the offer (specification §4.1), so a requester cannot tell
which phone in pairing mode shows the typed code. The requester now tries
each phone in pairing mode with the code, one at a time, before it reports
the code as not accepted. Losses and hazards are this record's: L-3; H-5.

### 23.2 Control structure

```
user --typed code--> requester
requester --pairing connection, offer read, CPace step 1--> custodian A, then B, ... (one at a time)
custodian --Y_B || T_B, or a close--> requester
requester --paired | "code not accepted" | "no phone in pairing mode"--> user
```

Before key confirmation the only authenticated feedback is `T_B`. A
verified `T_B` proves that the custodian holds the code; a mismatch, a
close or silence says only that this custodian does not. The requester
acted on a process model in which the one custodian it dialed was the one
showing the code, and read that custodian's mismatch as a wrong code.
Discovery records and offers name no phone, and nothing a custodian says
about itself is authenticated until the code is accepted.

### 23.3 Unsafe control actions

| ID | Controller | Control action | Type | Context | Hazard |
| :--- | :--- | :--- | :--- | :--- | :--- |
| UCA-81 | Requester | Report the pairing code as not accepted | P | While a custodian it found in pairing mode has not been tried with the code, or when it tried none: the user retypes or doubts a right code, and the phone that shows it is never asked. | H-5 |
| UCA-82 | Requester | Name a custodian in the pairing outcome or its progress | P | Before a code is accepted, from a discovery record, an advertisement or an offer: none of them is authenticated, so a rogue on the link chooses the name the user reads. | H-5 |

### 23.4 Controller constraints

| ID | Constraint | Closes |
| :--- | :--- | :--- |
| CC-83 | The requester tries every custodian it finds in pairing mode on any transport, from when the code is submitted until the last one tried refuses it: one pairing connection at a time, each endpoint opened at most once and each `offer_id` tried at most once per typed code, at most 8 pairing connections per code. A refused or closed connection, no CPace step 2 within the attempt deadline, or a `T_B` that does not verify moves on to the next; a verified `T_B` ends the search. It reports the code as not accepted only when every custodian tried refused it and no endpoint is left, or the limit is reached; when it tried none, it reports that no phone in pairing mode was found. Specification §4.2, "Trying Each Custodian in Pairing Mode"; `PairingCandidates` in the core. | UCA-81 |
| CC-84 | Until a code is accepted the requester names no custodian, in its progress or in the not-accepted report; it names the custodian only from the custodian's `pairing.hello`, inside the authenticated pairing channel. | UCA-82 |

The limit: a phone advertises pairing mode only during a ceremony, so a
real network shows one or two. The limit of 8 pairing connections per
typed code bounds what a flood of fake pairing-mode advertisers can cost:
the requester's time, and other custodians' attempts.

Residuals, accepted:

- Each custodian tried that does not show the code spends one of its
  offer's three attempts (specification §3.3 item 1). The limit still holds
  per custodian: one guess per typed code, never two at once, under its own
  attempt deadline, so the guessing bound of the 30-bit code is unchanged.
  A phone in pairing mode beside the right one can lose attempts it never
  saw typed, and after three mistyped codes its offer locks out with the
  backoff of §3.3 item 7; its holder starts a new offer.
- On BLE the advertisement shows no mode: a peripheral that serves no offer
  is not in pairing mode, and costs a connection but no attempt.
- Rogues that take up the 8 pairing connections, or one that serves a copy
  of a real offer's `offer_id` first, keep the requester from the real
  phone for that code, which is then reported as not accepted. That is a
  denial of service any party on the link can cause; it yields no pairing
  and no extra guess.

## 24. Naming the computer in the PIN prompt

### 24.1 Scope

The Android custodian's PIN 1 prompt named the paired computer and, on a
line of its own, the program taken from the requester's operation context.
On a Mac that context reads "macOS CryptoTokenKit": the token stack, never
the site, which no requester can know. The iPhone custodian already named
only the computer. The custodian's prompt now names only the paired
computer. Losses and hazards are this record's: L-1; H-1, H-5.

### 24.2 Unsafe control actions

| ID | Controller | Control action | Type | Context | Hazard |
| :--- | :--- | :--- | :--- | :--- | :--- |
| UCA-83 | Custodian | Show the requester's operation context in the PIN prompt | P | When the context names plumbing, such as the token stack, or anything else the requester cannot vouch for: the holder reads it as the party asking and consents or declines on a name that says nothing about the login. | H-5, H-1 |

### 24.3 Controller constraints

| ID | Constraint | Closes |
| :--- | :--- | :--- |
| CC-85 | The custodian's PIN prompt names the paired computer by its pairing's name, the `display_name` of its `pairing.hello`, and never a site; the requester's operation context is not shown. A signature's PIN 2 prompt keeps its document names (specification §9.3). This supersedes CC-55's display clause, "the phone shows the computer's name and the program, labelled as such"; CC-55's rule that the context never names a relying party the requester cannot know stands, as do CC-25 and CC-75. Specification §11 item 1. | UCA-83, UCA-58 |

## 25. A local card overrides the phone on the Mac

### 25.1 Scope

The Mac requester serves a card in its own reader and a paired phone's
card. Holding both, it offered two identities of one person to the
browser's chooser and kept the phone's session busy for a computer that
had a card of its own. The Mac app now lets a card in its own reader
override the phone: while one is present it holds no session to the
phone. The same change gives the holder a one-click way to forget the
phone, with no confirmation. Losses and hazards are this record's: L-3;
H-4, H-5, H-7.

### 25.2 Unsafe control actions

| ID | Controller | Control action | Type | Context | Hazard |
| :--- | :--- | :--- | :--- | :--- | :--- |
| UCA-84 | Requester | Hold or dial the phone session and offer the phone's identity | P | While a card is in the computer's own reader: the browser shows two identities of one person and the login may go to the card the holder did not mean, and the phone is kept busy for a computer that does not need it. | H-5, H-7 |
| UCA-85 | Requester | Keep the phone suppressed | P | After the local card has left: a phone that can serve is not dialed and the holder is offered nothing. | H-7, H-5 |
| UCA-86 | Requester | Route a signature to the phone | P | While a local card is present but not yet ready: the signing window asks for no PIN 2 and the phone path refuses, so signing fails without saying why. | H-5 |
| UCA-87 | Cardholder | Forget the pairing | P | By a slip, with no confirmation by design: the identity line must then show the state the vault holds, or the holder is shown a pairing that no longer exists. | H-4, H-5 |

### 25.3 Controller constraints

| ID | Constraint | Closes |
| :--- | :--- | :--- |
| CC-86 | While a card is in a reader attached to the computer, the requester holds no phone session, starts no dial, redial or Bluetooth scan, refuses operations its token extension hands over, and offers no phone identity. Local presence is read at each decision, never remembered, and the identity line shows only the local card. | UCA-84 |
| CC-87 | When the local card leaves, discovery and dialing resume at once and the phone's line returns; the override never changes the pairing. | UCA-85 |
| CC-88 | The signing device follows the same presence fact, read at the moment of signing: a signature goes to the local card whenever one is in a local reader, ready or not, so the local path's own feedback (reading the card, its PIN 2 prompt, its errors) tells the holder what happens; the phone signs only while no card is in a local reader. | UCA-86 |
| CC-89 | Forgetting ends the pairing as specification §4.6 says (`pairing_revoked` at once, or on the next session); the identity line then follows what the vault holds, and a refused forget is reported in development builds. Recovery is a new pairing. | UCA-87 |

Residual, accepted: while the Mac app is not running, nothing withdraws
the phone's identity when a local card is inserted, and the token
extension dials the phone itself. The app stays running without its
window and starts at login (CC-79).

## 26. Keeping the phone's near field warm

### 26.1 Scope

A browser login that needs several signatures in a row (the TLS
handshakes of one identification service) met a closed near field at
each one on the iPhone custodian. The hold ended ten seconds after the
last operation whatever the platform allowed, and an operation that
arrived while the app's own NFC sheet kept it inactive summoned the holder
as if the app were in the background. Each signature cost a summons, a
tap, PACE and often the reader's pause. The custodian now keeps the field,
the card session and the PACE channel open for the next queued operation
for as long as the platform keeps the slot. Losses and hazards are this
record's: L-1, L-3; H-1, H-5, H-7.

### 26.2 Control structure change

The holder feeds its warm state into the summons decision (CC-69), and
the PIN prompt path ends the field before it shows. Feedback: the slot's
state, looked at every second, and the answer to a keep-alive after two
seconds without an exchange.

### 26.3 Unsafe control actions

| ID | Controller | Control action | Type | Context | Hazard |
| :--- | :--- | :--- | :--- | :--- | :--- |
| UCA-88 | Custodian | Keep the field while showing a PIN prompt | P | The system sheet covers the prompt, so the holder cannot answer it and the operation waits out its lifetime. | H-5, H-7 |
| UCA-89 | Custodian | Command the card through a warm field | P | While the app is in the background (UCA-68): the platform refuses, and the holder was never told a card was wanted. | H-7, H-5 |
| UCA-90 | Custodian | Summon the holder | P | While a warm field holds the card and the app is only inactive under its own sheet: the summons waits for the sheet to close, which ends the field, and every further signature costs a new tap. | H-7 |

### 26.4 Controller constraints

| ID | Constraint | Closes |
| :--- | :--- | :--- |
| CC-90 | The field ends before any PIN prompt shows. | UCA-88 |
| CC-91 | Going to the background ends the field; a near-field operation from the background summons the holder as CC-69 says. | UCA-89 |
| CC-92 | An operation that finds a field the app opened in the foreground still holding the card runs on it while the app is inactive under its own sheet, with no summons. This relaxes CC-69's "commanded only once the app is active" for a warm field only; from the background CC-69 applies unchanged. | UCA-90 |
| CC-93 | The field has no idle limit of its own: it ends when the slot is gone (the card left, the sheet was closed, or the platform ended it), when a keep-alive or an operation goes unanswered, 50 seconds after it was asked for, when serving stops or the last session closes, and per CC-90 and CC-91. CC-41's watch on the slot and its keep-alive stand; the custodian adds no idle limit of its own on top of the platform's. | UCA-43, UCA-46 |

Residual, accepted, widening CC-66's: while PIN 1 is held, a paired
computer can obtain several authentication signatures within one field
instead of one per tap. The field lasts at most the platform's slot life
(about 20 seconds) and 50 seconds in any case, the system sheet is on
screen for all of it, and lifting the card, the background, Remote Access
off or the last session closing ends it. VERIFY with the held PIN still
runs before every signature, since the card keeps no PIN state between
them. A card swapped in fails the secure channel, so the next exchange
goes unanswered and the field ends.

## 27. The workstation's remote-use switch

### 27.1 Scope

A workstation gains one switch for remote use, off by default (hierarchy
specification §5.2). While it is off the workstation is a local card
reader only and asks the operating system for no network or Bluetooth
permission; turning it on asks for them in context. On the Mac the switch
sits in the window's toolbar and its icon is the state: off, on and
waiting, on with the phone connected, and on but blocked (the computer's
Bluetooth off or a permission denied). Losses and hazards are this
record's: L-3, L-4; H-3, H-5, H-6.

### 27.2 Control structure change

New control action: the holder turns remote use on or off. New feedback:
the switch's icon and its accessibility value, derived from the
requester's session state and from the platform's radio and permission
state.

### 27.3 Unsafe control actions

| ID | Controller | Control action | Type | Context | Hazard |
| :--- | :--- | :--- | :--- | :--- | :--- |
| UCA-91 | Requester | Browse, scan, dial or offer a phone's identity | P | While the holder has turned remote use off: the computer keeps talking to the phone and offers an identity the holder believes switched off. | H-3, H-5, H-6 |
| UCA-92 | Requester | Show the switch as connected | P | When no session is open, or show it as waiting when the computer's Bluetooth is off or a permission was denied, so the holder cannot tell a phone that is coming from one that cannot. | H-5 |
| UCA-93 | Requester | Request local-network or Bluetooth permission | P | At launch while remote use is off, so the holder is asked for something the app does not use. | H-5 |

### 27.4 Controller constraints

| ID | Constraint | Closes |
| :--- | :--- | :--- |
| CC-94 | Turning remote use off closes every session at once, withdraws every identity offered from a phone at once, halts discovery and scanning, and keeps the pairings; while it is off nothing dials or offers. | UCA-91 |
| CC-95 | The switch shows the requester's live state: connected only while a session is open, waiting while on with none, and blocked, with its cause named in the control's help and accessibility value, while the computer's Bluetooth is off or a permission was denied. No state is shown by colour alone. | UCA-92 |
| CC-96 | The workstation requests local-network and Bluetooth permission only when the holder turns remote use on, never at launch. | UCA-93 |
