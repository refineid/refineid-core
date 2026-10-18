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

## 10. Open questions

- Which of R-1 to R-6 are worth a protocol version, and which are better
  served by application behaviour over the existing messages?
- Should discovery carry any authenticated liveness at all, or should the
  requester hold a long-lived session instead of inferring presence?
- How much of the one-line failure text in 6.5 is a deliberate oracle
  defence, and how much is an omission?
