# Remote Authorization Proxy Protocol (RAPP) v26.11.8
## Pairing and Session Protocol over the BLE and Stream Transports

Status: Stamped specification, reviewed by the owner\
Document version: 26.11.8 (cited as "RAPP v26.11.8 section N")\
Wire version: `[26, 11, 8]` (`[Year, Month, Day]`; bumped whenever the wire vocabulary changes, §10.1 item 4)\
Versioning: the document version and the wire version are one stamp. A change of either moves both: the document, its state machine, its corpora and its models are renamed to the new stamp, and every citation follows\
Offer version: `[26, 11, 8]`\
Wire version history: `[26, 11, 2]` stamped specification; `[26, 11, 7]` adds the `waiting_for_unlock` progress event (§8.2 item 3); `[26, 11, 8]` keeps a forgotten pairing on the Requester until the Custodian echoes its `pairing_revoked` close (§4.6)\
Document history: 26.11.2 stamped specification; 26.11.8 restamps the document with the wire version, and lets a Requester show its connecting to the Custodian it has just paired (§4.7)\
Transport Profiles: `"fi.refineid.rapp.ble"`, `"fi.refineid.stream"` (§2.2)\
Date: 2026-11-08\
Change controller: RefineID project

---

## Abstract

This specification defines the pairing protocol and the operational protocol of the Remote Authorization Proxy Protocol (RAPP v26.11.8), carried over any registered transport profile (§2.2): the **Bluetooth Low Energy (BLE) Direct Proximity Transport Profile** (`"fi.refineid.rapp.ble"`) and the **Local Internet Protocol (IP) Stream Transport Profile** (`"fi.refineid.stream"`). Pairing, offer bootstrap, sessions, and operations are identical on every transport; only framing, routing, and discovery differ.

A user's mobile device acts as the Custodian holding physical custody of the Finnish Electronic Identification (FINEID) identity card over Near Field Communication (NFC). The workstation acts as a Requester. On BLE the Custodian is the Generic Attribute Profile (GATT) Peripheral and the Requester the GATT Central. The Peripheral is the side that advertises, accepts the connection, and serves the data (the GATT Server); the Central is the side that scans, connects, and reads or writes that data (the GATT Client). On the stream transport the Custodian listens and the Requester dials.

Pairing is established through a 6-character Crockford Base32 human code (`7K X4 M9`, 30.0 bits entropy) executed over `CPaceRistretto255` ([draft-irtf-cfrg-cpace-21](https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-cpace-21)). Advertisements broadcast zero pairing code material, zero ephemeral bucket hints, and zero user identifiers or personal device names. Device discovery is mediated by a standardized 128-bit RAPP Service Universally Unique Identifier (UUID) and finalized through authenticated `Noise_XXpsk3` key exchange. One guess of the pairing code runs at a time and the next is admitted no sooner than 500 ms later, so a 5-minute offer admits at most 600 guesses of its 30-bit code; an attempt is charged before the Custodian answers it, so disconnecting gains nothing.

To support upper-layer messages (such as X.509 certificate chains or document signing summaries) across single Attribute Protocol (ATT) transactions, this profile specifies a normative **BLE Segmentation and Reassembly (SAR) Adaptation Layer**, preserving upper-layer session and operation security guarantees without frame truncation.

---

## 1. Scope, System Architecture, and Status

### 1.1 Scope and Standalone Specification Model

This document defines the complete, standalone normative specification for the **Remote Authorization Proxy Protocol (RAPP) version 26.11.8**. It encompasses:
- The **Transport Profile Registry** (§2.2) with the **BLE Transport Profile** (`"fi.refineid.rapp.ble"`) and the **Local IP Stream Transport Profile** (`"fi.refineid.stream"`).
- The **pairing protocol** utilizing `CPaceRistretto255`, 6-character Crockford Base32 human factors, atomic attempt admission, and authenticated `Noise_XXpsk3` channel binding.
- The **BLE SAR Adaptation Layer** with latched invariant total lengths and stop-and-wait flow control.
- The **Authenticated Message Envelope**, sequential sequencing, and session multiplexing.
- The **operation model** (§8): one operation at a time on the card, queued across sessions, forgotten with its session.
- The **Registered Credential Profiles and Actions** for card status inspection, browser authentication, and qualified document signing.
- **Service Withdrawal** (§4.5): the Custodian's notice, keyed by each pairing's static agreement, that it has stopped serving, on discovery and on open sessions, and the Requester's notice, on open sessions, that it has stopped using remote access; how a Requester treats each way a session ends.
- **Pairing Storage Confirmation and Revocation** (§4.3, §4.6): each endpoint confirms its stored trust record before the pairing is active, an endpoint that forgets a pairing tells the other with a `pairing_revoked` close, in session, as the first message of the next session, which a Requester keeps looking for until the Custodian echoes the close, and a pairing with no session for 30 days expires on each endpoint.
- **Lifecycle** (§4.7): the Requester's remote use and its view of the Custodian, and the Custodian's service and its view of each computer, as machines with a stated answer for every state and event, formalized in `rapp-state-machine-v26.11.8.yaml` and explained in `rapp-state-machine.md`.
- **Card Presence** (§8.4): the Custodian's in-session notice of the card it holds and of whether a card reader is attached to it; a Requester's offer to local consumers follows the card, eventually consistent.
- **Concurrent Multi-Client Serving** (§8): the Custodian serves every paired Requester over its own session; card operations are serialized on the single card.
- The **Failure Semantics, Retry Protection, and PIN Contracts**.

This document is completely self-contained: all normative schemas, protocol state machines, cryptographic bindings, error handling rules, and wire formats required to implement, verify, and audit RAPP v26.11.8 are defined herein.

- **Migration and Compatibility**:
  RAPP v26.11.8 runs the same pairing and session protocol over every registered transport profile (§2.2). Its wire and offer versions are `[26, 11, 8]` (`[Year, Month, Day]`). It does not interoperate with other RAPP versions. Implementations must conform strictly to the schemas and state machines defined in this standalone specification.
- **Wire and Offer Versioning**:
  - Offer version: `[26, 11, 8]` in `pairing-offer`.
  - Wire version: `[26, 11, 8]` (`[Year, Month, Day]`) in channel envelopes, pairing context, and handshake prologues; the triple changes with every change of wire vocabulary (§10.1 item 4), and the document version moves with it.
- **Role Mapping**:
  - **Requester**: Corresponds to the RAPP Requester. On BLE it operates as GATT Client (Central); on the stream transport it dials the Custodian.
  - **Custodian**: Corresponds to the mobile device acting as the RAPP Authorization Proxy while holding exclusive physical NFC custody of the Credential Holder (FINEID Card). On BLE it operates as GATT Server (Peripheral); on the stream transport it listens.
- **Transport Preference**:
  A Requester reaches the Custodian over the first transport available to it, in this order: directly between Apple devices over Apple's peer-to-peer Wi-Fi, then the IP stream over the local network, then Bluetooth as the last resort. The [RAPP Transport and Discovery Hierarchy Specification](rapp-transport-and-discovery-hierarchy.md) defines discovery and advertisement for each.

### 1.2 Terminology and Requirements Language

* **Custodian**: the server. A mobile phone with NFC (an iPhone or an Android phone) that holds the identity card over NFC and serves it to its clients. In BLE topology, the Custodian operates as the **GATT Server (Peripheral)**.
* **Requester**: the client. A computer (macOS, Windows, Linux or BSD), an iPad or an Android tablet that asks the Custodian for authentication or qualified signatures. A tablet is a Requester only: it uses a card in a reader attached to it or a phone's card over RAPP, and never serves a card. In BLE topology, the Requester operates as the **GATT Client (Central)**.
* **Crockford Base32 Code**: A 6-character human-readable alphanumeric code sampled uniformly from Crockford's unambiguous Base32 alphabet.

---

## 2. Architecture and Transport Relationship

### 2.1 Transport Architecture & Protocol Lifecycle

- **Wire Version**: `[26, 11, 8]` (`[Year, Month, Day]`)
- **Offer Version**: `[26, 11, 8]`
- **Transport Profiles**: registered in §2.2

The transport acts as the underlying point-to-point bearer for RAPP frames. CPace establishes the 32-byte pre-shared key (PSK) that seeds mutual pairing authentication (`Noise_XXpsk3`), replay protection, monotonic sequence counters, and typed at-most-once operation dispatch. Every phase below runs unchanged on every registered transport profile; "transport frame" means one SAR-reassembled message on BLE (§5.3) and one length-prefixed frame on the stream transport (§2.2.2).

#### Protocol Lifecycle:
- **Phase 0: Routing**: Every connection starts with exactly one routing preamble transport frame from the Requester (§2.2). For purpose `"pairing"` with an active offer, the connection proceeds to the offer bootstrap. For purpose `"session"` whose routing tag a stored pairing keyed (§2.2.1), the connection transitions to the Noise session phase.
- **Phase 1: Offer Bootstrap**: The Requester obtains the canonical `pairing-offer`, carrying a fresh random 32-byte `offer_id`, the CPace session identifier (SID), over the transport in use (§4.2): on BLE by reading the Bootstrap Characteristic, on the stream transport as the Custodian's first transport frame after the pairing preamble. Both peers compute the canonical `offer_hash` and bind the transport entry of the offer that names the transport profile in use.
- **Phase 2: CPace Key Agreement & Confirmation**: Execute the `CPaceRistretto255` key confirmation variant 2 (KC2) profile, one transport frame per CPace message, with Context $C$ binding, mutually authenticating via Hash-based Message Authentication Code (HMAC) tags $T_B$ and $T_A$ to establish $PSK$ via HMAC-based Key Derivation Function (HKDF)-Expand. On success, transition to the Noise pairing phase and consume the offer.
- **Phase 3: Noise_XXpsk3 Pairing**: Perform the authenticated pairing handshake with prologue bound to canonical `offer_hash`, wire version `[26, 11, 8]`, suite, and the transport profile in use. Immediately on handshake completion, derive pairing-channel `session_id` and `pair_id`. Exchange `pairing.hello` (parameter echo using `session_id`) and `pairing.confirm` (capability grants), deriving `grants_hash`.
- **Phase 4: Pair Storage and Confirmation**: Atomically store the pairing trust record (`pair_id`, `grants_hash`, peer static public key, and local private key), then send `pairing.stored`. The pairing is active on an endpoint only once it has both stored its record and received the peer's `pairing.stored` (§4.3). A stored pairing is not bound to the transport it was created on; sessions may use any registered transport.
- **Subsequent Operational Sessions**: Operational connections start in the Routing phase, route by a fresh routing tag (§2.2.1), and open a fresh `Noise_KK` session with an independent operational `session_id`, bound to the transport profile of that connection.

The diagram shows the BLE profile; on the stream transport the Requester dials the Custodian's advertised Transmission Control Protocol (TCP) endpoint instead (§2.2.2).

```
┌─────────────────────────────────────────────────────────────┐
│                     REQUESTER (Central)                     │
│  - Linux, macOS, or Windows Desktop/Laptop                  │
│  - Takes the pairing code from the keyboard                 │
│  - Protocol engine (Noise session & operation)              │
└──────────────────────────────┬──────────────────────────────┘
                               │
                    Direct BLE 2.4 GHz Link
       Negotiated ATT maximum transmission unit (MTU) >= 512; sar_payload_capacity = min(MTU - 3, 512) - 6
              RAPP Segmentation & Reassembly (SAR) Bearer
                               │
┌──────────────────────────────▼──────────────────────────────┐
│                    CUSTODIAN (Peripheral)                   │
│  - iOS or Android phone (the Custodian)                     │
│  - Displays Crockford Base32 code on screen                 │
│  - Advertises Service UUID with ZERO hints / Anonymous Name │
│  - Holds exclusive NFC custody of FINEID Card               │
│  - One guess at a time, offer lifecycle                     │
└─────────────────────────────────────────────────────────────┘
```

### 2.2 Transport Profile Registry

Every transport profile defines a candidate identifier, framing, a routing preamble, and an offer bootstrap. CPace messages, Noise handshake messages, and envelopes each occupy exactly one transport frame. Discovery and advertisement for each profile are specified by the [RAPP Transport and Discovery Hierarchy Specification](rapp-transport-and-discovery-hierarchy.md); nothing derived from the pairing code, `offer_id` or `offer_hash` is ever advertised. Advertised discovery hints (hierarchy specification §4.3) and withdrawal hints (§4.5) are keyed by a pairing's static agreement (§4.3) and identify the pairing only to its two endpoints.

| Transport profile | `candidate_id` | Framing | Preamble domain | Offer bootstrap |
| :--- | :--- | :--- | :--- | :--- |
| `"fi.refineid.rapp.ble"` | `"ble"` | BLE SAR (§5.3) over the Channel Characteristic | `"rapp-ble"` | Read of the Bootstrap Characteristic (§4.2) |
| `"fi.refineid.stream"` | `"stream"` | 2-byte big-endian length prefix (§2.2.2) | `"rapp-stream"` | First Custodian frame after a pairing preamble (§4.2) |

#### 2.2.1 Routing Preamble

The routing preamble is the deterministic Concise Binary Object Representation (CBOR) encoding of a 3-element array, sent by the Requester as the first transport frame of every connection:
```cddl
routing-preamble = [
  preamble-domain,       ; "rapp-ble" or "rapp-stream" (§2.2)
  "pairing" / "session", ; purpose
  bstr                   ; empty for "pairing"; session-routing for "session"
]
session-routing = bstr .size 32   ; nonce (16 bytes) || routing_tag (16 bytes)
```
For a `"session"` preamble the Requester draws a fresh 16-byte `nonce` from a cryptographically secure random source for every connection and computes the following, where the input keying material (IKM) is the pairing's static X25519 agreement (X25519 is the Diffie-Hellman function over Curve25519, Request for Comments (RFC) 7748), and SHA-256 is the 256-bit Secure Hash Algorithm (SHA):
```text
K_route     = HKDF-SHA-256(salt = pair_id, IKM = X25519(local static private, peer static public),
                           info = "rapp-routing", L = 32)
routing_tag = first 16 bytes of HMAC-SHA-256(K_route, len(domain) || domain || nonce)
```
where `domain` is the preamble domain of the transport profile in use as 8-bit Unicode Transformation Format (UTF-8) octets and `len` is one octet. Both endpoints of a pairing derive the same `K_route` (§4.3); no other party can. A Requester never reuses a nonce.

The Custodian routes a `"session"` preamble as follows:
1. It evaluates the tag against `K_route` of every non-revoked stored pairing, comparing in constant time and without stopping at a match, so the work does not reveal which pairing matched or whether any did. The pre-authentication limiter (§3.3) bounds how often this runs.
2. On no match the Custodian closes the connection without changing stored state.
3. On a match it consults its replay memory: the nonces of the 256 most recently routed sessions. A nonce already there closes the connection; otherwise the nonce is added, displacing the oldest, and the connection proceeds to the Noise session phase for the matched pairing.

A preamble that does not decode, names another profile's domain, carries an unregistered purpose, a non-empty value with `"pairing"`, or a value other than 32 bytes with `"session"` closes the connection (§10.1) without changing stored state. An encoded preamble longer than 64 bytes is rejected before parsing. A `"session"` preamble encodes to 55 bytes on the stream transport and 52 bytes on BLE. The `routing_tag` and `routing_preamble` vectors of `vectors/rapp-routing-v26.11.8.json` pin the bytes.

The routing tag only selects a pairing; it authenticates nothing. Authentication is established exclusively by the `Noise_KK` handshake that follows.

#### 2.2.2 Stream Transport Profile (`"fi.refineid.stream"`)
- **Bearer**: one reliable, ordered TCP byte stream per connection. The Custodian listens and advertises the endpoint per the hierarchy specification; the Requester dials. The Custodian accepts any number of connections at the same time, one per client session (§8). An open connection from one client is never a reason to refuse another. Neither peer accepts inbound pairing or session connections on any other role.
- **Framing**: each transport frame is a 2-byte unsigned big-endian length $n$ followed by exactly $n$ payload bytes, $1 \le n \le 65535$. A zero length, a truncated frame, or a length above the receiver's limit closes the connection, and the session if one is established.
- **Offer parameters**: the stream transport entry of `pairing-offer` carries `parameters: {}`; endpoints are learned from discovery, never from the offer.
- **Ordering**: after a `"pairing"` preamble the Custodian sends the encoded `pairing-offer` as its first frame (§4.2); after a `"session"` preamble the Custodian routed (§2.2.1) the Requester sends `Noise_KK` message 1.

---

## 3. Human Factors and Pairing Code Specification

### 3.1 Crockford Base32 Alphabet and Code Entry

The pairing code consists of exactly 6 characters sampled uniformly at random from Crockford's Base32 alphabet:

```
Alphabet (32 symbols):
0 1 2 3 4 5 6 7 8 9 A B C D E F G H J K M N P Q R S T V W X Y Z
```

Excluded symbols:
- `I`, `L`: Excluded to eliminate visual confusion with digit `1`.
- `O`: Excluded to eliminate visual confusion with digit `0`.
- `U`: Excluded to eliminate accidental generation of offensive words in Latin-script languages.

#### Entering the code

The Requester's entry field accepts only the 32 alphabet characters, folding a lowercase letter to its uppercase form, and ignores spaces and hyphens typed between the displayed groups (§3.2); it accepts nothing else, so a mistyped `O` or `1` is corrected by the user, never guessed. The code is complete at exactly 6 characters.

Both endpoints derive the password octets as the UTF-8 encoding of the 6 uppercase characters:
$$\text{pw} = \text{UTF-8}(\text{code}) \quad (\text{e.g., } \text{UTF-8}(\texttt{"7KX4M9"}))$$

### 3.2 Display Formatting and Chunking

The Custodian must render the code on screen in two-character clusters separated by a space:

$$\text{Display: } \texttt{XX XX XX} \quad (\text{e.g., } \texttt{7K X4 M9})$$

This format structures visual transfer into three distinct 2-character groups. The Requester user interface (UI) receives the typed code and applies the entry rule of §3.1 before initiating the connection, on every transport.

### 3.3 Entropy, Attempt Admission, and the Guessing Bound

Each character carries $\log_2(32) = 5.0\text{ bits}$ of entropy. The 6-character code provides:

$$\text{Entropy} = 6 \times 5 = 30.0\text{ bits} \quad (1{,}073{,}741{,}824\text{ permutations})$$

#### Local Well-Formedness vs. Attempt Consumption
- **Local Validation**: If the user enters an invalid character, incomplete string ($< 6$ chars), or illegal symbol on the Requester, the Requester UI must reject the input locally. **No frame is transmitted on any transport, and no attempt is consumed.**

#### Atomic Attempt Admission and the Disconnect Oracle
An attempt here is one guess of the pairing code over the transport. It is unrelated to the card's personal identification number (PIN) try counter, which §10.2 governs.

In two-pass password-authenticated key exchange (PAKE) protocols, an adversary acting as initiator could transmit candidate public point $Y_A$, receive the Custodian's $Y_B$ and confirmation authenticator $T_B$, test its guess against $T_B$, and disconnect without submitting $T_A$. $T_B$ tests only the one code that $Y_A$ was built from (§6.1.3), so the attempt is charged at admission, before $Y_B \parallel T_B$ leave the Custodian, and a disconnect after $T_B$ costs the adversary the same as a completed wrong guess: one admission under the single-flight and spacing rules of item 6. No count of failed attempts ends an offer; only its lifetime and its consumption do.

1. **Attempt State Model**:
   The Custodian maintains for the offer:
   - `active_attempt`: boolean indicating an attempt is currently executing under its timer.
   - `consumed`: boolean set once a verified $T_A$ consumed the offer (item 5).
2. **Atomic Attempt Admission**:
   When the Custodian receives $Y_A$, it validates group membership. If `!active_attempt`, the offer is not consumed, the offer deadline has not passed, and the spacing of item 6 allows it, the Custodian atomically sets `active_attempt = true` and derives the shared secret. **This admission occurs strictly before transmitting $Y_B$ and $T_B$.** Otherwise the Custodian refuses the attempt as item 6 says.
3. **Attempt Deadline & Admission Timing**:
   Upon validating $Y_A$ and atomically admitting an attempt, the Custodian arms a non-extendable monotonic attempt timer bounded by:
   $$\text{attempt\_deadline} = \min(\text{admission\_time} + 5.0\text{ s}, \text{offer\_deadline})$$
   Starting the timer at admission strictly bounds local derivation computation before transmitting $Y_B \parallel T_B$ and guarantees an absolute ceiling on the round-trip completion window. If $\text{offer\_deadline}$ has already elapsed ($\text{remaining\_offer\_ttl} == 0$), no attempt can be admitted.
4. **End of a Failed Attempt**:
   If the Requester disconnects, drops the link, or fails to deliver a valid mutual confirmation authenticator $T_A$ before the attempt deadline expires, `active_attempt` is cleared and nothing else changes: the offer keeps being served on every transport, the pairing code stays on screen, and the next attempt is admitted under items 2 and 6. The Custodian keeps no count of failed attempts and shows the holder nothing about them.
5. **Successful PAKE Completion & Offer Consumption**:
   Upon receiving and verifying a valid mutual confirmation authenticator $T_A$ within the attempt deadline, `active_attempt` is cleared, the PAKE attempt timer is canceled, the pairing offer is permanently marked **consumed** (disabling any subsequent admissions under that `offer_id`), and the session transitions exclusively to the Noise pairing phase. Subsequent network faults during Noise or protocol mismatches do not restore the consumed offer; any new pairing ceremony mandates generating a fresh offer and pairing code.
   - **Multi-Attempt Replay Resistance & Composition Scope**: Although the 32-byte `offer_id` ($SID$) is shared across every attempt admitted under a single offer, each honest endpoint draws a fresh independent nonzero scalar ($x_A, x_B$) for every attempt. Transcript-bound confirmation prevents reuse of a prior tag against a different transcript except with the relevant cryptographic failure probabilities. This argument is not a formal proof that several guesses sharing one SID compose securely; that remains a recorded engineering assumption, bounded in operation by single-flight serialization and the admission spacing of item 6, monotonic attempt deadlines (5.0 s), the offer lifetime of item 7, and immediate offer consumption upon valid $T_A$.
6. **Single-Flight Serialization & Rate Limiting**:
   The Custodian never runs two pairing-code guesses at once: while `active_attempt` is true it admits no other attempt. In addition, pre-authentication connection attempts and CPace step 1 submissions, valid or invalid, are admitted at most once per 500 ms. A pairing connection the Custodian cannot admit for either reason is answered with `pairing-busy` (§4.2, "Busy Refusal"), which carries the time until the Custodian can admit again, and is then closed; nothing in the offer changes, and no code material of the refused connection is evaluated.
7. **Offer Lifecycle, Expiry Separation, and Post-PAKE Deadlines**:
   The pairing offer is valid for exactly 5 minutes (300 seconds) from user initiation (`offer_ttl_ms = 300000`).
   - **Offer Expiry**: When the 5-minute offer TTL passes, the offer is terminated: it stops being served on every transport, the pairing code leaves the screen, and ephemeral offer keys are zeroized. No penalty follows, and the user may immediately start a new offer. The attempts admitted or failed under the offer play no part in its termination.
   - **Active Attempt Clamping**: An active PAKE attempt cannot extend past the offer deadline: per item 3, the attempt timer is strictly clamped by $\text{attempt\_deadline} = \min(\text{admission\_time} + 5.0\text{ s}, \text{offer\_deadline})$. Admitting an attempt at $t = 299\text{ s}$ yields an attempt deadline of $1.0\text{ s}$, terminating at $t = 300\text{ s}$.
   - **Handed-Off Lifecycle & Finite Post-PAKE Deadlines**: Once CPace completes successfully and transfers exclusive custody to the Noise pairing phase, the active ceremony is **exempt** from destruction by the original 5-minute offer TTL. Instead, the active pairing channel is bounded by finite post-PAKE monotonic deadlines:
     1. **Noise Handshake Completion Deadline**: 10.0 seconds from local CPace handoff.
     2. **Grant Echo, Storage and Confirmation Deadline**: 10.0 seconds from local Noise completion, within which `pairing.confirm` is echoed, the record is stored, and the peer's `pairing.stored` is received (§4.3 item 4).
     Any timeout, peer silence, transport disconnect, or protocol error destroys candidate trust immediately, erases ephemeral keys, and closes the connection without persisting an unconfirmed pairing; a record already stored when the deadline passes without the peer's `pairing.stored` is revoked (§4.6). An indefinitely silent peer is terminated upon deadline expiry. The Requester enters Noise only after the transport frame carrying Message 3 has been sent; the transport's own delivery acknowledgment (on BLE, the ATT write acknowledgment) does not prove that the Custodian accepted $T_A$.

#### Guessing Bound
The code space is $2^{30}$ and CPace admits only online guessing: each attempt tests the one code its $Y_A$ was built from (§6.1.3), whether or not $T_A$ is sent. Items 3, 6 and 7 bound the attempts an offer admits: one at a time, at most one every 500 ms, for at most 300 s, so at most 600 attempts per offer. An adversary who guesses at that rate for the whole lifetime of an offer finds the code with probability at most $600 / 2^{30} \approx 2^{-20.8}$, about 1 in 1.8 million per offer, and has to be on the holder's network or within Bluetooth range during the minutes the Custodian is in pairing mode. Because no count of failures ends the offer, attempts that are not an adversary's guesses, such as a Requester trying this Custodian with a code shown by another Custodian (§4.2), or a connection lost during an attempt, cannot make the holder's offer unusable. A device that keeps the single-flight slot busy denies pairing for as long as it keeps connecting, which is inherent to pairing on a shared link and is bounded by the offer's lifetime.
---

## 4. Privacy, Bootstrap Discovery, and Noise Binding

### 4.1 Zero Hint Leakage Over Advertisements

No advertisement on any transport (BLE advertising data, Domain Name System Service Discovery (DNS-SD) names, text (TXT) records, or other discovery records) may carry pairing code material or offer material (`offer_id`, `offer_hash`), or any value derived from them. Discovery hints (hierarchy specification §4.3) and withdrawal hints (§4.5) are keyed by a pairing's static agreement (§4.3), which never crosses the wire. The rules below apply to BLE; the hierarchy specification applies the same rule to DNS-SD.

The BLE advertisement payload must not contain:
- Any bits, truncated representations, or hashes of the pairing code.
- Ephemeral bucket hints or index tags.
- Personal device names, user identifiers, or hardware serial numbers.

The Custodian must:
- Broadcast solely the standardized 128-bit RAPP Service UUID (`7E39FD01-A6B5-4D78-9E11-37E28E9545F1`).
- Set the BLE Local Name to an empty string or generic constant (`"RefineID"`), strictly avoiding default platform names (such as `"<owner's device name>"`).
- Rotate the BLE Resolvable Private Address (RPA) per Bluetooth Core Specification v5.4.

### 4.2 Bootstrap Discovery & PairingOffer Schema

The Custodian creates the `pairing-offer` when the user starts a pairing ceremony and serves it on every transport it accepts pairing connections on. The Custodian offers its user the start of a ceremony only while its remote access is on and it serves in the foreground. Offering a pairing does not end its service: its sessions stay open and it routes new session connections as before (§8.3).

The SID used in CPace must be an independent 32-byte cryptographic random value (`offer_id`) generated by the Custodian upon creating the offer, on every transport. It must not be derived from the pairing code. The Requester never derives an offer; it always obtains it through the offer bootstrap of the transport in use.

#### PairingOffer Schema (Deterministic CBOR):
```cddl
pairing-offer = {
  "scheme": "rapp",
  "version": [26, 11, 8],       ; offer version triple
  "offer_id": bstr .size 32,    ; 32-byte cryptographic random SID
  "suites": [
    "CPACE-RISTR255-SHA512-RAPP-KC2 + Noise_XXpsk3_25519_ChaChaPoly_SHA512"
  ],
  "profiles": [ + tstr ],       ; offered credential profiles (§9)
  "transports": [ + transport-entry ],
  "offer_ttl_ms": 300000
}

transport-entry = {
  "profile": tstr,              ; registered transport profile (§2.2)
  "candidate_id": tstr,         ; its registered candidate identifier (§2.2)
  "parameters": { * tstr => any }
}
```
The `transports` array lists one entry for each registered transport the Custodian accepts this pairing on, in ascending byte order of `profile`, with no duplicate profiles. The BLE entry carries `parameters: {"service_uuid": "7E39FD01-A6B5-4D78-9E11-37E28E9545F1"}`; the stream entry carries `parameters: {}`.

`pairing_secret` is never part of `pairing-offer`: the pairing secret is negotiated by CPace, and storing or serving a static pairing secret over an unauthenticated bootstrap is strictly prohibited.

The canonical `offer_hash` is computed with SHA-256 as:
$$\text{offer\_hash} = \text{SHA-256}(\text{encode\_deterministic\_cbor}(\text{pairing-offer}))$$

#### PairingBusy Schema (Deterministic CBOR):
```cddl
pairing-busy = {
  "scheme": "rapp",
  "version": [26, 11, 8],       ; offer version triple
  "retry_after_ms": 1..5000,     ; milliseconds until the Custodian can admit an attempt
}
```
The bootstrap answer of a Custodian in pairing mode is `pairing-offer` while it can admit an attempt (§3.3 items 2 and 6) and `pairing-busy` while it cannot: an attempt is active, or the 500 ms spacing has not passed. `retry_after_ms` is the larger of the time left on the active attempt's deadline and the time left of the spacing, rounded up to a millisecond, at least 1 and at most 5000. A `pairing-busy` is sent only on a connection whose routing preamble named `"pairing"` and only while an offer is active; it carries nothing derived from the code or the offer.

#### Bootstrap Read Flow:
1. **BLE**: the Custodian exposes the **RAPP Bootstrap Characteristic** (`7E39FD03-A6B5-4D78-9E11-37E28E9545F1`, Read-only). The Requester connects, sends the `"pairing"` routing preamble (§5.2), and performs an `ATT_READ_REQ` on this characteristic to obtain `encode_deterministic_cbor(pairing-offer)`, or `encode_deterministic_cbor(pairing-busy)` while the Custodian cannot admit an attempt.
2. **Stream**: after receiving the `"pairing"` routing preamble, the Custodian sends `encode_deterministic_cbor(pairing-offer)`, or `encode_deterministic_cbor(pairing-busy)` while it cannot admit an attempt, as its first transport frame; after `pairing-busy` it closes the connection. A Custodian with no active offer closes the connection instead.
3. The Requester decodes the bootstrap answer. A `pairing-busy` is a busy refusal ("Busy Refusal" below). An offer is rejected unless it is deterministic CBOR matching the schema, carries version `[26, 11, 8]`, lists an acceptable suite, and contains a `transports` entry whose `profile` is the transport profile of the connection. Unsupported suites terminate the pairing flow immediately before CPace; automatic downgrade or fallback to unconfirmed legacy suites is strictly prohibited.
4. Both peers bind the `candidate_id` of that entry and the connection's transport profile (§4.3, §6.1.1), use `offer_id` as SID for CPace, and compute `offer_hash` for the Noise pairing prologue.
5. A deterministic encoding of `pairing-offer` with the KC2 suite, the three registered profiles, and both transport entries stays within the 509-byte ATT value capacity at the minimum ATT Maximum Transmission Unit (MTU) of 512.

#### Busy Refusal:
A Custodian that cannot admit an attempt (§3.3 item 6) refuses the connection with `pairing-busy`:
1. **At bootstrap**: as Bootstrap Read Flow items 1 and 2 say.
2. **After the offer was served**: when CPace step 1 arrives on a connection the Custodian can no longer admit, because another connection was admitted in between or the spacing has not passed, the Custodian answers on the stream transport with `encode_deterministic_cbor(pairing-busy)` in place of step 2 and closes the connection; on BLE it refuses the step 1 write with the ATT error `0x11 Insufficient Resources` (Bluetooth Core Specification, Vol. 3, Part F, §3.4.1.1), which every platform's GATT server can send, and the Requester then reads the Bootstrap Characteristic once more: a `pairing-busy` is the busy refusal, and a `pairing-offer` counts as a busy refusal with `retry_after_ms` of 0.
3. A busy refusal admits no attempt, evaluates no code material, and changes nothing in the offer.

#### Trying Each Custodian in Pairing Mode:
A `mode=pairing` record and a BLE advertisement carry nothing derived from the code or the offer (§4.1), so a Requester cannot tell which of several Custodians in pairing mode shows the code its user typed. It tries them in turn with that code:
1. **Who is tried**: The Requester tries the Custodians it finds in pairing mode on any transport: those found when the user submits the code, and those found until the last Custodian it tried has refused the code. One found after that is not tried with this code. The Requester may gather what discovery finds for at most `pairing_gather_ms` = 3000 ms after the code is submitted before it opens the first pairing connection, and those it gathered count as found when the code was submitted: a Custodian that is found only over BLE, or later than another Custodian refuses, is then still tried. A BLE advertisement does not show the mode, so a BLE peripheral is in pairing mode when it serves an offer or a `pairing-busy` on a pairing connection (§5.2 item 3). The Requester opens a pairing connection to each endpoint it found once per typed code, and again to an endpoint that answered busy: after every other endpoint waiting to be opened, and no sooner than that endpoint's `retry_after_ms` after its busy answer, for as long as it keeps answering busy and the limit of item 5 allows.
2. **One guess per Custodian**: A Custodian serves one offer on every transport (§4.2), so the Requester tells Custodians apart by `offer_id`. Trying a Custodian means running CPace with it (§6.1). The Requester tries each `offer_id` at most once per typed code: a connection whose offer it rejects (Bootstrap Read Flow item 3), or whose `offer_id` it has already tried with this code, is closed before CPace step 1 and spends no attempt. A busy refusal is not a try: it names no `offer_id` the Requester has tried, and the endpoint is opened again (item 1).
3. **One at a time**: The Requester closes one pairing connection before it opens the next, and never runs two CPace attempts at once.
4. **Refusal**: A Custodian refuses the code when its pairing connection is refused or closed before $T_B$ verifies, when its CPace step 2 does not arrive within 5.0 s of step 1 (the attempt deadline of §3.3 item 3), or when its $T_B$ does not verify (§6.1.3 step 3). A busy refusal ("Busy Refusal" above) is not a refusal of the code. The Requester then closes that connection and tries the next Custodian. A verified $T_B$ shows that the Custodian holds the code: the Requester tries no other Custodian with it, and a later failure ends the ceremony as §3.3 item 7 says.
5. **Limit**: The Requester opens at most 8 pairing connections per typed code, whether or not CPace runs on them; every reopening after a busy answer counts, so a Custodian that stays busy is asked at most 8 times, over at most 35 s of waits.
6. **Report**: The Requester reports the code as not accepted only when it has tried at least one Custodian, every Custodian it tried has refused the code, and it has no endpoint left to open or has opened 8 pairing connections. A Custodian whose last answer was busy when the limit is reached counts as having refused the code. The report names no Custodian: until a code is accepted nothing a Custodian says about itself is authenticated, and the offer names no device. A Requester that tried no Custodian and received no busy answer found none in pairing mode and says so; it does not report the code as not accepted.
7. **One guess per Custodian per code**: A Custodian that admitted the attempt (§3.3 item 2) and then refused the code keeps its offer as it was (§3.3 item 4). Each Custodian receives at most one guess per typed code, never two at once (§3.3 item 6), each under its own attempt deadline; a try at a Custodian that shows another code costs that Custodian nothing but the attempt's time.

### 4.3 Mandatory Noise Binding, Temporal Derivation, and Reconnect Routing

1. **Noise_XXpsk3 Prologue**:
   The prologue for the pairing handshake is the deterministic-CBOR encoding of the 5-element array:
   ```cddl
   pairing-prologue = [
     "rapp-pairing",
     [26, 11, 8],                                                         ; wire version [Year, Month, Day]
     "CPACE-RISTR255-SHA512-RAPP-KC2 + Noise_XXpsk3_25519_ChaChaPoly_SHA512", ; cryptographic suite name
     bstr .size 32,                                                       ; offer_hash
     tstr                                                                 ; transport profile of the connection (§2.2)
   ]
   ```
   $$\text{prologue} = \text{encode\_deterministic\_cbor}(\text{pairing-prologue}) \quad (145\text{ bytes on BLE, 143 bytes on stream})$$

2. **Immediate Channel Identifier Derivation**:
   Immediately upon completing the `Noise_XXpsk3` handshake, both peers derive the channel identifiers from the completed handshake hash $h$ in strict order:
   ```text
   session_id = first 16 bytes of SHA-512("rapp-session-id" || h)
   pair_id    = first 16 bytes of SHA-512("rapp-pair-id" || h)
   ```
   Both peers immediately destroy `pairing_secret` ($PSK$) and all ephemeral handshake keys.
   The derived `session_id` immediately scopes the pairing-channel envelopes for `pairing.hello` and `pairing.confirm`.

3. **Parameter Echo & Mutual Grants**:
   - Inside the established pairing channel, each peer sends `pairing.hello`.
   - `pairing.hello` echoes `offer_hash`, the bound transport profile and `candidate_id` (§4.2), wire version `[26, 11, 8]`, suite name, the sender's display name, its platform description, and, from the Requester, its requested profiles.
   - **Display name**: every `pairing.hello` carries the sender's display name, the name the peer shows for it (§11 item 1). It is required and not blank: 1 to 256 bytes of UTF-8 holding at least one character that is not white space (§7.1); a `pairing.hello` without one aborts the pairing with an authenticated protocol violation. A name that already says the platform carries no operating-system prefix; any other name is prefixed by the operating system's own name, joined by a space, a hyphen and a space (`<operating system> - <name>`). A computer names itself by its host name with the prefix: `macOS - example-host`, `Windows - EXAMPLE-HOST`, `Linux - example-host`, `FreeBSD - example-host`. An iPhone and an iPad name themselves without a prefix, by the name their user gave them where the platform lets the application read it and by their model name otherwise: `iPhone 16`, `iPad Pro 11-inch (M4)`. An Android tablet names itself with the prefix, `Android - Example Tablet`, and an Android phone by its device name without a prefix: the name its user gave it where the platform lets the application read it, and its model name otherwise. A sender whose name would be longer than 256 bytes shortens the device's name at a character boundary until it fits. The `platform` field names the sender's operating system, likewise 1 to 256 bytes and not blank. The operating system's name is its own: `macOS`, `Windows`, `Linux`, `FreeBSD`, `OpenBSD`, `iPadOS`, `Android`. The name is sent again at the start of every session (§7.1, `session.ready` and `session.hello`), so a renamed device's new name reaches its peer with its next session.
   - **Names identify nothing**: a display name is a label for people. No endpoint finds, matches, replaces or revokes a pairing by its display name, its platform or anything else the peer says about itself; a pairing is known only by its `pair_id` and keys.
   - Custodian verifies matching echoes. Any mismatch aborts with an authenticated protocol violation.
   - The Custodian automatically grants the valid requested profiles matching its pairing offer (since possession and entry of the 30-bit pairing code constitutes user authorization), and transmits `pairing.confirm` carrying granted profiles. Requester echoes and confirms. Both granted sets must be identical.
   - Derive `grants_hash` from the confirmed, canonically sorted grant set:
     $$\text{grants\_hash} = \text{SHA-256}(\text{encode\_deterministic\_cbor}(\text{sorted\_profiles}))$$
     where `sorted_profiles` is a CBOR array of profile identifier strings (`tstr`, CBOR major type 3 with definite-length encoding) sorted in standard canonical byte-wise lexicographical order without duplicates (e.g. `["fi.refineid.authentication", "fi.refineid.card-status"]`).

4. **Atomic Permanent Key Storage**:
   Immediately upon receipt and verification of matching `pairing.confirm` messages:
   - **Fresh Pair-Specific Static Keys**: Each pairing ceremony must generate a fresh, cryptographically independent static X25519 keypair $(s, s_{pub})$ on each endpoint. Static keys must not be reused across different peer pairings or across distinct pairing ceremonies. This provides pairwise endpoint isolation and prevents correlation across peers. The private key is stored in the platform's protected key store, excluded from backups and cloud synchronization, and never exported.
   - Each endpoint atomically persists the pairing trust record:
     - `pair_id`
     - `grants_hash` and confirmed granted profiles
     - Remote peer's static public key
     - Local static private key
     - The peer's display name from its `pairing.hello`
   - The display name is part of the record: it is stored and destroyed with the record in one commit, so a record has a name for its whole life.
   - **Keeping the name current**: on every session the Custodian sends its current display name in `session.ready` and the Requester sends its own in `session.hello` (§7.1). The receiver checks the name as at pairing (item 3); a missing, blank or over-long name is an authenticated protocol violation that closes the session and keeps the pairing (§10.1 item 2). A valid name that differs from the one in the pair record replaces it there, atomically. If that store fails, the record keeps its old name and the session goes on; the next session tries again.
   - If the store fails, as on a full disk or a key store that refuses, nothing is stored: the endpoint sends no `pairing.stored`, sends `pairing.abort`, destroys the candidate keys, closes the connection and tells its user that the pairing could not be stored, with the cause its platform gives. A peer that stored its record revokes it at the deadline below.
   - Once its record is durably stored, each endpoint sends `pairing.stored` carrying the derived `pair_id` (§7.1). An endpoint treats the pairing as active only after it has both stored its own record and received the peer's `pairing.stored`; until then it neither routes nor dials for the pairing, and announces it in no discovery or withdrawal record. The stored record carries whether the peer confirmed it, and the endpoint rewrites the record as confirmed when the peer's `pairing.stored` arrives: a record found unconfirmed at a later start was stored inside a confirmation window the endpoint did not complete, and the endpoint revokes it (§4.6) before serving anything. A `pairing.stored` whose `pair_id` differs from the derived one aborts the pairing: the endpoint revokes the record it stored (§4.6). If the deadline of §3.3 item 7 passes without the peer's `pairing.stored`, the endpoint revokes the record it stored (§4.6), so a pairing that only one side holds does not survive.
   - The pairing channel is cleanly closed once both `pairing.stored` messages have been exchanged.

5. **Reconnect Routing for Operational Sessions (`Noise_KK`)**:
   Subsequent connections for credential operations (authentication, qualified signing) do not rerun CPace or the offer bootstrap, and may use any registered transport.
   - Every connection starts in the Routing phase (§2.2.1).
   - Requester transmits a single routing preamble with purpose `"session"` and a fresh routing tag (§2.2.1). On BLE it is written to the Channel Characteristic via `ATT_WRITE_REQ` in a `SINGLE` SAR frame (§5.2).
   - The Custodian finds the stored pairing whose `K_route` keyed the tag, retrieves `pair_id`, `grants_hash`, and peer static key, and initiates the Noise session phase (`Noise_KK`).
   - If no non-revoked pairing keyed the tag, or its nonce was already routed, the Custodian immediately closes the link without altering stored state.
   - **Keys from the static agreement**: Every value that names a pairing outside its encrypted channel is keyed by the pairing's static X25519 agreement, which only its two endpoints can compute:
     ```text
     K_x = HKDF-SHA-256(salt = pair_id, IKM = X25519(local static private, peer static public), info, L = 32)
     ```
     with `info` `"rapp-routing"` for routing tags (§2.2.1), `"rapp-discovery-hint"` for discovery hints (hierarchy specification §4.3), and `"rapp-withdrawal"` for withdrawal hints (§4.5). Both endpoints obtain the same agreement from their own private key and the peer's public key. An agreement equal to the identity point yields no key; such a pairing is never announced or routed. The `pair_keys` vectors of `vectors/rapp-routing-v26.11.8.json` pin the keys.
   - **Routing privacy**: A routing tag is fresh for every connection and computationally unlinkable without `K_route`, so an observer of preambles cannot tell whether two connections belong to the same pairing, and no routing value recurs. A replayed preamble is refused in the Routing phase while its nonce is in the Custodian's replay memory; a preamble replayed after its nonce has left the memory reaches `Noise_KK` message 1, which the replaying party cannot complete. That timing difference reveals only that some stored pairing once routed that preamble, which the observer already saw; it is mitigated by single-flight connection serialization and the pre-authentication limiter (§3.3).
   - Session Prologue:
     ```cddl
     session-prologue = [
       "rapp-session",
       [26, 11, 8],                                                         ; wire version [Year, Month, Day]
       "Noise_KK_25519_ChaChaPoly_SHA512",                              ; suite name
       pair_id,                                                         ; bstr .size 16
       grants_hash,                                                     ; bstr .size 32
       tstr                                                             ; transport profile of the connection (§2.2)
     ]
     prologue = encode_deterministic_cbor(session-prologue)
     ```
   - Operational handshakes derive a fresh operational `session_id` (`first 16 bytes of SHA-512("rapp-session-id" || h_session)`). The pairing `session_id` is never reused.

### 4.4 Structural Role Separation as Relay Defense

Under Bluetooth Core Specification v5.4 and this profile (§5.2, §6.3), ATT and CPace roles are strictly asymmetric and immutable: the Requester is Central ($A$), transmitting exclusively via `ATT_WRITE_REQ`, while the Custodian is Peripheral ($B$), replying exclusively via `ATT_HANDLE_VALUE_IND`. Per draft-irtf-cfrg-cpace-21 Section 10.1, strict initiator/responder role separation structurally eliminates relay loopback and reflection attacks: an adversary cannot reflect the Custodian's $Y_B \parallel T_B$ indication back to the Custodian as an initiator write $Y_A$, nor can it relay frames between two peers acting in the same role.

A transparent radio frequency (RF) relay that forwards packets between distant rooms without decrypting them bypasses any physical-distance assumption. PAKE secrecy keeps the session key from the relay, so it carries only what the paired endpoints send and cannot originate an operation. Signal analysis cannot detect a bit-preserving relay, so none is attempted.

### 4.5 Service Withdrawal

An endpoint **withdraws** when it deliberately stops serving, or stops using, remote access for every stored pairing and keeps the pairings. A Custodian withdraws when its user turns remote access off or quits the application. A Requester withdraws when a card in a reader attached to the computer suspends remote use (hierarchy specification §5.2), and when its user quits the application. Nothing else is withdrawal: suspension or termination by the operating system, sleep, loss of the network, and a session restart with reason `"normal"` or `"shutdown"` (§7.2) are not, and a Requester's user turning remote use off forgets its pairing, which is revocation (§4.6). Withdrawal revokes no pairing; a Custodian serves again with its next `mode=session` advertisement, and a Requester dials again once the card that suspended remote use leaves the reader or, after it quit, at its next launch. A Custodian whose user turns remote access on again serves at once: it registers its stream service under a fresh instance name (hierarchy specification §4.2) with the `mode=session` record and advertises over BLE, whether or not a withdrawal is still being announced, with every pairing it kept. Items 1 to 7 are the Custodian's withdrawal and how a Requester receives it; items 8 and 9 are the Requester's withdrawal and how a Custodian receives it.

1. **Withdrawal Key**:
   Each stored pairing has a withdrawal key that both endpoints derive from their static keys, the static agreement $S$ serving as the IKM, and that never crosses the wire:
   $$S = \text{X25519}(\text{local static private}, \text{peer static public})$$
   $$K_{\text{wd}} = \text{HKDF-SHA-256}(\text{salt} = \text{pair\_id}, \text{IKM} = S, \text{info} = \texttt{"rapp-withdrawal"}, L = 32)$$
   HKDF is [RFC 5869](https://www.rfc-editor.org/rfc/rfc5869.html), with the pseudorandom key $\text{PRK} = \text{HMAC-SHA-256}(\text{pair\_id}, S)$ over the 16-byte `pair_id`, then the single block $K_{\text{wd}} = \text{HMAC-SHA-256}(\text{PRK}, \text{info} \parallel \texttt{0x01})$. An $S$ equal to the X25519 identity (all zero) yields no key; such a pairing is never announced. The Requester may cache $K_{\text{wd}}$ with the pairing.

2. **Withdrawal Hint**:
   $$\text{whint} = \text{first 8 bytes of }\text{HMAC-SHA-256}(K_{\text{wd}}, \text{len} \parallel \text{instance} \parallel \text{counter\_be64})$$
   where $\text{instance}$ is the instance portion of the DNS-SD service instance name the Custodian publishes ([RFC 6763](https://www.rfc-editor.org/rfc/rfc6763.html) §4.1): the name exactly as published, without the service type (`_refineid-stream._tcp`) and the domain (`local.`), as UTF-8 octets, 1 to 63 octets (hierarchy specification §4.2). Instance names may contain dots; a value ending in a service type or domain suffix is a misuse and is refused. $\text{len}$ is its length as one octet, and $\text{counter} = \lfloor \text{unix\_time} / 60 \rfloor$ as an unsigned 64-bit big-endian integer. The `withdrawal_key` and `withdrawal_hint` vectors of `vectors/rapp-withdrawal-v26.11.8.json` pin the bytes.

3. **Custodian Order**:
   On withdrawal the Custodian, in this order:
   1. sends `session.close` with reason `"service_withdrawn"` (§7.1) on every open operational session, waits at most 1 second (`quit_withdrawal_bound_ms`) for each Requester's echo of it (§7.1 item 7), and closes its link;
   2. stops accepting connections;
   3. replaces the TXT record of its current `_refineid-stream._tcp` service instance with the withdrawn record (item 4), in place, without unregistering the instance first;
   4. unregisters the service after at least 2 and at most 10 seconds.

   It stops advertising over BLE when it stops accepting connections.

   Withdrawal ends every session, and with it every operation, as §8.1 item 3 says.

4. **Withdrawn Record**:
   ```text
   v=1
   mode=withdrawn
   withdrawn=<entry_1>,<entry_2>,...,<entry_8>
   ```
   The `withdrawn` value holds exactly 8 entries, each 16 lowercase hexadecimal digits, separated by commas without spaces. The Custodian places the withdrawal hint, for its current instance and counter, of each of the 8 most recently used stored pairings, fills the remaining entries with independent random 8-byte values, and orders all 8 by fresh random sort keys. A pairing's use time is the start of its most recent established session, or its creation when it has had none; equal times are ordered by the hints' bytes, lowest first. The record carries no other attribute. Pairings beyond the eighth are not announced and fall under unannounced loss (item 6). The `announcement_selection` vectors pin the choice.

   TXT keys compare case-insensitively ([RFC 6763](https://www.rfc-editor.org/rfc/rfc6763.html) §6.4); a key that appears twice in any case is a repeated key. Values compare exactly: `mode` is `withdrawn` in lowercase, and every entry is lowercase hexadecimal.

5. **BLE**:
   The BLE advertisement carries only the Service UUID (§4.1) and no withdrawal marker. A Requester on BLE learns of withdrawal through an open session or as unannounced loss.

6. **Requester Behavior**:
   - **Open session first.** While the Requester holds an established session to the pairing, discovery records do not change its presence. An authenticated `session.close` with reason `"service_withdrawn"` is a **verified withdrawal**; any other close reason, or loss of the session, is not.
   - **Discovery.** Without an open session, a Requester honours a withdrawn record only on the service instance it currently associates with the pairing: the instance whose discovery hint matched the pairing, or the instance it last established a session to. It parses the record and computes the pairing's hint for that instance and for $\text{counter} - 1$, $\text{counter}$ and $\text{counter} + 1$ of its own clock, comparing every entry in constant time. A match is a **verified withdrawal**. Because the window is one counter step either side of $\lfloor t/60 \rfloor$, it tolerates a clock difference of at least 60 seconds and, depending on where both times fall within their minutes, up to just under 120 seconds. Implementations must not widen it.
   - **Malformed records.** A record with a key other than `v`, `mode` and `withdrawn` (in any case), a repeated key (in any case), a `v` other than `1`, a `mode` other than `withdrawn`, or a `withdrawn` value that is not exactly 8 lowercase 16-digit entries is malformed, as is a `hints` attribute beside `withdrawn`.
   - **Effect.** On a verified withdrawal the Requester withdraws the pairing's presence at once: it stops offering the Custodian's credentials to local consumers, drops any dial being set up, and neither dials, offers nor holds anything for the Custodian until the Custodian announces itself again: a `mode=session` record for the pairing appears (§8.3), or the RAPP BLE advertisement is first seen after the withdrawal. While withdrawn it may scan for BLE passively; seeing an advertisement that was already in sight is not an announcement. A local consumer that asks for the card meanwhile is answered at once that no remote card is available, and nothing is dialed. The withdrawn record's later unregistration announces nothing. The Requester changes no stored pairing state and shows no error.
   - **Unannounced loss.** A malformed record, a withdrawn record without a match, a record on another instance, or a service that disappears without one is unannounced loss: it withdraws nothing, and the Requester goes on as the next item says.
   - **How a session ends.** A Requester treats the end of a session to the pairing by what ended it:
     1. A `session.close` with reason `"pairing_revoked"` received (§4.6 item 4), or the Requester's own revocation close sent (§4.6 items 1 and 6): the Requester forgets the pairing; it destroys the pairing on the Custodian's echo of its close and otherwise keeps it in its revocation backlog (§4.6 item 6).
     2. A `session.close` with reason `"service_withdrawn"` received: a verified withdrawal, with the effect above. A `session.close` with reason `"card_unavailable"` has the same effect (§8.4 item 5): the Requester drops the Custodian's identity at once, without the grace of §8.4 item 3, never offering a certificate whose key cannot be used, and waits for the Custodian to announce itself again.
     3. An authenticated protocol violation, the Custodian's `session.close` with reason `"protocol_violation"` or one the Requester detects and closes with (§10.1 item 2): the Requester keeps the pairing and does not redial; it dials again only when the Custodian next appears (§8.3) or a local consumer asks. A version mismatch is the likely cause, which an update of either endpoint may fix.
     4. Anything else, a loss of the session (transport close, the silence limit of §8.3, an AEAD or framing failure) or a close with reason `"normal"`, `"complete"`, `"user_disconnect"`, `"policy"` or `"shutdown"`: a **loss**. A loss opens the redial window of §8.3 at once, whether or not the Custodian is still in sight; its redials go to the endpoint the Requester last reached or to a BLE scan. What the user sees after a loss comes only from the offer to local consumers, which follows §8.4 item 3.
7. **Authenticity and Replay**:
   Only the two endpoints of a pairing know its static agreement, so no other party can compute a withdrawal hint; observing sessions, routing preambles or discovery records does not help. A party on the local link that recorded a genuine withdrawn record can republish it under the same instance name for at most about three minutes (the counter window), and only while the Requester still associates that instance with the pairing; instance names are fresh on every advertisement start (hierarchy specification §4.2). The effect is the same as a spoofed multicast DNS (mDNS) goodbye: presence is withdrawn until the Custodian is next discovered. These bounds assume the Requester's clock is not under the attacker's control; an attacker who can move the Requester's time, for example through an unauthenticated Network Time Protocol (NTP) source, can stretch the replay window for as long as it controls that clock, with the same effect and no other. Random fillers keep the record the same size whatever the number of stored pairings, and the hints are unlinkable across instances and minutes.

8. **Requester Withdrawal**:
   On withdrawal the Requester, in this order:
   1. sends `session.close` with reason `"service_withdrawn"` (§7.1) on every open operational session, one whose `session.ready` it verified, waits for each Custodian's echo of it as §7.1 item 7 says, and closes its link; a connection whose session is not yet open it closes without a notice;
   2. stops dialing and browsing for every pairing, apart from the revocation backlog (§4.6 item 6); a Requester that a local card suspended resumes once the card leaves the reader. Hierarchy specification §5.2 lists what else a workstation stops.

   It keeps every stored pairing. A Requester publishes no discovery record and no BLE advertisement, so it announces nothing else. Withdrawal ends every session, and with it every operation, as §8.1 item 3 says.

   Quitting is best effort: a Requester that quits sends its closes before it exits and waits at most 1 second for the Custodians' echoes (§7.1 item 7). A close not echoed by then is not known to have been delivered: the Requester exits all the same, and a Custodian the close did not reach sees that session as lost.

9. **Custodian Behavior**:
   An authenticated `session.close` with reason `"service_withdrawn"` from a Requester is that Requester's **withdrawal**; any other close reason, or loss of the session, is not. Both endpoints send this reason, and receiving it is never a protocol violation; only the paired Requester can send it, inside the session's authenticated channel. The Custodian answers with its own `session.close` carrying `"service_withdrawn"` (§7.1 item 7) and closes that session, keeps the pairing, and records that the computer withdrew. Its user interface may show that computer as off, not merely disconnected, until the next session from that pairing, and shows no error. It goes on serving every pairing, that one included, and accepts the Requester's next dial as any other.

### 4.6 Pairing Revocation

An endpoint **revokes** a pairing when its user forgets it, when the pairing expires (item 5), when a pairing fails after its record was stored (§4.3), when the confirmation deadline of §4.3 item 4 passes, or when its peer tells it so. A Requester holds at most one active pairing; its user forgets it by turning remote use off, and by pairing another Custodian, which replaces it (item 6). The record is marked revoked at once and serves nothing from then on. Whichever endpoint revokes, Custodian or Requester, tells the other with `session.close` carrying reason `"pairing_revoked"` (§7.1), so that the peer forgets the pairing on its side too, except as items 3 and 6 say:

1. **In Session**:
   If the revoking endpoint holds an open session to the peer, it sends the close at once.

2. **On the Next Session**:
   Otherwise the endpoint keeps the static private key for the close alone. A Custodian goes on announcing the pairing's discovery hint (hierarchy specification §4.3) as if nothing had changed, and a Requester keeps looking for the Custodian (item 6); on the next session with the peer the revoking endpoint completes the handshake of §6.3, sends the close as its first message, waits for the peer's echo as §7.1 item 7 says, and no card session starts.

3. **Key Destruction**:
   A Custodian destroys the static private key once the close has been sent and the wait for its echo has ended (§7.1 item 7), or 30 days after the revocation (`revocation_notice_days`), whichever comes first. A Requester destroys it, and the record with it, when the Custodian's echo of the close arrives, or when the pairing's idle expiry would have passed: 30 days (`pairing_idle_expiry_days`) after its latest established session, or its creation while it has had none (item 5), whichever comes first. The Requester counts from that session, not from the forget, and a close sent without its echo keeps the key for the next session (item 6). A pairing not yet confirmed, and a revocation the confirmation deadline causes, destroy the key at once and tell nobody.

4. **Receiving the Close**:
   An endpoint that receives `session.close` with reason `"pairing_revoked"` at any point of a session revokes the pairing at once, destroys its key, withdraws any identity it offers for the pairing (§8.4), answers with its own `session.close` carrying `"pairing_revoked"` (§7.1 item 7), and closes the transport. That echo tells the revoking endpoint that its peer forgot the pairing.

5. **Idle Expiry**:
   A pairing that has had no established session for 30 days (`pairing_idle_expiry_days`) expires. A session is established from the moment the Custodian sends, or the Requester verifies, its `session.ready` until it ends. Each endpoint keeps with the stored pairing the latest wall-clock time at which it had a session to the pairing established, noting it at least when a session is established and when it ends; an earlier reading, as from a clock set back, does not replace a later one, and while the pairing has had none, that time is its creation. The endpoint revokes the pairing once that time is 30 days past. A pairing never expires while a session to it is established: every check for expiry takes whether a session to the pairing is established, and with one it notes the time instead. Custodian and Requester apply this each on its own, by their own clocks, and check for expiry when they start and at least once a day while they run. Expiry is silent: nothing is sent at that moment, since the peer has been out of reach, and no user is interrupted. On a Custodian items 2 to 4 then apply as to any revocation, so a Requester that opens a session within the notice window receives the `pairing_revoked` close; a Requester destroys the key of an expired pairing at once (item 6). Idle expiry is also how a Custodian forgets a Requester whose revocation close did not reach it before the forgotten pairing expired on the Requester (item 6).

6. **Requester Revocation**:
   A Requester's user forgets the pairing the Requester holds by turning remote use off (hierarchy specification §5.2), and by pairing another Custodian: once the new pairing is active (§4.3 item 4) the Requester forgets the one it held. Every forget its user makes, with a session open or not and whether or not a card is in a reader attached to the Requester, marks the record forgotten and keeps the static private key for the `pairing_revoked` close alone, and the pairing joins the Requester's **revocation backlog**. A forgotten pairing serves nothing else: it offers no identity, starts no operation, presents no card, and is never the pairing the Requester selects or dials for its user. The Requester holds at most one active pairing; the backlog is apart from it, may hold several forgotten pairings at once, and has no limit but their expiry (item 3). With a session open the Requester sends the close as item 1 says and waits at most 1 second for the Custodian's echo (§7.1 item 7), as for quitting (§4.5 item 8). With none open, and after a close the Custodian did not echo, the Requester keeps looking for the Custodian with the discovery of §4.5 item 6 and the hierarchy specification §3 and §4: a `mode=session` record carrying the pairing's discovery hint, or a RAPP BLE peripheral. Each time the Custodian appears for the pairing (§8.3) the Requester opens one connection for the forgotten pairing, by the route that appeared: to the instance whose hint matched when a `mode=session` record carrying the hint appeared, and to the peripheral when a RAPP BLE advertisement was first seen; it tries no other route on that appearance, and a pairing whose key has expired (item 3) opens none. It completes the handshake of §6.3, sends the close as its first message, and waits for the echo as §7.1 item 7 says. On the echo it destroys the key and the record. A connection that fails, a session that ends without the echo, and a Custodian that does not hold the pairing leave it in the backlog until the Custodian next appears; the Requester never dials a forgotten pairing on a timer. Over BLE a Requester holds one link to a peripheral at a time, as the Custodian keeps one link per central (§5.2): it opens a forgotten pairing's connection only to the peripheral that appeared, one forgotten pairing at a time, and never while a session dial or session over BLE may hold a link to that peripheral; its session dial over BLE waits for such a connection to end. When a session over BLE ends, its peripheral counts as appearing for the forgotten pairings held back while it ran. The backlog runs whether remote use is on, off or suspended by a local card: while remote use is off or suspended it is the only remote activity, and while remote use is on it runs alongside the active pairing. It offers no identity and starts no operation. A forgotten pairing whose Custodian does not appear before its idle expiry would have passed is destroyed untold, as item 3 says, and that Custodian forgets the computer by its own idle expiry (item 5). A pairing that ends without its user's action sends nothing: a Requester's idle expiry (item 5) destroys the key at once, and a local card only suspends remote use and keeps the pairing (§4.5 item 8).

7. **No Stable Requester Identity**:
   Every pairing ceremony makes fresh static keys on both endpoints (§4.3 item 4), so a Custodian cannot tell that a new pairing comes from a computer it was paired with before, and does not try: names identify nothing (§4.3 item 3). A pairing a Requester forgot leaves the Custodian's list when the Requester's revocation close reaches it (items 1 and 6): the Requester keeps the forgotten pairing in its revocation backlog, so the Custodian forgets the computer the next time they meet. Until then the Custodian lists it beside the new one; a pair that does not meet again before the pairing's idle expiry leaves it to that expiry, 30 days without a session (item 5).

8. **Ends That Send Nothing**:
   An endpoint that crashes, is ended by its operating system or loses power sends nothing: no withdrawal, no revocation close. Its peer sees a loss and handles it as one, within the bounded windows of §4.5 item 6 and §8.3, and a pairing the dead endpoint meant to forget stays on the peer until the 30-day idle expiry (item 5). No protocol can send a message from an endpoint that is gone; this is a known limit.

### 4.7 Lifecycle

The lifecycle of both endpoints is three machines above the pairing and session machines, and the presentation of the Custodian's pairing states. [rapp-state-machine-v26.11.8.yaml](rapp-state-machine-v26.11.8.yaml) states every state and event of each, with a transition, an ignored event or a reason why the event cannot happen in every cell; [rapp-state-machine.md](rapp-state-machine.md) explains them with diagrams; the `scenarios` of `vectors/rapp-lifecycle-v26.11.8.json` walk them.

| Machine | Instances | What it holds |
| :--- | :--- | :--- |
| `requester_remote_use` | one per Requester | the remote-use switch, the code entry and pairing search, suspension by a local card, launch and quit (hierarchy specification §5.2) |
| `requester_view_of_custodian` | one per active pairing while remote use is on with discovery running | idle, connecting within the redial window, connected, or withdrawn (§4.5 item 6, §8.3) |
| `custodian_service` | one per Custodian | remote access off, serving (with or without an offer up), withdrawing, limited by the operating system (§4.5 items 3 and 4) |
| `pairing` (presentation) | one per stored pairing on a Custodian | how the holder sees each computer: connected, not connected, off after its withdrawal, or no longer listed (§4.5 item 9, §4.6) |

**Presenting the Custodian on a Requester.** A Requester presents the Custodian only through its card. While a session confirms a card (§8.4) the identity is offered and shown; in every other state, whether the Custodian is out of sight, withdrawn, lost, being dialed or held, the Requester shows no remote card, exactly as if no phone were there, and names neither the Custodian's state nor a reason. Dialing, scanning and redialing run in the background within the bounds of §4.5 item 6 and §8.3 and are never shown, with one exception: a pairing ceremony its user has just completed. From the ceremony's completion (§4.3 item 4) until the Requester shows the Custodian's identity or a request for its card (§8.4), the Custodian reports that it holds no card, or `redial_window_ms` has passed, the Requester shows that it is connecting to the Custodian, named by the display name of its `pairing.hello` (§4.3 item 3), in place of the code entry; the ceremony's user is waiting for that connection and nothing else answers them. The one other line that names the Custodian is the notice, after a `"pairing_revoked"` close from it (§4.6 item 4), that the phone forgot this computer. In that state the user's actions are the ordinary ones: use a card in a reader attached to the computer, pair another phone, which replaces the pairing (§4.6 item 6), or turn remote use off.

**Turning the Custodian's remote access off** is withdrawal and only withdrawal (§4.5 items 3 and 4): every pairing is kept, and turning it on again serves at once under a fresh instance name. **Turning the Requester's remote use off** forgets its pairing (§4.6 item 6). The Requester's switch goes off only by its user's action: a revocation from the Custodian or idle expiry leaves it on and offers the code entry (hierarchy specification §5.2).

---

## 5. GATT Profile and Wire Protocol

### 5.1 Service and Characteristic Definitions

* **Primary Service UUID**:
  `7E39FD01-A6B5-4D78-9E11-37E28E9545F1`
* **RAPP Channel Characteristic UUID**:
  `7E39FD02-A6B5-4D78-9E11-37E28E9545F1`
  * **Properties**: `Write` (`0x08`), `Indicate` (`0x20`)
  * **Descriptors**: Client Characteristic Configuration Descriptor (CCCD, UUID `0x2902`, Access: `Read | Write`, permitted values: `0x0000` Disabled, `0x0002` Indications Enabled).
  * **Permissions**: Unauthenticated Writeable. Application security is provided exclusively by CPace and Noise authenticated encryption with associated data (AEAD).
* **RAPP Bootstrap Characteristic UUID**:
  `7E39FD03-A6B5-4D78-9E11-37E28E9545F1`
  * **Properties**: `Read` (`0x02`)
  * **Permissions**: Unauthenticated Readable (carries `encode_deterministic_cbor(pairing-offer)`).

### 5.2 ATT Roles and Connection Setup

The Requester is the GATT Client and the Custodian the GATT Server. Every fragment from Requester to Custodian is an `ATT_WRITE_REQ` (write with response) on the Channel Characteristic, answered by `ATT_WRITE_RSP`; every fragment from Custodian to Requester is an `ATT_HANDLE_VALUE_IND` (indication), answered by `ATT_HANDLE_VALUE_CFM`. Notifications and reads of the Channel Characteristic carry no protocol frame. Each direction has one fragment in flight: the next fragment is sent only after the answer to the previous one has arrived, which gives ordered, duplicate-free delivery.

A connection is set up in this order:

1. **MTU exchange**: The Requester requests an ATT MTU of at least 515 bytes. If the negotiated MTU is below 512 bytes, the connection is dropped.
2. **Indications on**: The Requester writes `0x0002` to the Channel Characteristic's CCCD. Until then the Custodian accepts no preamble and sends no indication; a preamble that arrives before it closes the connection.
3. **Routing**: The Requester sends the routing preamble of §2.2.1 with domain `"rapp-ble"` as a `SINGLE` SAR frame (§5.3). With purpose `"pairing"` and an active offer (§4.2), the Requester reads the Bootstrap Characteristic and the connection enters the CPace phase, or is closed after a `pairing-busy` (§4.2, "Busy Refusal"); with purpose `"session"`, the Custodian routes the tag as §2.2.1 says and the connection enters the Noise session phase. A `"pairing"` preamble with no active offer closes the connection.

A Custodian keeps one link per central: a central that enables indications again ends its previous link. Every client on one Requester device shares that device's connection to the Custodian and its indications, so a Requester holds one link to a peripheral at a time, whatever it carries: a pairing, a session, or a forgotten pairing's close (§4.6 item 6).

### 5.3 BLE SAR Adaptation Layer

Every transport frame on the Channel Characteristic, the routing preamble, the CPace steps, the Noise handshake messages and the Noise transport frames alike, is carried as one SAR message: a 6-byte header in front of each fragment, one fragment per ATT write or indication. A frame that fits in one fragment is sent as `SINGLE`; a longer one is segmented into `FIRST`, `CONT` ... `LAST`.

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|       Total Frame Length      |         Chunk Sequence        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|     Flags     |    Reserved   |      Fragment Payload...      |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

- **Total Frame Length** (`u16`, big-endian): length of the whole frame without SAR headers, 1 to 65,535.
- **Chunk Sequence** (`u16`, big-endian): index of this fragment within the frame, from 0, below 1,024.
- **Flags** (`u8`): `0x01` `FIRST`, `0x02` `CONT`, `0x04` `LAST`, `0x05` `SINGLE` (`FIRST | LAST`). Any other value is a violation.
- **Reserved** (`u8`): `0x00`.

The fragment payload holds at most
$$\text{sar\_payload\_capacity} = \min(\text{negotiated\_att\_mtu} - 3, 512) - 6$$
bytes, since an attribute value is at most 512 bytes (Bluetooth Core Specification v5.4, Vol 3, Part F, Section 3.2.9) and the ATT header takes 3: 506 bytes at an MTU of 515 or more. A smaller limit the platform reports, such as `maximumUpdateValueLength`, is honored instead.

The receiver keeps `expected_total`, `expected_seq` and `accumulated_bytes` per connection and direction, all zero when idle. Every violation below zeroizes the buffer, cancels the timer and closes the connection.

1. **Idle receiver**: the fragment is `FIRST` or `SINGLE` with sequence 0. For `SINGLE` the payload length equals Total Frame Length and is at most the capacity; for `FIRST` the payload is 64 bytes to the capacity and shorter than Total Frame Length. The receiver latches `expected_total` and arms a 5-second timer that is never extended; its expiry is a violation.
2. **In progress**: the fragment is `CONT` or `LAST`, its Total Frame Length equals `expected_total`, its sequence equals `expected_seq`, its payload is at most the capacity, at least 64 bytes for `CONT` and at least 1 byte for `LAST`, and `accumulated_bytes` plus the payload is at most `expected_total`.
3. **Advance**: the payload is appended and `accumulated_bytes` advanced. On `LAST` or `SINGLE`, `accumulated_bytes` must now equal `expected_total`; the timer is cancelled, the state reset and the frame handed to the phase the connection is in. Otherwise `expected_seq` is incremented.

A reassembled frame goes to the handler of the phase the connection is in, the Routing phase (§2.2.1), the CPace phase (§6.1), the Noise pairing phase (§6.2) or the Noise session phase (§6.3). The payload never selects the handler; a frame in the wrong phase is a violation.

---

### 6. Normative Cryptographic Protocols

RAPP v26.11.8 specifies three normative cryptographic protocols:
1. **`CPaceRistretto255`**: the PAKE of the pairing ceremony (§6.1).
2. **`Noise_XXpsk3`**: the pairing handshake that turns the PAKE result into a stored pairing (§6.2).
3. **`Noise_KK`**: the session handshake between paired endpoints (§6.3).

### 6.1 CPaceRistretto255 KC2 Profile (draft-irtf-cfrg-cpace-21, RFC 9496, RFC 5869)

RAPP v26.11.8 specifies the **`CPaceRistretto255-KC2`** application profile over [draft-irtf-cfrg-cpace-21](https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-cpace-21), [RFC 9496](https://www.rfc-editor.org/rfc/rfc9496.html), and [RFC 5869](https://www.rfc-editor.org/rfc/rfc5869.html):

#### 6.1.1 Cryptographic Suite Definition
- **Group**: Prime-order Ristretto255 group (order $q = 2^{252} + 27742317777372353535851937790883648493$).
- **Hash Function**: SHA-512 (block size 128 bytes, output 64 bytes).
- **Domain Separation Identifiers (DSI)**:
  - Base Point DSI: `CPaceRistretto255` (`b"CPaceRistretto255"`)
  - Intermediate Session Key DSI: `CPaceRistretto255_ISK` (`b"CPaceRistretto255_ISK"`)
- **MapToGroup & Identity Handling**: Maps 64-byte uniform hash output to a Ristretto255 group element using `RistrettoPoint::from_uniform_bytes` per [RFC 9496 Section 4.3.4](https://www.rfc-editor.org/rfc/rfc9496.html#section-4.3.4) and draft-irtf-cfrg-cpace-21 Appendix A.2. If the mapped point is the group identity $\mathcal{O}$ (probability $2^{-252}$), the endpoint aborts the pairing offer, zeroizes every intermediate value and stops advertising the offer.
- **Scalar Sampling**:
  Each ephemeral scalar is drawn as 64 uniform bytes from a cryptographically secure pseudorandom number generator (CSPRNG), reduced modulo $q$, and redrawn if the result is zero. This yields a scalar in $[1, q-1]$ at a statistical distance below $2^{-128}$ from uniform, in place of the rejection sampler of draft-irtf-cfrg-cpace-21 §8.3.
- **Context $C$ and Protocol Binding**:
  The channel identifier `CI` binds the pairing ceremony parameters in deterministic CBOR ([RFC 8949 Section 4.2.1](https://www.rfc-editor.org/rfc/rfc8949.html#section-4.2.1)):
  ```cddl
  pairing-context = [
    "rapp-pairing-context",
    [26, 11, 8],                                                              ; wire version [Year, Month, Day]
    "CPACE-RISTR255-SHA512-RAPP-KC2 + Noise_XXpsk3_25519_ChaChaPoly_SHA512", ; full suite literal
    tstr,                                                                    ; transport profile of the connection (§2.2)
    tstr,                                                                    ; candidate_id of its offer entry (§4.2)
    bstr .size 32,                                                           ; offer_hash
    "requester",                                                             ; initiator role A
    "custodian"                                                              ; responder role B
  ]
  ```
  $$C = \text{encode\_deterministic\_cbor}(\text{pairing-context}) \quad (177\text{ bytes on BLE, 178 bytes on stream})$$
  Both parties' associated data (AD) is empty:
  $$\text{CI} = C, \quad \text{AD}_A = \emptyset, \quad \text{AD}_B = \emptyset$$
  Role strings designate protocol roles, not device identities: the Requester is the initiator ($A$) and the Custodian the responder ($B$) on every transport.

#### 6.1.2 Generator Derivation (draft-21 Appendix A.2)
The generator point $G$ is derived from the password-related string (PRS), the 6-character pairing code as UTF-8 (§3.1), by length-value (LV) encoding with zero-padding to align the first hash block:
1. **Length-Value Encoding**:
   Each byte string $S$ is encoded with a Little Endian Base 128 (LEB128) length prefix as $\text{lv}(S) = \text{LEB128}(|S|) \parallel S$, where $|S|$ is the length of $S$ in bytes, and $\text{LEB128}$ is unsigned little-endian base 128 encoding (1 byte for lengths $< 128$). The total encoded length is $|\text{lv}(S)| = |\text{LEB128}(|S|)| + |S|$. The concatenation of multiple fields is $\text{lv\_cat}(S_1, S_2, \dots, S_k) = \text{lv}(S_1) \parallel \text{lv}(S_2) \parallel \dots \parallel \text{lv}(S_k)$.
2. **First-Block Zero-Padding**:
   The zero padding $\text{len\_zpad}$ makes the encoded prefix $\text{lv}(\text{DSI}) \parallel \text{lv}(\text{PRS}) \parallel \text{lv}(\text{zero\_bytes}(\text{len\_zpad}))$ fill the first SHA-512 input block of 128 bytes exactly. Because $\text{len\_zpad} < 128$, its length prefix is 1 byte, so:
   $$\text{len\_zpad} = \max(0, 128 - 1 - |\text{lv}(\text{PRS})| - |\text{lv}(\text{DSI})|)$$
   where:
   - $|\text{lv}(\text{DSI})| = |\text{LEB128}(|\text{DSI}|)| + |\text{DSI}| = 1 + 17 = 18\text{ bytes}$ for $\text{DSI} = \text{b"CPaceRistretto255"}$
   - $|\text{lv}(\text{PRS})| = |\text{LEB128}(|\text{PRS}|)| + |\text{PRS}| = 1 + 6 = 7\text{ bytes}$
   - Yielding $\text{len\_zpad} = 128 - 1 - 7 - 18 = 102\text{ bytes}$ of zeros.
3. **Generator String & Point Evaluation**:
   $$\text{gen\_str} = \text{lv\_cat}(\text{DSI}, \text{PRS}, \text{zero\_bytes}(102), C, \text{SID}) \quad (340\text{ bytes on BLE, 341 bytes on stream})$$
   $$G = \text{MapToGroup}(\text{SHA-512}(\text{gen\_str}))$$
   where $\text{SID} = \text{offer\_id}$. $G = \mathcal{O}$ aborts as §6.1.1 says.

#### 6.1.3 Ephemeral Exchange, Key Schedule, and Mutual Confirmation
1. **Initiator (Requester - Step 1)**:
   - Samples scalar $x_A \leftarrow \text{Scalar} \setminus \{0\}$ as §6.1.1 says.
   - Computes $Y_A = x_A \cdot G$. Encodes to 32 bytes via canonical Ristretto255 point compression.
   - Transmits 32-byte $Y_A$ in CPace Step 1 as one transport frame.
2. **Responder (Custodian - Step 2)**:
   - Receives $Y_A$, decodes and validates $Y_A \ne \mathcal{O}$ and canonical Ristretto255 element.
   - Atomically admits the attempt (`active_attempt = true`, §3.3 item 2).
   - Arms the attempt timer at admission: $\text{attempt\_deadline} = \min(\text{admission\_time} + 5.0\text{ s}, \text{offer\_deadline})$.
   - Samples scalar $x_B \leftarrow \text{Scalar} \setminus \{0\}$ as §6.1.1 says.
   - Computes $Y_B = x_B \cdot G$.
   - Computes shared point $K = x_B \cdot Y_A$. Verifies $K \ne \mathcal{O}$.
   - Derives Intermediate Session Key (ISK):
     $$\text{transcript\_ir} = \text{lv\_cat}([Y_A, \emptyset]) \parallel \text{lv\_cat}([Y_B, \emptyset])$$
     $$\text{isk\_input} = \text{lv\_cat}([\text{DSI}_{\text{ISK}}, \text{SID}, K]) \parallel \text{transcript\_ir}$$
     $$\text{ISK} = \text{SHA-512}(\text{isk\_input}) \quad (64\text{ bytes})$$
   - Derives the transcript hash ($TH$), the pseudorandom key ($PRK$) and the keys drawn from it with HKDF-SHA-512 (RFC 5869):
     $$TH = \text{SHA-512}(\text{lv\_cat}([\text{"rapp-cpace-transcript"}, \text{SID}, C, Y_A, Y_B])) \quad (64\text{ bytes})$$
     $$PRK = \text{HKDF-Extract-SHA512}(\text{salt} = TH, \text{IKM} = \text{ISK}) \quad (64\text{ bytes})$$
     $$PSK = \text{HKDF-Expand-SHA512}(PRK, \text{info} = \text{"rapp-noise-psk"}, L = 32)$$
     $$K_A = \text{HKDF-Expand-SHA512}(PRK, \text{info} = \text{"rapp-cpace-confirm-a-key"}, L = 32)$$
     $$K_B = \text{HKDF-Expand-SHA512}(PRK, \text{info} = \text{"rapp-cpace-confirm-b-key"}, L = 32)$$
   - Computes mutual confirmation authenticator $T_B$:
     $$T_B = \text{FIRST32}(\text{HMAC-SHA512}(\text{key} = K_B, \text{data} = \text{lv\_cat}([\text{"rapp-cpace-confirm-b"}, TH])))$$
   - Transmits 64-byte $Y_B \parallel T_B$ in CPace Step 2 as one transport frame.
3. **Key Confirmation (Requester - Step 3)**:
   - Requester receives $Y_B \parallel T_B$, decodes and validates $Y_B \ne \mathcal{O}$ and canonical point.
   - Computes shared point $K = x_A \cdot Y_B$. Verifies $K \ne \mathcal{O}$.
   - Derives identical $\text{ISK}, TH, PRK, PSK, K_A, K_B$.
   - Verifies $T_B$ in constant time against received 32-byte tag. Any mismatch immediately aborts the attempt and destroys temporary state.
   - Computes mutual confirmation authenticator $T_A$:
     $$T_A = \text{FIRST32}(\text{HMAC-SHA512}(\text{key} = K_A, \text{data} = \text{lv\_cat}([\text{"rapp-cpace-confirm-a"}, TH])))$$
   - Transmits 32-byte $T_A$ in CPace Step 3 as one transport frame.

#### 6.1.4 Finalization and PSK Handoff
- The Custodian verifies $T_A$ in constant time within the attempt deadline. On success it clears `active_attempt`, marks the offer **consumed**, cancels the attempt timer and hands the connection to the Noise pairing phase, which completes the handshake of §6.2 within 10 seconds; the parameter echo, grant exchange and storage of §4.3 that follow complete within 10 seconds of the handshake. A ceremony that has been handed off is not destroyed by the offer's 5-minute TTL; any Noise failure, protocol mismatch or missed deadline destroys the candidate trust at once.
- Both parties zeroize $\text{ISK}, PRK, K_A, K_B, x_A, x_B$ and $K$ at once.
- The 32-byte $PSK$ is the pre-shared key of the `Noise_XXpsk3` pairing handshake (§6.2).

### 6.2 Noise_XXpsk3 Pairing Handshake (RFC 7748, RFC 8439, RFC 5869)

- **Suite**: `Noise_XXpsk3_25519_ChaChaPoly_SHA512`
- **Underlying Primitives**:
  - Diffie-Hellman (DH): Curve25519 / X25519 per [RFC 7748](https://www.rfc-editor.org/rfc/rfc7748.html) (32-byte keys).
  - Cipher: ChaCha20-Poly1305 per [RFC 8439](https://www.rfc-editor.org/rfc/rfc8439.html) (32-byte key, 12-byte nonce, 16-byte tag). Nonce layout: 4 zero bytes followed by the 64-bit sequence counter as 8 little-endian bytes (Noise Protocol Framework revision 34 Section 12.3).
  - Hash: SHA-512 per Federal Information Processing Standard (FIPS) 180-4 of the National Institute of Standards and Technology (NIST), [doi:10.6028/NIST.FIPS.180-4](https://doi.org/10.6028/NIST.FIPS.180-4) (64-byte output, 128-byte block size).
  - Key derivation: HKDF-SHA-512 per [RFC 5869](https://www.rfc-editor.org/rfc/rfc5869.html).
- **Static Keys**: the fresh pair-specific X25519 keypair $(s, s_{pub})$ of §4.3.
- **Handshake Pattern**:
  ```text
  Noise_XXpsk3(s, rs):
    -> e
    <- e, ee, s, es
    -> s, se, psk
  ```
- **Pre-messages**: None.
- **Prologue**: `encode_deterministic_cbor(pairing-prologue)` (§4.3).
- **PSK Input**: The 32-byte $PSK$ of §6.1.4 enters at token `psk` through `MixKeyAndHash(psk)` (Noise revision 34 Section 9.2).
- **Handshake Payload Policy**: All handshake message payloads are empty ($\emptyset$, length 0). Encrypting an empty payload produces a 16-byte Poly1305 authentication tag.
- **Handshake Messages**:
  - Message 1 (Initiator -> Responder):
    Tokens: `e`.
    Per Noise revision 34 §9.2 (PSK mode), processing token `e` executes `MixKey(e.public_key)`, keying the CipherState. Encrypting the empty handshake payload produces a 16-byte Poly1305 authentication tag appended after the unencrypted 32-byte ephemeral public key $e_{pub}$.
    Total size: $32 + 16 = 48\text{ bytes}$.
  - Message 2 (Responder -> Initiator):
    Tokens: `e, ee, s, es`.
    Carries unencrypted 32-byte ephemeral public key $e_{pub}$, encrypted 32-byte static public key $s_{pub}$ (48 bytes including 16-byte Poly1305 tag), and 16-byte empty payload tag.
    Total size: $32 + 48 + 16 = 96$ bytes.
  - Message 3 (Initiator -> Responder):
    Tokens: `s, se, psk`.
    Carries encrypted 32-byte static public key $s_{pub}$ (48 bytes including 16-byte Poly1305 tag), mixes $psk$, and 16-byte empty payload tag.
    Total size: $48 + 16 = 64$ bytes.
- **Identifiers**:
  On completing Message 3, both endpoints derive from the 64-byte handshake hash $h$:
  ```text
  session_id = first 16 bytes of SHA-512("rapp-session-id" || h)
  pair_id    = first 16 bytes of SHA-512("rapp-pair-id" || h)
  ```
  Both endpoints then zeroize $PSK$ and the ephemeral keys.

### 6.3 Noise_KK Operational Session Handshake (RFC 7748, RFC 8439, RFC 5869)

- **Suite**: `Noise_KK_25519_ChaChaPoly_SHA512`, over the primitives of §6.2.
- **Handshake Pattern**:
  ```text
  Noise_KK(s, rs):
    -> s
    <- s
    ...
    -> e, es, ss
    <- e, ee, se
  ```
- **Initialization**: `protocol_name` is `"Noise_KK_25519_ChaChaPoly_SHA512"`, 32 bytes, so $h = \text{protocol\_name} \parallel 0^{32}$ and $ck = h$. The prologue mixed into $h$ is `encode_deterministic_cbor(session-prologue)` (§4.3). The pre-message static keys are mixed in pattern order: the initiator's (the Requester's) first, then the responder's (the Custodian's).
- **Messages**: Both handshake payloads are empty, so each message is a 32-byte ephemeral public key followed by a 16-byte Poly1305 tag over the empty payload with $h$ as associated data: 48 bytes, one transport frame. Tokens are processed as Noise revision 34 Section 5 prescribes; each `MixKey` runs $\text{HKDF-SHA-512}(ck, \text{DH output}, 2)$ and resets the cipher state's sequence counter to 0. A received ephemeral public key that is the all-zero point is rejected.
- **Transport Mode**: On completing Message 2 both endpoints call `Split()`:
  $$PRK = \text{HMAC-SHA-512}(ck, \emptyset), \quad out1 = \text{HMAC-SHA-512}(PRK, \text{0x01}), \quad out2 = \text{HMAC-SHA-512}(PRK, out1 \parallel \text{0x02})$$
  $$c_1 = out1[0..32], \quad c_2 = out2[0..32]$$
  The Requester sends under $c_1$ and receives under $c_2$; the Custodian the reverse. Each direction's nonce starts at 0 and increases by 1 per frame. The session identifier is
  $$\text{session\_id} = \text{SHA-512}(\texttt{"rapp-session-id"} \parallel h)[0..16]$$
  and scopes every envelope of the session (§7). The ephemeral private keys are zeroized at once.

### 6.4 Session Handshake Vectors

The entries `"session-kk-fixed-transcript-ble"` and `"session-kk-fixed-transcript-stream"` of `doc/protocols/vectors/rapp-v26.11.8.json` pin, for fixed static and ephemeral keys and a fixed session prologue, both handshake messages, the final handshake hash $h$, the directional keys $c_1$ and $c_2$ and the `session_id` of §6.3, one entry per transport profile. An implementation reproduces them byte for byte.

---

## 7. Authenticated Message Envelopes and Wire Framing

### 7.1 Message Envelope and Schemas
Every message inside the Noise pairing phase or the Noise session phase is a deterministic CBOR envelope conforming to this Concise Data Definition Language (CDDL):

```cddl
rapp-message = {
  "version": [26, 11, 8],
  "session_id": bstr .size 16,
  "sequence": uint,
  message
}

message //= ( "type": "pairing.hello",      "body": pairing-hello-body )
message //= ( "type": "pairing.confirm",    "body": pairing-confirm-body )
message //= ( "type": "pairing.abort",      "body": pairing-abort-body )
message //= ( "type": "pairing.stored",     "body": pairing-stored-body )
message //= ( "type": "session.ready",      "body": session-ready-body )
message //= ( "type": "session.hello",      "body": session-hello-body )
message //= ( "type": "session.close",      "body": session-close-body )
message //= ( "type": "liveness.ping",      "body": liveness-ping-body )
message //= ( "type": "liveness.pong",      "body": liveness-pong-body )
message //= ( "type": "operation.request",  "body": operation-request-body )
message //= ( "type": "operation.result",   "body": operation-result-body )
message //= ( "type": "operation.progress", "body": operation-progress-body )
message //= ( "type": "card.status",        "body": card-status-body )
message //= ( "type": "error",              "body": error-body )

; 1. Pairing Peer Introduction
pairing-hello-body = {
  "parameters": negotiated-parameters,
  "display_name": tstr .size (1..256),   ; the sender's name, not blank (§4.3 item 3)
  "platform": tstr .size (1..256),       ; the sender's platform description, not blank
  ? "requested_profiles": [* tstr]
}

negotiated-parameters = {
  "version": [26, 11, 8],
  "suite": "CPACE-RISTR255-SHA512-RAPP-KC2 + Noise_XXpsk3_25519_ChaChaPoly_SHA512",
  "offer_hash": bstr .size 32,
  "transport_profile": tstr,   ; transport profile of the connection (§2.2)
  "candidate_id": tstr         ; candidate_id of its offer entry (§4.2)
}

; 2. Grant Confirmation
pairing-confirm-body = {
  "granted_profiles": [* tstr]
}

; 3. Pairing Abort
pairing-abort-body = {
  "reason": tstr
}

; 4. Pairing Storage Confirmation
pairing-stored-body = {
  "pair_id": bstr .size 16
}

; 5. Session Ready
session-ready-body = {
  "parameters": session-parameters,
  "nonce": bstr .size 32,
  "display_name": tstr .size (1..256)    ; the Custodian's current name, not blank (§4.3 items 3 and 4)
}

; 5a. Session Hello
session-hello-body = {
  "display_name": tstr .size (1..256)    ; the Requester's current name, not blank (§4.3 items 3 and 4)
}

session-parameters = {
  "version": [26, 11, 8],
  "suite": "Noise_KK_25519_ChaChaPoly_SHA512",
  "transport_profile": tstr,   ; transport profile of the connection (§2.2)
  "candidate_id": tstr,        ; its registered candidate_id (§2.2)
  "grants_hash": bstr .size 32
}

; 6. Session Close
session-close-body = {
  "reason": close-reason-val
}

close-reason-val =
    "normal"
  / "complete"
  / "user_disconnect"
  / "policy"
  / "protocol_violation"
  / "pairing_revoked"    ; the sender revoked the pairing: its user forgot it, or it expired (§4.6)
  / "shutdown"
  / "card_unavailable"   ; the Custodian can no longer serve the card
  / "service_withdrawn"  ; the sender withdrew: a Custodian stopped serving, or a Requester stopped using, every pairing (§4.5)

; 7. Liveness Challenge
liveness-ping-body = {
  "challenge": bstr .size 32
}

; 8. Liveness Echo
liveness-pong-body = {
  "challenge": bstr .size 32
}

; 9. Operation Request
operation-request-body = {
  "operation_id": bstr .size 16,
  "profile": tstr,
  "action": tstr,
  "context": { * tstr => any },
  "payload": { * tstr => any },
  ? "expires_after_ms": uint
}

; 10. Operation Result
operation-result-body = {
  "operation_id": bstr .size 16,
  "status": operation-status-val,
  ? "response": { * tstr => any },
  ? "error": tstr
}

operation-status-val =
    "completed"
  / "rejected"
  / "cancelled"

; 11. Operation Progress
operation-progress-body = {
  "operation_id": bstr .size 16,
  "event": progress-event-val
}

progress-event-val =
    "queued"            ; another session's operation holds the card (§8.2)
  / "consent_shown"
  / "waiting_for_card"
  / "card_wait_ended"
  / "waiting_for_unlock" ; the Custodian's device is locked (§8.2 item 3); added 2026-11-07

; 12. Card Presence
card-status-body = {
  "card_present": bool,
  "reader_attached": bool,                   ; a contact card reader is connected to the Custodian (§8.4 item 1)
  "certificate_fingerprint": bstr .size 32   ; SHA-256 of the authentication certificate; all zero when card_present is false
}

; 13. Protocol Error: error-body is defined in §10.3
```

#### Message Semantics:
1. **`pairing.hello`**: Sent by each endpoint in the Noise pairing phase right after the handshake. Echoes the negotiated parameters and carries the sender's display name and platform (§4.3 item 3); the Requester's also carries `requested_profiles`, exactly the profiles of the offer, and the Custodian's carries no `requested_profiles` field; a Requester's hello without it, or a Custodian's with it, aborts the pairing. Each endpoint checks every echoed parameter against the offer; any difference, and a missing, blank or over-long `display_name` or `platform`, aborts the pairing.
2. **`pairing.confirm`**: Sent by the Custodian with the profiles it grants from those requested, then echoed by the Requester. Both verify the lists are identical before deriving `grants_hash` (§4.3).
3. **`pairing.abort`**: Sent by either endpoint to cancel a pairing before the records are stored, with a reason for display. Ephemeral keys are destroyed at once.
4. **`pairing.stored`**: Sent by each endpoint once its pairing record is durably stored, carrying the derived `pair_id`. An endpoint treats the pairing as active only after receiving it (§4.3 item 4).
5. **`session.ready`**: Sent by the Custodian on completing the `Noise_KK` handshake, echoing the session parameters with a fresh random 32-byte `nonce` and carrying the Custodian's current display name (§4.3 item 4).
6. **`session.hello`**: Sent by the Requester as its first message once it has verified `session.ready`, carrying its current display name (§4.3 item 4); a Requester whose pairing is revoking sends its `pairing_revoked` close instead (§4.6 item 2). A Custodian that receives any other message first, apart from that close, closes the session as an authenticated protocol violation. The Custodian sends `card.status` (§8.4) without waiting for it, and admits no `operation.request` before it.
7. **`session.close`**: Sent by either endpoint to end a session, with a registered reason. A close is acknowledged. An endpoint that receives an authenticated `session.close`, whatever its reason and wherever in the session, in place of `session.ready` and as the Requester's first message included, acts on it, answers with its own `session.close` carrying the same reason (the **echo**), and closes the transport. The sender of a close sends nothing more on the session, ignores every message but a `session.close`, and closes the transport once the echo arrives or its wait ends: at most 1 second (`quit_withdrawal_bound_ms`). The echo is the evidence that the peer received the close and acted on it, for example forgot the pairing. Without the echo inside the wait the close is not known to have been delivered, and the stated limits apply: a Requester keeps the pairing it forgot in its revocation backlog for the next session (§4.6 item 6), a pairing the peer was told to forget otherwise leaves it by idle expiry (§4.6 items 5 and 8), and a peer told of a withdrawal sees a loss. An echo is never answered: a `session.close` that arrives while an endpoint waits for the echo of its own close is that echo, whatever its reason, so two closes that cross acknowledge each other; the endpoint still acts on the reason it received. An endpoint that ends a session on an AEAD or framing failure or on the silence limit (§8.3) sends no close and waits for nothing (STPA UCA-124, CC-123).
8. **`liveness.ping`** and **`liveness.pong`**: Keepalive sent by either endpoint with a fresh 32-byte `challenge`, echoed exactly by the peer.
9. **`operation.request`**: Sent by the Requester to start a credential action under a registered profile (§8, §9).
10. **`operation.result`**: Sent by the Custodian with the outcome of the operation: its status and the response, or the error (§8).
11. **`operation.progress`**: Sent by the Custodian while an operation is pending, for every change of its state: queued behind another session's operation, waiting for the holder to unlock the Custodian's device, a PIN prompt on screen, waiting for the card, card found (§8.2). A Requester shows each event to its user: feedback is never withheld in the name of security.
12. **`card.status`**: Sent by the Custodian once right after `session.ready` and again whenever the card it holds changes (present or absent, and which card, by the fingerprint of its authentication certificate) or a card reader is attached to it or detached (§8.4).
13. **`error`**: Sent on a protocol condition that is not an operation outcome, such as a second request while one operation of the session is live; schema and codes in §10.3.

### 7.2 Envelope Rules
1. **Version**: `version` is `[26, 11, 8]`, as `[Year, Month, Day]`. A version mismatch in a Noise prologue fails the handshake's AEAD: the link drops and stored pairings stay. An authenticated envelope with any other version closes the session.
2. **Session**: `session_id` is the identifier derived from the handshake hash of the phase the envelope belongs to, the pairing `session_id` of §6.2 or the operational `session_id` of §6.3. An envelope with another `session_id` closes the session.
3. **Sequence**: `sequence` starts at 0 in each direction and increases by exactly 1 per envelope; it equals the nonce of the Noise cipher state that encrypted the envelope. The first envelope received in a direction has `sequence` 0 and each accepted envelope raises the expected value by 1. An envelope whose `sequence` is not the expected value closes the session. A session ends as §8.3 says; the counter never wraps in practice, and an endpoint that would exceed $2^{64}-1$ closes the session with reason `"normal"`.
4. **Encapsulation**: The `rapp-message` is encoded as deterministic CBOR (RFC 8949 Section 4.2) and encrypted with ChaCha20-Poly1305 under the direction's Noise cipher state, giving the ciphertext and a 16-byte tag. The ciphertext is one transport frame (§2.2).

---

## 8. Operations

An operation is one credential action, an authentication signature, a document signature or a read, carried out on the card for one Requester. It lives inside the session that carried it.

### 8.1 Operation Lifetime

1. **Request**: The Requester sends `operation.request` with a fresh 16-byte `operation_id`, the profile and action (§9), the context and payload maps, and `expires_after_ms` if it has a deadline of its own. An `operation_id` the session has already seen is rejected with `error` `"duplicate_operation"`. A session carries one operation at a time: a request that arrives while another is live on the session is rejected with `error` `"busy"`.
2. **Deadline**: `expires_after_ms`, if present, is above 0; 0 is rejected with `"invalid_lifetime"`. If absent, the Custodian uses 300,000 ms. The Custodian takes the deadline on a clock that keeps running while the device sleeps and the process is suspended (`CLOCK_BOOTTIME`, `mach_continuous_time`, `SystemClock.elapsedRealtime`). An operation whose deadline passes before the card has been commanded is cancelled: `operation.result` with `status` `"cancelled"` and `error` `"operation_expired"`, and its PIN prompt, if any, is taken down or never shown. A Custodian that wakes from suspension checks every pending operation against the clock before showing anything.
3. **End**: An operation ends with its `operation.result`, or with the session. When the session closes, every operation of it is over: one that has not yet commanded the card is dropped, one whose card command is in progress runs to the card's answer, since a card command is never interrupted, and the answer is discarded. The Custodian remembers nothing of an operation once it is over. A Requester that did not receive a result starts a new operation with a new `operation_id` if it still needs one.

### 8.2 Execution

1. **Authorization**: The requested profile must be among the pairing's `granted_profiles`; otherwise `operation.result` with `status` `"rejected"` and `error` `"unauthorized"`.
2. **Queue**: The card serves one operation at a time, across every session the Custodian holds. Operations take the card in the order they arrived. While an operation of another session holds the card, the Custodian sends the waiting operation `operation.progress` with event `"queued"`, once when it joins the queue; when its turn comes it proceeds. An operation that expires in the queue is cancelled as §8.1 item 2 says.
3. **PIN**: A credential action (§9) runs only while the Custodian's device is unlocked. While its lock screen is up, whatever secures it, the Custodian starts no credential command: it sends `operation.progress` with event `"waiting_for_unlock"`, shows the request on the lock screen (which computer asks, and whether it is a login with PIN 1 or a signature with PIN 2), and continues when the holder unlocks within the operation's deadline (§8.1 item 2); the holder is not asked for a PIN the Custodian holds. A card command already sent when the device locks runs to its answer (§8.1 item 3): the holder who approved and then locked the phone gets the result. A device with no lock screen configured is never locked; that is the holder's choice. An action that needs a PIN (§9) takes it on the Custodian. When the Custodian does not hold the PIN, it asks the holder on its own screen and, once the prompt is on screen, sends `operation.progress` with event `"consent_shown"`: entering the PIN is the holder's consent, and there is no other consent view; a browser authentication whose PIN 1 the Custodian holds (§11 item 2) runs without a prompt. The prompt renders from a snapshot of the request taken at admission; nothing that arrives later changes it. If the holder declines, the operation ends with `status` `"rejected"` and `error` `"user_cancelled"`; no card command is sent.
4. **Card**: The Custodian checks the retry floor (§10.2) and commands the card over NFC or through its reader. While it waits for the holder to present the card it sends `operation.progress` with event `"waiting_for_card"`, and `"card_wait_ended"` when the card is found or the wait is over.
5. **Result**: The Custodian sends `operation.result` with `status` `"completed"` and the response, `"rejected"` with the error, or `"cancelled"` with the error.
6. **Reads**: A read-only action (`inspect_card`, `read_identity`, `read_certificate`) commands no private key and no PIN. It takes its turn in the queue and asks the holder nothing.

### 8.3 Session Lifetime

A session lives as long as both endpoints are in sight. An endpoint that has heard nothing from its peer for 5 seconds sends `liveness.ping`; the peer answers `liveness.pong` at once. Thirty seconds without any message from the peer, or a transport close, ends the session (§10.1 item 2). While it has not withdrawn (§4.5), a Requester keeps a session open to its paired Custodian while the Custodian is in sight, so that an operation can start at once and the Custodian's state reaches the Requester as it changes. A Custodian holds as many sessions as Requesters dial (§2.2.2), and goes on serving them while it offers a pairing (§4.2).

The Custodian is **in sight** while a `mode=session` record whose discovery hint matches the pairing (hierarchy specification §4.3), or a `mode=session` record that carries no hints, or the RAPP BLE advertisement, is seen; routing decides whether a hint-less record belongs to the pairing. The Custodian **appears** when such a record comes into sight, for the first time, under a fresh instance name, or back after vanishing, and when the BLE advertisement is first seen after it was out of sight. A Requester dials only:
1. when the Custodian appears;
2. when a local consumer asks for the card with no session open (§8.4 item 3);
3. within the **redial window**: after a loss of the session (§4.5 item 6, item 4; a protocol violation opens no window), or after a dial that ended before `session.ready`, the Requester redials with a back-off of its own for at most `redial_window_ms` = 120000 ms, counted from the loss or from the first failed dial since the Custodian last appeared. The window equals `identity_offer_grace_ms` (§8.4 item 3), so the Requester stops redialing when it would stop offering the Custodian's identity after a loss. When the window has passed without a session, the Requester dials again only when the Custodian next appears or a consumer asks.

No dial runs on a timer outside the redial window, and none while the Custodian is withdrawn (§4.5 item 6). Two connections are outside these rules: a pairing connection while a code is tried (§4.2), and the one connection a forgotten pairing in the Requester's revocation backlog opens each time its Custodian appears (§4.6 item 6), which runs whether remote use is on, off or suspended. A `mode=session` record that appears is dialed at once, before any BLE scan still running for the pairing (hierarchy specification §3). Dialing, scanning and redialing are never shown to the user (§4.7).

### 8.4 Card Presence and Identity Offering

A Requester that offers the Custodian's credentials to local consumers (a browser's certificate chooser, a CryptoTokenKit or Public-Key Cryptography Standards (PKCS)#11 token) makes a claim on the Custodian's behalf: that the card can answer when asked. The claim rests on the Custodian's own word on an authenticated session, never on discovery, and follows it eventually: a card that is gone leaves every Requester within the grace of item 3.

1. **`card.status`**:
   On every session the Custodian sends `card.status` once right after `session.ready`, and again whenever the card it holds changes or a card reader is attached to it or detached. `card_present` is true while the Custodian holds a card: a card in its reader, from insertion until removal, or an NFC card the holder has added to the Custodian, from adding until the holder removes it there. An operation that ends without the card answering (no card within the card wait, the card lost before a command was transmitted, the field lost) ends with `"card_error"` and leaves presence unchanged; the next operation asks the holder to present the card again. A card busy with another session's operation is present: the queue of §8.2 item 2 holds the waiting operation, and `card.status` does not change. `reader_attached` is true while a contact card reader is connected to the Custodian: a reader built into it, or one attached to its Universal Serial Bus (USB) or Lightning port. It is false otherwise, including on a Custodian that reads cards only over NFC. Attaching or detaching a reader leaves `card_present` as it is, except that detaching a reader removes the card in it; an NFC card the holder has added stays present.
2. **Which Card**:
   While `card_present` is true, `certificate_fingerprint` carries the SHA-256 digest of the Distinguished Encoding Rules (DER) encoding of the card's authentication certificate; while it is false the field is 32 zero bytes. A Requester compares a present card's fingerprint with the fingerprint of the certificates it holds for the pairing and, on any difference or when it holds none, reads the certificates afresh (§9) before offering anything; a report of absence is not a different card; it offers only an identity whose fingerprint the Custodian confirmed on a session.
3. **Offering Rule**:
   A Requester offers a pairing's credentials to local consumers on a certificate whose fingerprint the Custodian confirmed on a session, and keeps offering it between sessions: when a request arrives with no session open, the Requester dials the Custodian and holds the request until a session opens or the consumer's own deadline passes. It withdraws the offer when, for 120 seconds, no session to the Custodian has been open or the Custodian has reported absence, with no `card.status` reporting the card present in that time; at once when the pairing is forgotten or revoked (§4.6); at once when the Requester itself withdraws (§4.5 item 8); at once on a verified withdrawal of the Custodian, or its `"card_unavailable"` close (§4.5 item 6); and at once when a session reports a different card present (item 2). It offers again as soon as a session confirms the card. Discovery records (hierarchy specification §4.3) tell a Requester whom to dial; they never justify an offer.
4. **Privacy**:
   `card.status` travels only inside the AEAD-encrypted session. No discovery record, advertisement, or plaintext frame reflects the card's presence or the Custodian's card reader.
5. **Ending the Session**:
   A Custodian that can no longer serve any card for the rest of the session closes it with reason `"card_unavailable"`; a Custodian that expects the card back keeps the session open and reports presence through `card.status`. A Requester that receives a `"card_unavailable"` close withdraws the Custodian's identity at once, does not redial, and waits for the Custodian's next announcement (§4.5 item 6). A Custodian that closed sessions with `"card_unavailable"` announces itself again when it can serve a card once more: it registers its stream service under a fresh instance name in place of the current one and restarts its BLE advertisement, so every Requester sees it appear (§8.3).
6. **Asking for the Card**:
   A Requester that asks its user for the card names the Custodian's card reader only while the latest `card.status` on an open session reports the card absent and `reader_attached` true, and then asks for the card in that reader. Otherwise it asks the user to present the card to the Custodian. `reader_attached` changes no offer: item 3 alone governs offering and withdrawal.

---

## 9. Registered Credential Profiles and Actions

The profiles a pairing can grant (§4.3), and the actions of each:

| Profile | Purpose | Card commands |
| :--- | :--- | :--- |
| `"fi.refineid.card-status"` | Answer to reset (ATR), identity | Reads only |
| `"fi.refineid.authentication"` | Workstation/browser authentication signatures | PIN 1 verify & private-key signature |
| `"fi.refineid.document-signing"` | Qualified Electronic Signatures (QES) | PIN 2 verify & private-key signature |

### 9.1 Profile: `"fi.refineid.card-status"`
- **`inspect_card`** (Safe Read):
  - Context & Payload: Empty maps (`{}`).
  - Response:
    ```cddl
    inspect-card-response = {
      "atr": bstr                        ; answer to reset, or its historical bytes; empty when the platform exposes neither
    }
    ```
- **`read_identity`** (Safe Read):
  - Context & Payload: Empty maps (`{}`).
  - Response:
    ```cddl
    read-identity-response = {
      "card_holder_name": tstr .size (1..128),
      "card_id": tstr .size (1..64),
      "issuance_date": tstr .size (10..10),     ; "YYYY-MM-DD"
      "expiration_date": tstr .size (10..10),   ; "YYYY-MM-DD"
      "certificates": [ + bstr ],               ; Array of DER-encoded X.509 certificates
      ? "token_display_name": tstr .size (1..64)
    }
    ```

### 9.2 Profile: `"fi.refineid.authentication"`
- **`read_certificate`** (Safe Read):
  - Payload: `{"kind": "authentication"}`.
  - Response: `certificate` (DER-encoded X.509 certificate bytes).
- **`browser_authenticate`**:
  - Context: `origin` (`tstr .size (1..256)`): the Requester's own label for what is asking, such as the program and the computer it runs on (e.g. `"Firefox on work-laptop"`). No Requester can know the site, so it names none, and the Custodian does not show it (§11 item 1).
  - Payload:
    - `key_profile` (`tstr`): Registered key profile (`"ecdsa_p256"`, `"ecdsa_p384"`, `"rsa_2048"`, `"rsa_3072"`).
    - `algorithm` (`tstr`): Registered algorithm, with the digest length its hash fixes:

      | `algorithm` | Key profiles | Digest bytes |
      | :--- | :--- | :--- |
      | `"ecdsa_sha224"` | `ecdsa_p256`, `ecdsa_p384` | 28 |
      | `"ecdsa_sha256"` | `ecdsa_p256`, `ecdsa_p384` | 32 |
      | `"ecdsa_sha384"` | `ecdsa_p256`, `ecdsa_p384` | 48 |
      | `"ecdsa_sha512"` | `ecdsa_p256`, `ecdsa_p384` | 64 |
      | `"rsa_pkcs1_sha256"` | `rsa_2048`, `rsa_3072` | 32 |
      | `"rsa_pkcs1_sha384"` | `rsa_2048`, `rsa_3072` | 48 |
      | `"rsa_pkcs1_sha512"` | `rsa_2048`, `rsa_3072` | 64 |
      | `"rsa_pss_sha256"` | `rsa_2048`, `rsa_3072` | 32 |

      A P-384 key signing a Transport Layer Security (TLS) 1.3 handshake needs `"ecdsa_sha384"`.
    - `digest` (`bstr`): Pre-hashed challenge bytes matching algorithm digest length (e.g. 32 bytes for SHA-256).
  - Validation: If a request specifies an unrecognized or unsupported `key_profile` or `algorithm`, the Custodian must respond with `operation.result` carrying `status: "rejected"` and `error: "unsupported_parameter"`. The session and the pairing stay.
  - Signature Wire Format:
    - For `"ecdsa_sha256"`: The signature must be serialized as fixed-width raw Institute of Electrical and Electronics Engineers (IEEE) P1363 big-endian concatenation $r \parallel s$. For `"ecdsa_p256"`, exactly 64 bytes (32-byte $r \parallel$ 32-byte $s$); for `"ecdsa_p384"`, exactly 96 bytes (48-byte $r \parallel$ 48-byte $s$). ASN.1 DER encoding is strictly prohibited on the wire.
    - For `"rsa_pkcs1_sha256"`: The signature must be serialized as raw big-endian integer bytes matching the Rivest-Shamir-Adleman (RSA) key modulus length (256 bytes for `"rsa_2048"`, 384 bytes for `"rsa_3072"`), computed via RSASSA-PKCS1-v1_5 per RFC 8017 Section 8.2 (EMSA-PKCS1-v1_5 with SHA-256 DigestInfo prefix `3031300d060960864801650304020105000420` followed by 32-byte SHA-256 digest).
    - For `"rsa_pkcs1_sha384"` and `"rsa_pkcs1_sha512"`: as `"rsa_pkcs1_sha256"`, with the SHA-384 or SHA-512 DigestInfo prefix of RFC 8017 Section 9.2 Note 1.
    - For `"rsa_pss_sha256"`: RSASSA-PSS, the Probabilistic Signature Scheme (PSS) per RFC 8017 Section 8.1 with Mask Generation Function 1 (MGF1) over SHA-256 and the salt length the card publishes in its CIAInfo (FINEID S4-1 v4.2 Section 8.1.3), serialized as for `"rsa_pkcs1_sha256"`. Two signatures over the same digest differ.
    - For every `"ecdsa_*"` algorithm: fixed-width raw $r \parallel s$ sized by the key profile, as for `"ecdsa_sha256"`.
  - Response: `signature` (`bstr`, matching the specified signature wire format).

### 9.3 Profile: `"fi.refineid.document-signing"`
- **`read_certificate`** (Safe Read):
  - Payload: `{"kind": "signature"}`.
  - Response: `certificate` (DER-encoded X.509 signature certificate bytes).
- **`sign_document`**:
  - Context:
    ```cddl
    sign-document-context = {
      "document_name": tstr .size (1..256),          ; e.g. "Employment_Contract_2026.pdf"
      ? "contained_files": [+ tstr .size (1..256)]  ; present exactly when the document is a package
    }
    ```
    `document_name` is the document's name as the Requester knows it. A Requester asked for a signature by a program that hands it only a digest and names no document, such as an operating system's signing interface, sends in its place a truthful description of the request in the language of the computer's user interface: the program as the computer identifies it, this computer, and that the program did not name the document (e.g. `"Word on work-laptop asks for a signature (the program did not name the document)"`). It never makes up a file name, and never takes the description from the program's request.

    A package is a document that carries files: an ASiC-E container. `document_name` is the package's own name. `contained_files` is present exactly when the document is a package and absent for a single document: the names of the data objects the package holds, as the container holds them (the entry names its manifest and signature cover), in container order, each unique, none under `META-INF/` in any letter case, UTF-8. A package of one file sends its one entry. The request encodes in one transport frame (§7.2 item 4): the Requester refuses a package whose request does not fit, and never shortens the list or an entry; an entry outside `tstr .size (1..256)` is refused. The Custodian validates each entry as it validates an entry of `document_names`.
  - Payload: `key_profile`, `algorithm`, `digest` (pre-hashed document digest).
  - PIN: PIN 2 on the Custodian's screen, with the document name and, for a package, the full list of `contained_files` under it, shown as the full list of a batch is shown.
  - Signature Wire Format: as §9.2.
  - Response: `signature` (`bstr`).
- **`batch_sign_documents`**:
  - Context: `document_names` (`[+ tstr .size (1..256)]`, the documents' display names, in order). Every entry of a batch is a single document; a package is signed with `sign_document`.
  - Payload:
    - `key_profile`, `algorithm`.
    - `digests` (`[+ bstr]`, one per document, in the same order).
  - PIN: PIN 2 once for the batch on the Custodian's screen, with the full list of document names. The card takes PIN 2 for one signature at a time (FINEID S1); how the Custodian carries one entry through the batch is its own, and PIN 2 never leaves it (§11).
  - Signature Wire Format: each entry as §9.2.
  - Response: `signatures` (`[+ bstr]`, in the same order).
  - An interrupted batch ends with its session (§8.1 item 3); no signature of it is delivered.

---

## 10. Failure Semantics, Error Handling, and Retry Protection

### 10.1 Failure Handling
What an endpoint does when something goes wrong depends on how much it knows about its peer:

1. **Before authentication**: a malformed preamble, an unrouted or replayed routing tag, a short MTU, a frame out of order. The endpoint closes the connection; nothing stored changes.
2. **On a session**: a link drop, a timeout, an AEAD failure, a wrong version, a wrong `session_id` or `sequence`. A bit flip and an attacker look the same, so the endpoint closes the session and keeps the pairing; every operation of the session is over (§8). The card is never touched on the way out. A Requester redials a session that ended this way within the redial window (§8.3), except one that ended for an authenticated protocol violation, which it does not redial until the Custodian next appears (§4.5 item 6).
3. **Inside an operation**: an unknown `operation_id`, an unsupported parameter, a credential the card refused. The endpoint rejects that operation with `operation.result` or `error` (§10.3); the session and the pairing stay.

4. **Unknown vocabulary**: a message type, a progress event, a status, an error name or a field value this version does not define. The endpoint treats it as malformed and fails as items 1 to 3 say for its stage; it never ignores it. There is one version of RAPP, every peer updates together, and an endpoint that meets a word it does not know is talking to a peer it must not trust to mean the same thing. Tolerating unknown vocabulary would let two versions drift apart silently; failing loudly is the design (maintainer decision 2026-11-07).

No failure revokes an active pairing: an active pairing is revoked by its user, by idle expiry, or by its peer's `pairing_revoked` close (§4.6). A pairing whose confirmation fails is undone as §4.3 item 4 says.

### 10.2 PIN Entry and the Retry Floor
- **Retry floor (PIN 1 and PIN 2)**: Before any command that could decrement a PIN try counter, the Custodian reads the card's remaining attempts for that PIN. With **2 or 1** remaining, or a counter it cannot read, it refuses without sending any verification command, answering `operation.result` with `status: "rejected"` and `error: "retry_floor"`, and tells the holder that the card's remaining attempts are reserved for the card issuer's software. Otherwise it sends the verification: with 3 or more remaining, with the PIN reported verified, and with 0 remaining or the PIN reported blocked, where the card answers for itself and spends nothing. The card's refusal at 0 remaining or blocked ends the operation with the same `"rejected"` and `"retry_floor"`. A Custodian may tell the holder that a PIN is blocked before prompting, from a status it has read, since that sends no credential. RefineID therefore never consumes a card's last two attempts and can never block a PIN. RAPP defines no unblocking; a blocked card is unblocked with the PIN unblocking key (PUK) outside RAPP.
- **Wrong PIN**: If the card rejects the PIN (status word (SW) `63 Cx`), the Custodian tells the holder, with the attempts the card still allows, and prompts again, subject to the floor. The Requester learns nothing of it: an operation that needs a PIN ends only as `"completed"`, as `"rejected"` with `"user_cancelled"` or `"retry_floor"`, or as §8.1 says.

### 10.3 Errors
```cddl
error-body = {
  "error_name": tstr .size (1..64),
  "message": tstr .size (1..512),
  ? "operation_id": bstr .size 16
}
```

The same names appear in the `error` field of `operation.result`, except `"busy"` and `"duplicate_operation"`, which refuse a request before it becomes an operation and travel only in `error`:

| `error_name` | Meaning |
| :--- | :--- |
| `"busy"` | A request arrived while another operation of the session is live (§8.1 item 1). |
| `"duplicate_operation"` | The `operation_id` was already used on this session (§8.1 item 1). |
| `"invalid_lifetime"` | `expires_after_ms` of 0 (§8.1 item 2). |
| `"operation_expired"` | The deadline passed before the card was commanded (§8.1 item 2). |
| `"unauthorized"` | The profile is not granted to the pairing (§8.2 item 1). |
| `"unsupported_parameter"` | Unsupported key profile, algorithm or parameter value (§9). |
| `"user_cancelled"` | The holder declined the PIN prompt (§8.2 item 3). |
| `"retry_floor"` | The card reports 2 or 1 remaining attempts for the PIN, or its counter cannot be read, and no verification was sent; or the PIN has no tries left or is blocked (§10.2). |
| `"card_error"` | The card did not answer: no card within the wait, the field lost, a transmission fault. |
| `"operation_failed"` | The Custodian could not carry the operation out for a reason of its own. |

---

## 11. PINs and Secrets

1. **The holder sees what the Requester asked for**: A PIN prompt on the Custodian shows the operation it authorizes and names the paired computer that asked by the display name stored in its pair record, the `display_name` of its `pairing.hello` (§4.3 items 3 and 4). For authentication: the operation; the prompt names no site and does not show the request's `context`, since no Requester can know the site. It shows no name from the holder's certificate: the holder has their own phone and card, and the question is whether this computer may ask. For document signing: the `document_name`, or the full list of names for a batch; for a package, its name and every file it holds, as the Requester named them; for a program that named no document, the Requester's description saying so (§9.3). The Custodian never sees the document (item 3), so what the holder approves is the Requester's description of it: the Custodian attests that the holder consented to signing these digests under these names, not the content behind them. A holder who does not recognise the names declines; a Requester that describes a document falsely is the computer's own compromise, which RAPP does not claim to detect.
2. **PIN 1 and PIN 2**: PIN 1 is asked once and held only in the Custodian's memory, never in storage, until the card is removed or replaced (§8.4 item 1), the card rejects it, the holder clears it, the Custodian's process ends or the device restarts; while it is held, a browser authentication runs without a prompt. PIN 2 is entered by the holder on the Custodian for every signature or batch and kept no longer; nothing signs unattended. Neither PIN is used while the Custodian's device is locked: the request waits, visible on the lock screen, for the holder to unlock (§8.2 item 3), and the held PIN 1 is kept through the wait.
3. **Documents stay home**: Document bytes and unhashed browser data never cross RAPP; the Requester hashes locally and sends the digest.
4. **Secrets never on the wire**: PIN 1, PIN 2, the card access number (CAN) and the PUK have no representation in any RAPP message and never traverse any transport. The Custodian presents them to the card itself; a Requester receives only the signature or the result.

---

## 12. Threat Model

| Threat | What the attacker does | What stops it |
| :--- | :--- | :--- |
| **Eavesdropping** | Records traffic on the radio or the network. | Nothing in an advertisement or discovery record names a pairing. CPace resists offline guessing of the code; every handshake and session is encrypted with ChaCha20-Poly1305 under keys separated by HKDF-SHA-512. |
| **Man in the middle** | Injects, modifies or drops frames during pairing or a session. | CPace binds the context $C$ (protocol, suite, offer, transport, roles) into the generator, so a mismatched channel yields no shared key; the confirmation tags $T_B$ and $T_A$ prove the key before Noise; `Noise_XXpsk3` with fresh pairwise static keys authenticates both endpoints. A wrong code fails its attempt, and the next is admitted no sooner than 500 ms later (§3.3). |
| **Disconnect oracle** | Tests $T_B$ and disconnects before sending $T_A$, to guess faster than completed attempts allow. | The attempt is admitted before $Y_B$ and $T_B$ are sent, under the same single flight and 500 ms spacing as a completed one, and $T_B$ tests only the one code $Y_A$ was built from; disconnecting gains no guess (§3.3, §6.1.3). |
| **Rogue Custodian** | Advertises the RAPP service without the pairing code. | Without the code it cannot derive $G$ or pass the confirmation tags; the Requester pairs with nothing and tries the next Custodian in pairing mode (§4.2). Rogues that take up the 8 pairing connections of a typed code, or one that serves a copy of a real offer's `offer_id` first, can keep the Requester from the real Custodian for that code, which is then reported as not accepted; they gain nothing else, and each real Custodian still receives at most one guess per typed code. A rogue that answers `pairing-busy` holds the Requester for at most 8 openings and 35 s of waits per typed code (§4.2, "Trying Each Custodian in Pairing Mode" item 5), after which the code is reported as not accepted. |
| **Relay** | Relays frames between two distant endpoints. | Roles are fixed per transport and protocol (§4.4), so frames cannot be reflected or looped; a relay carries only what the paired endpoints send. A bit-exact relay of a pairing in progress stays possible at the physical layer and is not detected. |
| **Guess flooding** | Connects repeatedly to guess the code or to keep the offer busy. | An offer exists only while the holder opens one, for 5 minutes; one guess runs at a time, admitted at most every 500 ms, so at most 600 guesses of a 30-bit code per offer, about 1 in 1.8 million (§3.3, "Guessing Bound"). No number of failed guesses ends the offer or delays the next one, so another device's guesses cannot lock the holder out. A device that keeps the single-flight slot busy denies pairing for as long as it keeps connecting; that is inherent to pairing on a shared link and ends with the offer. |
| **Tracking** | Records discovery records and routing preambles over time to recognise a phone or link a computer's connections. | Discovery hints rotate every 15 minutes and routing tags are fresh per connection; both are keyed by the pairing's static agreement, which never crosses the wire (§2.2.1, §4.3, hierarchy specification §4.3). No stable pairing identifier is ever sent in clear. |
| **Routing replay** | Replays a captured routing preamble to probe presence or cause work. | The tag selects a pairing and authenticates nothing. A nonce in the replay memory of 256 routed sessions is refused in the Routing phase; an older replay reaches `Noise_KK` message 1 and fails. The pre-authentication limiter bounds the work (§3.3). |
| **Withdrawal forgery or replay** | Publishes a forged `mode=withdrawn` record, or republishes a recorded one. | Withdrawal hints are keyed by the static agreement and cannot be forged. A recorded record counts only on the instance the Requester associates with the pairing and within one minute of its counter, and only withdraws presence until the Custodian is next discovered; a spoofed clock widens that window and nothing more. A replayed `hints=` value only makes a Requester dial an endpoint that then fails routing. An open session ignores records and ends only on an authenticated `session.close` (§4.5). |
| **Stale pairing** | Uses the stored pairing of a computer or phone its holder lost, sold or stopped using: recognises the other endpoint's discovery hints, or dials it and asks for operations. | Every key operation needs the holder's PIN on the Custodian, except a browser authentication while the Custodian holds PIN 1 (§8.2 item 3, §11 item 2). A pairing with no session for 30 days expires on each endpoint (§4.6 item 5), and the user of either endpoint can forget it at once (§4.6); a Requester's forget reaches the Custodian in its open session or the next time the Requester finds the Custodian, while the forgotten pairing waits in its revocation backlog (§4.6 item 6). |
| **Name impersonation** | Pairs a device under the display name of another computer or phone the holder knows. | Pairing needs the code on the holder's screen (§3). A display name is a label only: nothing finds, matches or replaces a pairing by it (§4.3 item 3), so a borrowed name changes no other pairing. |
