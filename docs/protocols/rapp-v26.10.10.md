# Remote Authorization Proxy Protocol (RAPP) v26.10.10
## Transport-Generic Pairing, BLE Direct Proximity and Stream Transport Specification

Status: Normative Specification / Research Record  
Document version: 26.10.10  
Wire version: `[26, 10, 10]` (`[Year, Month, Day]`)  
Offer version: `[26, 10, 10]`  
Transport Profiles: `"fi.refineid.rapp.ble.v1"`, `"fi.refineid.stream.v1"` (§2.2)  
Date: 2026-10-10  
Change controller: RefineID project  

---

## Abstract

This specification defines the **Enhanced Human-Factor Pairing Protocol** and the operational protocol of the Remote Authorization Proxy Protocol (RAPP v26.10.10), carried over any registered transport profile (§2.2): the **Bluetooth Low Energy (BLE) Direct Proximity Transport Profile** (`"fi.refineid.rapp.ble.v1"`) and the **Local IP Stream Transport Profile** (`"fi.refineid.stream.v1"`). Pairing, offer bootstrap, sessions, and operations are identical on every transport; only framing, routing, and discovery differ.

A user's mobile device acts as a Sovereign Server (Custodian) holding physical custody of the FINEID identity card over Near Field Communication (NFC). The workstation acts as a Requester. On BLE the Custodian is the GATT Peripheral and the Requester the GATT Central; on the stream transport the Custodian listens and the Requester dials.

Pairing is established through a 6-character Crockford Base32 human code (`7K X4 M9`, 30.0 bits entropy) executed over `CPaceRistretto255` ([draft-irtf-cfrg-cpace-21](https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-cpace-21)). Advertisements broadcast zero pairing code material, zero ephemeral bucket hints, and zero user identifiers or personal device names. Device discovery is mediated by a standardized 128-bit RAPP Service UUID filtered by an advisory proximity gate ($\ge -55\text{ dBm}$) and finalized through authenticated `Noise_XXpsk3` key exchange. Rate limiting enforces a strict 3-attempt budget per 60-second offer lifecycle with atomic attempt reservation preventing disconnect oracles.

To support upper-layer messages (such as X.509 certificate chains or document signing summaries) across single ATT transactions, this profile specifies a normative **BLE Segmentation and Reassembly (SAR) Adaptation Layer**, preserving upper-layer session and operation security guarantees without frame truncation.

---

## 1. Scope, System Architecture, and Status

### 1.1 Scope and Standalone Specification Model

This document defines the complete, standalone normative specification for the **Remote Authorization Proxy Protocol (RAPP) version 26.10.10**. It encompasses:
- The **Transport Profile Registry** (§2.2) with the **Bluetooth Low Energy (BLE) Direct Proximity Transport Profile** (`"fi.refineid.rapp.ble.v1"`) and the **Local IP Stream Transport Profile** (`"fi.refineid.stream.v1"`).
- The **Enhanced Human-Factor Proximity Pairing Protocol** utilizing `CPaceRistretto255`, 6-character Crockford Base32 human factors, atomic attempt reservation, and authenticated `Noise_XXpsk3` channel binding.
- The **BLE Segmentation and Reassembly (SAR) Adaptation Layer** with latched invariant total lengths and stop-and-wait flow control.
- The **Authenticated Message Envelope**, sequential sequencing, and session multiplexing.
- The **Direct Idempotent Operation Model** providing strict at-most-once physical card execution via write-ahead journaling and `operation_id` deduplication.
- The **Registered Credential Profiles and Actions** for card status inspection, browser authentication, and qualified document signing.
- **Service Withdrawal** (§4.5): the Custodian's notice, keyed by each pairing's static agreement, that it has stopped serving, on discovery and on open sessions.
- The **Failure Semantics, Retry Protection, and Human Consent Contracts**.

This document is completely self-contained: all normative schemas, protocol state machines, cryptographic bindings, error handling rules, and wire formats required to implement, verify, and audit RAPP v26.10.10 are defined herein.

- **Migration and Compatibility**:
  RAPP v26.10.10 runs the same pairing and session protocol over every registered transport profile (§2.2). Its wire and offer versions are `[26, 10, 10]` (`[Year, Month, Day]`). It does not interoperate with other RAPP versions. Implementations must conform strictly to the schemas and state machines defined in this standalone specification.
- **Wire and Offer Versioning**:
  - Offer version: `[26, 10, 10]` in `pairing-offer`.
  - Wire version: `[26, 10, 10]` (`[Year, Month, Day]`) in channel envelopes, pairing context, and handshake prologues.
- **Role Mapping**:
  - **Requester**: Corresponds to the RAPP Requester. On BLE it operates as GATT Client (Central); on the stream transport it dials the Custodian.
  - **Custodian**: Corresponds to the Sovereign Server (mobile device) acting as the RAPP Authorization Proxy while holding exclusive physical NFC custody of the Credential Holder (FINEID Card). On BLE it operates as GATT Server (Peripheral); on the stream transport it listens.
- **Transport Hierarchy**:
  The BLE profile constitutes **Tier 2** and the stream profile **Tier 3** of the normative [RAPP Transport and Discovery Hierarchy Specification](rapp-transport-and-discovery-hierarchy.md), which defines discovery and advertisement for each tier.

### 1.2 Implementation and Verification Status Matrix

Per project engineering standards, specification requirements are strictly distinguished from reference software implementation and observed physical hardware operations:

| Specification Domain | Status | Coverage & Artifact Reference |
| :--- | :--- | :--- |
| **BLE GATT Service & Characteristic Layout** (§5.1) | Partially Observed on Hardware | Service UUID and Channel characteristic properties observed on iOS peripheral hardware (`RappBlePeripheral.swift`). Bootstrap characteristic is Specified (unverified on physical hardware). |
| **GATT Connection & ATT MTU Exchange** (§5.2, §7.1) | Partially Observed on Hardware | BLE connection duration (~1.2 s setup; 735.6 ms Linux connect call) and 512-byte API update value capacity observed on hardware. Exact ATT MTU exchange and Indication-only path are Specified (unverified on physical hardware). |
| **Over-The-Air Data Transfer** (§7.1) | Observed on Physical Hardware | Synthetic 64-byte write and 256-byte read on Channel characteristic verified over physical BLE link. |
| **BLE SAR Framing & State Machine** (§5.3) | Normative Specification | Fully specified with invariant total length, attribute capacity limits, pre-copy capacity checks, and stop-and-wait flow control. |
| **Crockford Base32 Canonical Normalization** (§3.1) | Normative Specification | Fully specified 7-step pipeline with Crockford decode alias mapping (`I`/`L` $\to$ `1`, `O` $\to$ `0`). |
| **CPaceRistretto255 KC2 Profile & Key Confirmation** (§6.1) | Normative Specification | Fully specified with Context $C$ binding, RFC 5869 HKDF key schedule, HMAC-SHA-512 confirmation tags $T_A, T_B$, scalar sampling options, and abort-on-identity. Implemented in `crates/rapp/src/cpace.rs` and verified with in-tree synthetic golden vectors (`cpace_kc2_golden_synthetic_vectors`) as well as standalone research harnesses (`kc2-v2-harness`, `verify_kc2_review.py`). |
| **Attempt Reservation & Disconnect Oracle Protection** (§3.3) | Normative Specification | State machine rules fully defined. |
| **Noise_XXpsk3 & Noise_KK Handshakes** (§6.2, §6.3) | Normative Specification | Complete token schedules (including 48-byte Message 1 and little-endian sequence nonces), directional key splits, and prologues fully specified. |
| **Authenticated Envelopes & 14 Registered Messages** (§7, §8) | Normative Specification | Complete CDDL discriminated union schemas and normative semantics for all 14 registered message types fully specified herein (§7.1). |

### 1.3 Terminology and Requirements Language

The key words **MUST**, **MUST NOT**, **REQUIRED**, **SHALL**, **SHALL NOT**, **SHOULD**, **SHOULD NOT**, **RECOMMENDED**, **NOT RECOMMENDED**, **MAY**, and **OPTIONAL** in this document are to be interpreted as described in [BCP 14](https://www.rfc-editor.org/info/bcp14) when they appear in capitals.

* **Custodian (Sovereign Server)**: The mobile phone maintaining NFC coupling to the FINEID smart card. In BLE topology, the Custodian operates as the **GATT Server (Peripheral)**.
* **Requester (Client)**: The computer requesting cryptographic authentication or qualified signatures. In BLE topology, the Requester operates as the **GATT Client (Central)**.
* **Proximity Gate**: An advisory client-side discovery filter requiring a filtered received signal strength indication (RSSI) threshold before connection or PAKE initiation.
* **Crockford Base32 Code**: A 6-character human-readable alphanumeric code sampled uniformly from Crockford's unambiguous Base32 alphabet.
* **Fail-Stop**: The permanent termination of a pairing offer upon reaching its exhausted attempt budget (`attempts_failed == 3`), destroying all ephemeral key material and imposing exponential backoff before permitting a new offer (Section 3.3). Offer TTL expiration without 3 failed attempts tears down the offer cleanly without backoff. Reserving the 3rd attempt blocks subsequent admissions but permits that active 3rd attempt to finish under its clamped timer.

---

## 2. Architecture and Transport Relationship

### 2.1 Transport Architecture & Protocol Lifecycle

- **Wire Version**: `[26, 10, 10]` (`[Year, Month, Day]`)
- **Offer Version**: `[26, 10, 10]`
- **Transport Profiles**: registered in §2.2

The transport acts as the underlying point-to-point bearer for RAPP frames. CPace establishes the 32-byte pre-shared key ($PSK$) that seeds mutual pairing authentication (`Noise_XXpsk3`), replay protection, monotonic sequence counters, and typed at-most-once operation dispatch. Every phase below runs unchanged on every registered transport profile; "transport frame" means one SAR-reassembled message on BLE (§5.3) and one length-prefixed frame on the stream transport (§2.2.2).

#### Protocol Lifecycle:
- **Phase 0: Routing (`Phase::Routing`)**: Every connection starts with exactly one routing preamble transport frame from the Requester (§2.2). For purpose `"pairing"` with an active offer, the connection proceeds to the offer bootstrap. For purpose `"session"` whose routing tag a stored pairing keyed (§2.2.1), the connection transitions to `Phase::NoiseSession`.
- **Phase 1: Offer Bootstrap**: The Requester obtains the canonical `pairing-offer`, carrying a fresh random 32-byte `offer_id` (SID), over the transport in use (§4.2): on BLE by reading the Bootstrap Characteristic, on the stream transport as the Custodian's first transport frame after the pairing preamble. Both peers compute the canonical `offer_hash` and bind the transport entry of the offer that names the transport profile in use.
- **Phase 2: CPace Key Agreement & Confirmation (`Phase::CPace`)**: Execute the `CPaceRistretto255` KC2 profile, one transport frame per CPace message, with Context $C$ binding, mutually authenticating via HMAC tags $T_B$ and $T_A$ to establish $PSK$ via HKDF-Expand. On success, transition to `Phase::NoisePairing` and consume the offer.
- **Phase 3: Noise_XXpsk3 Pairing (`Phase::NoisePairing`)**: Perform the authenticated pairing handshake with prologue bound to canonical `offer_hash`, wire version `[26, 10, 10]`, suite, and the transport profile in use. Immediately on handshake completion, derive pairing-channel `session_id` and `pair_id`. Exchange `pairing.hello` (parameter echo using `session_id`) and `pairing.confirm` (capability grants), deriving `grants_hash`.
- **Phase 4: Pair Storage**: Atomically store the pairing trust record (`pair_id`, `grants_hash`, peer static public key, and local private key). A stored pairing is not bound to the transport it was created on; sessions may use any registered transport.
- **Subsequent Operational Sessions (`Phase::NoiseSession`)**: Operational connections start in `Phase::Routing`, route by a fresh routing tag (§2.2.1), and open a fresh `Noise_KK` session with an independent operational `session_id`, bound to the transport profile of that connection.

The diagram shows the BLE profile; on the stream transport the Requester dials the Custodian's advertised TCP endpoint instead (§2.2.2).

```
┌─────────────────────────────────────────────────────────────┐
│                     REQUESTER (Central)                     │
│  - Linux, macOS, or Windows Desktop/Laptop                  │
│  - Evaluates Proximity Gate (Filtered RSSI >= -55 dBm)      │
│  - Normalizes Crockford Base32 input from keyboard          │
│  - Safe Rust Protocol Engine (Noise Session & Operation)    │
└──────────────────────────────┬──────────────────────────────┘
                               │
                    Direct BLE 2.4 GHz Link
       Negotiated ATT MTU >= 512 (sar_payload_capacity = min(MTU - 3, 512) - 6; max 506 B)
              RAPP Segmentation & Reassembly (SAR) Bearer
                               │
┌──────────────────────────────▼──────────────────────────────┐
│                    CUSTODIAN (Peripheral)                   │
│  - iOS or Android Sovereign Mobile Server                   │
│  - Displays Crockford Base32 code on screen                 │
│  - Advertises Service UUID with ZERO hints / Anonymous Name │
│  - Holds exclusive NFC custody of FINEID Card               │
│  - Enforces atomic 3-attempt budget and offer lifecycle     │
└─────────────────────────────────────────────────────────────┘
```

### 2.2 Transport Profile Registry

Every transport profile defines a candidate identifier, framing, a routing preamble, and an offer bootstrap. CPace messages, Noise handshake messages, and envelopes each occupy exactly one transport frame. Discovery and advertisement for each profile are specified by the [RAPP Transport and Discovery Hierarchy Specification](rapp-transport-and-discovery-hierarchy.md); nothing derived from the pairing code, `offer_id` or `offer_hash` is ever advertised. Advertised discovery hints (hierarchy specification §4.3) and withdrawal hints (§4.5) are keyed by a pairing's static agreement (§4.3) and identify the pairing only to its two endpoints.

| Transport profile | `candidate_id` | Framing | Preamble domain | Offer bootstrap |
| :--- | :--- | :--- | :--- | :--- |
| `"fi.refineid.rapp.ble.v1"` | `"ble-direct-1"` | BLE SAR (§5.3) over the Channel Characteristic | `"RAPP-ble-v1"` | Read of the Bootstrap Characteristic (§4.2) |
| `"fi.refineid.stream.v1"` | `"stream-1"` | 2-byte big-endian length prefix (§2.2.2) | `"RAPP-stream-v1"` | First Custodian frame after a pairing preamble (§4.2) |

#### 2.2.1 Routing Preamble

The routing preamble is the deterministic-CBOR encoding of a 3-element array, sent by the Requester as the first transport frame of every connection:
```cddl
routing-preamble = [
  preamble-domain,       ; "RAPP-ble-v1" or "RAPP-stream-v1" (§2.2)
  "pairing" / "session", ; purpose
  bstr                   ; empty for "pairing"; session-routing for "session"
]
session-routing = bstr .size 32   ; nonce (16 bytes) || routing_tag (16 bytes)
```
For a `"session"` preamble the Requester draws a fresh 16-byte `nonce` from a cryptographically secure random source for every connection and computes
```text
K_route     = HKDF-SHA-256(salt = pair_id, IKM = X25519(local static private, peer static public),
                           info = "RAPP-routing-v1", L = 32)
routing_tag = first 16 bytes of HMAC-SHA-256(K_route, len(domain) || domain || nonce)
```
where `domain` is the preamble domain of the transport profile in use as UTF-8 octets and `len` is one octet. Both endpoints of a pairing derive the same `K_route` (§4.3); no other party can. A Requester never reuses a nonce.

The Custodian routes a `"session"` preamble as follows:
1. It evaluates the tag against `K_route` of every non-revoked stored pairing, comparing in constant time and without stopping at a match, so the work does not reveal which pairing matched or whether any did. The pre-authentication limiter (§3.3) bounds how often this runs.
2. No match is Class 1 invalid input: the Custodian closes the connection without changing stored state.
3. On a match it consults its replay memory: the nonces of the 256 most recently routed sessions. A nonce already there is Class 1 invalid input; otherwise the nonce is added, displacing the oldest, and the connection proceeds to `Phase::NoiseSession` for the matched pairing.

A preamble that does not decode, names another profile's domain, carries an unregistered purpose, a non-empty value with `"pairing"`, or a value other than 32 bytes with `"session"` is Class 1 invalid input (§10.1): the Custodian closes the connection without changing stored state. An encoded preamble longer than 64 bytes is rejected before parsing. A `"session"` preamble encodes to 58 bytes on the stream transport and 55 bytes on BLE. The `routing_tag` and `routing_preamble` vectors of `vectors/rapp-routing-v26.10.10.json` pin the bytes.

The routing tag only selects a pairing; it authenticates nothing. Authentication is established exclusively by the `Noise_KK` handshake that follows.

#### 2.2.2 Stream Transport Profile (`"fi.refineid.stream.v1"`)
- **Bearer**: one reliable, ordered TCP byte stream per connection. The Custodian listens and advertises the endpoint per the hierarchy specification; the Requester dials. Neither peer accepts inbound pairing or session connections on any other role.
- **Framing**: each transport frame is a 2-byte unsigned big-endian length $n$ followed by exactly $n$ payload bytes, $1 \le n \le 65535$. A zero length, a truncated frame, or a length above the receiver's limit closes the connection (Class 1 before authentication, Class 2 after).
- **Offer parameters**: the stream transport entry of `pairing-offer` carries `parameters: {}`; endpoints are learned from discovery, never from the offer.
- **Ordering**: after a `"pairing"` preamble the Custodian sends the encoded `pairing-offer` as its first frame (§4.2); after a `"session"` preamble the Custodian routed (§2.2.1) the Requester sends `Noise_KK` message 1.

---

## 3. Human Factors and Pairing Code Specification

### 3.1 Crockford Base32 Alphabet and Canonical Normalization

The pairing code consists of exactly 6 characters sampled uniformly at random from Crockford's Base32 alphabet:

```
Alphabet (32 symbols):
0 1 2 3 4 5 6 7 8 9 A B C D E F G H J K M N P Q R S T V W X Y Z
```

Excluded symbols:
- `I`, `L`: Excluded to eliminate visual confusion with digit `1`.
- `O`: Excluded to eliminate visual confusion with digit `0`.
- `U`: Excluded to eliminate accidental generation of offensive words in Latin-script languages.

#### Canonical Normalization Pipeline
Both Custodian and Requester **MUST** apply an identical 7-step canonicalization pipeline:
1. Accept input string from human keyboard or local interface.
2. Apply Unicode NFKC normalization first (normalizing compatibility characters).
3. Convert all ASCII lowercase characters (`a-z`) to ASCII uppercase (`A-Z`).
4. Strip all standard ASCII whitespace (`0x20` SPACE, `0x09` TAB, `0x0A` LF, `0x0B` VT, `0x0C` FF, `0x0D` CR) and hyphens (`-`).
5. Apply Crockford decode aliases: map uppercase `I` and `L` to digit `1`; map uppercase `O` to digit `0`. Reject `U` (as invalid input).
6. Verify that the resulting string is **exactly 6 characters in length** and composed **exclusively** of characters in Crockford's Base32 alphabet.
7. Derive the password octets as exact UTF-8:
   $$\text{pw} = \text{UTF-8}(\text{normalized\_code}) \quad (\text{e.g., } \text{UTF-8}(\texttt{"7KX4M9"}))$$

### 3.2 Display Formatting and Chunking

The Custodian **MUST** render the code on screen in two-character clusters separated by a space:

$$\text{Display: } \texttt{XX XX XX} \quad (\text{e.g., } \texttt{7K X4 M9})$$

This format structures visual transfer into three distinct 2-character groups. The Requester UI receives human input and performs local validation before initiating the GATT connection.

### 3.3 Entropy, Attempt Accounting, and Disconnect Oracle Mitigation

Each character carries $\log_2(32) = 5.0\text{ bits}$ of entropy. The 6-character code provides:

$$\text{Entropy} = 6 \times 5 = 30.0\text{ bits} \quad (1{,}073{,}741{,}824\text{ permutations})$$

#### Local Well-Formedness vs. Attempt Consumption
- **Local Validation**: If the user enters an invalid character, incomplete string ($< 6$ chars), or illegal symbol on the Requester, the Requester UI **MUST** reject the input locally. **No BLE packet is transmitted, and no attempt is consumed.**

#### Atomic Attempt Accounting & Disconnect Oracle Mitigation
In two-pass PAKE protocols, an adversary acting as initiator could transmit candidate public point $Y_A$, receive the Custodian's $Y_B$ and confirmation authenticator $T_B$, test their guess offline against $T_B$, and disconnect without submitting $T_A$, attempting to evade strike accounting.

To mathematically close this oracle while permitting the final legitimate attempt to complete:
1. **Attempt State Model**:
   The Custodian maintains explicit state:
   - `attempts_admitted`: monotonically increasing counter of initiated attempts (initial: 0, maximum: 3). Admission exhaustion triggers when `attempts_admitted == 3`.
   - `active_attempt`: boolean indicating an attempt is currently executing under its timer.
   - `attempts_failed`: count of failed, timed-out, or abandoned attempts (initial: 0, maximum: 3). Fail-stop lockout triggers strictly when `attempts_failed == 3`. (Offer TTL expiration without 3 failed attempts tears down the offer cleanly without triggering fail-stop lockout or backoff).
2. **Atomic Attempt Reservation**:
   When the Custodian receives $Y_A$, it validates group membership. If `attempts_admitted < 3` and `!active_attempt`, it atomically increments `attempts_admitted`, sets `active_attempt = true`, and derives the shared secret. **This reservation occurs strictly before transmitting $Y_B$ and $T_B$.**
3. **Attempt Deadline & Admission Timing**:
   Upon validating $Y_A$ and atomically admitting an attempt, the Custodian arms a non-extendable monotonic attempt timer bounded by:
   $$\text{attempt\_deadline} = \min(\text{admission\_time} + 5.0\text{ s}, \text{offer\_deadline})$$
   Starting the timer at admission strictly bounds local derivation computation before transmitting $Y_B \parallel T_B$ and guarantees an absolute ceiling on the round-trip completion window. If $\text{offer\_deadline}$ has already elapsed ($\text{remaining\_offer\_ttl} == 0$), no attempt can be admitted.
4. **Completion of the Third Attempt**:
   Reserving the 3rd attempt (`attempts_admitted == 3`) blocks any further admissions (`attempts_admitted >= 3`). However, **ephemeral offer keys remain active during the attempt deadline to allow that 3rd attempt to successfully complete.**
5. **No Refund on Disconnect or Timeout**:
   If the Requester disconnects, drops the link, or fails to deliver a valid mutual confirmation authenticator $T_A$ before the attempt deadline expires, `active_attempt` is cleared and `attempts_failed` increments. If `attempts_failed == 3`, the offer is permanently destroyed (fail-stop lockout).
6. **Successful PAKE Completion & Offer Consumption**:
   Upon receiving and verifying a valid mutual confirmation authenticator $T_A$ within the attempt deadline, `active_attempt` is cleared, the PAKE attempt timer is canceled, the pairing offer is permanently marked **consumed** (disabling any subsequent admissions or attempt reservations under that `offer_id`), and the session transitions exclusively to `Phase::NoisePairing`. Subsequent network faults during Noise or protocol mismatches do not restore the consumed offer or alter PAKE strike accounting; any new pairing ceremony mandates generating a fresh offer and pairing code.
   - **Multi-Attempt Replay Resistance & Composition Scope**: Although the 32-byte `offer_id` ($SID$) is shared across the up to 3 admitted attempts of a single offer, each honest endpoint draws a fresh independent nonzero scalar ($x_A, x_B$) for every attempt. Transcript-bound confirmation prevents reuse of a prior tag against a different transcript except with the relevant cryptographic failure probabilities. This replay argument does not establish a multi-session UC theorem. Security of the shared-SID, multi-attempt composition remains an explicitly recorded engineering assumption subject to further review, bounded in operation by strict atomic attempt accounting (`attempts_admitted <= 3`), single-flight serialization, monotonic attempt deadlines (5.0 s), and immediate offer consumption upon valid $T_A$.
7. **Offer Lifecycle, Expiry Separation, and Post-PAKE Deadlines**:
   The pairing offer is valid for exactly 60 seconds from user initiation (`offer_ttl_ms = 60000`).
   - **Clean Offer Expiry**: If the 60-second offer TTL expires without an active attempt or after all admitted attempts have finished with `attempts_failed < 3`, the offer is terminated cleanly: BLE advertising ceases and ephemeral offer keys are zeroized. No strike penalty or exponential backoff is imposed; the user may immediately start a new offer without delay.
   - **Active Attempt Clamping**: An active PAKE attempt cannot extend past the offer deadline: per rule 3, the attempt timer is strictly clamped by $\text{attempt\_deadline} = \min(\text{admission\_time} + 5.0\text{ s}, \text{offer\_deadline})$. Reserving an attempt at $t = 59\text{ s}$ yields an attempt deadline of $1.0\text{ s}$, terminating at $t = 60\text{ s}$.
   - **Handed-Off Lifecycle & Finite Post-PAKE Deadlines**: Once CPace completes successfully and transfers exclusive custody to `Phase::NoisePairing`, the active ceremony is **exempt** from destruction by the original 60-second offer TTL. Instead, the active pairing channel is bounded by finite post-PAKE monotonic deadlines:
     1. **Noise Handshake Completion Deadline**: 10.0 seconds from local CPace handoff.
     2. **Grant Echo & Storage Deadline**: 10.0 seconds from local Noise completion.
     Any timeout, peer silence, transport disconnect, or protocol error destroys candidate trust immediately, erases ephemeral keys, and closes the connection without persisting an unconfirmed pairing. An indefinitely silent peer is terminated upon deadline expiry. Requester enters Noise only after its ATT write of Message 3 completes; an ATT write acknowledgment alone does not prove Custodian acceptance of $T_A$.
   - **Fail-Stop Lockout and Exponential Backoff**: Triggered strictly upon attempt budget exhaustion (`attempts_failed == 3`). Upon fail-stop lockout:
     1. The Custodian destroys all ephemeral keys, terminates BLE advertising, and surfaces an on-screen notification to the user ("Pairing failed: 3 incorrect attempts. Pairing locked.").
     2. The Custodian enforces an exponential backoff penalty of $\text{delay\_seconds} = \min(2^n, 300\text{ s})$ before permitting the generation of a new offer, where $n = \text{consecutive\_failed\_offers}$ (saturating at $n = 9$; $2^8 = 256\text{ s}$, $2^9 \to 300\text{ s}$).
     3. The counter $n$ starts at $0$, increments by $1$ only upon a fail-stop lockout (`attempts_failed == 3`), and resets to $0$ upon any successful pairing completion (Phase 5), upon conscious manual user reset/unlock in the Custodian settings UI, or after 15 minutes of user inactivity. The counter $n$ is held in volatile memory and resets to $0$ across device reboot.
8. **Single-Flight Serialization & Rate Limiting**:
   The Custodian **MUST NOT** accept concurrent GATT PAKE exchanges. Any secondary Central attempting to initiate CPace while `active_attempt` is true is immediately rejected with an ATT error (`0x80 Application Error`). In addition, pre-authentication connection attempts and invalid $Y_A$ candidate submissions are rate-limited to at most 1 attempt per 500 ms to mitigate serial resource consumption.

---

## 4. Privacy, Bootstrap Discovery, and Noise Binding

### 4.1 Zero Hint Leakage Over Advertisements

No advertisement on any transport (BLE advertising data, DNS-SD names, TXT records, or other discovery records) may carry pairing code material or offer material (`offer_id`, `offer_hash`), or any value derived from them. Discovery hints (hierarchy specification §4.3) and withdrawal hints (§4.5) are keyed by a pairing's static agreement (§4.3), which never crosses the wire. The rules below apply to BLE; the hierarchy specification applies the same rule to DNS-SD.

The BLE advertisement payload **MUST NOT** contain:
- Any bits, truncated representations, or hashes of the pairing code.
- Ephemeral bucket hints or index tags.
- Personal device names, user identifiers, or hardware serial numbers.

The Custodian **MUST**:
- Broadcast solely the standardized 128-bit RAPP Service UUID (`7E39FD01-A6B5-4D78-9E11-37E28E9545F1`).
- Set the BLE Local Name to an empty string or generic constant (`"RefineID"`), strictly avoiding default platform names (such as `"<owner's device name>"`).
- Rotate the BLE Resolvable Private Address (RPA) per Bluetooth Core Specification v5.4. (Note: On iOS, CoreBluetooth manages RPA rotation and background advertisement payload filtering automatically; local names may be omitted or moved to scan responses in background modes without compromising foreground pairing).

### 4.2 Bootstrap Discovery & PairingOffer Schema

The Custodian creates the `pairing-offer` when the user starts a pairing ceremony and serves it on every transport it accepts pairing connections on.

The Session Identifier (SID) used in CPace **MUST** be an independent 32-byte cryptographic random value (`offer_id`) generated by the Custodian upon creating the offer, on every transport. It **MUST NOT** be derived from the pairing code. The Requester never derives an offer; it always obtains it through the offer bootstrap of the transport in use.

#### PairingOffer Schema (Deterministic CBOR):
```cddl
pairing-offer = {
  "scheme": "rapp",
  "version": [26, 10, 10],       ; offer version triple
  "offer_id": bstr .size 32,    ; 32-byte cryptographic random SID
  "suites": [
    "CPACE-RISTR255-SHA512-RAPP-KC2 + Noise_XXpsk3_25519_ChaChaPoly_SHA512"
  ],
  "profiles": [ + tstr ],       ; offered credential profiles (§9)
  "transports": [ + transport-entry ],
  "offer_ttl_ms": 60000
}

transport-entry = {
  "profile": tstr,              ; registered transport profile (§2.2)
  "candidate_id": tstr,         ; its registered candidate identifier (§2.2)
  "parameters": { * tstr => any }
}
```
The `transports` array lists one entry for each registered transport the Custodian accepts this pairing on, in ascending byte order of `profile`, with no duplicate profiles. The BLE entry carries `parameters: {"service_uuid": "7E39FD01-A6B5-4D78-9E11-37E28E9545F1"}`; the stream entry carries `parameters: {}`.

`pairing_secret` is never part of `pairing-offer`: the pairing secret is negotiated by CPace, and storing or serving a static pairing secret over an unauthenticated bootstrap is strictly prohibited.

The canonical `offer_hash` is computed as:
$$\text{offer\_hash} = \text{SHA-256}(\text{encode\_deterministic\_cbor}(\text{pairing-offer}))$$

#### Bootstrap Read Flow:
1. **BLE**: the Custodian exposes the **RAPP Bootstrap Characteristic** (`7E39FD03-A6B5-4D78-9E11-37E28E9545F1`, Read-only). The Requester connects, sends the `"pairing"` routing preamble (§5.2), and performs an `ATT_READ_REQ` on this characteristic to obtain `encode_deterministic_cbor(pairing-offer)`.
2. **Stream**: after receiving the `"pairing"` routing preamble, the Custodian sends `encode_deterministic_cbor(pairing-offer)` as its first transport frame. A Custodian with no active offer closes the connection instead.
3. The Requester decodes the offer and rejects it unless it is deterministic CBOR matching the schema, carries version `[26, 10, 10]`, lists an acceptable suite, and contains a `transports` entry whose `profile` is the transport profile of the connection. Unsupported suites terminate the pairing flow immediately before CPace; automatic downgrade or fallback to unconfirmed legacy suites is strictly prohibited.
4. Both peers bind the `candidate_id` of that entry and the connection's transport profile (§4.3, §6.1.1), use `offer_id` as SID for CPace, and compute `offer_hash` for the Noise pairing prologue.
5. A deterministic encoding of `pairing-offer` with the KC2 suite, the three registered profiles, and both transport entries stays within the 509-byte ATT value capacity at the minimum ATT MTU of 512.

### 4.3 Mandatory Noise Binding, Temporal Derivation, and Reconnect Routing

1. **Noise_XXpsk3 Prologue**:
   The prologue for the pairing handshake is the deterministic-CBOR encoding of the 5-element array:
   ```cddl
   pairing-prologue = [
     "RAPP-pairing-v1",
     [26, 10, 10],                                                         ; wire version [Year, Month, Day]
     "CPACE-RISTR255-SHA512-RAPP-KC2 + Noise_XXpsk3_25519_ChaChaPoly_SHA512", ; cryptographic suite name
     bstr .size 32,                                                       ; offer_hash
     tstr                                                                 ; transport profile of the connection (§2.2)
   ]
   ```
   $$\text{prologue} = \text{encode\_deterministic\_cbor}(\text{pairing-prologue}) \quad (151\text{ bytes on BLE, 149 bytes on stream})$$

2. **Immediate Channel Identifier Derivation**:
   Immediately upon completing the `Noise_XXpsk3` handshake, both peers derive the channel identifiers from the completed handshake hash $h$ in strict order:
   ```text
   session_id = first 16 bytes of SHA-512("RAPP-session-id-v1" || h)
   pair_id    = first 16 bytes of SHA-512("RAPP-pair-id-v1" || h)
   ```
   Both peers immediately destroy `pairing_secret` ($PSK$) and all ephemeral handshake keys.
   The derived `session_id` immediately scopes the pairing-channel envelopes for `pairing.hello` and `pairing.confirm`.

3. **Parameter Echo & Mutual Grants**:
   - Inside the established pairing channel, peers exchange `pairing.hello`.
   - `pairing.hello` echoes `offer_hash`, the bound transport profile and `candidate_id` (§4.2), wire version `[26, 10, 10]`, suite name, display name, platform description, and requester's requested profiles.
   - Custodian verifies matching echoes. Any mismatch aborts with an authenticated protocol violation.
   - The Custodian automatically grants the valid requested profiles matching its pairing offer (since possession and entry of the 30-bit pairing code constitutes user authorization), and transmits `pairing.confirm` carrying granted profiles. Requester echoes and confirms. Both granted sets **MUST** be identical.
   - Derive `grants_hash` from the confirmed, canonically sorted grant set:
     $$\text{grants\_hash} = \text{SHA-256}(\text{encode\_deterministic\_cbor}(\text{sorted\_profiles}))$$
     where `sorted_profiles` is a CBOR array of profile identifier strings (`tstr`, CBOR major type 3 with definite-length encoding) sorted in standard canonical byte-wise lexicographical order without duplicates (e.g. `["fi.refineid.authentication.v1", "fi.refineid.card-status.v1"]`).

4. **Atomic Permanent Key Storage**:
   Immediately upon receipt and verification of matching `pairing.confirm` messages:
   - **Fresh Pair-Specific Static Keys**: Each pairing ceremony **MUST** generate a fresh, cryptographically independent static X25519 keypair $(s, s_{pub})$ on each endpoint. Static keys **MUST NOT** be reused across different peer pairings or across distinct pairing ceremonies. This provides pairwise endpoint isolation and prevents correlation across peers. Private keys **MUST** be stored in platform-encrypted secure hardware (Secure Enclave / TPM / OS Keychain), excluded from backups and cloud synchronization, and marked non-exportable.
   - Each endpoint atomically persists the pairing trust record:
     - `pair_id`
     - `grants_hash` and confirmed granted profiles
     - Remote peer's static public key
     - Local static private key (stored in platform-encrypted secure hardware / keychain)
   - The pairing channel is then cleanly closed.

5. **Reconnect Routing for Operational Sessions (`Noise_KK`)**:
   Subsequent connections for credential operations (authentication, qualified signing) do not rerun CPace or the offer bootstrap, and may use any registered transport.
   - Every connection starts in `Phase::Routing` (§2.2.1).
   - Requester transmits a single routing preamble with purpose `"session"` and a fresh routing tag (§2.2.1). On BLE it is written to the Channel Characteristic via `ATT_WRITE_REQ` in a `SINGLE` SAR frame (§5.2).
   - The Custodian finds the stored pairing whose `K_route` keyed the tag, retrieves `pair_id`, `grants_hash`, and peer static key, and initiates `Phase::NoiseSession` (`Noise_KK`).
   - If no non-revoked pairing keyed the tag, or its nonce was already routed, the Custodian immediately closes the link without altering stored state.
   - **Keys from the static agreement**: Every value that names a pairing outside its encrypted channel is keyed by the pairing's static X25519 agreement, which only its two endpoints can compute:
     ```text
     K_x = HKDF-SHA-256(salt = pair_id, IKM = X25519(local static private, peer static public), info, L = 32)
     ```
     with `info` `"RAPP-routing-v1"` for routing tags (§2.2.1), `"RAPP-discovery-hint-v2"` for discovery hints (hierarchy specification §4.3), and `"RAPP-withdrawal-v1"` for withdrawal hints (§4.5). Both endpoints obtain the same agreement from their own private key and the peer's public key. An agreement equal to the identity point yields no key; such a pairing is never announced or routed. The `pair_keys` vectors of `vectors/rapp-routing-v26.10.10.json` pin the keys.
   - **Routing privacy**: A routing tag is fresh for every connection and computationally unlinkable without `K_route`, so an observer of preambles cannot tell whether two connections belong to the same pairing, and no routing value recurs. A replayed preamble is refused in `Phase::Routing` while its nonce is in the Custodian's replay memory; a preamble replayed after its nonce has left the memory reaches `Noise_KK` message 1, which the replaying party cannot complete. That timing difference reveals only that some stored pairing once routed that preamble, which the observer already saw; it is mitigated by single-flight connection serialization and the pre-authentication limiter (§3.3).
   - Session Prologue:
     ```cddl
     session-prologue = [
       "RAPP-session-v1",
       [26, 10, 10],                                                         ; wire version [Year, Month, Day]
       "Noise_KK_25519_ChaChaPoly_SHA512",                              ; suite name
       pair_id,                                                         ; bstr .size 16
       grants_hash,                                                     ; bstr .size 32
       tstr                                                             ; transport profile of the connection (§2.2)
     ]
     prologue = encode_deterministic_cbor(session-prologue)
     ```
   - Operational handshakes derive a fresh operational `session_id` (`first 16 bytes of SHA-512("RAPP-session-id-v1" || h_session)`). The pairing `session_id` is never reused.

### 4.4 Proximity RSSI Gating & Transparent Relay Analysis

RSSI is treated as an **advisory discovery heuristic** and defense-in-depth barrier, not as a standalone cryptographic proof of proximity:
1. **Requester Filter**: The Requester **MUST** ignore advertisements whose filtered RSSI falls below $-55\text{ dBm}$ (configurable to $-85\text{ dBm}$ strictly in isolated development environments).
2. **Temporal Filtering**: To compensate for multipath fading and orientation variance, the Requester **SHOULD** compute the median RSSI over at least 3 advertisement packets with a 3 dB hysteresis before initiating a connection.
3. **Transparent Relay Analysis**: An adversary utilizing high-gain directional antennas and power amplifiers can increase signal strength at the receiver. A transparent RF wormhole or relay forwarder can tunnel RF packets between distant rooms without decrypting them. While PAKE secrecy prevents an attacker from learning the session key, the physical distance assumption is bypassed. Explicit per-operation user authorization on the Custodian phone screen protects authorized operation semantics/intent (e.g. for qualified signing); transparent physical RF tunneling remains a physical-layer relay risk that cannot be detected by RF signal analysis alone.
4. **Structural Role Separation as Protocol-Level Relay Defense**:
   Under Bluetooth Core Specification v5.4 and this profile (§5.2, §6.3), ATT and CPace roles are strictly asymmetric and immutable: the Requester is Central ($A$), transmitting exclusively via `ATT_WRITE_REQ`, while the Custodian is Peripheral ($B$), replying exclusively via `ATT_HANDLE_VALUE_IND`. Per draft-irtf-cfrg-cpace-21 Section 10.1, strict initiator/responder role separation structurally eliminates relay loopback and reflection attacks: an adversary cannot reflect the Custodian's $Y_B \parallel T_B$ indication back to the Custodian as an initiator write $Y_A$, nor can it relay frames between two peers acting in the same role.

### 4.5 Service Withdrawal

A Custodian **withdraws** when it deliberately stops serving every stored pairing. Exactly two causes are withdrawal: the user turns remote access off, and the user quits the application. Suspension or termination by the operating system, loss of the network, and a session restart with reason `"normal"` or `"shutdown"` (§7.2) are not withdrawal. Withdrawal changes no stored pairing; serving resumes with the next `mode=session` advertisement.

1. **Withdrawal Key**:
   Each stored pairing has a withdrawal key that both endpoints derive from their static keys and that never crosses the wire:
   $$S = \text{X25519}(\text{local static private}, \text{peer static public})$$
   $$K_{\text{wd}} = \text{HKDF-SHA-256}(\text{salt} = \text{pair\_id}, \text{IKM} = S, \text{info} = \texttt{"RAPP-withdrawal-v1"}, L = 32)$$
   HKDF is [RFC 5869](https://www.rfc-editor.org/rfc/rfc5869.html): $\text{PRK} = \text{HMAC-SHA-256}(\text{pair\_id}, S)$ over the 16-byte `pair_id`, then the single block $K_{\text{wd}} = \text{HMAC-SHA-256}(\text{PRK}, \text{info} \parallel \texttt{0x01})$. An $S$ equal to the X25519 identity (all zero) yields no key; such a pairing is never announced. The Requester may cache $K_{\text{wd}}$ with the pairing.

2. **Withdrawal Hint**:
   $$\text{whint} = \text{first 8 bytes of }\text{HMAC-SHA-256}(K_{\text{wd}}, \text{len} \parallel \text{instance} \parallel \text{counter\_be64})$$
   where $\text{instance}$ is the instance portion of the DNS-SD service instance name the Custodian publishes ([RFC 6763](https://www.rfc-editor.org/rfc/rfc6763.html) §4.1): the name exactly as published, without the service type (`_refineid-stream._tcp`) and the domain (`local.`), as UTF-8 octets, 1 to 63 octets (hierarchy specification §4.2). Instance names may contain dots; a value ending in a service type or domain suffix is a misuse and is refused. $\text{len}$ is its length as one octet, and $\text{counter} = \lfloor \text{unix\_time} / 60 \rfloor$ as an unsigned 64-bit big-endian integer. The `withdrawal_key` and `withdrawal_hint` vectors of `vectors/rapp-withdrawal-v26.10.10.json` pin the bytes.

3. **Custodian Order**:
   On withdrawal the Custodian, in this order:
   1. sends `session.close` with reason `"service_withdrawn"` (§7.1) on every open operational session and closes its link;
   2. stops accepting connections;
   3. replaces the TXT record of its current `_refineid-stream._tcp` service instance with the withdrawn record (item 4);
   4. unregisters the service after at least 2 and at most 10 seconds.

   Withdrawal does not alter the operation journal: an operation whose card exchange has begun completes or is recorded exactly as §8 requires, and the Requester reconciles it through §8.3 on its next session.

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
   - **Discovery.** Without an open session, a Requester honours a withdrawn record only on the service instance it currently associates with the pairing: the instance whose discovery hint matched the pairing, or the instance it last established a session to. It parses the record and computes the pairing's hint for that instance and for $\text{counter} - 1$, $\text{counter}$ and $\text{counter} + 1$ of its own clock, comparing every entry in constant time. A match is a **verified withdrawal**. Because the window is one counter step either side of $\lfloor t/60 \rfloor$, it tolerates a clock difference of at least 60 seconds and, depending on where both times fall within their minutes, up to just under 120 seconds. Implementations **MUST NOT** widen it.
   - **Malformed records.** A record with a key other than `v`, `mode` and `withdrawn` (in any case), a repeated key (in any case), a `v` other than `1`, a `mode` other than `withdrawn`, or a `withdrawn` value that is not exactly 8 lowercase 16-digit entries is malformed, as is a `hints` attribute beside `withdrawn`.
   - **Effect.** On a verified withdrawal the Requester withdraws the pairing's presence at once: it stops offering the Custodian's credentials to local consumers and does not dial the Custodian again until it discovers it in `mode=session` or sees its BLE advertisement. It changes no stored pairing state and shows no error.
   - **Unannounced loss.** A malformed record, a withdrawn record without a match, a record on another instance, or a service that disappears without one is unannounced loss; the Requester applies its own hold before withdrawing presence, so that a brief discovery gap does not withdraw a Custodian that is still serving.

7. **Authenticity and Replay**:
   Only the two endpoints of a pairing know its static agreement, so no other party can compute a withdrawal hint; observing sessions, routing preambles or discovery records does not help. A party on the local link that recorded a genuine withdrawn record can republish it under the same instance name for at most about three minutes (the counter window), and only while the Requester still associates that instance with the pairing; instance names are fresh on every advertisement start (hierarchy specification §4.2). The effect is the same as a spoofed mDNS goodbye without the Requester's hold: presence is withdrawn until the Custodian is next discovered. These bounds assume the Requester's clock is not under the attacker's control; an attacker who can move the Requester's time, for example through an unauthenticated NTP source, can stretch the replay window for as long as it controls that clock, with the same effect and no other. Random fillers keep the record the same size whatever the number of stored pairings, and the hints are unlinkable across instances and minutes.

---

## 5. GATT Profile and Wire Protocol

### 5.1 Service and Characteristic Definitions

* **Primary Service UUID**:
  `7E39FD01-A6B5-4D78-9E11-37E28E9545F1`
* **RAPP Channel Characteristic UUID**:
  `7E39FD02-A6B5-4D78-9E11-37E28E9545F1`
  * **Properties**: `Write` (`0x08`), `Indicate` (`0x20`)
  * **Descriptors**: Client Characteristic Configuration Descriptor (CCCD, UUID `0x2902`, Access: `Read | Write`, permitted values: `0x0000` Disabled, `0x0002` Indications Enabled).
  * **Permissions**: Unauthenticated Writeable. Application security is provided exclusively by CPace and Noise AEAD.
* **RAPP Bootstrap Characteristic UUID**:
  `7E39FD03-A6B5-4D78-9E11-37E28E9545F1`
  * **Properties**: `Read` (`0x02`)
  * **Permissions**: Unauthenticated Readable (carries `encode_deterministic_cbor(pairing-offer)`).

### 5.2 ATT Roles, Connection Setup, and Delivery Primitives

Under Bluetooth Core Specification v5.4, ATT roles are strictly asymmetric:
- **Requester to Custodian (Client -> Server)**:
  All messages **MUST** be transmitted exclusively using **`ATT_WRITE_REQ`** (Write With Response). The Custodian responds with `ATT_WRITE_RSP`.
- **Custodian to Requester (Server -> Client)**:
  All responses (CPace Step 2, Noise handshake replies, operational responses, signatures, and errors) **MUST** be transmitted exclusively using **`ATT_HANDLE_VALUE_IND`** (GATT Indication). The Requester acknowledges receipt with `ATT_HANDLE_VALUE_CFM`.
- GATT Notifications (`ATT_HANDLE_VALUE_NTF`) and Characteristic Reads on the Channel Characteristic are strictly prohibited for protocol frame transport, guaranteeing strictly ordered, duplicate-free delivery.
- **Outbound Backpressure & Flow Control**:
  The transmitting endpoint maintains a FIFO queue of fragments for the current frame. For indications, the Custodian transmits fragment $k$ and MUST NOT transmit fragment $k+1$ until `ATT_HANDLE_VALUE_CFM` is received. For writes, the Requester transmits fragment $k$ and MUST NOT transmit fragment $k+1$ until `ATT_WRITE_RSP` is received.
- **At-Most-Once Operation Execution**:
  If a connection drops during response transmission, smart card cryptographic operations MUST NEVER be re-executed to re-generate or re-send lost responses. Operations are strictly at-most-once. The Requester must handle the disconnect/timeout error.

#### Mandatory Connection Setup Sequence:
1. **ATT MTU Exchange**:
   Immediately upon connection establishment, the Requester (GATT Client) **MUST** initiate an ATT MTU Exchange (`Exchange MTU Request`, opcode `0x02`) requesting an MTU of at least 515 bytes (giving a 512-byte ATT payload `maximumUpdateValueLength`).
   If the resulting negotiated ATT MTU is $< 512$ bytes, the connection **MUST** be dropped immediately.
   (Implementation note: On Linux with BlueZ, the client initiates MTU exchange on the connection socket/D-Bus channel; on iOS, CoreBluetooth manages peripheral MTU exchange automatically).
2. **CCCD Indication Enablement**:
   Immediately following MTU exchange and before transmitting the routing preamble, the Requester **MUST** write `0x0002` (Indications Enabled) to the Channel Characteristic CCCD (`0x2902`) via `ATT_WRITE_REQ`.
   The Custodian **MUST NOT** accept routing preambles or emit Indications until Indications are enabled in the CCCD. If a preamble is received before CCCD enablement, the Custodian closes the connection.
3. **Initial Connection Routing (`Phase::Routing`)**:
Every newly established BLE connection begins in **`Phase::Routing`**.
1. The Requester MUST transmit exactly one plaintext `ble-routing-preamble` preamble frame, the BLE instance of `routing-preamble` (§2.2.1), over the Channel Characteristic via `ATT_WRITE_REQ` (in a `SINGLE` SAR frame):
   ```cddl
   ble-routing-preamble = [
     "RAPP-ble-v1",
     tstr,                     ; purpose: "pairing" / "session"
     bstr                      ; purpose "pairing": empty (bstr .size 0)
                               ; purpose "session": session-routing (bstr .size 32, §2.2.1)
   ]
   ```
2. The Custodian in `Phase::Routing` decodes and evaluates the preamble:
   - **Purpose `"pairing"`**:
     - Verify the value is empty.
     - Check if Custodian has an active pairing offer (within 60-second TTL).
     - If active: the Requester reads the Bootstrap Characteristic (§4.2), and the connection transitions to **`Phase::CPace`**.
     - If no active offer exists: close connection immediately.
   - **Purpose `"session"`**:
     - Verify the value is 32 bytes.
     - Route it per §2.2.1 against the non-revoked stored pairings and the replay memory.
     - If routed: retrieve `pair_id`, `grants_hash`, and peer static public key, and transition connection to **`Phase::NoiseSession`**.
     - Otherwise: close connection immediately without altering any stored pairing.
   - **Invalid Preamble**:
     - Unknown purpose, malformed CBOR, a non-empty value for `"pairing"`, a value other than 32 bytes for `"session"`, oversized frame, or any non-preamble frame received in `Phase::Routing` is pre-authentication invalid input: close connection immediately.
3. Exactly one preamble frame is permitted per connection. Any preamble received after transitioning out of `Phase::Routing` is an unrecoverable protocol violation. A routing tag never authenticates a caller; authentication is established exclusively by the subsequent Noise handshake.

### 5.3 BLE Segmentation and Reassembly (SAR) Adaptation Layer

While operational session handshake messages in `Noise_KK` are compact (Message 1 and Message 2 are each 48 bytes, fitting cleanly in single 512-byte ATT frames), upper-layer application envelopes (carrying X.509 certificate chains or document signing digests) frequently exceed 512 bytes and cannot be assumed to fit in a single ATT transaction.

All RAPP messages over the Channel Characteristic **MUST** be encapsulated in the **RAPP BLE SAR Framing**:

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|       Total Frame Length      |         Chunk Sequence        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|     Flags     |    Reserved   |      Fragment Payload...      |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

#### Field Definitions:
- **Total Frame Length** (`u16`, 2 bytes, network byte order / big-endian): Total byte length of the complete RAPP message payload (excluding this 6-byte SAR header). Permitted range: $1..65{,}535$ bytes.
- **Chunk Sequence** (`u16`, 2 bytes, network byte order / big-endian): 0-indexed sequence counter for fragments of the current message (`0, 1, 2, ...`). Permitted range: $0..1{,}023$.
- **Flags** (`u8`, 1 byte):
  - `0x01` (`FIRST`): Initial fragment of a multi-fragment frame.
  - `0x02` (`CONT`): Intermediate fragment.
  - `0x04` (`LAST`): Final fragment.
  - `0x05` (`SINGLE` = `FIRST | LAST`): Self-contained single-fragment message (carrying payload $\le \text{sar\_payload\_capacity}$).
  - All other bit patterns are illegal. Any message with non-zero reserved bits (bits 3–7) or illegal flag combinations (e.g., `0x00`, `0x03`, `0x06`, `0x07`) MUST be rejected as an unrecoverable protocol violation.
- **Reserved** (`u8`, 1 byte): Must be set to `0x00`.

#### Normative SAR Receive State Machine with Invariant Total Length:
1. **Capacity & MTU Requirement**: Negotiated ATT MTU **MUST** be $\ge 512$ bytes.
   Per Bluetooth Core Specification v5.4, Vol 3, Part F, Section 3.2.9, any attribute value is hard-capped at 512 bytes. Accounting for the 3-byte ATT header and the 6-byte SAR header, the uniform maximum fragment payload capacity for all fragments (`FIRST`, `CONT`, `LAST`, `SINGLE`) is defined as:
   $$\text{sar\_payload\_capacity} = \min(\text{negotiated\_att\_mtu} - 3, 512) - 6$$
   Any smaller platform-reported usable value limit (e.g. `maximumUpdateValueLength`) **MUST** also be honored.
   - At negotiated ATT MTU 512: $\min(509, 512) - 6 = 503\text{ bytes}$.
   - At negotiated ATT MTU 515: $\min(512, 512) - 6 = 506\text{ bytes}$.
   - At negotiated ATT MTU 517: $\min(514, 512) - 6 = 506\text{ bytes}$.
   If negotiated ATT MTU $< 512$ bytes, the connection **MUST** be dropped immediately.
2. **Initial Fragment Processing (Receiver Idle: `expected_seq == 0` and `accumulated_bytes == 0`)**:
   - The fragment MUST have `flags == FIRST` (`0x01`) or `flags == SINGLE` (`0x05`), and `Chunk Sequence == 0`.
   - Validate `Total Frame Length`:
     - Range: $1 \le \text{Total Frame Length} \le 65{,}535$.
     - For `SINGLE` (`flags == 0x05`): MUST satisfy $\text{Total Frame Length} == \text{fragment\_payload\_len} \le \text{sar\_payload\_capacity}$.
     - For `FIRST` (`flags == 0x01`): MUST satisfy $64 \le \text{fragment\_payload\_len} \le \text{sar\_payload\_capacity}$ and $\text{fragment\_payload\_len} < \text{Total Frame Length}$.
   - Latch `expected_total = fragment.total_frame_length`. This latched value is frozen for the duration of the frame.
   - Arm non-extendable 5.0-second reassembly timer.
3. **Subsequent Fragment Processing (`expected_seq > 0`)**:
   - Flags MUST be `CONT` (`0x02`) or `LAST` (`0x04`). Any `FIRST` or `SINGLE` received while reassembly is in progress is an illegal transition: abort immediately, zeroize buffer, cancel timer, and close connection.
   - Non-final chunks (`CONT`) MUST carry $\ge 64$ bytes.
4. **Header Invariance & Sequence Check (Every Fragment)**:
   - **Total Length Invariance**: The fragment's declared `Total Frame Length` MUST equal `expected_total` exactly:
     $$\text{fragment.total\_frame\_length} == \text{expected\_total}$$
     Any mismatch (increasing or decreasing declared total) MUST be rejected immediately before copying, zeroizing buffer, cancelling timer, and dropping connection.
   - **Sequence Continuity**: `fragment.chunk_sequence == expected_seq`.
   - **Sequence Bound**: `fragment.chunk_sequence < 1024`.
   - Zero-payload chunks are forbidden: `fragment_payload_len > 0`.
   - Any violation aborts immediately, zeroizes buffer, cancels timer, and drops connection.
5. **Cumulative Length Pre-Copy Check**:
   - Compute candidate accumulated bytes:
     $$\text{new\_total} = \text{accumulated\_bytes} + \text{fragment\_payload\_len}$$
   - Verify:
     $$\text{new\_total} \le \text{expected\_total}$$
   - If `new_total > expected_total`, reject before copying, zeroize buffer, cancel timer, and drop connection.
6. **Buffer Copy & Counter Advance**:
   - Copy `fragment_payload` into the reassembly buffer at offset `accumulated_bytes`.
   - Advance counter: `accumulated_bytes = new_total`.
7. **Completion & State Reset**:
   - If `flags & LAST != 0` (i.e. `LAST` or `SINGLE`):
     - Verify exact completion: $\text{accumulated\_bytes} == \text{expected\_total}$.
     - If equal: cancel the 5.0-second timer, reset receiver state (`expected_seq = 0`, `accumulated_bytes = 0`, `expected_total = 0`), and pass the complete reassembled frame to the active phase engine.
     - If unequal: reject, zeroize buffer, cancel timer, and close connection.
   - If `flags & LAST == 0` (i.e. `FIRST` or `CONT`):
     - Increment `expected_seq = expected_seq + 1`. Await next fragment.
8. **Buffer Ownership & Pre-Authentication Limits**:
   - Reassembly buffers are bound per BLE connection and direction.
   - Custodian permits at most 1 concurrent pre-authentication connection (single-flight peripheral serialization).
   - If reassembly does not complete within the 5.0-second timer, buffer is zeroized and connection is dropped.
9. **Wire Framing of Channel Messages**:
   - Routing Preamble: deterministic CBOR `["RAPP-ble-v1", purpose, routing]` encapsulated in a `SINGLE` SAR frame.
   - CPace Step 1 ($Y_A$): raw 32 bytes of compressed Ristretto255 point $Y_A$ encapsulated in a `SINGLE` SAR frame (`Total Frame Length = 32`, `Chunk Sequence = 0`, `Flags = 0x05`).
   - CPace Step 2 ($Y_B, T_B$): raw concatenation $Y_B \parallel T_B$ ($32 + 32 = 64\text{ bytes}$) encapsulated in a `SINGLE` SAR frame (`Total Frame Length = 64`, `Chunk Sequence = 0`, `Flags = 0x05`).
   - CPace Step 3 ($T_A$): raw 32 bytes of confirmation authenticator $T_A$ encapsulated in a `SINGLE` SAR frame (`Total Frame Length = 32`, `Chunk Sequence = 0`, `Flags = 0x05`).
   - Noise Handshake & Transport Frames: raw Noise ciphertext payloads encapsulated in SAR frames (segmented across multiple chunks if payload exceeds $\text{sar\_payload\_capacity} = \min(\text{negotiated\_att\_mtu} - 3, 512) - 6$ bytes, e.g. $> 506$ bytes at MTU $\ge 515$, $> 503$ bytes at MTU 512).
10. **Phase-Specific Frame Dispatch**:
   - Reassembled complete frames are dispatched strictly according to the internal connection state machine:
     - `Phase::Routing`: Dispatched to connection routing evaluator (Section 5.2).
     - `Phase::CPace`: Dispatched to `CPaceRistretto255` handler.
     - `Phase::NoisePairing`: Dispatched to `Noise_XXpsk3` pairing engine.
     - `Phase::NoiseSession`: Dispatched to `Noise_KK` operational session engine.
   - Handlers NEVER select dispatch targets based on unauthenticated payload inspection. Any frame arriving out of expected phase is an unrecoverable protocol violation.

---

### 6. Normative Cryptographic Protocols

RAPP v26.10.10 specifies three normative cryptographic protocols:
1. **`CPaceRistretto255`**: Password-Authenticated Key Exchange (PAKE) for initial proximity pairing (§6.1).
2. **`Noise_XXpsk3`**: Initial mutual pairing authentication handshake (§6.2).
3. **`Noise_KK`**: Mutual operational session handshake (§6.3).

### 6.1 CPaceRistretto255 KC2 Profile (draft-irtf-cfrg-cpace-21, RFC 9496, RFC 5869)

RAPP v26.10.10 specifies the **`CPaceRistretto255-KC2`** application profile over [draft-irtf-cfrg-cpace-21](https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-cpace-21), [RFC 9496](https://www.rfc-editor.org/rfc/rfc9496.html), and [RFC 5869](https://www.rfc-editor.org/rfc/rfc5869.html):

#### 6.1.1 Cryptographic Suite Definition
- **Group**: Prime-order Ristretto255 group (order $q = 2^{252} + 27742317777372353535851937790883648493$).
- **Hash Function**: SHA-512 (block size 128 bytes, output 64 bytes).
- **Domain Separation Identifiers (DSI)**:
  - Base Point DSI: `CPaceRistretto255` (`b"CPaceRistretto255"`)
  - Intermediate Session Key DSI: `CPaceRistretto255_ISK` (`b"CPaceRistretto255_ISK"`)
- **MapToGroup & Identity Handling**: Maps 64-byte uniform hash output to a Ristretto255 group element using `RistrettoPoint::from_uniform_bytes` per [RFC 9496 Section 4.3.4](https://www.rfc-editor.org/rfc/rfc9496.html#section-4.3.4) and draft-irtf-cfrg-cpace-21 Appendix A.2. If the mapped point is the group identity $\mathcal{O}$ (probability $2^{-252}$), the node **MUST** immediately abort the pairing offer, zeroize all intermediate ephemeral values, and cease pairing advertising. No fallback to a basepoint constant is permitted.
- **Scalar Sampling Profile**:
  CPace draft-21 §8.3 specifies scalar generation in $[1, q-1]$ using either its recommended masked-bit sampler or uniform sampling. Conforming RAPP implementations generate non-zero scalars $x \in [1, q-1]$ using either:
  1. *Option A (Exact Rejection Sampling per draft-21 §8.3)*: Repeatedly draw 32 bytes from CSPRNG, interpret as an unsigned little-endian integer, and accept if $1 \le x < q$; if $x == 0$ or $x \ge q$, redraw 32 bytes locally from CSPRNG until $1 \le x < q$.
  2. *Option B (Profile Deviation: 64-Byte Wide Reduction per `crates/rapp`)*: Draw 64 uniform bytes from CSPRNG and reduce modulo $q$ using the wide modular reduction primitive (`Scalar::from_bytes_mod_order_wide`); if $x == 0$ (probability $2^{-512}$), redraw 64 bytes locally until $x \ne 0$. (Design Note: Because $2^{512} \pmod q \ne 0$, 64-byte wide reduction is a reviewed RAPP application profile deviation from draft-21 §8.3. The statistical distance from uniform on $[1, q-1]$ is bounded by $(q-1) / (4(2^{512} - k - 1)) \approx q / 2^{512} \approx 2^{-260}$, which is cryptographically negligible ($< 2^{-128}$) and enables constant-time arithmetic in the reduction primitive).
- **Context $C$ and Protocol Binding**:
  The Context input `CI` binds the pairing ceremony parameters in deterministic CBOR ([RFC 8949 Section 4.2.1](https://www.rfc-editor.org/rfc/rfc8949.html#section-4.2.1)):
  ```cddl
  pairing-context = [
    "RAPP-PAIRING-CONTEXT-v2",
    [26, 10, 10],                                                              ; wire version [Year, Month, Day]
    "CPACE-RISTR255-SHA512-RAPP-KC2 + Noise_XXpsk3_25519_ChaChaPoly_SHA512", ; full suite literal
    tstr,                                                                    ; transport profile of the connection (§2.2)
    tstr,                                                                    ; candidate_id of its offer entry (§4.2)
    bstr .size 32,                                                           ; offer_hash
    "requester",                                                             ; initiator role A
    "custodian"                                                              ; responder role B
  ]
  ```
  $$C = \text{encode\_deterministic\_cbor}(\text{pairing-context}) \quad (192\text{ bytes on BLE, 186 bytes on stream})$$
  $$\text{CI} = C, \quad \text{AD}_A = \emptyset, \quad \text{AD}_B = \emptyset$$
  Role strings designate protocol roles, not persistent device identities. The Requester acts strictly as Initiator ($A$) and the Custodian strictly as Responder ($B$) on every transport; on BLE the Requester transmits via `ATT_WRITE_REQ` and the Custodian via `ATT_HANDLE_VALUE_IND`.

#### 6.1.2 Generator Derivation (draft-21 Appendix A.2)
The generator point $G$ is derived from length-value (LV) encoding with zero-padding to align the first hash block:
1. **Length-Value Encoding**:
   Each byte string $S$ is encoded as $\text{lv}(S) = \text{LEB128}(|S|) \parallel S$, where $|S|$ is the length of $S$ in bytes, and $\text{LEB128}$ is unsigned little-endian base 128 encoding (1 byte for lengths $< 128$). The total encoded length is $|\text{lv}(S)| = |\text{LEB128}(|S|)| + |S|$. The concatenation of multiple fields is $\text{lv\_cat}(S_1, S_2, \dots, S_k) = \text{lv}(S_1) \parallel \text{lv}(S_2) \parallel \dots \parallel \text{lv}(S_k)$.
2. **First-Block Zero-Padding**:
   The zero padding $\text{len\_zpad}$ is designed such that the encoded prefix $\text{lv}(\text{DSI}) \parallel \text{lv}(\text{PRS}) \parallel \text{lv}(\text{zero\_bytes}(\text{len\_zpad}))$ completely fills the first SHA-512 input block ($s = 128\text{ bytes}$). Because $\text{len\_zpad} < 128$, its length prefix occupies exactly 1 byte ($|\text{LEB128}(\text{len\_zpad})| = 1$). The required padding length is therefore:
   $$\text{len\_zpad} = \max(0, 128 - 1 - |\text{lv}(\text{PRS})| - |\text{lv}(\text{DSI})|)$$
   where:
   - $|\text{lv}(\text{DSI})| = |\text{LEB128}(|\text{DSI}|)| + |\text{DSI}| = 1 + 17 = 18\text{ bytes}$ for $\text{DSI} = \text{b"CPaceRistretto255"}$
   - $|\text{lv}(\text{PRS})| = |\text{LEB128}(|\text{PRS}|)| + |\text{PRS}| = 1 + 6 = 7\text{ bytes}$ for 6-character Crockford Base32 pairing code $\text{PRS}$
   - Yielding $\text{len\_zpad} = 128 - 1 - 7 - 18 = 102\text{ bytes}$ of zeros.
   *(Note on draft-irtf-cfrg-cpace-21 §8.1: The draft states $\text{len\_zpad} = \max(0, s - \text{len}(\text{prepend\_len}(\text{PRS})) - \text{len}(\text{prepend\_len}(\text{DSI})) - 1)$, where §6.3 defines $\text{prepend\_len}(S) = \text{lv}(S)$ as the entire length-prefixed octet string, not merely the length prefix. An implementer interpreting $\text{prepend\_len}(S)$ as only the 1-byte LEB128 prefix would calculate $128 - 1 - 1 - 1 = 125$, overflowing the first block to 151 bytes and producing a non-conformant generator $G' \ne G$).*
3. **Generator String & Point Evaluation**:
   $$\text{gen\_str} = \text{lv\_cat}(\text{DSI}, \text{PRS}, \text{zero\_bytes}(102), C, \text{SID}) \quad (355\text{ bytes on BLE, 349 bytes on stream})$$
   $$G = \text{MapToGroup}(\text{SHA-512}(\text{gen\_str}))$$
   where $\text{PRS} = \text{UTF-8}(\text{normalized pairing code})$ and $\text{SID} = \text{offer\_id}$. Verify $G \ne \mathcal{O}$ (abort on identity).

#### 6.1.3 Ephemeral Exchange, Key Schedule, and Mutual Confirmation
1. **Initiator (Requester - Step 1)**:
   - Samples scalar $x_A \leftarrow \text{Scalar} \setminus \{0\}$ using either Option A or Option B.
   - Computes $Y_A = x_A \cdot G$. Encodes to 32 bytes via canonical Ristretto255 point compression.
   - Transmits 32-byte $Y_A$ in CPace Step 1 as one transport frame (on BLE via `ATT_WRITE_REQ` in a `SINGLE` SAR frame).
2. **Responder (Custodian - Step 2)**:
   - Receives $Y_A$, decodes and validates $Y_A \ne \mathcal{O}$ and canonical Ristretto255 element.
   - Atomically reserves attempt slot ($1 \le \text{attempts\_admitted} \le 3$, `active_attempt = true`).
   - Arms the attempt timer at admission: $\text{attempt\_deadline} = \min(\text{admission\_time} + 5.0\text{ s}, \text{offer\_deadline})$.
   - Samples scalar $x_B \leftarrow \text{Scalar} \setminus \{0\}$ using either Option A or Option B.
   - Computes $Y_B = x_B \cdot G$.
   - Computes shared point $K = x_B \cdot Y_A$. Verifies $K \ne \mathcal{O}$.
   - Derives Intermediate Session Key (ISK):
     $$\text{transcript\_ir} = \text{lv\_cat}([Y_A, \emptyset]) \parallel \text{lv\_cat}([Y_B, \emptyset])$$
     $$\text{isk\_input} = \text{lv\_cat}([\text{DSI}_{\text{ISK}}, \text{SID}, K]) \parallel \text{transcript\_ir}$$
     $$\text{ISK} = \text{SHA-512}(\text{isk\_input}) \quad (64\text{ bytes})$$
   - Derives Transcript Hash ($TH$) and Application Key Schedule (RFC 5869 HKDF-SHA-512):
     $$TH = \text{SHA-512}(\text{lv\_cat}([\text{"RAPP-CPACE-TRANSCRIPT-v2"}, \text{SID}, C, Y_A, Y_B])) \quad (64\text{ bytes})$$
     $$PRK = \text{HKDF-Extract-SHA512}(\text{salt} = TH, \text{IKM} = \text{ISK}) \quad (64\text{ bytes})$$
     $$PSK = \text{HKDF-Expand-SHA512}(PRK, \text{info} = \text{"RAPP-NOISE-PSK-v2"}, L = 32)$$
     $$K_A = \text{HKDF-Expand-SHA512}(PRK, \text{info} = \text{"RAPP-CPACE-CONFIRM-A-KEY-v2"}, L = 32)$$
     $$K_B = \text{HKDF-Expand-SHA512}(PRK, \text{info} = \text{"RAPP-CPACE-CONFIRM-B-KEY-v2"}, L = 32)$$
   - Computes mutual confirmation authenticator $T_B$:
     $$T_B = \text{FIRST32}(\text{HMAC-SHA512}(\text{key} = K_B, \text{data} = \text{lv\_cat}([\text{"RAPP-CPACE-CONFIRM-B-v2"}, TH])))$$
   - Transmits 64-byte $Y_B \parallel T_B$ in CPace Step 2 as one transport frame (on BLE via `ATT_HANDLE_VALUE_IND` in a `SINGLE` SAR frame).
3. **Key Confirmation (Requester - Step 3)**:
   - Requester receives $Y_B \parallel T_B$, decodes and validates $Y_B \ne \mathcal{O}$ and canonical point.
   - Computes shared point $K = x_A \cdot Y_B$. Verifies $K \ne \mathcal{O}$.
   - Derives identical $\text{ISK}, TH, PRK, PSK, K_A, K_B$.
   - Verifies $T_B$ in constant time against received 32-byte tag. Any mismatch immediately aborts the attempt and destroys temporary state.
   - Computes mutual confirmation authenticator $T_A$:
     $$T_A = \text{FIRST32}(\text{HMAC-SHA512}(\text{key} = K_A, \text{data} = \text{lv\_cat}([\text{"RAPP-CPACE-CONFIRM-A-v2"}, TH])))$$
   - Transmits 32-byte $T_A$ in CPace Step 3 as one transport frame (on BLE via `ATT_WRITE_REQ` in a `SINGLE` SAR frame).

#### 6.1.4 Finalization, PSK Handoff, and Post-PAKE Lifecycles
- Custodian receives and verifies $T_A$ in constant time within the clamped attempt deadline.
- Upon successful verification, Custodian clears `active_attempt`, marks the offer **consumed**, cancels the PAKE attempt timer, and transfers exclusive ownership to `Phase::NoisePairing` under a 10.0-second Noise handshake completion deadline.
- Subsequent post-Noise parameter echo, grant exchange, and trust storage is bounded by a 10.0-second monotonic deadline from local Noise completion. Active handed-off ceremonies are exempt from destruction by the original 60-second offer TTL; any failure of Noise, protocol mismatch, or deadline expiry destroys candidate trust immediately.
- Both parties immediately zeroize all intermediate ephemeral values ($\text{ISK}, PRK, K_A, K_B, x_A, x_B, K$).
- The established 32-byte $PSK$ is passed directly as the pre-shared key into the `Noise_XXpsk3` pairing handshake (§6.2).
- Security of the pairing ceremony is bounded by the ~252-bit prime order of Ristretto255, the uniform 30-bit entropy of the 6-character code, and the strict 3-attempt rate limit. Pairing and subsequent operational sessions provide industry-standard classical 128-bit cryptographic security via Curve25519, ChaCha20-Poly1305, and SHA-512 (§6.2, §6.3).

### 6.2 Noise_XXpsk3 Pairing Handshake (RFC 7748, RFC 8439, RFC 5869)

- **Suite**: `Noise_XXpsk3_25519_ChaChaPoly_SHA512`
- **Underlying Primitives**:
  - DH: Curve25519 / X25519 per [RFC 7748](https://www.rfc-editor.org/rfc/rfc7748.html) (32-byte keys).
  - Cipher: ChaCha20-Poly1305 per [RFC 8439](https://www.rfc-editor.org/rfc/rfc8439.html) (32-byte key, 12-byte nonce, 16-byte tag). Nonce layout: 4 zero bytes (`0x00, 0x00, 0x00, 0x00`) followed by 8 little-endian bytes representing the 64-bit sequence counter (per Noise Protocol Framework rev 34 Section 12.3 and reference implementation `crates/rapp/src/noise.rs:97`).
  - Hash: SHA-512 per [FIPS 180-4](https://doi.org/10.6028/NIST.FIPS.180-4) (64-byte output, 128-byte block size).
  - KDF: HKDF-SHA-512 per [RFC 5869](https://www.rfc-editor.org/rfc/rfc5869.html).
- **Fresh Static Key Generation Requirement**:
  Each pairing ceremony **MUST** generate a fresh, cryptographically independent static X25519 keypair $(s, s_{pub})$ on each endpoint. Static keys **MUST NOT** be reused across different peer pairings. Private keys MUST be stored in platform-encrypted secure hardware and marked non-exportable.
- **Handshake Pattern**:
  ```text
  Noise_XXpsk3(s, rs):
    -> e
    <- e, ee, s, es
    -> s, se, psk
  ```
- **Pre-messages**: None.
- **Prologue**: `encode_deterministic_cbor(pairing-prologue)` (§4.3.1).
- **PSK Input**: The 32-byte $PSK$ derived from CPace KC2 via HKDF-Expand-SHA512 (§6.1.3, §6.1.4) is injected as the pre-shared key at token `psk` via `MixKeyAndHash(psk)` per Noise revision 34 Section 9.2.
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
- **Immediate Channel Identifier Derivation**:
  Upon completing Message 3, both endpoints derive channel identifiers from the completed 64-byte handshake hash $h$:
  ```text
  session_id = first 16 bytes of SHA-512("RAPP-session-id-v1" || h)
  pair_id    = first 16 bytes of SHA-512("RAPP-pair-id-v1" || h)
  ```
  Both peers immediately zeroize $PSK$ and ephemeral keys.

### 6.3 Noise_KK Operational Session Handshake (RFC 7748, RFC 8439, RFC 5869)

- **Suite**: `Noise_KK_25519_ChaChaPoly_SHA512`
- **Pinned Cryptographic Standards**:
  - Noise Protocol Framework: Revision 34 (June 2018).
  - Classical DH: Curve25519 / X25519 per [RFC 7748](https://www.rfc-editor.org/rfc/rfc7748.html) (32-byte keys).
  - AEAD Cipher: ChaCha20-Poly1305 per [RFC 8439](https://www.rfc-editor.org/rfc/rfc8439.html) (32-byte key, 12-byte nonce, 16-byte tag). Nonce layout: 4 zero prefix bytes followed by 8 little-endian sequence counter bytes.
  - Hash Function: SHA-512 per [FIPS 180-4](https://doi.org/10.6028/NIST.FIPS.180-4) (64-byte output, 128-byte block size).
  - Key Derivation: HKDF-SHA-512 per [RFC 5869](https://www.rfc-editor.org/rfc/rfc5869.html).
- **Handshake Pattern**:
  ```text
  Noise_KK(s, rs):
    -> s
    <- s
    ...
    -> e, es, ss
    <- e, ee, se
  ```
- **State Initialization**:
  1. `protocol_name` = `"Noise_KK_25519_ChaChaPoly_SHA512"` (32 ASCII bytes).
  2. Because $|\text{protocol\_name}| \le 64$, $h$ is initialized by right-padding with 32 zero bytes to 64 bytes:
     $$h = \text{protocol\_name} \parallel 0^{32}$$
  3. Chaining key initialized to $ck = h$.
  4. MixHash(prologue): $h = \text{SHA-512}(h \parallel \text{prologue})$ where prologue is `encode_deterministic_cbor(session-prologue)` (§4.3).
  5. Pre-message static point hashing:
     - Initiator (Requester): $h = \text{SHA-512}(h \parallel s_{local\_pub})$; then $h = \text{SHA-512}(h \parallel s_{remote\_pub})$.
     - Responder (Custodian): $h = \text{SHA-512}(h \parallel s_{remote\_pub})$; then $h = \text{SHA-512}(h \parallel s_{local\_pub})$.
- **Message 1 (Initiator -> Responder)**: Tokens `e, es, ss`
  1. `e`: Initiator samples fresh ephemeral X25519 private key $e_{priv}$, computes 32-byte public key $e_{pub} = \text{X25519}(e_{priv}, G)$. Appends $e_{pub}$ (32 bytes) unencrypted to message buffer. Calls `MixHash(e_pub)`: $h = \text{SHA-512}(h \parallel e_{pub})$.
  2. `es`: Initiator computes classical DH shared secret $DH(e_{priv}, rs_{pub})$ (32 bytes). Calls `MixKey`:
     $$(ck, k) = \text{HKDF-SHA-512}(ck, DH(e_{priv}, rs_{pub}), 2)$$
     Cipher state rekeyed with $k$, sequence counter reset to 0.
  3. `ss`: Initiator computes static DH shared secret $DH(s_{priv}, rs_{pub})$ (32 bytes). Calls `MixKey`:
     $$(ck, k) = \text{HKDF-SHA-512}(ck, DH(s_{priv}, rs_{pub}), 2)$$
     Cipher state rekeyed with $k$, sequence counter reset to 0.
  4. Handshake Payload: Empty ($\emptyset$). Initiator calls `EncryptAndHash("")` with $h$ as associated data, producing a 16-byte Poly1305 authentication tag appended to message buffer. Updates $h = \text{SHA-512}(h \parallel \text{tag})$.
  **Total Message 1 Length**: $32 + 16 = 48\text{ bytes}$ (fits entirely in a single ATT Write Request frame without SAR fragmentation).
- **Message 1 Processing by Responder (Custodian)**:
  1. Reads 32 bytes $re_{pub}$. Validates non-zero point. Calls `MixHash(re_pub)`.
  2. `es`: Computes $DH(s_{priv}, re_{pub})$ (32 bytes). Calls `MixKey`:
     $$(ck, k) = \text{HKDF-SHA-512}(ck, DH(s_{priv}, re_{pub}), 2)$$
     Cipher state rekeyed with $k$, sequence counter reset to 0.
  3. `ss`: Computes $DH(s_{priv}, rs_{pub})$ (32 bytes). Calls `MixKey`:
     $$(ck, k) = \text{HKDF-SHA-512}(ck, DH(s_{priv}, rs_{pub}), 2)$$
     Cipher state rekeyed with $k$, sequence counter reset to 0.
  4. Reads 16-byte encrypted empty payload tag. Calls `DecryptAndHash`: verifies Poly1305 tag over empty plaintext with $h$ as associated data. Updates $h = \text{SHA-512}(h \parallel \text{tag})$.
- **Message 2 (Responder -> Initiator)**: Tokens `e, ee, se`
  1. `e`: Responder samples fresh ephemeral X25519 private key $e_{priv}$, computes 32-byte public key $e_{pub}$. Appends $e_{pub}$ (32 bytes) unencrypted to message buffer. Calls `MixHash(e_pub)`.
  2. `ee`: Responder computes ephemeral DH shared secret $DH(e_{priv}, re_{pub})$ (32 bytes, using initiator's ephemeral public key $re_{pub}$). Calls `MixKey`:
     $$(ck, k) = \text{HKDF-SHA-512}(ck, DH(e_{priv}, re_{pub}), 2)$$
     Cipher state rekeyed with $k$, sequence counter reset to 0.
  3. `se`: Responder computes DH shared secret between its ephemeral private key $e_{priv}$ and Initiator's static public key $rs_{pub}$ (32 bytes): $DH(e_{priv}, rs_{pub})$. Calls `MixKey`:
     $$(ck, k) = \text{HKDF-SHA-512}(ck, DH(e_{priv}, rs_{pub}), 2)$$
     Cipher state rekeyed with $k$, sequence counter reset to 0.
  4. Handshake Payload: Empty ($\emptyset$). Calls `EncryptAndHash("")` with $h$ as associated data, producing a 16-byte Poly1305 authentication tag appended to message buffer. Updates $h = \text{SHA-512}(h \parallel \text{tag})$.
  **Total Message 2 Length**: $32 + 16 = 48\text{ bytes}$ (fits entirely in a single ATT Indication frame without SAR fragmentation).
- **Message 2 Processing by Initiator (Requester)**:
  1. Reads 32 bytes $re_{pub}$. Calls `MixHash(re_pub)`.
  2. `ee`: Computes ephemeral DH shared secret $DH(e_{priv}, re_{pub})$ (32 bytes, using initiator's ephemeral private key $e_{priv}$ and responder's ephemeral public key $re_{pub}$). Calls `MixKey`:
     $$(ck, k) = \text{HKDF-SHA-512}(ck, DH(e_{priv}, re_{pub}), 2)$$
     Cipher state rekeyed with $k$, sequence counter reset to 0.
  3. `se`: Initiator computes DH shared secret between its static private key $s_{priv}$ and Responder's ephemeral public key $re_{pub}$ (32 bytes): $DH(s_{priv}, re_{pub})$. Calls `MixKey`:
     $$(ck, k) = \text{HKDF-SHA-512}(ck, DH(s_{priv}, re_{pub}), 2)$$
     Cipher state rekeyed with $k$, sequence counter reset to 0.
  4. Reads 16-byte encrypted empty payload tag. Calls `DecryptAndHash`: verifies Poly1305 tag over empty plaintext with $h$ as associated data. Updates $h = \text{SHA-512}(h \parallel \text{tag})$.
- **Transport Mode Transition & Directional Key Split**:
  Immediately upon completing Message 2:
  1. Both endpoints call `Split()` on the final chaining key $ck$:
     $$PRK = \text{HMAC-SHA-512}(ck, \emptyset)$$
     $$out1 = \text{HMAC-SHA-512}(PRK, \text{0x01})$$
     $$out2 = \text{HMAC-SHA-512}(PRK, out1 \parallel \text{0x02})$$
     $$c_1 = out1[0..32], \quad c_2 = out2[0..32]$$
  2. Directional Key Assignment:
     - **Initiator (Requester)**: Transmits using cipher key $c_1$; receives using cipher key $c_2$.
     - **Responder (Custodian)**: Transmits using cipher key $c_2$; receives using cipher key $c_1$.
  3. Both cipher states initialize sequence nonces to 0. Nonces increment strictly by 1 for each encrypted frame.
  4. Operational Session Identifier Derivation:
     $$\text{session\_id} = \text{SHA-512}(\texttt{"RAPP-session-id-v1"} \parallel h)[0..16]$$
     This fresh 16-byte `session_id` scopes all envelopes in the operational session.
  5. Ephemeral handshake state ($e_{priv}$) is immediately zeroized.

### 6.4 Independent Standard Noise_KK Interoperability Test Vector

The following normative test vector specifies the exact cryptographic transcript and intermediate values for `Noise_KK_25519_ChaChaPoly_SHA512` adhering strictly to Noise Protocol Framework Revision 34 and Section 6.3. Conforming implementations MUST produce byte-for-byte identical output for these inputs:

- **Static Keypairs**:
  - Initiator Static Private Key ($s_{i, priv}$): `1111111111111111111111111111111111111111111111111111111111111111`
  - Initiator Static Public Key ($s_{i, pub}$): `7b4e909bbe7ffe44c465a220037d608ee35897d31ef972f07f74892cb0f73f13`
  - Responder Static Private Key ($s_{r, priv}$): `2222222222222222222222222222222222222222222222222222222222222222`
  - Responder Static Public Key ($s_{r, pub}$): `0faa684ed28867b97f4a6a2dee5df8ce974e76b7018e3f22a1c4cf2678570f20`
- **Ephemeral Keypairs**:
  - Initiator Ephemeral Private Key ($e_{i, priv}$): `3333333333333333333333333333333333333333333333333333333333333333`
  - Initiator Ephemeral Public Key ($e_{i, pub}$): `7b0d47d93427f8311160781c7c733fd89f88970aef490d8aa0ee19a4cb8a1b14`
  - Responder Ephemeral Private Key ($e_{r, priv}$): `4444444444444444444444444444444444444444444444444444444444444444`
  - Responder Ephemeral Public Key ($e_{r, pub}$): `ff2ee45601ec1b67310c7790404585ae697331eee1c1f8cf2419731c1fff3e6b`
- **Session Prologue (§4.3)**:
  - Input `pair_id`: `8ab9b8bcde5c6eec845d9b1ca0d3a7be` (16 bytes)
  - Input `grants_hash`: `7777777777777777777777777777777777777777777777777777777777777777` (32 bytes)
  - Input `transport_profile`: `"fi.refineid.rapp.ble.v1"`
  - Encoded `prologue` (deterministic CBOR array, hex):
    `866f524150502d73657373696f6e2d763183181a0a0a78204e6f6973655f4b4b5f32353531395f436861436861506f6c795f534841353132508ab9b8bcde5c6eec845d9b1ca0d3a7be582077777777777777777777777777777777777777777777777777777777777777777766692e726566696e6569642e726170702e626c652e7631`
- **Handshake Wire Messages**:
  - **Message 1** (`-> e, es, ss`, 48 bytes: 32 bytes $e_{i, pub} \parallel 16$ bytes empty payload tag):
    `7b0d47d93427f8311160781c7c733fd89f88970aef490d8aa0ee19a4cb8a1b149a63e73abf65ea4dec7a3df0025f5b6c`
  - **Message 2** (`<- e, ee, se`, 48 bytes: 32 bytes $e_{r, pub} \parallel 16$ bytes empty payload tag):
    `ff2ee45601ec1b67310c7790404585ae697331eee1c1f8cf2419731c1fff3e6b518e03ebb38bc0cc00aad6d71427cdff`
- **Handshake Completion & Split Output**:
  - Final Handshake Hash ($h$, 64 bytes):
    `b054428bd222f4590ede01fa9b58ae0a32a0eb9f209519cc2c682cd6c8fcd70686aa615b02b04c3c6945d356e8c0a25c3134c3b55e5f209be5c3d6ed75df4f70`
  - Initiator-to-Responder Directional Transport Cipher Key ($c_1$, 32 bytes):
    `271245e9b5ffc357a6d442e04a376531bd3a0f81d69d7b97eaa132cc81d209ab`
  - Responder-to-Initiator Directional Transport Cipher Key ($c_2$, 32 bytes):
    `f3364ea960fcb3b95518b6029e2fbac8d1f259e630fa53beb63cf647e672ca40`
  - Operational Session Identifier (`session_id`, 16 bytes):
    `78260a69cecd4931778e59a9e0d2de4e`

This test vector is also cataloged under entry `"session-kk-fixed-transcript-ble"` in `docs/protocols/vectors/rapp-v26.10.10.json`, beside `"session-kk-fixed-transcript-stream"` for the stream transport profile (same keys, prologue naming `"fi.refineid.stream.v1"`).

---

## 7. Authenticated Message Envelopes and Wire Framing

### 7.1 Common Post-Handshake Message Envelope & Complete Message Schemas
Every message transmitted inside an established pairing channel (`Phase::NoisePairing`) or operational session (`Phase::NoiseSession`) is encapsulated in a deterministic CBOR envelope conforming to the following normative CDDL specification:

```cddl
rapp-message =
    { "version": [26, 10, 10], "session_id": bstr .size 16, "sequence": uint, "type": "pairing.hello", "body": pairing-hello-body, * common-opt }
  / { "version": [26, 10, 10], "session_id": bstr .size 16, "sequence": uint, "type": "pairing.confirm", "body": pairing-confirm-body, * common-opt }
  / { "version": [26, 10, 10], "session_id": bstr .size 16, "sequence": uint, "type": "pairing.abort", "body": pairing-abort-body, * common-opt }
  / { "version": [26, 10, 10], "session_id": bstr .size 16, "sequence": uint, "type": "session.ready", "body": session-ready-body, * common-opt }
  / { "version": [26, 10, 10], "session_id": bstr .size 16, "sequence": uint, "type": "session.close", "body": session-close-body, * common-opt }
  / { "version": [26, 10, 10], "session_id": bstr .size 16, "sequence": uint, "type": "liveness.ping", "body": liveness-ping-body, * common-opt }
  / { "version": [26, 10, 10], "session_id": bstr .size 16, "sequence": uint, "type": "liveness.pong", "body": liveness-pong-body, * common-opt }
  / { "version": [26, 10, 10], "session_id": bstr .size 16, "sequence": uint, "type": "operation.request", "body": operation-request-body, * common-opt }
  / { "version": [26, 10, 10], "session_id": bstr .size 16, "sequence": uint, "type": "operation.result", "body": operation-result-body, * common-opt }
  / { "version": [26, 10, 10], "session_id": bstr .size 16, "sequence": uint, "type": "operation.result_ack", "body": operation-result-ack-body, * common-opt }
  / { "version": [26, 10, 10], "session_id": bstr .size 16, "sequence": uint, "type": "operation.status_request", "body": operation-status-request-body, * common-opt }
  / { "version": [26, 10, 10], "session_id": bstr .size 16, "sequence": uint, "type": "operation.status", "body": operation-status-body, * common-opt }
  / { "version": [26, 10, 10], "session_id": bstr .size 16, "sequence": uint, "type": "operation.progress", "body": operation-progress-body, * common-opt }
  / { "version": [26, 10, 10], "session_id": bstr .size 16, "sequence": uint, "type": "error", "body": error-body, * common-opt }

common-opt = (
  ? "critical": [* tstr],           ; unrecognized critical fields abort session
  ? "extensions": { * tstr => any } ; forward-compatible non-critical data
)

; 1. Pairing Peer Introduction
pairing-hello-body = {
  "parameters": negotiated-parameters,
  "display_name": tstr,
  "platform": tstr,
  ? "requested_profiles": [* tstr]
}

negotiated-parameters = {
  "version": [26, 10, 10],
  "suite": "CPACE-RISTR255-SHA512-RAPP-KC2 + Noise_XXpsk3_25519_ChaChaPoly_SHA512",
  "offer_hash": bstr .size 32,
  "transport_profile": tstr,   ; transport profile of the connection (§2.2)
  "candidate_id": tstr         ; candidate_id of its offer entry (§4.2)
}

; 2. Explicit Grant Confirmation
pairing-confirm-body = {
  "granted_profiles": [* tstr]
}

; 3. Pairing Abort
pairing-abort-body = {
  "reason": tstr
}

; 4. Operational Session Ready Proof
session-ready-body = {
  "parameters": session-parameters,
  "nonce": bstr .size 32
}

session-parameters = {
  "version": [26, 10, 10],
  "suite": "Noise_KK_25519_ChaChaPoly_SHA512",
  "transport_profile": tstr,   ; transport profile of the connection (§2.2)
  "candidate_id": tstr,        ; its registered candidate_id (§2.2)
  "grants_hash": bstr .size 32
}

; 5. Authenticated Session Close
session-close-body = {
  "reason": close-reason-val,
  "last_received_sequence": uint
}

close-reason-val =
    "normal"
  / "complete"
  / "user_disconnect"
  / "policy"
  / "credential_rejected"
  / "protocol_violation"
  / "pairing_revoked"
  / "shutdown"
  / "card_unavailable"   ; the Custodian can no longer serve the card
  / "service_withdrawn"  ; the Custodian stopped serving every pairing (§4.5)

; 6. Liveness Challenge
liveness-ping-body = {
  "challenge": bstr .size 32,
  "last_received_sequence": uint
}

; 7. Liveness Challenge Echo
liveness-pong-body = {
  "challenge": bstr .size 32,
  "last_received_sequence": uint
}

; 8. Operation Request
operation-request-body = {
  "operation_id": bstr .size 16,
  "profile": tstr,
  "action": tstr,
  "context": { * tstr => any },
  "payload": { * tstr => any },
  ? "expires_after_ms": uint
}

; 9. Operation Result
operation-result-body = {
  "operation_id": bstr .size 16,
  "request_hash": bstr .size 32,
  "status": operation-status-val,
  ? "response": { * tstr => any },
  ? "error": tstr,
  ? "remaining_retries": uint,
  ? "retired": bool
}

operation-status-val =
    "completed"
  / "rejected"
  / "credential_rejected"
  / "cancelled"
  / "ambiguous"

operation-state-val =
    "in_flight"
  / operation-status-val

; 10. Operation Result Acknowledgment
operation-result-ack-body = {
  "operation_id": bstr .size 16,
  "request_hash": bstr .size 32
}

; 11. Operation Status Request (Reconciliation Query)
operation-status-request-body = {
  "operation_id": bstr .size 16
}

; 12. Operation Status Report (Reconciliation Response)
operation-status-body = {
  "operation_id": bstr .size 16,
  "known": bool,
  ? "state": operation-state-val,
  ? "request_hash": bstr .size 32,
  ? "retired": bool
}

; 13. Operation Progress Update
operation-progress-body = {
  "operation_id": bstr .size 16,
  "request_hash": bstr .size 32,
  "event": progress-event-val
}

progress-event-val =
    "waiting_for_card"
  / "card_wait_ended"
  / tstr

; 14. Protocol Error Body: error-body is defined in §10.4
```

#### Normative Semantics of Registered Message Types:
1. **`pairing.hello`**: Transmitted by the Requester inside `Phase::NoisePairing` immediately following handshake completion. Echoes negotiated pairing parameters (`version`, `suite`, `offer_hash`, `transport_profile`, `candidate_id`), peer display name, and requested profile names. The Custodian verifies that all echoed parameters match its local offer state; any discrepancy aborts pairing.
2. **`pairing.confirm`**: Transmitted by the Custodian to grant the requested profiles matching the active offer; subsequently echoed by the Requester. Contains the canonical list of `granted_profiles`. Both peers verify that the sets are identical before deriving `grants_hash` (Section 4.3).
3. **`pairing.abort`**: Transmitted by either peer to cancel an in-progress pairing ceremony prior to final trust record storage, providing an advisory reason string. Ephemeral keys are destroyed immediately.
4. **`session.ready`**: Transmitted by the Custodian upon completing `Phase::NoiseSession` (`Noise_KK`) to prove possession of the operational session key and fresh session state, echoing session parameters and a fresh random 32-byte `nonce`.
5. **`session.close`**: Transmitted by either peer to signal an orderly, authenticated termination of an operational session, providing a registered `close-reason-val` and acknowledging the `last_received_sequence`.
6. **`liveness.ping`**: Periodic authenticated keepalive request transmitted by either peer carrying a fresh 32-byte `challenge` and sequence acknowledgment.
7. **`liveness.pong`**: Periodic authenticated keepalive response echoing the exact 32-byte `challenge` and sequence acknowledgment.
8. **`operation.request`**: Transmitted by the Requester to initiate a credential action under a registered profile (§8.2, §9).
9. **`operation.result`**: Transmitted by the Custodian to deliver the final card execution outcome, status, signature/response payload, or credential error (§8.2).
10. **`operation.result_ack`**: Transmitted by the Requester to acknowledge delivery of a successful (`"completed"`) operation result, permitting the Custodian to prune the write-ahead journal entry (§8.2).
11. **`operation.status_request`**: Transmitted by the Requester after reconnecting to reconcile the terminal outcome of an interrupted or ambiguous operation (§8.3).
12. **`operation.status`**: Transmitted by the Custodian in response to `operation.status_request`, reporting whether the operation is journaled (`known`) and its terminal state (§8.3).
13. **`operation.progress`**: Advisory notification transmitted by the Custodian during long-running card transactions (e.g. prompt to present card to NFC antenna).
14. **`error`**: Application protocol error envelope transmitted upon encountering unexpected conditions (e.g. a second request while one operation is live, refused with `operation_failed`, or an unknown operation race); bounded schema and numeric error code mappings are defined in §10.4.

### 7.2 Field Semantics, Version Precedence, and Sequencing
1. **Wire Version & Skew Precedence**:
   - The envelope wire version is fixed to `[26, 10, 10]` (`[Year, Month, Day]`).
   - If version skew is observed during handshake prologue negotiation (e.g. mismatched version in the Noise prologue), the handshake fails AEAD decryption and surfaces as a **Class 2 (Transport Loss)** failure; the link drops and stored pairings remain intact.
   - If an authenticated envelope carrying a version other than `[26, 10, 10]` is received on an establishing or active session, the receiver MUST reject the message and terminate the session as a **Class 2** transport failure without modifying stored pairing records.
   - **Class 4 (Pairing Revocation)** is strictly NOT triggered by version mismatch; Class 4 is reserved exclusively for authenticated cryptographic tampering, repeat echo mismatches, or sequence manipulation by an established, paired peer.
2. **Session Scoping (`session_id`)**:
   - For pairing-channel envelopes (`pairing.hello`, `pairing.confirm`), `session_id` MUST equal the 16-byte pairing `session_id` derived immediately from $h$ (Section 4.3).
   - For operational sessions, `session_id` MUST equal the independent 16-byte operational `session_id` derived from $h_{\text{session}}$ (Section 4.3).
   - An envelope carrying a mismatched `session_id` is an unrecoverable session error: close the session immediately (Class 2) without altering stored pairings.
3. **Sequential Monotonic Sequencing (`sequence`) & Rollover Rules**:
   - The sequence counter starts at `0` independently for each direction (`0, 1, 2, ...`) and is represented as an unsigned 64-bit integer (`u64`).
   - It increases by exactly `1` for each transmitted envelope.
   - **Initial State & Inbound Sequencing**: Before any inbound envelope has been received on an established transport channel, the expected incoming sequence counter is `0` (`expected_inbound_seq = 0`), and `last_received_sequence` is initialized to an unreceived state (`None` in local state, represented as `0` in outgoing acknowledge fields where sequence 0 has not yet arrived). The very first inbound envelope from a peer on a new session **MUST** have `sequence == 0`. Each accepted inbound envelope advances `expected_inbound_seq = expected_inbound_seq + 1` and updates `last_received_sequence = Some(envelope.sequence)`.
   - **Rollover & Session Lifetime**: If `sequence` approaches $2^{64}-1$, or upon reaching the local policy session limit (e.g. 10,000 messages or 1 hour of continuous inactivity), the endpoints MUST execute an orderly session restart by transmitting `session.close` with reason `"normal"` or `"shutdown"` and dropping the link. Subsequent operations reconnect via `Phase::Routing` with a fresh session and sequence reset to 0. Rollover is an orderly lifecycle transition, NOT a protocol violation or pairing revocation.
   - **Acknowledged Delivery & Invariants**: Because ATT Indications are stop-and-wait acknowledged (`ATT_HANDLE_VALUE_CFM`), and transport nonces are sequential, any confirmed sequence regression (backward jump, duplicate, or gap) observed across the authenticated decrypted stream proves that an authenticated peer tampered with protocol sequencing: close the session immediately and revoke pairing (Class 4). Outbound indication retries at the ATT layer are deduplicated by the underlying BLE controller before delivery to the RAPP layer.
4. **Cryptographic AEAD Encapsulation**:
   - The plaintext `rapp-message` is encoded via deterministic CBOR (RFC 8949 Section 4.2).
   - Encrypted via ChaCha20-Poly1305 with a 16-byte Poly1305 authentication tag using the active directional Noise cipher state.
   - The resulting ciphertext payload is one transport frame (§2.2): on BLE it is framed into RAPP SAR fragments (Section 5.3) and transmitted via `ATT_WRITE_REQ` (Central to Peripheral) or `ATT_HANDLE_VALUE_IND` (Peripheral to Central); on the stream transport it is one length-prefixed frame (§2.2.2).

---

## 8. Operation Model and Execution Lifecycle (Direct Idempotent Execution)

Credential operations (authentication signatures, qualified document signing) invoke sensitive, stateful cryptographic operations on the physical identity card over NFC.

### 8.1 Strict At-Most-Once Physical Transmission Contract
1. **Zero Repeated Executions**:
   Cryptographic private key commands and PIN verifications **MUST NEVER** be executed more than once per user authorization. Replaying network requests or reconnecting after a transport failure **MUST NEVER** trigger re-execution of a physical card command.
2. **Write-Ahead Journaling**:
   Before physically dispatching any APDU command that can decrement a try counter or invoke a card private key, the Custodian **MUST** durably record a write-ahead journal entry in platform secure storage:
   - `pair_id` (16 bytes, scoping the entry to the authenticated pairing)
   - `operation_id` (16 bytes, uniquely identifying the operation within the pairing)
   - `request_hash` (32 bytes, session-independent deterministic commitment)
   - State: `in_flight`
   - Timestamp (UTC / local monotonic milliseconds)
   - Optional provenance: `session_id` (16 bytes, recording the session on which the request originally arrived; advisory metadata, not bound into `request_hash`)
   - For `batch_sign_documents`: `batch_total` ($1..64$), `completed_signatures` (`[bstr]`), and currently executing document index.
3. **Ambiguity Protection**:
   If the link drops or the process terminates while an operation is executing on the card, physical card re-execution is strictly prohibited. Recovery and reconciliation occur exclusively through durable journal status inspection (§8.3).

### 8.2 Direct Idempotent Operation Lifecycle

1. **Operation Request & Deterministic Commitment**:
   - Requester transmits `operation.request` carrying a fresh 16-byte `operation_id`, profile, action, context map, payload map, and optional `expires_after_ms`.
   - Both endpoints derive the deterministic, session-independent request commitment:
     $$\text{request\_hash} = \text{SHA-256}(\text{encode\_deterministic\_cbor}([\texttt{"RAPP-request-v1"}, \text{pair\_id}, \text{operation\_id}, \text{profile}, \text{action}, \text{context}, \text{payload}]))$$
     - **Session-Independent Commitment Scope**:
       This fixed-order array preimage binds the protocol domain label (`"RAPP-request-v1"`), the authenticated `pair_id` (16 bytes), the unique `operation_id` (16 bytes), the profile string, the action string, and all context/payload maps.
       `pair_id` replaces ephemeral session identifiers in the commitment preimage. This ensures that the commitment is stable across transport disruptions and BLE reconnections: an otherwise identical request retransmitted across session boundaries under the same pairing computes the exact same `request_hash`. Ephemeral session binding is supplied by the outer authenticated envelope (`rapp-message.session_id` and directional AEAD transport encryption).
       Requests originating from different pairings are cryptographically isolated: because each pairing possesses a distinct `pair_id`, requests from different pairings will never produce matching `request_hash` commitments even if an identical `operation_id` is accidentally or maliciously chosen.
   - **`expires_after_ms` Semantics**:
     - `expires_after_ms` is strictly **excluded** from `request_hash` so that local expiry policies do not alter cryptographic commitments.
     - If present, `expires_after_ms` MUST be $> 0$; a value of 0 is rejected immediately with error `invalid_lifetime`. If absent, the Custodian applies a local default lifetime $\text{effective\_expires\_after\_ms} = 300{,}000\text{ ms}$ (5 minutes).
     - Upon receiving `operation.request`, the Custodian derives a monotonic local deadline using saturating arithmetic:
       $$\text{local\_deadline} = \text{local\_start\_monotonic\_ms}.\text{saturating\_add}(\min(\text{effective\_expires\_after\_ms}, \text{local\_policy\_max\_lifetime}))$$
     - If `local_deadline` passes before the user authorizes the operation on the phone screen, the operation expires. The Custodian transitions the in-memory state to `cancelled`, releases held resources, and responds with `operation.result` (`status: "cancelled"`, `error: "operation_expired"`). No card APDU is dispatched.
2. **Atomic Admission, In-Flight Reservation, and Content Freezing**:
   - **Pairing Scope & Cross-Pairing Isolation**: All operations, active task tables, write-ahead journal records, and durable tombstones are strictly scoped by `pair_id`. An `operation_id` is evaluated exclusively within the context of the calling pairing. The Custodian **MUST NEVER** deliver another pairing's cached results, join another pairing's in-flight task, or expose another pairing's journal entries.
   - **Atomic Admission Transaction**: Upon receiving `operation.request`, the Custodian executes an atomic check-and-reserve transaction against its active in-memory task table, write-ahead journal, and durable tombstones:
     a. **Existing Operation Match**: If `(pair_id, operation_id)` is found in ANY state (awaiting consent, in-flight, completed, retired, ambiguous, rejected, cancelled):
        - The Custodian **MUST validate the commitment**:
          $$\text{incoming.request\_hash} == \text{existing.request\_hash}$$
        - **Changed-Content Collision**: If $\text{incoming.request\_hash} \ne \text{existing.request\_hash}$:
          The request is an illegal aliasing or parameter tampering attempt. The Custodian **MUST immediately reject** the request with `error: "duplicate_operation"` (Class 3). The existing operation, active prompt, NFC card execution, or tombstone MUST NOT be replaced, cancelled, mutated, or joined.
        - **Identical Retransmission**: If $\text{incoming.request\_hash} == \text{existing.request\_hash}$:
          - `awaiting_consent`: Join the active authorization flow. The retransmitted request attaches as an observer awaiting user confirmation. No duplicate consent dialog is presented to the user.
          - `in_flight`: Join the active NFC/card transaction. The retransmitted request attaches as an observer awaiting card completion and receives the single `operation.result`. No duplicate card APDUs are dispatched.
          - `completed`: Re-transmit the cached `operation.result` immediately with cached response payload/status without re-accessing the card.
          - `retired`: Re-transmit `operation.result` reporting `status: tombstone.terminal_disposition` (preserving `"completed"`, `"rejected"`, `"credential_rejected"`, or `"ambiguous"`), `retired: true`, and `error: "operation_already_retired"` (or the preserved error string for failed/rejected operations) without re-accessing the card or presenting user prompts (see Durable Tombstones below).
          - `rejected` / `credential_rejected`: Re-transmit cached terminal error result (e.g. invalid PIN error with remaining retries) without re-accessing the card.
          - `ambiguous`: Re-transmit terminal `operation.result` (`status: "ambiguous"`). Re-dispatching card APDUs is strictly forbidden.
          - `cancelled`: Respond with `operation.result` (`status: "cancelled"`, `error: "operation_expired"`).
     b. **New Operation Admission & Content Freezing**: If `(pair_id, operation_id)` is not present in active tasks, write-ahead journal, or durable tombstones:
        - The Custodian atomically inserts a reservation entry in `state: "awaiting_consent"`, binding `pair_id`, `operation_id`, and `request_hash`.
        - **Immutable Request Snapshot**: The Custodian takes an immutable snapshot of all request parameters (`profile`, `action`, `context`, `payload`, `request_hash`, `local_deadline`).
        - The sovereign user consent UI presented on the phone screen (§11) **MUST** render strictly from this frozen immutable snapshot. Subsequent messages on the connection or other sessions cannot mutate or replace parameters under authorization.
3. **Authorization and Conscious Consent**:
   - The Custodian validates that the requested profile is present in `granted_profiles` for the active pairing. If not granted, the Custodian responds with `operation.result` (`status: "rejected"`, `error: "unauthorized"`).
   - If the action requires user authorization or PIN entry (e.g. document signing under `"fi.refineid.document-signing.v1"` or browser authentication under `"fi.refineid.authentication.v1"`), the Custodian displays sovereign transaction details on the phone screen (§11).
   - If the user declines on screen, the operation terminates immediately; the Custodian transitions the reservation slot to `state: "rejected"`, transmits `operation.result` (`status: "rejected"`, `error: "user_cancelled"`), and releases in-memory state. No card APDUs are dispatched and no write-ahead journal entry is created.
4. **Write-Ahead Journaling & Card Execution**:
   - Upon conscious human approval on the phone screen, the Custodian **MUST** write a durable write-ahead journal entry to persistent platform secure storage before dispatching any APDU to the smart card:
     `[pair_id, operation_id, request_hash, state: "in_flight", timestamp]`.
   - If the durable journal write fails (e.g. platform storage I/O error), the Custodian **MUST NOT** dispatch APDUs to the card; it aborts execution and returns Class 3 `operation_failed`.
   - Once durably recorded, the Custodian verifies the retry counter floor (§10.3) and dispatches APDUs to the FINEID card over NFC.
   - Upon completing card execution, the Custodian transitions the journal entry to `state: "completed"` (or `state: "rejected"` / `"credential_rejected"` if card SW indicates verification failure) and caches the response payload.
5. **Result Delivery, Acknowledgment Validation, and Durable Tombstones**:
   - The Custodian transmits `operation.result` carrying `operation_id`, `request_hash`, and final execution status (`"completed"`, `"rejected"`, or `"credential_rejected"`).
   - For `status == "completed"`, the Requester transmits `operation.result_ack`.
   - **Acknowledgment Validation**:
     Upon receiving `operation.result_ack`, the Custodian validates:
     a. `pair_id` matches the authenticated pairing owning the operation.
     b. `operation_id` matches an existing unretired journal entry.
     c. `request_hash` matches the entry's stored `request_hash`.
     d. The operation is in an unacknowledged terminal state (`completed`).
     If validation fails (unknown identifier, hash mismatch, or already retired), the acknowledgment is rejected or safely ignored without altering existing tombstones.
   - **Durable Tombstone Transition**:
     Upon receiving a valid `operation.result_ack` (or when storage garbage collection runs on completed entries), the Custodian is permitted to delete the large cached response payload (signatures, certificates, diagnostic payloads) to conserve device storage, **BUT MUST RETAIN A DURABLE TOMBSTONE** in persistent platform secure storage:
     `[pair_id, operation_id, request_hash, state: "retired", terminal_disposition, timestamp]`
     where `terminal_disposition` preserves the terminal outcome (`"completed"`, `"rejected"`, `"credential_rejected"`, or `"ambiguous"`).
   - **Tombstone Retention Contract & Pairing Lifetime Durability**:
     - **Pairing Lifetime Retention**: The Custodian **MUST** retain durable tombstones in persistent secure storage for the **entire active lifetime of the pairing** (`pair_id`).
     - Because `operation.request` and the 16-byte `operation_id` contain no creation timestamp or authenticated operation epoch, time-based expiration (e.g. 30 days) and FIFO ring-buffer eviction during an active pairing are **strictly prohibited**. Evicting a tombstone while the pairing remains active would allow a retransmitted or delayed `operation_id` to appear unknown in a fresh session and be silently re-admitted, violating identifier-level idempotency and physical card safety.
     - Tombstones survive application termination, process restarts, OS updates, and device reboots.
     - **Destruction Contract**: Durable tombstones associated with a `pair_id` are purged if and only if the pairing itself is explicitly revoked or deleted (e.g. unpair ceremony or manual deletion of the pairing by the user in settings).
     - **Storage Exhaustion Safety**: In the event that device persistent secure storage allocated for pairing tombstones is exhausted, the Custodian **MUST fail closed**: it MUST refuse to admit new operations by returning error `"storage_exhausted"` (Class 3), rather than evicting historical tombstones.
     - **Subsequent Queries & Requests Matching a Retained Tombstone**:
       - If $\text{incoming.request\_hash} == \text{tombstone.request\_hash}$: The Custodian responds with `operation.result` reporting `status: tombstone.terminal_disposition`, `retired: true`, and `error: "operation_already_retired"` (if disposition was completed) or the original preserved error (if rejected / credential_rejected / ambiguous), omitting pruned response payloads. The preserved terminal disposition (`"completed"`, `"rejected"`, `"credential_rejected"`, `"ambiguous"`) is strictly honored; a retired failed or ambiguous operation is never reported as completed. Under NO circumstances are smart card APDUs re-dispatched or user consent prompts presented.
       - If $\text{incoming.request\_hash} \ne \text{tombstone.request\_hash}$: The Custodian rejects immediately with `error: "duplicate_operation"` (Class 3).
6. **Safe Reads (Direct Optimization)**:
   - Actions that perform read-only card operations (e.g. `inspect_card`, `read_identity`, `read_certificate`) involve no private-key operations or PIN try decrements.
   - Safe reads omit write-ahead journaling and screen consent prompts, executing card read APDUs directly and responding with `operation.result`.

### 8.3 Durable Status Reconciliation and Ambiguity Recovery

When a BLE connection drops, a timeout occurs, or the mobile device restarts while an operation is in progress, recovery is governed by strict deterministic reconciliation rules. Because `request_hash` is session-independent (§8.2.1) and durable tombstones are preserved (§8.2.5), reconciliation supports two equivalent paths: direct request retransmission and explicit status querying.

1. **Pre-Execution Disconnect (Awaiting Human Consent)**:
   - If the BLE connection drops or `local_deadline` expires while the phone screen is awaiting user confirmation (prior to write-ahead journal commit):
     - The operation is aborted in memory (`state: "cancelled"`).
     - No write-ahead journal entry was written; no card commands were issued; retry counters are untouched.
     - On reconnect, querying `operation.status_request` for this `operation_id` returns `known: false`.
2. **In-Flight Disconnect (Card APDU in Progress)**:
   - When the BLE connection drops while a card APDU is actively being executed over NFC:
     - The Custodian's local NFC transaction runner continues executing the single active physical APDU sequence to its natural conclusion:
       a. **Card APDU Succeeds**: If the card returns `SW 90 00` and the cryptographic signature, the Custodian writes `state: "completed"` and caches the signature in the write-ahead journal.
       b. **Card APDU Reports Error**: If the card returns a definitive failure status (e.g. `SW 63 Cx` wrong PIN or `SW 69 83` blocked), the Custodian updates the journal to `state: "rejected"` or `"credential_rejected"` with remaining retries.
       c. **NFC Field Interrupted / Custodian Crash**: If NFC coupling is dropped, the card is removed mid-command, or the phone restarts before terminal card status can be written: the Custodian transitions the journal record to `state: "ambiguous"`.
     - In all cases, the Custodian **MUST NEVER** automatically re-dispatch the physical card command.
3. **Reconciliation Protocol (`operation.status_request` / `operation.status`)**:
   - Upon reconnecting in a fresh operational session (`Phase::NoiseSession`), the Requester transmits `operation.status_request` carrying the queried `operation_id` (or retransmits `operation.request` identically).
   - The Custodian consults its durable write-ahead journal and durable tombstones for that `pair_id`:
     - **Completed Operation (Unretired / Cached Payload)**: If `operation_id` is journaled in state `completed`:
       - Custodian responds with `operation.status` (`known: true`, `state: "completed"`, `request_hash: <hash>`, `retired: false`).
       - Custodian also re-delivers `operation.result` carrying the cached signature or response bytes without re-accessing the card.
       - Requester completes the exchange with `operation.result_ack`.
     - **Retired Operation (Acknowledged / Pruned Result)**: If `operation_id` matches a durable tombstone (`state: "retired"`):
       - Custodian responds with `operation.status` (`known: true`, `state: tombstone.terminal_disposition`, `request_hash: tombstone.request_hash`, `retired: true`). The reported `state` preserves the exact original outcome (`"completed"`, `"rejected"`, `"credential_rejected"`, or `"ambiguous"`).
       - If queried via `operation.request`, Custodian responds with `operation.result` (`status: tombstone.terminal_disposition`, `request_hash: tombstone.request_hash`, `retired: true`, `error: "operation_already_retired"` for completed operations, or the preserved terminal error for rejected/ambiguous operations). Pruned response payloads are omitted. Card APDUs are NEVER re-dispatched and user consent prompts are NEVER shown.
     - **Terminal Rejected Operation (Unretired)**: If `operation_id` is journaled in state `rejected` or `credential_rejected`:
       - Custodian responds with `operation.status` (`known: true`, `state: <state>`, `request_hash: <hash>`, `retired: false`).
       - Custodian re-delivers `operation.result` carrying the cached error string and remaining retry count.
     - **Still In-Flight**: If `operation_id` is currently executing on the smart card (e.g. lengthy key generation or awaiting NFC presentation):
       - Custodian responds with `operation.status` (`known: true`, `state: "in_flight"`, `request_hash: <hash>`).
       - Requester awaits the asynchronous `operation.result` indication or re-queries status periodically.
     - **Ambiguous Operation (Unretired)**: If `operation_id` is journaled in state `ambiguous`:
       - Custodian responds with `operation.status` (`known: true`, `state: "ambiguous"`, `request_hash: <hash>`, `retired: false`).
       - If partial batch progress was recorded (`batch_sign_documents`), `operation.result` returns `response: {"completed_signatures": [sig_0, ..., sig_{k-1}], "completed_count": k}`.
     - **Unknown Operation**: If `operation_id` is not present in active tasks, write-ahead journal, or durable tombstones: Custodian responds with `operation.status` (`known: false`).
4. **Terminal Exit from Ambiguous State**:
   - An ambiguous operation is permanently terminal for that `operation_id`. It CANNOT be retried or re-executed under the same identifier.
   - If the application wishes to retry the action after an ambiguous or failed operation, the Requester **MUST** allocate a fresh 16-byte `operation_id` and initiate a completely new operation lifecycle, requiring fresh human consent and authorization on the Custodian phone screen.


---

## 9. Registered Credential Profiles and Actions

The profile registry defines the operations permitted over authenticated RAPP sessions:

| Profile Identifier | Human Purpose | Consequential Card Commands |
| :--- | :--- | :--- |
| `"fi.refineid.card-status.v1"` | Inspect card status, ATR, and retry counters | None (Safe Reads) |
| `"fi.refineid.authentication.v1"` | Workstation/browser authentication signatures | PIN 1 verify & private-key signature |
| `"fi.refineid.document-signing.v1"` | Qualified Electronic Signatures (QES) | PIN 2 verify & private-key signature |

### 9.1 Profile: `"fi.refineid.card-status.v1"`
- **`inspect_card`** (Safe Read):
  - Context & Payload: Empty maps (`{}`).
  - Response:
    ```cddl
    inspect-card-response = {
      "card_present": bool,
      "atr": bstr,                       ; answer to reset, or its historical bytes; empty when the platform exposes neither
      "supported_profiles": [* tstr],
      ? "pin1_factory": bool,            ; PIN 1 still holds factory reference data
      ? "pin2_factory": bool,
      ? "pin1_attempts": uint / null,    ; remaining tries; null when the card does not expose the counter
      ? "pin2_attempts": uint / null,
      ? "puk_attempts": uint / null
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

### 9.2 Profile: `"fi.refineid.authentication.v1"`
- **`read_certificate`** (Safe Read):
  - Payload: `{"kind": "authentication"}`.
  - Response: `certificate` (DER-encoded X.509 certificate bytes).
- **`browser_authenticate`**:
  - Context: `origin` (`tstr .size (1..256)`, e.g. `"https://login.example.fi"`).
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

      A P-384 key signing a TLS 1.3 handshake needs `"ecdsa_sha384"`.
    - `digest` (`bstr`): Pre-hashed challenge bytes matching algorithm digest length (e.g. 32 bytes for SHA-256).
  - Validation: If a request specifies an unrecognized or unsupported `key_profile` or `algorithm`, the Custodian MUST respond with `operation.result` carrying `status: "rejected"` and `error: "unsupported_parameter"`. This is a semantic rejection, NOT an authenticated protocol violation (Class 4).
  - Signature Wire Format:
    - For `"ecdsa_sha256"`: The signature MUST be serialized as fixed-width raw IEEE P1363 big-endian concatenation $r \parallel s$. For `"ecdsa_p256"`, exactly 64 bytes (32-byte $r \parallel$ 32-byte $s$); for `"ecdsa_p384"`, exactly 96 bytes (48-byte $r \parallel$ 48-byte $s$). ASN.1 DER encoding is strictly prohibited on the wire.
    - For `"rsa_pkcs1_sha256"`: The signature MUST be serialized as raw big-endian integer bytes matching the RSA key modulus length (256 bytes for `"rsa_2048"`, 384 bytes for `"rsa_3072"`), computed via RSASSA-PKCS1-v1_5 per RFC 8017 Section 8.2 (EMSA-PKCS1-v1_5 with SHA-256 DigestInfo prefix `3031300d060960864801650304020105000420` followed by 32-byte SHA-256 digest).
    - For `"rsa_pkcs1_sha384"` and `"rsa_pkcs1_sha512"`: as `"rsa_pkcs1_sha256"`, with the SHA-384 or SHA-512 DigestInfo prefix of RFC 8017 Section 9.2 Note 1.
    - For `"rsa_pss_sha256"`: RSASSA-PSS per RFC 8017 Section 8.1 with MGF1 over SHA-256 and the salt length the card publishes in its CIAInfo (FINEID S4-1 v4.2 Section 8.1.3), serialized as for `"rsa_pkcs1_sha256"`. Two signatures over the same digest differ.
    - For every `"ecdsa_*"` algorithm: fixed-width raw $r \parallel s$ sized by the key profile, as for `"ecdsa_sha256"`.
  - Response: `signature` (`bstr`, matching the specified signature wire format).

### 9.3 Profile: `"fi.refineid.document-signing.v1"`
- **`read_certificate`** (Safe Read):
  - Payload: `{"kind": "signature"}`.
  - Response: `certificate` (DER-encoded X.509 signature certificate bytes).
- **`sign_document`**:
  - Context: `document_name` (`tstr .size (1..256)`, e.g. `"Employment_Contract_2026.pdf"`).
  - Payload: `key_profile`, `algorithm`, `digest` (pre-hashed document digest).
  - Consent: Always requires conscious visual confirmation and PIN 2 entry on Custodian screen.
  - Signature Wire Format: Conforms strictly to the signature wire encoding specified in §9.2.
  - Response: `signature` (`bstr`).
- **`batch_sign_documents`**:
  - Context: `document_names` (`[1* tstr .size (1..256)]`, list of 1 to 64 document display names).
  - Payload:
    - `key_profile`, `algorithm`.
    - `digests` (`[1* bstr]`, ordered list of 1 to 64 document digests).
    - Invariant: `len(document_names) == len(digests) <= 64`.
  - Consent: Custodian presents full document list and collects PIN 2 once to authorize the entire batch.
  - Signature Wire Format: Each entry conforms strictly to the signature wire encoding specified in §9.2.
  - Response: `signatures` (`[1* bstr]`, ordered list of signatures).
  - **Write-Ahead Journal Granularity and Crash Recovery**:
    - For `batch_sign_documents`, the Custodian maintains a durable journal entry recording per-document progress:
      - `batch_total` ($1 \le N \le 64$)
      - `completed_signatures` array of byte strings ($0 \le k \le N$)
      - Active document index $k$
    - The Custodian executes card signature APDUs sequentially ($k = 0, 1, \dots, N-1$).
    - If interrupted mid-batch (e.g. BLE disconnect or card removed after document $k$), the batch state is marked `ambiguous`.
    - On reconnection, the Requester queries `operation.status_request`. The Custodian reports `state: "ambiguous"`, and `operation.result` returns partial results:
      `response: {"completed_signatures": [sig_0, ..., sig_{k-1}], "completed_count": k}`.
    - Already executed document signatures are NEVER re-executed.

---

## 10. Failure Semantics, Error Handling, and Retry Protection

### 10.1 Failure Classification
1. **Pre-Authentication Invalid Input (Class 1)**: Malformed preamble, an unrouted or replayed routing tag, invalid MTU, or out-of-order writes prior to Noise authentication. Action: close BLE connection immediately; zero stored state modified.
2. **Transport Loss, Bearer Disruption, and Version Skew (Class 2)**: Radio drop, ATT timeout, link termination, failed AEAD MAC verification / decryption failure on an established channel, or unexpected wire version on connect/envelope. Because the bearer is untrusted and subject to RF corruption or relay tampering, ciphertext authentication failure cannot establish authenticated peer misconduct. Action: terminate active session and BLE link immediately, zeroize ephemeral session state; active operation marked `cancelled` (if before card execution) or `ambiguous` (if journaled in-flight). Stored pairing trust records and vault keys REMAIN INTACT. Smart card operations are NEVER re-executed.
3. **Stale-Reference Race and Semantic Rejection (Class 3)**: Decrypted operation message for an unknown or already terminal `operation_id` (e.g. duplicate request for expired operation), or unsupported algorithm/parameter. Action: respond with `error` name `"unknown_operation"` or `operation.result` status `"rejected"` with `"unsupported_parameter"`; no pairing revocation.
4. **Authenticated Protocol Violation (Class 4)**: Verified sequence regression across an established authenticated link (where AEAD MAC is valid and sequence < expected), parameter echo mismatch in an authenticated `pairing.hello`, authenticated `pair_id` mismatch, or explicit local user deletion/revocation. Action: close session immediately, mark pairing revoked, destroy pairing keys in local storage, and require new manual pairing.

### 10.2 Typo Handling vs. Permanent Card Lockout
- **Ordinary Typo (Retries Remain)**: If the card reports invalid PIN 1, PIN 2, or CAN (`SW 63 Cx`), and remaining retry count $> 0$:
  - Custodian transmits `operation.result` with `status: "rejected"`, `error: "invalid_credential"`, and exact `remaining_retries: count`.
  - The operation terminates, but stored pairings and vault keys **REMAIN INTACT**.
- **Low Retry Warning & Confirmation**:
  Before transmitting any PIN verification command when the card's remaining retry counter is $\le 1$, the Custodian **MUST** display an explicit warning on screen ("Warning: 1 attempt remaining before card lockout") and require explicit, conscious user confirmation to proceed. If the user declines, the operation terminates with `status: "rejected"`, `error: "user_declined"`, preserving the card's remaining try.
- **Permanent Card Lockout (Zero Retries Remain)**: If a PIN try counter reaches 0 (card blocked, `SW 69 83`) or hardware tampering is detected:
  - Terminate card transmissions immediately.
  - Transmit `operation.result` with `status: "credential_rejected"`, `error: "card_blocked"`.
  - Mark active pairing `revoked`, permanently delete pairing keys from local secure storage, and close the connection. Both peers require a completely new manual pairing ceremony after card unblocking.

### 10.3 Retry Floor Protection
Before transmitting any command that could decrement a PIN try counter, the Custodian **MUST** query the card's remaining try counter. If the counter indicates $\le 1$ attempt remaining, the Custodian MUST enforce the low-retry confirmation workflow (§10.2). If the try counter is 0 or unreadable, the Custodian **MUST** refuse the operation without transmitting verification commands to the card, answering `operation.result` with `status: "rejected"` and `error: "operation_failed"`. A Custodian MAY apply a stricter local floor (for example refusing below three remaining attempts) with the same answer.

### 10.4 Standardized Error Envelope Body Schema & Code Mapping
```cddl
error-body = {
  "error_code": uint,
  "error_name": tstr .size (1..64),
  "message": tstr .size (1..512),
  ? "operation_id": bstr .size 16
}
```

| `error_name` | `error_code` | Semantic Description | Failure Class |
| :--- | :--- | :--- | :--- |
| `"unknown_operation"` | `1001` | Queried or submitted `operation_id` is unknown or already terminal. | Class 3 |
| `"operation_expired"` | `1002` | Local monotonic operation deadline passed prior to authorization. | Class 3 |
| `"user_cancelled"` | `1003` | User consciously declined or canceled the operation on the screen. | Class 3 |
| `"unauthorized"` | `1004` | Requested profile or action is not granted in active pairing. | Class 3 |
| `"unsupported_parameter"` | `1005` | Unsupported key profile, algorithm, or parameter value. | Class 3 |
| `"card_blocked"` | `1006` | Card retry counter exhausted / credential blocked (`SW 69 83`); status `credential_rejected` (§10.2). | Class 4 |
| `"pin_blocked"` | `1007` | Specific PIN retry counter exhausted. | Class 4 |
| `"invalid_credential"` | `1008` | Incorrect PIN entered; retries remain (`SW 63 Cx`). | Class 3 |
| `"card_error"` | `1009` | APDU transmission failure, NFC loss, or smart card hardware fault. | Class 2 |
| `"operation_failed"` | `1010` | Consequential hardware execution or durable journal write failed. | Class 3 |
| `"duplicate_operation"` | `1011` | Non-idempotent attempt to execute an existing operation. | Class 3 |
| `"user_declined"` | `1012` | User declined proceeding under low-retry warning floor. | Class 3 |
| `"storage_exhausted"` | `1013` | Device persistent secure storage allocated for pairing tombstones is exhausted. | Class 3 |
| `"operation_already_retired"` | `1014` | Operation was already executed, acknowledged, and retired. | Class 3 |
| `"invalid_lifetime"` | `1015` | `expires_after_ms` of 0 (§8.2.1). | Class 3 |

`operation_failed` also answers a second `operation.request` while another operation is live on the pairing (the `error` message) and the retry floor refusal of §10.3 (an `operation.result`).

**Normative Error Handling Rule**:
Semantic error handling is driven exclusively by `error_name`. The numeric `error_code` is informative and provides predictable numeric mappings across language bindings. If an implementation receives an unrecognized `error_code` with a recognized `error_name`, `error_name` takes precedence. If both are unrecognized, the error MUST be handled as a general Class 3 `operation_failed`.

---

## 11. User Experience and Consent Contract

1. **Sovereign Display of Authorized Intent**:
   - The Custodian screen acts as the authoritative human trust anchor.
   - For authentication: Custodian displays relying-party origin (`origin`), operation type, and card holder name.
   - For document signing: Custodian displays document name (`document_name`) or complete list of document names (batch signing) alongside hash summaries.
2. **Conscious vs. Seamless Authorization**:
   - **PIN 1 (Authentication)**: May use platform-cached authorization (e.g. biometric authentication or Secure Enclave session policy) if configured by user policy.
   - **PIN 2 (Qualified Signing)**: Strictly mandates conscious, explicit human interaction on the phone screen for every signature or batch request. No automatic or unattended signing is permitted.
3. **Document Secrecy**: Raw document bytes and unhashed browser data **MUST NEVER** cross the RAPP protocol. Requester hashes all content locally before transmission.

---

## 12. Threat Model & Security Analysis

| Threat Class | Adversary Vector | RAPP Defense |
| :--- | :--- | :--- |
| **Passive Eavesdropper** | Captures 2.4 GHz RF packets using SDR. | Zero hint in beacon. CPace KC2 provides mathematical resistance to offline dictionary attacks; intermediate keys separated via RFC 5869 HKDF-SHA-512. Handshake and sessions encrypted with ChaCha20-Poly1305. |
| **Active MITM** | Injects, modifies, or drops BLE packets. | CPace KC2 binds ceremony context $C$ into generator input $CI$, rejecting mismatched protocol, suite, offer, and channel parameters. CPace authenticates possession of the pairing code; mutual endpoint identity authentication rests on Noise_XXpsk3 with fresh pairwise static keys. Explicit HMAC tags $T_B, T_A$ confirm keys before Noise handoff. Unmatched codes burn strikes and terminate the offer under rate-limiting. |
| **Disconnect Oracle** | Attacker tests $T_B$ and disconnects before $T_A$. | Atomic attempt reservation increments `attempts_admitted` *before* emitting $Y_B$ and $T_B$; disconnects do not refund the reserved attempt. |
| **Evil Twin / Rogue Beacon** | Attacker broadcasts identical Service UUID. | Requester requires matching 30-bit pairing code to derive generator $G$ and verify confirmation tags; rogue beacons lacking the code cannot complete CPace or Noise handshake. |
| **Transparent Wormhole / Relay** | Attacker relays RF traffic over WAN between distant devices. | Advisory proximity gate limits local discovery, but RSSI cannot prove physical proximity or detect bit-preserving RF tunneling (§4.4). Strict asymmetric ATT and CPace role separation structurally prevents relay loopback and reflection attacks, while explicit user consent and sovereign phone display enforce authorized operation intent at execution time (§4.4, §5.2, §11). |
| **DoS Strike Burning** | Malicious central connects to phone to burn strikes. | Offers are open only upon explicit user trigger for 60 seconds; single-flight pre-authentication serialization limits concurrency. Fail-stop lockout imposes exponential backoff ($2^n$ seconds, up to 300 s) and alerts user with on-screen notification (§3.3.5). |
| **Passive Tracking & Linking** | Attacker records discovery records and routing preambles over time and across networks to recognise a phone or link a computer's connections. | Discovery hints rotate every 15 minutes and routing tags are fresh per connection; both are keyed by the pairing's static agreement, which never crosses the wire, so an observer can neither recompute nor correlate them (§2.2.1, §4.3, hierarchy specification §4.3). No stable pairing identifier is ever sent in clear. |
| **Routing Replay / Presence Probing** | Attacker replays a captured routing preamble to probe presence or induce cryptographic work. | The routing tag selects a pairing but authenticates nothing. A replay is refused in `Phase::Routing` while its nonce is in the Custodian's replay memory of 256 routed sessions; an older replay reaches `Noise_KK` message 1 and fails. The residual timing difference reveals only what the captured preamble already showed and is mitigated by single-flight connection serialization and the pre-authentication limiter (§3.3). |
| **Withdrawal Forgery & Replay** | Attacker publishes a forged `mode=withdrawn` record, or republishes a recorded one. | Withdrawal hints are keyed by the pairing's static X25519 agreement, which never crosses the wire, so they cannot be forged. A recorded record is honoured only on the instance the Requester associates with the pairing and within one minute either side of its counter; its effect is limited to withdrawing presence until the Custodian is next discovered. These bounds assume the Requester's clock is not attacker-controlled; spoofing its time source, for example unauthenticated NTP, extends the replay window, still with no effect beyond the presence drop. The same holds for discovery-hint epochs, where a replayed `hints=` value can only make a Requester dial an endpoint that then fails routing. An open session ignores discovery records and ends only on an authenticated `session.close` (§4.5). |

---

## 13. Empirical Physical Hardware Observations (Informative)

This section provides informative reference data, observed hardware benchmarks, and implementation notes. Normative protocol requirements are established exclusively in Sections 1 through 12 and 14.

Empirical execution was observed on physical hardware on October 1, 2026:
- **Central (Requester)**: Linux host (Linux Kernel 7.0, BlueZ 5.85, Intel AX211 Bluetooth 5.4).
- **Peripheral (Custodian)**: Apple iPhone 15 Pro Max (`RefineID-dev`, iOS 26/27).

### 13.1 Observed Metrics
- **Connect Timing**: $735.6\text{ ms}$ (Linux `Device1.Connect()` call duration; typical full connection establishment ~1.2 s).
- **Observed Notification/Update Capacity**: $512\text{ bytes}$ (`maximumUpdateValueLength` on iOS peripheral API). Note: This is a platform API buffer capacity observation, not a direct trace of the ATT MTU exchange (which is specified in §5.2 as requiring MTU >= 512).
- **Synthetic Frame Transfer**: 64-byte write and 256-byte read on Channel characteristic verified over the physical BLE link.
- **Beacon Privacy**: Advertised standardized service UUID and generic name only; zero pairing code bits in broadcast.

### 13.2 Implementation Findings for BlueZ & CoreBluetooth
- **BlueZ D-Bus Asynchronous Responsiveness**:
  On Linux, `bluetoothd` dispatches link-layer Security Manager Protocol (SMP) agent callbacks (`org.bluez.Agent1.RequestConfirmation`) asynchronously over D-Bus. Linux implementations **MUST** ensure that BlueZ D-Bus callback dispatching is not blocked by synchronous ATT operations (e.g. using non-blocking asynchronous event loops or dedicated worker threads).
- **Application vs. Link Security**:
  Link-layer Bluetooth pairing (SMP) is independent of RAPP. RAPP treats the BLE link as completely untrusted, anchoring end-to-end security exclusively in `CPaceRistretto255` and Noise AEAD at the application layer.
- **OS Background Advertising**:
  On iOS, CoreBluetooth manages background advertisement payloads, RPA rotation, and peripheral state transitions. Background advertisements suppress local names and move overflow service UUIDs to internal Apple-proprietary beacons. RAPP pairing is designed for active foreground Custodian interaction where standard 128-bit UUID discovery is operational.

---

## 14. RefineID Project Security Rules Compliance

1. **Inviolable Rule #1: Secret Exclusion over the Wire**:
   PIN1, PIN2, CAN, and PUK values **MUST NEVER** traverse any transport. The RAPP wire format contains zero fields, messages, or representations for credential secrets.
2. **Inviolable Rule #2: Zero PIN and PIN-Length Logging Across All Environments**:
   PIN codes (PIN1, PIN2), PUK, and CAN **MUST NEVER** be logged, printed, or rendered in any development, test, staging, or production context.
   Furthermore, PIN lengths and candidate digit counts **MUST NEVER** be logged or rendered in error messages, diagnostic traces, or telemetry.
   Disclosing candidate digit counts or PIN lengths leaks secret entropy and reduces keyspace security.
   Diagnostic output (`diag!`), tracing, event logs, and `Display`/`Error` formatting must never include PIN values, PIN lengths, or candidate digit counts.
   If specialized debugging is ever needed, it is done exclusively via temporary private test harnesses and never checked into the repository.
3. **Credential Custody and Memory Safety**:
   All pairing codes, private CPace scalars ($x_A, x_B$), generator input buffers, intermediate keys ($\text{ISK}$), and session keys ($PSK, K_{\text{sess}}$) **MUST** implement zeroize-on-drop semantics and **MUST NOT** implement `Debug`, `Display`, or serialization traits.
4. **Character Encoding Preservation**:
   Card APDUs carrying ISO-8859-15 text are losslessly decoded to Unicode at the Custodian NFC layer before encapsulation into UTF-8 CBOR strings. Unmappable bytes trigger explicit validation errors rather than lossy replacement or silent truncation. Display UIs must fully render `§` (U+00A7), `€` (U+20AC), `ä` (U+00E4), `ö` (U+00F6).

