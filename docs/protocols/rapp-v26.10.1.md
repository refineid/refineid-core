# Remote Authorization Proxy Protocol (RAPP) v26.10.1
## Bluetooth Low Energy (BLE) Direct Proximity Transport and Enhanced Pairing Specification

Status: Normative Specification / Research Record  
Document version: 26.10.1  
Wire version: `[26, 10]` (`[major, minor]`)  
Offer version: `[26, 10, 1]`  
Transport Profile: `"fi.refineid.rapp.ble.v1"`  
Date: 2026-10-01  
Change controller: RefineID project  

---

## Abstract

This specification defines the **Bluetooth Low Energy (BLE) Direct Proximity Transport Profile** (`"fi.refineid.rapp.ble.v1"`) and **Enhanced Human-Factor Pairing Protocol** for the Remote Authorization Proxy Protocol (RAPP v26.10.1).

A user's mobile device acts as a Sovereign Server (GATT Peripheral / Custodian) holding physical custody of the FINEID identity card over Near Field Communication (NFC). The workstation acts as a Requester (GATT Central).

Pairing is established through a 6-character Crockford Base32 human code (`7K X4 M9`, 30.0 bits entropy) executed over `CPaceRistretto255` ([draft-irtf-cfrg-cpace-21](https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-cpace-21)). Advertisements broadcast zero pairing code material, zero ephemeral bucket hints, and zero user identifiers or personal device names. Device discovery is mediated by a standardized 128-bit RAPP Service UUID filtered by an advisory proximity gate ($\ge -55\text{ dBm}$) and finalized through post-handshake mutual Short Authentication String (SAS) device confirmation. Rate limiting enforces a strict 3-attempt budget per 60-second offer lifecycle with atomic attempt reservation preventing disconnect oracles.

To support the Noise pairing handshake (`Noise_XXpsk3`) and post-quantum hybrid operational session handshake (`Noise_KKhfs`, requiring up to 1,248 bytes) across single ATT transactions, this profile specifies a normative **BLE Segmentation and Reassembly (SAR) Adaptation Layer**, preserving upper-layer session and operation security guarantees without frame truncation.

---

## 1. Scope, System Architecture, and Status

### 1.1 Scope and Standalone Specification Model

This document defines the complete, standalone normative specification for the **Remote Authorization Proxy Protocol (RAPP) version 26.10.1**. It encompasses:
- The **Bluetooth Low Energy (BLE) Direct Proximity Transport Profile** (`"fi.refineid.rapp.ble.v1"`).
- The **Enhanced Human-Factor Proximity Pairing Protocol** utilizing `CPaceRistretto255`, 6-character Crockford Base32 human factors, atomic attempt reservation, and exact unbiased Short Authentication String (SAS) confirmation.
- The **BLE Segmentation and Reassembly (SAR) Adaptation Layer** with latched invariant total lengths and stop-and-wait flow control.
- The **Authenticated Message Envelope**, sequential sequencing, and session multiplexing.
- The **Two-Phase Commit Operation Model** providing strict at-most-once physical card execution.
- The **Registered Credential Profiles and Actions** for card status inspection, browser authentication, and qualified document signing.
- The **Failure Semantics, Retry Protection, and Human Consent Contracts**.

This document is completely self-contained: all normative schemas, protocol state machines, cryptographic bindings, error handling rules, and wire formats required to implement, verify, and audit RAPP v26.10.1 are defined herein.

- **Migration and Compatibility**:
  RAPP v26.10.1 specifies the BLE Direct Proximity Transport Profile (`"fi.refineid.rapp.ble.v1"`). It advances the wire version to `[26, 10]` and offer version to `[26, 10, 1]`. It does not interoperate with legacy RAPP v26.9.28. Implementations must conform strictly to the schemas and state machines defined in this standalone specification.
- **Wire and Offer Versioning**:
  - Offer version: `[26, 10, 1]` in `pairing-offer`.
  - Wire version: `[26, 10]` (`[major, minor]`) in channel envelopes and handshake prologues.
- **Role Mapping**:
  - **Requester**: Corresponds to the RAPP Requester, operating as GATT Client (Central).
  - **Custodian**: Corresponds to the Sovereign Server (mobile device) acting as the RAPP Authorization Proxy while holding exclusive physical NFC custody of the Credential Holder (FINEID Card), operating as GATT Server (Peripheral).

### 1.2 Implementation and Verification Status Matrix

Per project engineering standards, specification requirements are strictly distinguished from reference software implementation and observed physical hardware operations:

| Specification Domain | Status | Coverage & Artifact Reference |
| :--- | :--- | :--- |
| **BLE GATT Service & Characteristic Layout** (§5.1) | Partially Observed on Hardware | Service UUID and Channel characteristic properties observed on iOS peripheral hardware (`RappBlePeripheral.swift`). Bootstrap characteristic is Specified (unverified on physical hardware). |
| **GATT Connection & ATT MTU Exchange** (§5.2, §7.1) | Partially Observed on Hardware | BLE connection duration (~1.2 s setup; 735.6 ms Linux connect call) and 512-byte API update value capacity observed on hardware. Exact ATT MTU exchange and Indication-only path are Specified (unverified on physical hardware). |
| **Over-The-Air Data Transfer** (§7.1) | Observed on Physical Hardware | Synthetic 64-byte write and 256-byte read on Channel characteristic verified over physical BLE link. |
| **BLE SAR Framing & State Machine** (§5.3) | Normative Specification | Fully specified with invariant total length, attribute capacity limits, pre-copy capacity checks, and stop-and-wait flow control. |
| **Crockford Base32 Canonical Normalization** (§3.1) | Normative Specification | Fully specified 7-step pipeline with Crockford decode alias mapping (`I`/`L` $\to$ `1`, `O` $\to$ `0`). |
| **CPaceRistretto255 Mathematical Primitives** (§6.1) | Reference Implementation | Implemented in Rust `crates/rapp/src/cpace.rs` per draft-irtf-cfrg-cpace-21 and RFC 9496; unit-tested with test vectors. (Defensive basepoint fallback on $2^{-252}$ and $PSK = \text{ISK}[0..32]$ truncation noted as RAPP design choices). |
| **Attempt Reservation & Disconnect Oracle Protection** (§3.3) | Normative Specification | State machine rules fully defined. |
| **Advancing-Counter Unbiased SAS Sampling** (§4.5) | Normative Specification | Mathematical algorithm with advancing block counter and exact uniform cutoff fully specified. |
| **Noise_XXpsk3 & Noise_KKhfs Handshakes** (§6.2, §6.3) | Normative Specification | Complete token schedules, ML-KEM-768 encapsulation/decapsulation, directional key splits, and prologues fully specified. |
| **Authenticated Envelopes & 17 Registered Messages** (§7, §8) | Normative Specification | Complete CDDL discriminated union schemas and normative semantics for all 17 registered message types fully specified herein (§7.1). |

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

- **Wire Version**: `[26, 10]` (`[major, minor]`)
- **Offer Version**: `[26, 10, 1]`
- **Transport Profile Identifier**: `"fi.refineid.rapp.ble.v1"`

The BLE transport acts as the underlying point-to-point bearer for RAPP session frames. CPace establishes the 32-byte pre-shared key ($PSK$) that seeds mutual pairing authentication (`Noise_XXpsk3`), replay protection, monotonic sequence counters, and typed at-most-once operation dispatch.

#### Protocol Lifecycle:
- **Phase 0: Routing (`Phase::Routing`)**: Every connection transmits exactly one `ble-rendezvous` preamble frame via `ATT_WRITE_REQ`. For purpose `"pairing"` with an active offer, the connection transitions to `Phase::CPace`. For purpose `"session"` with a matching stored `rendezvous_token`, the connection transitions to `Phase::NoiseSession`.
- **Phase 1: Discovery & Bootstrap**: Read fresh random 32-byte `offer_id` (SID) and canonical `pairing-offer` from the Custodian's Bootstrap Characteristic. Compute canonical `offer_hash`.
- **Phase 2: CPace Key Agreement (`Phase::CPace`)**: Execute `CPaceRistretto255` over GATT SAR frames to agree on $PSK = \text{ISK}[0..32]$. On success, transition to `Phase::NoisePairing`.
- **Phase 3: Noise_XXpsk3 Pairing (`Phase::NoisePairing`)**: Perform authenticated pairing handshake with prologue bound to canonical `offer_hash`, wire version `[26, 10]`, suite, and transport profile name. Immediately on handshake completion, derive pairing-channel `session_id`, `pair_id`, and `rendezvous_token`. Exchange `pairing.hello` (parameter echo using `session_id`) and `pairing.confirm` (capability grants), deriving `grants_hash`.
- **Phase 4: Post-Handshake SAS Confirmation**: Visually verify uniform 4-digit SAS derived from the authenticated Noise pairing handshake hash $h$ using an advancing block counter.
- **Phase 5: Pair Storage & Operational Session**: Only after SAS confirmation and both grant confirmations succeed, atomically store the pairing trust record (`pair_id`, `rendezvous_token`, `grants_hash`, peer static public key, and local private key). Operational connections start in `Phase::Routing`, verify `rendezvous_token`, and open a fresh post-quantum `Noise_KKhfs` session with an independent operational `session_id`.

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
3. **Attempt Deadline & Offer TTL Clamping**:
   Transmitting $Y_B$ and $T_B$ arms a non-extendable attempt timer on the Custodian, clamped by the remaining offer TTL:
   $$\text{attempt\_deadline} = \min(5.0\text{ s}, \text{remaining\_offer\_ttl})$$
   If $\text{remaining\_offer\_ttl} == 0$, no attempt can be admitted.
4. **Completion of the Third Attempt**:
   Reserving the 3rd attempt (`attempts_admitted == 3`) blocks any further admissions (`attempts_admitted >= 3`). However, **ephemeral offer keys remain active during the attempt deadline to allow that 3rd attempt to successfully complete.**
5. **No Refund on Disconnect or Timeout**:
   If the Requester disconnects, drops the link, or fails to deliver a valid mutual confirmation authenticator $T_A$ before the attempt deadline expires, `active_attempt` is cleared and `attempts_failed` increments. If `attempts_failed == 3`, the offer is permanently destroyed (fail-stop lockout).
6. **Successful PAKE Completion**:
   Upon receiving and verifying a valid $T_A$ within the attempt deadline, `active_attempt` is cleared, the PAKE attempt timer is canceled, and the session transitions exclusively to `Phase::NoisePairing`. Subsequent network faults during Noise are session-level events and do not consume PAKE attempts.
7. **Offer Lifecycle & Expiry Separation**:
   The pairing offer is valid for exactly 60 seconds from user initiation (`offer_ttl_ms = 60000`).
   - **Clean Offer Expiry**: If the 60-second offer TTL expires without an active attempt or after all admitted attempts have finished with `attempts_failed < 3`, the offer is terminated cleanly: BLE advertising ceases and ephemeral offer keys are zeroized. No strike penalty or exponential backoff is imposed; the user may immediately start a new offer without delay.
   - **Active Attempt Clamping**: An active attempt cannot extend past the offer deadline: per rule 3, the attempt timer is strictly clamped by $\text{attempt\_deadline} = \min(5.0\text{ s}, \text{remaining\_offer\_ttl})$. Reserving an attempt at $t = 59\text{ s}$ yields an attempt deadline of $1.0\text{ s}$, terminating at $t = 60\text{ s}$.
   - **Fail-Stop Lockout and Exponential Backoff**: Triggered strictly upon attempt budget exhaustion (`attempts_failed == 3`). Upon fail-stop lockout:
     1. The Custodian destroys all ephemeral keys, terminates BLE advertising, and surfaces an on-screen notification to the user ("Pairing failed: 3 incorrect attempts. Pairing locked.").
     2. The Custodian enforces an exponential backoff penalty of $\text{delay\_seconds} = \min(2^n, 300\text{ s})$ before permitting the generation of a new offer, where $n = \text{consecutive\_failed\_offers}$ (saturating at $n = 9$; $2^8 = 256\text{ s}$, $2^9 \to 300\text{ s}$).
     3. The counter $n$ starts at $0$, increments by $1$ only upon a fail-stop lockout (`attempts_failed == 3`), and resets to $0$ upon any successful pairing completion (Phase 5), upon conscious manual user reset/unlock in the Custodian settings UI, or after 15 minutes of user inactivity. The counter $n$ is held in volatile memory and resets to $0$ across device reboot.
8. **Single-Flight Serialization & Rate Limiting**:
   The Custodian **MUST NOT** accept concurrent GATT PAKE exchanges. Any secondary Central attempting to initiate CPace while `active_attempt` is true is immediately rejected with an ATT error (`0x80 Application Error`). In addition, pre-authentication connection attempts and invalid $Y_A$ candidate submissions are rate-limited to at most 1 attempt per 500 ms to mitigate serial resource consumption.

---

## 4. Privacy, Bootstrap Discovery, and Noise Binding

### 4.1 Zero Hint Leakage Over Advertisements

The BLE advertisement payload **MUST NOT** contain:
- Any bits, truncated representations, or hashes of the pairing code.
- Ephemeral bucket hints or index tags.
- Personal device names, user identifiers, or hardware serial numbers.

The Custodian **MUST**:
- Broadcast solely the standardized 128-bit RAPP Service UUID (`7E39FD01-A6B5-4D78-9E11-37E28E9545F1`).
- Set the BLE Local Name to an empty string or generic constant (`"RefineID"`), strictly avoiding default platform names (such as `"<owner's device name>"`).
- Rotate the BLE Resolvable Private Address (RPA) per Bluetooth Core Specification v5.4. (Note: On iOS, CoreBluetooth manages RPA rotation and background advertisement payload filtering automatically; local names may be omitted or moved to scan responses in background modes without compromising foreground pairing).

### 4.2 Bootstrap Discovery & PairingOffer Schema

The Custodian acts as the GATT Peripheral advertiser and creates the `pairing-offer`.

The Session Identifier (SID) used in CPace **MUST** be an independent 32-byte cryptographic random value (`offer_id`) generated by the Custodian upon creating the offer. It **MUST NOT** be derived from the pairing code.

#### PairingOffer Schema (Deterministic CBOR):
```cddl
pairing-offer = {
  "scheme": "rapp",
  "version": [26, 10, 1],     ; offer version triple
  "offer_id": bstr .size 32,    ; 32-byte cryptographic random SID
  "suites": [
    "CPACE-RISTR255-SHA512 + Noise_XXpsk3_25519_ChaChaPoly_SHA512"
  ],
  "profiles": [
    "fi.refineid.card-status.v1",
    "fi.refineid.authentication.v1",
    "fi.refineid.document-signing.v1"
  ],
  "transports": [
    {
      "profile": "fi.refineid.rapp.ble.v1",
      "candidate_id": "ble-direct-1",
      "parameters": {
        "service_uuid": "7E39FD01-A6B5-4D78-9E11-37E28E9545F1"
      }
    }
  ],
  "offer_ttl_ms": 60000
}
```

In the BLE direct proximity profile, `pairing_secret` is omitted from `pairing-offer` because pairing secrets are negotiated dynamically via CPace over the air. Storing or broadcasting a static `pairing_secret` over the public unauthenticated bootstrap characteristic is strictly prohibited.

The canonical `offer_hash` is computed as:
$$\text{offer\_hash} = \text{SHA-256}(\text{encode\_deterministic\_cbor}(\text{pairing-offer}))$$

#### Bootstrap Read Flow:
1. The Custodian exposes the **RAPP Bootstrap Characteristic** (`7E39FD03-A6B5-4D78-9E11-37E28E9545F1`, Read-only).
2. The Requester connects over BLE and performs an `ATT_READ_REQ` on this characteristic to obtain `encode_deterministic_cbor(pairing-offer)`.
3. The Requester parses `offer_id` (SID) for CPace Step 1 and computes `offer_hash` for the Noise pairing prologue. Both endpoints bind to `candidate_id = "ble-direct-1"`.

### 4.3 Mandatory Noise Binding, Temporal Derivation, and Reconnect Rendezvous

1. **Noise_XXpsk3 Prologue**:
   The prologue for the pairing handshake is the deterministic-CBOR encoding of:
   ```cddl
   pairing-prologue = [
     "RAPP-pairing-v1",
     [26, 10],                                                        ; wire version [major, minor]
     "CPACE-RISTR255-SHA512 + Noise_XXpsk3_25519_ChaChaPoly_SHA512", ; cryptographic suite name
     bstr .size 32,                                                   ; offer_hash
     "fi.refineid.rapp.ble.v1"                                        ; transport profile name
   ]
   ```
   $$\text{prologue} = \text{encode\_deterministic\_cbor}(\text{pairing-prologue})$$

2. **Immediate Channel Identifier Derivation**:
   Immediately upon completing the `Noise_XXpsk3` handshake, both peers derive the channel identifiers from the completed handshake hash $h$ in strict order:
   ```text
   session_id       = first 16 bytes of SHA-512("RAPP-session-id-v1" || h)
   pair_id          = first 16 bytes of SHA-512("RAPP-pair-id-v1" || h)
   rendezvous_token = first 16 bytes of SHA-512("RAPP-rendezvous-v1" || h)
   ```
   Both peers immediately destroy `pairing_secret` ($PSK$) and all ephemeral handshake keys.
   The derived `session_id` immediately scopes the pairing-channel envelopes for `pairing.hello` and `pairing.confirm`.

3. **Parameter Echo & Mutual Grants**:
   - Inside the established pairing channel, peers exchange `pairing.hello`.
   - `pairing.hello` echoes `offer_hash`, `candidate_id` (`"ble-direct-1"`), wire version `[26, 10]`, suite name, display name, platform description, and requester's requested profiles.
   - Custodian verifies matching echoes. Any mismatch aborts with an authenticated protocol violation.
   - Custodian presents proposed grants to the user, and transmits `pairing.confirm` carrying granted profiles. Requester displays and confirms. Both granted sets **MUST** be identical.
    - Derive `grants_hash` from the confirmed, canonically sorted grant set:
      $$\text{grants\_hash} = \text{SHA-256}(\text{encode\_deterministic\_cbor}(\text{sorted\_profiles}))$$
      where `sorted_profiles` is a CBOR array of profile identifier strings (`tstr`, CBOR major type 3 with definite-length encoding) sorted in standard canonical byte-wise lexicographical order without duplicates (e.g. `["fi.refineid.authentication.v1", "fi.refineid.card-status.v1"]`).

4. **Post-Handshake SAS Confirmation**:
   Following receipt and verification of `pairing.confirm`, both devices compute and visually confirm the 4-digit SAS derived from handshake hash $h$ using the advancing block counter (Section 4.5).

5. **Atomic Permanent Key Storage**:
   Only after SAS visual confirmation succeeds AND both `pairing.confirm` messages are processed:
   - **Fresh Pair-Specific Static Keys**: Each pairing ceremony **MUST** generate a fresh, cryptographically independent static X25519 keypair $(s, s_{pub})$ on each endpoint. Static keys **MUST NOT** be reused across different peer pairings or across distinct pairing ceremonies. This provides pairwise endpoint isolation and prevents correlation across peers. Private keys **MUST** be stored in platform-encrypted secure hardware (Secure Enclave / TPM / OS Keychain), excluded from backups and cloud synchronization, and marked non-exportable.
   - Each endpoint atomically persists the pairing trust record:
     - `pair_id`
     - `rendezvous_token`
     - `grants_hash` and confirmed granted profiles
     - Remote peer's static public key
     - Local static private key (stored in platform-encrypted secure hardware / keychain)
   - The pairing channel is then cleanly closed.

6. **Reconnect Rendezvous for Operational Sessions (`Noise_KKhfs`)**:
   Subsequent connections for credential operations (authentication, qualified signing) do not rerun CPace or read bootstrap characteristics.
   - Every connection starts in `Phase::Routing` (Section 5.2).
   - Requester transmits a single `ble-rendezvous` preamble frame with purpose `"session"` (§5.2) over the Channel Characteristic via `ATT_WRITE_REQ`:
     ```cddl
     session-reconnect-preamble = [
       "RAPP-ble-v1",
       "session",       ; purpose
       rendezvous_token ; bstr .size 16
     ]
     ```
     Encapsulated in a `SINGLE` SAR frame.
   - The Custodian looks up stored pairing by `rendezvous_token`, retrieves `pair_id`, `grants_hash`, and peer static key, and initiates `Phase::NoiseSession` (`Noise_KKhfs`).
   - If `rendezvous_token` is unknown or revoked, the Custodian immediately closes the link without altering stored state.
   - **Rendezvous Privacy Analysis & Presence Oracle**:
     Using `rendezvous_token` hides `pair_id` (which remains a strictly local identifier) and prevents observers from connecting the session to other pairings or credentials. However, two residual behaviors exist:
     1. *Token Recurrence Correlation*: Because `rendezvous_token` is static per pairing, a radio observer capturing multiple reconnect preambles over time can recognize that token's recurrence and correlate that the same unidentified pairing is reconnecting. Stronger unlinkability across reconnections would require rotating tokens (a separate profile extension); it is not claimed for this static token.
     2. *Presence Probing Oracle*: An unauthenticated nearby attacker who replays a captured `rendezvous_token` observes that the Custodian does not immediately close the link in `Phase::Routing`, but instead proceeds to `Phase::NoiseSession` (`Noise_KKhfs`). In `Noise_KKhfs`, the Custodian processes handshake message 1 (performing `mix_hash`, DH operations, and ML-KEM encapsulation key decryption and parsing; it does not decapsulate) before payload AEAD authentication fails and the connection is dropped. Depending on the input, processing can fail during ephemeral key validation, DH computation, ML-KEM key decryption, static DH, or payload authentication. The timing difference between an unknown token (immediate link drop in Phase::Routing) and a known token (handshake message 1 processing) constitutes an accepted residual presence oracle for static tokens. This is mitigated by single-flight connection serialization and rate-limiting reconnect attempts from unauthenticated centrals.
   - Session Prologue:
     ```cddl
     session-prologue = [
       "RAPP-session-v1",
       [26, 10],                                                        ; wire version [major, minor]
       "Noise_KKhfs_25519+MLKEM768_ChaChaPoly_SHA512",                  ; suite name
       pair_id,                                                         ; bstr .size 16
       grants_hash,                                                     ; bstr .size 32
       "fi.refineid.rapp.ble.v1"                                        ; transport profile name
     ]
     prologue = encode_deterministic_cbor(session-prologue)
     ```
   - Operational handshakes derive a fresh operational `session_id` (`first 16 bytes of SHA-512("RAPP-session-id-v1" || h_session)`). The pairing `session_id` is never reused.

### 4.4 Proximity RSSI Gating & Transparent Relay Analysis

RSSI is treated as an **advisory discovery heuristic** and defense-in-depth barrier, not as a standalone cryptographic proof of proximity:
1. **Requester Filter**: The Requester **MUST** ignore advertisements whose filtered RSSI falls below $-55\text{ dBm}$ (configurable to $-85\text{ dBm}$ strictly in isolated development environments).
2. **Temporal Filtering**: To compensate for multipath fading and orientation variance, the Requester **SHOULD** compute the median RSSI over at least 3 advertisement packets with a 3 dB hysteresis before initiating a connection.
3. **Transparent Relay Analysis**: An adversary utilizing high-gain directional antennas and power amplifiers can increase signal strength at the receiver. A transparent RF wormhole or relay forwarder can tunnel RF packets between distant rooms without decrypting them. While PAKE secrecy prevents an attacker from learning the session key, the physical distance assumption is bypassed. User consent on the Custodian phone screen protects authorized operation semantics/intent; transparent physical RF tunneling remains a physical-layer relay risk that cannot be detected by SAS or RSSI alone.
4. **Structural Role Separation as Protocol-Level Relay Defense**:
   Under Bluetooth Core Specification v5.4 and this profile (§5.2, §6.3), ATT and CPace roles are strictly asymmetric and immutable: the Requester is Central ($A$), transmitting exclusively via `ATT_WRITE_REQ`, while the Custodian is Peripheral ($B$), replying exclusively via `ATT_HANDLE_VALUE_IND`. Per draft-irtf-cfrg-cpace-21 Section 10.1, strict initiator/responder role separation structurally eliminates relay loopback and reflection attacks: an adversary cannot reflect the Custodian's $Y_B \parallel T_B$ indication back to the Custodian as an initiator write $Y_A$, nor can it relay frames between two peers acting in the same role.

### 4.5 Post-Handshake Mutual Device Confirmation (Exact Unbiased SAS with Advancing Block Counter)

To defeat rogue beacon and Evil Twin attacks:
1. Upon completing the `Noise_XXpsk3` pairing handshake, both devices compute a 4-digit Short Authentication String (SAS) bound to the authenticated Noise handshake hash $h$.
2. **Advancing Block Stream Generation**:
   Candidate streams are derived in sequential 32-byte blocks using HKDF-Expand with SHA-512 over PRK = $h$:
   For block counter $b \in \{0, 1, 2\}$ encoded as an unsigned 8-bit integer (`u8`):
   $$\text{info}_b = \texttt{"RAPP-SAS-CONFIRM-v1"} \parallel [b] \quad (19 + 1 = 20\text{ bytes})$$
   $$\text{BLOCK}_b = \text{HKDF-Expand}(\text{PRK}=h, \text{info}=\text{info}_b, \text{length}=32)$$
   Because the completed Noise pairing handshake hash $h$ is already a cryptographically uniform 64-byte pseudorandom hash from SHA-512, HKDF-Extract is omitted and HKDF-Expand is applied directly with $\text{PRK} = h$.
3. **Candidate Integer Parsing**:
   Each 32-byte block yields eight 32-bit big-endian candidate integers:
   $$V_{b, i} = \text{u32::from\_be\_bytes}(\text{BLOCK}_b[4i .. 4i+4]) \quad \text{for } i \in \{0..7\}$$
4. **Rejection Sampling Loop**:
   Iterate sequentially through $b \in \{0, 1, 2\}$ and $i \in \{0..7\}$ (evaluating up to $3 \times 8 = 24$ candidates):
   - If $V_{b, i} < 4{,}294{,}960{,}000$ ($429{,}496 \times 10{,}000$):
     $$\text{SAS\_VAL} = V_{b, i} \pmod{10000}$$
     Halt search. Format $\text{SAS\_VAL}$ as exactly 4 decimal digits with leading zeros (e.g. `0492`).
5. **Bounded Candidate Budget & Fail-Safe**:
   If all 24 candidate integers across all 3 blocks are rejected (probability $(7296 / 2^{32})^{24} \approx 3.3 \times 10^{-139}$), the pairing terminates cleanly as an unrecoverable mathematical anomaly: ephemeral keys are destroyed, the link is closed, and an error is surfaced to the user.
6. **Visual Confirmation**:
   Both devices display the resulting 4-digit SAS. The user visually confirms matching digits on both screens before pair storage is finalized.

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
1. The Requester MUST transmit exactly one plaintext `ble-rendezvous` preamble frame over the Channel Characteristic via `ATT_WRITE_REQ` (in a `SINGLE` SAR frame):
   ```cddl
   ble-rendezvous = [
     "RAPP-ble-v1",
     tstr,                     ; purpose: "pairing" / "session"
     bstr                      ; purpose "pairing": empty (bstr .size 0)
                               ; purpose "session": rendezvous_token (bstr .size 16)
   ]
   ```
2. The Custodian in `Phase::Routing` decodes and evaluates the preamble:
   - **Purpose `"pairing"`**:
     - Verify `token.len == 0`.
     - Check if Custodian has an active pairing offer (within 60-second TTL).
     - If active: transition connection to **`Phase::CPace`**.
     - If no active offer exists: close connection immediately.
   - **Purpose `"session"`**:
     - Verify `token.len == 16`.
     - Look up `token` in the local vault of non-revoked stored pairings.
     - If found: retrieve `pair_id`, `grants_hash`, and peer static public key, and transition connection to **`Phase::NoiseSession`**.
     - If unknown or revoked: close connection immediately without altering any stored pairing.
   - **Invalid Preamble**:
     - Unknown purpose, malformed CBOR, non-empty token for `"pairing"`, invalid token length for `"session"`, oversized frame, or any non-preamble frame received in `Phase::Routing` is pre-authentication invalid input: close connection immediately.
3. Exactly one preamble frame is permitted per connection. Any preamble received after transitioning out of `Phase::Routing` is an unrecoverable protocol violation. Knowing a routing token never authenticates a caller; authentication is established exclusively by the subsequent Noise handshake.

### 5.3 BLE Segmentation and Reassembly (SAR) Adaptation Layer

Because Noise handshake messages (`Noise_KKhfs`: initiator message carrying ML-KEM-768 public key requires up to 1,248 bytes; responder message carrying ML-KEM-768 ciphertext requires up to 1,152 bytes, or up to 2.3 kB with hybrid static keys) and upper-layer application envelopes (carrying X.509 certificate chains or document digests) require several kilobytes, RAPP frames cannot be assumed to fit in a single ATT transaction.

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
   - Routing Preamble: deterministic CBOR `["RAPP-ble-v1", purpose, token]` encapsulated in a `SINGLE` SAR frame.
   - CPace Step 1 ($Y_A$): raw 32 bytes of compressed Ristretto255 point $Y_A$ encapsulated in a `SINGLE` SAR frame (`Total Frame Length = 32`, `Chunk Sequence = 0`, `Flags = 0x05`).
   - CPace Step 2 ($Y_B, T_B$): raw concatenation $Y_B \parallel T_B$ ($32 + 32 = 64\text{ bytes}$) encapsulated in a `SINGLE` SAR frame (`Total Frame Length = 64`, `Chunk Sequence = 0`, `Flags = 0x05`).
   - CPace Step 3 ($T_A$): raw 32 bytes of confirmation authenticator $T_A$ encapsulated in a `SINGLE` SAR frame (`Total Frame Length = 32`, `Chunk Sequence = 0`, `Flags = 0x05`).
   - Noise Handshake & Transport Frames: raw Noise ciphertext payloads encapsulated in SAR frames (segmented across multiple chunks if payload exceeds $\text{sar\_payload\_capacity} = \min(\text{negotiated\_att\_mtu} - 3, 512) - 6$ bytes, e.g. $> 506$ bytes at MTU $\ge 515$, $> 503$ bytes at MTU 512).
10. **Phase-Specific Frame Dispatch**:
   - Reassembled complete frames are dispatched strictly according to the internal connection state machine:
     - `Phase::Routing`: Dispatched to connection routing evaluator (Section 5.2).
     - `Phase::CPace`: Dispatched to `CPaceRistretto255` handler.
     - `Phase::NoisePairing`: Dispatched to `Noise_XXpsk3` pairing engine.
     - `Phase::NoiseSession`: Dispatched to `Noise_KKhfs` operational session engine.
   - Handlers NEVER select dispatch targets based on unauthenticated payload inspection. Any frame arriving out of expected phase is an unrecoverable protocol violation.

---

### 6. Normative Cryptographic Protocols

RAPP v26.10.1 specifies three normative cryptographic protocols:
1. **`CPaceRistretto255`**: Password-Authenticated Key Exchange (PAKE) for initial proximity pairing (§6.1).
2. **`Noise_XXpsk3`**: Initial mutual pairing authentication handshake (§6.2).
3. **`Noise_KKhfs`**: Hybrid post-quantum operational session handshake (§6.3).

### 6.1 CPaceRistretto255 (draft-irtf-cfrg-cpace-21 & RFC 9496)

RAPP v26.10.1 implements **`CPaceRistretto255`** per [draft-irtf-cfrg-cpace-21 Section 7.2 & Appendix A.2](https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-cpace-21) and reference implementation [`crates/rapp/src/cpace.rs`](../../crates/rapp/src/cpace.rs):

#### 6.1.1 Cryptographic Suite Definition
- **Group**: Prime-order Ristretto255 group (order $q = 2^{252} + 27742317777372353535851937790883648493$).
- **Hash Function**: SHA-512 (block size 128 bytes, output 64 bytes).
- **Domain Separation Identifiers (DSI)**:
  - Base Point DSI: `CPaceRistretto255` (`b"CPaceRistretto255"`)
  - Intermediate Session Key DSI: `CPaceRistretto255_ISK` (`b"CPaceRistretto255_ISK"`)
- **MapToGroup**: Maps 64-byte uniform hash output to a Ristretto255 group element using `RistrettoPoint::from_uniform_bytes` per [RFC 9496 Section 4.3.4](https://www.rfc-editor.org/rfc/rfc9496.html#section-4.3.4) and draft-irtf-cfrg-cpace-21 Appendix A.2. If the mapped point is the group identity $\mathcal{O}$ (probability $2^{-252}$), fallback to `RISTRETTO_BASEPOINT_POINT`. (Note: This fallback to the basepoint constant is an RAPP-specific defensive extension implemented in `crates/rapp/src/cpace.rs` to guarantee non-identity output; it is not defined in draft-21 §8.3 or RFC 9496 §4.3.4).
- **PAKE Identity Binding & Role Separation**: CPace is executed purely as an anonymous PAKE to exchange ephemeral keys and establish a shared secret $PSK$ under the random session identifier $SID$. Endpoint party identifiers ($\text{ID}_A, \text{ID}_B$) and auxiliary data ($\text{AD}_A, \text{AD}_B$) in CPace are empty ($\emptyset$); mutual endpoint authentication and cryptographic identity binding are deferred to the subsequent `Noise_XXpsk3` handshake. The Requester acts strictly as Initiator ($A$), transmitting via `ATT_WRITE_REQ`, while the Custodian acts strictly as Responder ($B$), transmitting via `ATT_HANDLE_VALUE_IND`. Per draft-irtf-cfrg-cpace-21 Section 10.1, this fixed asymmetric role assignment prevents relay loopback and reflection attacks.

#### 6.1.2 Generator Derivation (draft-21 Appendix A.2)
The generator point $G$ is derived from length-value encoding with single zero-padding:
$$\text{len\_zpad} = \max(0, 128 - 1 - |\text{prepend\_len}(\text{pw})| - |\text{prepend\_len}(\text{DSI})|)$$
$$\text{gen\_input} = \text{lv\_cat}(\text{DSI}, \text{pw}, \text{zero\_bytes}(\text{len\_zpad}), \text{CI}=\emptyset, \text{SID})$$
$$G = \text{MapToGroup}(\text{SHA-512}(\text{gen\_input}))$$
where $\text{prepend\_len}(x)$ prefixes $x$ with its LEB128 length, and $\text{CI}$ is empty length-value (`&[]`).

#### 6.1.3 Ephemeral Exchange & Validation
1. **Initiator (Requester)**:
   - Samples 64 random bytes, derives scalar $x_A = \text{Scalar::from\_bytes\_mod\_order\_wide}(\text{random}_A)$.
   - Verifies $x_A \ne 0$.
   - Computes $Y_A = x_A \cdot G$. Encodes to 32 bytes via `compress().to_bytes()`.
   - Transmits 32-byte $Y_A$ in CPace Step 1 via `ATT_WRITE_REQ` in a `SINGLE` SAR frame.
2. **Responder (Custodian)**:
   - Receives $Y_A$, decodes and validates $Y_A \ne \mathcal{O}$ and valid Ristretto255 point.
   - Atomically reserves attempt slot ($1 \le \text{attempts\_admitted} \le 3$, `active_attempt = true`).
   - Samples 64 random bytes, derives scalar $x_B \ne 0$.
   - Computes $Y_B = x_B \cdot G$.
   - Computes shared point $K = x_B \cdot Y_A$. Verifies $K \ne \mathcal{O}$.
   - Derives Intermediate Session Key (ISK):
     $$\text{isk\_input} = \text{lv\_cat}([\text{DSI}_{\text{ISK}}, \text{SID}, K]) \parallel \text{transcript\_ir}(Y_A, \emptyset, Y_B, \emptyset)$$
     $$\text{ISK} = \text{SHA-512}(\text{isk\_input}) \quad (64\text{ bytes})$$
   - Computes mutual confirmation authenticator $T_B = \text{SHA-512}(\text{ISK} \parallel \texttt{"CONFIRM-B"} \parallel \text{SID})[0..32]$.
   - Arms the attempt timer defined in §3.3.3: $\text{attempt\_deadline} = \min(5.0\text{ s}, \text{remaining\_offer\_ttl})$. If $\text{remaining\_offer\_ttl} == 0$, abort without admitting the attempt.
   - Transmits 64-byte $Y_B \parallel T_B$ in CPace Step 2 via `ATT_HANDLE_VALUE_IND` in a `SINGLE` SAR frame.
3. **Key Confirmation (Requester)**:
   - Requester receives $Y_B$ and $T_B$, validates $Y_B \ne \mathcal{O}$.
   - Computes shared point $K = x_A \cdot Y_B$. Verifies $K \ne \mathcal{O}$.
   - Derives identical $\text{ISK} = \text{SHA-512}(\text{isk\_input})$.
   - Verifies $T_B$ in constant time.
   - Computes $T_A = \text{SHA-512}(\text{ISK} \parallel \texttt{"CONFIRM-A"} \parallel \text{SID})[0..32]$.
   - Transmits 32-byte $T_A$ in CPace Step 3 via `ATT_WRITE_REQ` in a `SINGLE` SAR frame.
#### 6.1.4 Finalization & PSK Derivation
- Custodian verifies $T_A$ in constant time within the clamped attempt deadline.
- Upon verification, Custodian clears `active_attempt`, cancels the PAKE attempt timer, and transfers exclusive ownership to `Phase::NoisePairing`.
- Both parties extract the 32-byte Application Pairing Secret ($PSK$):
  $$PSK = \text{ISK}[0..32]$$
  (Design Note: Slicing the first 32 bytes of the 64-byte uniform $\text{ISK}$ is an intentional RAPP design choice relative to the general KDF recommendations in draft-irtf-cfrg-cpace-21 Section 10.3 and Section 10.4, directly matching the reference implementation in `crates/rapp/src/cpace.rs`. Under CPace assumptions, security of the PAKE is bounded by the ~252-bit prime order of Ristretto255 (~126 bits of classical security against Pollard's rho) and the online rate limiting of the human pairing code. Classical discrete-log PAKEs are not post-quantum secure against large-scale quantum computers; hybrid post-quantum forward secrecy against future quantum adversaries is established separately during subsequent operational sessions via the `Noise_KKhfs` handshake using ML-KEM-768).
- $PSK$ is passed directly as the pre-shared key into the `Noise_XXpsk3` pairing handshake (§6.2).

### 6.2 Noise_XXpsk3 Pairing Handshake (RFC 7748, RFC 8439, RFC 5869)

- **Suite**: `Noise_XXpsk3_25519_ChaChaPoly_SHA512`
- **Underlying Primitives**:
  - DH: Curve25519 / X25519 per [RFC 7748](https://www.rfc-editor.org/rfc/rfc7748.html) (32-byte keys).
  - Cipher: ChaCha20-Poly1305 per [RFC 8439](https://www.rfc-editor.org/rfc/rfc8439.html) (32-byte key, 12-byte nonce, 16-byte tag). Nonce layout: 4 zero bytes (`0x00, 0x00, 0x00, 0x00`) followed by 8 big-endian bytes representing the 64-bit sequence counter.
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
- **PSK Input**: The 32-byte $PSK = \text{ISK}[0..32]$ derived from CPace (§6.1.4) is injected as the pre-shared key at token `psk` (`MixKey(psk)`).
- **Handshake Payload Policy**: All handshake message payloads are empty ($\emptyset$, length 0). Encrypting an empty payload produces a 16-byte Poly1305 authentication tag.
- **Handshake Messages**:
  - Message 1 (Initiator -> Responder):
    Tokens: `e`.
    Carries unencrypted 32-byte ephemeral public key $e_{pub}$.
    Total size: 32 bytes.
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
  session_id       = first 16 bytes of SHA-512("RAPP-session-id-v1" || h)
  pair_id          = first 16 bytes of SHA-512("RAPP-pair-id-v1" || h)
  rendezvous_token = first 16 bytes of SHA-512("RAPP-rendezvous-v1" || h)
  ```
  Both peers immediately zeroize $PSK$ and ephemeral keys.

### 6.3 Noise_KKhfs Operational Session Handshake (NIST FIPS 203, RFC 7748, RFC 8439, RFC 5869)

- **Suite**: `Noise_KKhfs_25519+MLKEM768_ChaChaPoly_SHA512`
- **Pinned Cryptographic Standards**:
  - Noise Protocol Framework: Revision 34 (June 2018), with the Hybrid Forward Secrecy (HFS) extension.
  - Classical DH: Curve25519 / X25519 per [RFC 7748](https://www.rfc-editor.org/rfc/rfc7748.html) (32-byte keys).
  - Post-Quantum KEM: ML-KEM-768 per [NIST FIPS 203](https://doi.org/10.6028/NIST.FIPS.203):
    - Encapsulation key ($ek$ / public key) size: 1,184 bytes.
    - Decapsulation key ($dk$ / private key) size: 2,400 bytes (or 64-byte seed).
    - Ciphertext ($ct$) size: 1,088 bytes.
    - Shared secret ($ss_{kem}$) size: 32 bytes.
  - AEAD Cipher: ChaCha20-Poly1305 per [RFC 8439](https://www.rfc-editor.org/rfc/rfc8439.html) (32-byte key, 12-byte nonce, 16-byte tag). Nonce layout: 4 zero prefix bytes followed by 8 big-endian sequence counter bytes.
  - Hash Function: SHA-512 per [FIPS 180-4](https://doi.org/10.6028/NIST.FIPS.180-4) (64-byte output, 128-byte block size).
  - Key Derivation: HKDF-SHA-512 per [RFC 5869](https://www.rfc-editor.org/rfc/rfc5869.html).
- **Handshake Pattern**:
  ```text
  Noise_KKhfs(s, rs):
    <- s
    -> s
    ...
    -> e, es, ekem, ss
    <- e, ee, kemct, se
  ```
- **State Initialization**:
  1. `protocol_name` = `"Noise_KKhfs_25519+MLKEM768_ChaChaPoly_SHA512"` (46 ASCII bytes).
  2. Because $|\text{protocol\_name}| \le 64$, $h$ is initialized by right-padding with 18 zero bytes to 64 bytes:
     $$h = \text{protocol\_name} \parallel 0^{18}$$
  3. Chaining key initialized to $ck = h$.
  4. MixHash(prologue): $h = \text{SHA-512}(h \parallel \text{prologue})$ where prologue is `encode_deterministic_cbor(session-prologue)` (§4.3.6).
  5. Pre-message static point hashing:
     - Initiator (Requester): $h = \text{SHA-512}(h \parallel s_{local\_pub})$; then $h = \text{SHA-512}(h \parallel s_{remote\_pub})$.
     - Responder (Custodian): $h = \text{SHA-512}(h \parallel s_{remote\_pub})$; then $h = \text{SHA-512}(h \parallel s_{local\_pub})$.
- **Message 1 (Initiator -> Responder)**: Tokens `e, es, ekem, ss`
  1. `e`: Initiator samples fresh ephemeral X25519 private key $e_{priv}$, computes 32-byte public key $e_{pub} = \text{X25519}(e_{priv}, G)$. Appends $e_{pub}$ (32 bytes) unencrypted to message buffer. Calls `MixHash(e_pub)`: $h = \text{SHA-512}(h \parallel e_{pub})$.
  2. `es`: Initiator computes classical DH shared secret $DH(e_{priv}, rs_{pub})$ (32 bytes). Calls `MixKey`:
     $$(ck, k) = \text{HKDF-SHA-512}(ck, DH(e_{priv}, rs_{pub}), 2)$$
     Cipher state rekeyed with $k$, sequence counter reset to 0.
  3. `ekem`: Initiator generates fresh ephemeral ML-KEM-768 keypair $(dk_E, ek_E)$ per NIST FIPS 203 ($ek_E$ is 1,184 bytes).
     Calls `EncryptAndHash(ek_E)`: encrypts 1,184-byte $ek_E$ under current cipher state using $h$ as associated data. Produces 1,200 bytes ($1,184 + 16$ Poly1305 tag). Appends encrypted key to message buffer. Updates $h = \text{SHA-512}(h \parallel \text{ciphertext})$.
  4. `ss`: Initiator computes static DH shared secret $DH(s_{priv}, rs_{pub})$ (32 bytes). Calls `MixKey`:
     $$(ck, k) = \text{HKDF-SHA-512}(ck, DH(s_{priv}, rs_{pub}), 2)$$
     Cipher state rekeyed with $k$, sequence counter reset to 0.
  5. Handshake Payload: Empty ($\emptyset$). Initiator calls `EncryptAndHash("")` with $h$ as associated data, producing a 16-byte Poly1305 authentication tag appended to message buffer. Updates $h = \text{SHA-512}(h \parallel \text{tag})$.
  **Total Message 1 Length**: $32 + 1{,}200 + 16 = 1{,}248\text{ bytes}$.
- **Message 1 Processing by Responder (Custodian)**:
  1. Reads 32 bytes $e_{pub}$. Validates non-zero point. Calls `MixHash(e_pub)`.
  2. Computes $DH(s_{priv}, e_{pub})$ (32 bytes). Calls `MixKey`.
  3. Reads 1,200 bytes encrypted ML-KEM key. Calls `DecryptAndHash`: verifies Poly1305 tag with $h$ as associated data and decrypts 1,184-byte $ek_E$. Parses $ek_E$ per NIST FIPS 203. Updates $h = \text{SHA-512}(h \parallel \text{ciphertext})$. (Note: The Responder does NOT decapsulate here).
  4. Computes $DH(s_{priv}, rs_{pub})$ (32 bytes). Calls `MixKey`.
  5. Reads 16-byte encrypted empty payload tag. Calls `DecryptAndHash`: verifies Poly1305 tag over empty plaintext with $h$ as associated data. Updates $h = \text{SHA-512}(h \parallel \text{tag})$.
- **Message 2 (Responder -> Initiator)**: Tokens `e, ee, kemct, se`
  1. `e`: Responder samples fresh ephemeral X25519 private key $e_{priv}$, computes 32-byte public key $e_{pub}$. Appends $e_{pub}$ (32 bytes) unencrypted to message buffer. Calls `MixHash(e_pub)`.
  2. `ee`: Responder computes ephemeral DH shared secret $DH(e_{priv}, re_{pub})$ (32 bytes). Calls `MixKey`.
  3. `kemct`: Responder encapsulates against initiator's ML-KEM-768 public key $ek_E$ per NIST FIPS 203:
     $$(ct, ss_{kem}) = \text{ML-KEM-768.Encaps}(ek_E)$$
     producing 1,088-byte ciphertext $ct$ and 32-byte shared secret $ss_{kem}$.
     Calls `EncryptAndHash(ct)`: encrypts 1,088-byte $ct$ under current cipher state with $h$ as associated data. Produces 1,104 bytes ($1,088 + 16$ Poly1305 tag). Appends to message buffer. Updates $h = \text{SHA-512}(h \parallel \text{ciphertext})$.
     Then mixes KEM shared secret via `MixKey(ss_kem)`:
     $$(ck, k) = \text{HKDF-SHA-512}(ck, ss_{kem}, 2)$$
     Cipher state rekeyed with $k$, sequence counter reset to 0.
  4. `se`: Responder computes DH shared secret $DH(e_{priv}, rs_{pub})$ (32 bytes). Calls `MixKey`.
  5. Handshake Payload: Empty ($\emptyset$). Calls `EncryptAndHash("")` with $h$ as associated data, producing a 16-byte Poly1305 authentication tag appended to message buffer. Updates $h = \text{SHA-512}(h \parallel \text{tag})$.
  **Total Message 2 Length**: $32 + 1{,}104 + 16 = 1{,}152\text{ bytes}$.
- **Message 2 Processing by Initiator (Requester)**:
  1. Reads 32 bytes $e_{pub}$. Calls `MixHash(e_pub)`.
  2. Computes $DH(e_{priv}, re_{pub})$ (32 bytes). Calls `MixKey`.
  3. Reads 1,104 bytes encrypted ML-KEM ciphertext. Calls `DecryptAndHash`: verifies Poly1305 tag with $h$ as associated data and decrypts 1,088-byte $ct$. Updates $h = \text{SHA-512}(h \parallel \text{ciphertext})$.
     Initiator decapsulates $ct$ using its ephemeral ML-KEM-768 decapsulation key $dk_E$ per NIST FIPS 203:
     $$ss_{kem} = \text{ML-KEM-768.Decaps}(dk_E, ct)$$
     Calls `MixKey(ss_kem)` to mix the recovered 32-byte shared secret.
  4. Computes $DH(s_{priv}, re_{pub})$ (32 bytes). Calls `MixKey`.
  5. Reads 16-byte encrypted empty payload tag. Calls `DecryptAndHash`: verifies Poly1305 tag over empty plaintext with $h$ as associated data. Updates $h = \text{SHA-512}(h \parallel \text{tag})$.
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
  5. Ephemeral handshake state ($e_{priv}, dk_E, ss_{kem}$) is immediately zeroized.

---

## 7. Authenticated Message Envelopes and Wire Framing

### 7.1 Common Post-Handshake Message Envelope & Complete Message Schemas
Every message transmitted inside an established pairing channel (`Phase::NoisePairing`) or operational session (`Phase::NoiseSession`) is encapsulated in a deterministic CBOR envelope conforming to the following normative CDDL specification:

```cddl
rapp-message =
    { "version": [26, 10], "session_id": bstr .size 16, "sequence": uint, "type": "pairing.hello", "body": pairing-hello-body, * common-opt }
  / { "version": [26, 10], "session_id": bstr .size 16, "sequence": uint, "type": "pairing.confirm", "body": pairing-confirm-body, * common-opt }
  / { "version": [26, 10], "session_id": bstr .size 16, "sequence": uint, "type": "pairing.abort", "body": pairing-abort-body, * common-opt }
  / { "version": [26, 10], "session_id": bstr .size 16, "sequence": uint, "type": "session.ready", "body": session-ready-body, * common-opt }
  / { "version": [26, 10], "session_id": bstr .size 16, "sequence": uint, "type": "session.close", "body": session-close-body, * common-opt }
  / { "version": [26, 10], "session_id": bstr .size 16, "sequence": uint, "type": "liveness.ping", "body": liveness-ping-body, * common-opt }
  / { "version": [26, 10], "session_id": bstr .size 16, "sequence": uint, "type": "liveness.pong", "body": liveness-pong-body, * common-opt }
  / { "version": [26, 10], "session_id": bstr .size 16, "sequence": uint, "type": "operation.request", "body": operation-request-body, * common-opt }
  / { "version": [26, 10], "session_id": bstr .size 16, "sequence": uint, "type": "operation.prepared", "body": operation-prepared-body, * common-opt }
  / { "version": [26, 10], "session_id": bstr .size 16, "sequence": uint, "type": "operation.commit", "body": operation-commit-body, * common-opt }
  / { "version": [26, 10], "session_id": bstr .size 16, "sequence": uint, "type": "operation.cancel", "body": operation-cancel-body, * common-opt }
  / { "version": [26, 10], "session_id": bstr .size 16, "sequence": uint, "type": "operation.result", "body": operation-result-body, * common-opt }
  / { "version": [26, 10], "session_id": bstr .size 16, "sequence": uint, "type": "operation.result_ack", "body": operation-result-ack-body, * common-opt }
  / { "version": [26, 10], "session_id": bstr .size 16, "sequence": uint, "type": "operation.status_request", "body": operation-status-request-body, * common-opt }
  / { "version": [26, 10], "session_id": bstr .size 16, "sequence": uint, "type": "operation.status", "body": operation-status-body, * common-opt }
  / { "version": [26, 10], "session_id": bstr .size 16, "sequence": uint, "type": "operation.progress", "body": operation-progress-body, * common-opt }
  / { "version": [26, 10], "session_id": bstr .size 16, "sequence": uint, "type": "error", "body": error-body, * common-opt }

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
  "version": [26, 10],
  "suite": "CPACE-RISTR255-SHA512 + Noise_XXpsk3_25519_ChaChaPoly_SHA512",
  "offer_hash": bstr .size 32,
  "transport_profile": "fi.refineid.rapp.ble.v1",
  "candidate_id": "ble-direct-1"
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
  "version": [26, 10],
  "suite": "Noise_KKhfs_25519+MLKEM768_ChaChaPoly_SHA512",
  "transport_profile": "fi.refineid.rapp.ble.v1",
  "candidate_id": "ble-direct-1",
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

; 9. Operation Prepared
operation-prepared-body = {
  "operation_id": bstr .size 16,
  "request_hash": bstr .size 32
}

; 10. Operation Commit
operation-commit-body = {
  "operation_id": bstr .size 16,
  "request_hash": bstr .size 32
}

; 11. Operation Cancel
operation-cancel-body = {
  "operation_id": bstr .size 16,
  "request_hash": bstr .size 32,
  ? "reason": tstr
}

; 12. Operation Result
operation-result-body = {
  "operation_id": bstr .size 16,
  "request_hash": bstr .size 32,
  "status": operation-status-val,
  ? "response": { * tstr => any },
  ? "error": tstr,
  ? "remaining_retries": uint
}

operation-status-val =
    "completed"
  / "rejected"
  / "credential_rejected"
  / "cancelled"
  / "ambiguous"

; 13. Operation Result Acknowledgment
operation-result-ack-body = {
  "operation_id": bstr .size 16,
  "request_hash": bstr .size 32
}

; 14. Operation Status Request (Reconciliation Query)
operation-status-request-body = {
  "operation_id": bstr .size 16
}

; 15. Operation Status Report (Reconciliation Response)
operation-status-body = {
  "operation_id": bstr .size 16,
  "known": bool,
  ? "state": operation-status-val,
  ? "request_hash": bstr .size 32
}

; 16. Operation Progress Update
operation-progress-body = {
  "operation_id": bstr .size 16,
  "request_hash": bstr .size 32,
  "event": progress-event-val
}

progress-event-val =
    "waiting_for_card"
  / "card_wait_ended"
  / tstr

; 17. Protocol Error Body: error-body is defined in §10.4
```

#### Normative Semantics of Registered Message Types:
1. **`pairing.hello`**: Transmitted by the Requester inside `Phase::NoisePairing` immediately following handshake completion. Echoes negotiated pairing parameters (`version`, `suite`, `offer_hash`, `transport_profile`, `candidate_id`), peer display name, and requested profile names. The Custodian verifies that all echoed parameters match its local offer state; any discrepancy aborts pairing.
2. **`pairing.confirm`**: Transmitted by the Custodian after displaying the proposed grants to the user and collecting confirmation; subsequently echoed by the Requester. Contains the canonical list of `granted_profiles`. Both peers verify that the sets are identical before deriving `grants_hash` (Section 4.3).
3. **`pairing.abort`**: Transmitted by either peer to cancel an in-progress pairing ceremony prior to final trust record storage, providing an advisory reason string. Ephemeral keys are destroyed immediately.
4. **`session.ready`**: Transmitted by the Custodian upon completing `Phase::NoiseSession` (`Noise_KKhfs`) to prove possession of the operational session key and fresh session state, echoing session parameters and a fresh random 32-byte `nonce`.
5. **`session.close`**: Transmitted by either peer to signal an orderly, authenticated termination of an operational session, providing a registered `close-reason-val` and acknowledging the `last_received_sequence`.
6. **`liveness.ping`**: Periodic authenticated keepalive request transmitted by either peer carrying a fresh 32-byte `challenge` and sequence acknowledgment.
7. **`liveness.pong`**: Periodic authenticated keepalive response echoing the exact 32-byte `challenge` and sequence acknowledgment.
8. **`operation.request`**: Transmitted by the Requester to initiate a credential action under a registered profile (§8.2, §9).
9. **`operation.prepared`**: Transmitted by the Custodian to confirm that parameters, profile grants, and user authorization have succeeded, echoing the derived `request_hash` (§8.2).
10. **`operation.commit`**: Transmitted by the Requester as the definitive point of no return, instructing the Custodian to physically dispatch card APDU commands (§8.2).
11. **`operation.cancel`**: Transmitted by either peer prior to commit to abort an operation cleanly without executing card commands (§8.2.4).
12. **`operation.result`**: Transmitted by the Custodian to deliver the final card execution outcome, status, signature/response payload, or credential error (§8.2).
13. **`operation.result_ack`**: Transmitted by the Requester to acknowledge delivery of a successful (`"completed"`) operation result (§8.2).
14. **`operation.status_request`**: Transmitted by the Requester after reconnecting to reconcile the terminal outcome of an interrupted or ambiguous operation (§8.3).
15. **`operation.status`**: Transmitted by the Custodian in response to `operation.status_request`, reporting whether the operation is journaled (`known`) and its terminal state (§8.3).
16. **`operation.progress`**: Advisory notification transmitted by the Custodian during long-running card transactions (e.g. prompt to present card to NFC antenna).
17. **`error`**: Application protocol error envelope transmitted upon encountering unexpected conditions (e.g. busy session or unknown operation race); bounded schema and numeric error code mappings are defined in §10.4.

### 7.2 Field Semantics, Version Precedence, and Sequencing
1. **Wire Version & Skew Precedence**:
   - The envelope wire version is fixed to `[26, 10]` (`[major, minor]`).
   - If version skew is observed during handshake prologue negotiation (e.g. mismatched version in the Noise prologue), the handshake fails AEAD decryption and surfaces as a **Class 2 (Transport Loss)** failure; the link drops and stored pairings remain intact.
   - If an authenticated envelope carrying a version other than `[26, 10]` is received on an establishing or active session, the receiver MUST reject the message and terminate the session as a **Class 2** transport failure without modifying stored pairing records.
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
   - The resulting ciphertext payload is framed into RAPP BLE SAR fragments (Section 5.3) and transmitted via `ATT_WRITE_REQ` (Central to Peripheral) or `ATT_HANDLE_VALUE_IND` (Peripheral to Central).

---

## 8. Operation Model and Execution Lifecycle (Two-Phase Commit)

Credential operations (authentication signatures, qualified document signing) invoke sensitive, stateful cryptographic operations on the physical identity card over NFC.

### 8.1 Strict At-Most-Once Physical Transmission Contract
1. **Zero Repeated Executions**:
   Cryptographic private key commands and PIN verifications **MUST NEVER** be executed more than once per user authorization. Replaying network requests or reconnecting after a transport failure **MUST NEVER** trigger re-execution of a physical card command.
2. **Write-Ahead Journaling**:
   Before physically dispatching any APDU command that can decrement a try counter or invoke a card private key, the Custodian **MUST** durably record a write-ahead journal entry in platform secure storage:
   - `pair_id` and `session_id`
   - `operation_id` (16 bytes)
   - `request_hash` (32 bytes)
   - State: `committed`
   - For `batch_sign_documents`: `batch_total` ($1..64$), `completed_signatures` (`[bstr]`), and currently executing document index.
3. **Ambiguity on Interruption**:
   If the link drops or the process terminates while an operation is executing on the card, the state on restart or reconnection is classified as `ambiguous`. The Custodian MUST NOT re-send the command to the card.

### 8.2 Two-Phase Operation Lifecycle

1. **Phase 1: Request & Preparation**:
   - Requester transmits `operation.request` carrying a fresh 16-byte `operation_id`, profile, action, context map, payload map, and optional `expires_after_ms`.
   - Both endpoints derive the deterministic request commitment:
     $$\text{request\_hash} = \text{SHA-256}(\text{encode\_deterministic\_cbor}([\texttt{"RAPP-request-v1"}, \text{session\_id}, \text{operation\_id}, \text{profile}, \text{action}, \text{context}, \text{payload}]))$$
     This fixed-order array preimage binds the protocol domain label (`"RAPP-request-v1"`), the active `session_id`, the unique `operation_id`, the profile, the action, and all context/payload maps.
   - **`expires_after_ms` Semantics**:
     - `expires_after_ms` is strictly **excluded** from `request_hash` so that local expiry policies do not alter cryptographic commitments.
     - If present, `expires_after_ms` MUST be $> 0$; a value of 0 is rejected immediately with error `invalid_lifetime`. If absent, the Custodian applies a local default lifetime $\text{effective\_expires\_after\_ms} = 300{,}000\text{ ms}$ (5 minutes).
     - Upon receiving `operation.request`, the Custodian derives a monotonic local deadline using saturating arithmetic:
       $$\text{local\_deadline} = \text{local\_start\_monotonic\_ms}.\text{saturating\_add}(\min(\text{effective\_expires\_after\_ms}, \text{local\_policy\_max\_lifetime}))$$
     - If `local_deadline` passes before the user authorizes the operation on the phone screen or before `operation.commit` is received, the operation expires. The Custodian transitions the state to `cancelled`, releases held resources, and responds with `operation.result` (`status: "cancelled"`, `error: "operation_expired"`). No card APDU is dispatched.
   - Custodian validates profile grants, parameters, and card state. If the action requires user approval or PIN verification, Custodian presents consent details on the phone screen.
   - Upon successful human authorization, Custodian responds with `operation.prepared` echoing `operation_id` and `request_hash`.
2. **Phase 2: Commit & Execution**:
   - Requester verifies `request_hash` received in `operation.prepared` and transmits `operation.commit`. Commit is the Requester's point of no return.
   - **Commit Validation & Journaling Order**:
     Upon receiving `operation.commit`, the Custodian evaluates the commit in strict sequence:
     a. Verify that the operation exists in memory and is in state `Prepared`.
     b. Verify that `commit.operation_id` matches prepared `operation_id`.
     c. Recompute `request_hash` from the immutable in-memory prepared request fields (§8.2.1) and verify that received `commit.request_hash` matches byte-for-byte. If mismatching, reject immediately with `operation.result` carrying `status: "rejected"`, `error: "invalid_commitment"`; do not dispatch APDUs.
     d. Before issuing any APDU to the smart card, the Custodian **MUST** write a durable write-ahead journal entry to persistent storage:
        `[operation_id, session_id, pair_id, request_hash, state: "committed", timestamp]`.
     e. If the durable journal write fails (e.g. storage I/O error, disk full), the Custodian **MUST NOT** dispatch APDUs to the card; it aborts execution and returns Class 3 `operation_failed`.
     f. Once durably recorded, the Custodian verifies the retry counter floor (§10.3) and dispatches APDUs to the FINEID card over NFC.
   - Duplicate `operation.commit` frames matching the active `request_hash` are discarded idempotently without re-triggering card commands.
   - Custodian transmits `operation.result` carrying the outcome.
   - For `status == "completed"`, Requester transmits `operation.result_ack`.
3. **Safe Reads (Single-Phase Optimization)**:
   Actions that define no consequential command (e.g. `inspect_card`, `read_identity`, `read_certificate`) omit `operation.prepared` and `operation.commit`. The Custodian executes the read and responds directly with `operation.result`.
4. **Cancellation and Race Precedence**:
   - Prior to commit, either peer may transmit `operation.cancel`, producing status `"cancelled"` and releasing resources without consuming card attempts.
   - **Commit vs. Cancel Race Precedence**:
     - If `operation.commit` arrives at the Custodian before `operation.cancel`, commit takes precedence: the operation proceeds to physical execution. Any subsequent `operation.cancel` for that `operation_id` is advisory and ignored; the Custodian delivers `operation.result` with the card outcome.
     - If `operation.cancel` arrives at the Custodian before `operation.commit`, cancel takes precedence: the operation is immediately aborted, state transitioned to `cancelled`, and resources released. A subsequent `operation.commit` arriving for that cancelled operation matches a terminal state and is handled as a benign Class 3 stale-reference race, returning `error` with `"unknown_operation"`. It is NOT an authenticated protocol violation and does not destroy pairing.

### 8.3 Durable Status Reconciliation and Ambiguity Recovery

When a BLE connection drops, a timeout occurs, or the Custodian restarts while an operation is executing on the smart card, the state is classified as `ambiguous`.

1. **Anti-Duplication Enforcement**:
   The Custodian **MUST NEVER** re-dispatch card private-key APDUs for an ambiguous operation upon reconnection. Doing so would violate the strict at-most-once execution contract.
2. **Reconciliation Protocol (`operation.status_request` / `operation.status`)**:
   - Upon reconnecting in a fresh operational session (`Phase::NoiseSession`), the Requester transmits `operation.status_request` carrying the queried `operation_id`.
   - The Custodian consults its durable write-ahead journal:
     - **Known Operation**: If `operation_id` matches a journaled entry:
       - Custodian responds with `operation.status` (`known: true`, `state: <journaled_state>`, `request_hash: <hash>`).
       - If the journal holds a cached terminal result (e.g. execution succeeded before the network drop, or failed with a card error), the Custodian also re-delivers `operation.result` with the cached response bytes without re-accessing the card.
       - If the state remains `ambiguous` (e.g. card transaction was interrupted or card was removed mid-APDU), `state: "ambiguous"` is reported.
     - **Unknown Operation**: If `operation_id` is not present in the journal (e.g. request was dropped before commit), Custodian responds with `operation.status` (`known: false`).
3. **Terminal Exit from Ambiguous State**:
   - An ambiguous operation is permanently terminal for that `operation_id`. It CANNOT be recommitted or retried with `operation.commit` under the same identifier.
   - If the application wishes to retry the action after an ambiguous failure, the Requester **MUST** allocate a fresh 16-byte `operation_id` and initiate a completely new Two-Phase Commit lifecycle, requiring fresh human consent and authorization on the Custodian phone screen.

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
  - Response: `card_present` (`bool`), `atr` (`bstr`), `supported_profiles` (`[* tstr]`).
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
    - `algorithm` (`tstr`): Registered algorithm (`"ecdsa_sha256"`, `"rsa_pkcs1_sha256"`). No other algorithms are defined in v26.10.1.
    - `digest` (`bstr`): Pre-hashed challenge bytes matching algorithm digest length (e.g. 32 bytes for SHA-256).
  - Validation: If a request specifies an unrecognized or unsupported `key_profile` or `algorithm`, the Custodian MUST respond with `operation.result` carrying `status: "rejected"` and `error: "unsupported_parameter"`. This is a semantic rejection, NOT an authenticated protocol violation (Class 4).
  - Signature Wire Format:
    - For `"ecdsa_sha256"`: The signature MUST be serialized as fixed-width raw IEEE P1363 big-endian concatenation $r \parallel s$. For `"ecdsa_p256"`, exactly 64 bytes (32-byte $r \parallel$ 32-byte $s$); for `"ecdsa_p384"`, exactly 96 bytes (48-byte $r \parallel$ 48-byte $s$). ASN.1 DER encoding is strictly prohibited on the wire.
    - For `"rsa_pkcs1_sha256"`: The signature MUST be serialized as raw big-endian integer bytes matching the RSA key modulus length (256 bytes for `"rsa_2048"`, 384 bytes for `"rsa_3072"`), computed via RSASSA-PKCS1-v1_5 per RFC 8017 Section 8.2 (EMSA-PKCS1-v1_5 with SHA-256 DigestInfo prefix `3031300d060960864801650304020105000420` followed by 32-byte SHA-256 digest).
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
1. **Pre-Authentication Invalid Input (Class 1)**: Malformed preamble, unknown routing token, invalid MTU, or out-of-order writes prior to Noise authentication. Action: close BLE connection immediately; zero stored state modified.
2. **Transport Loss, Bearer Disruption, and Version Skew (Class 2)**: Radio drop, ATT timeout, link termination, failed AEAD MAC verification / decryption failure on an established channel, or unexpected wire version on connect/envelope. Because the bearer is untrusted and subject to RF corruption or relay tampering, ciphertext authentication failure cannot establish authenticated peer misconduct. Action: terminate active session and BLE link immediately, zeroize ephemeral session state; active operation marked `cancelled` (if before commit) or `ambiguous` (if committed). Stored pairing trust records and vault keys REMAIN INTACT. Smart card operations are NEVER re-executed.
3. **Stale-Reference Race and Semantic Rejection (Class 3)**: Decrypted operation message for an unknown or already terminal `operation_id` (e.g. commit arriving after cancel), or unsupported algorithm/parameter. Action: respond with `error` name `"unknown_operation"` or `operation.result` status `"rejected"` with `"unsupported_parameter"`; no pairing revocation.
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
  - Mark active pairing `revoked`, permanently delete pairing keys from local secure storage, and close BLE connection. Both peers require a completely new manual pairing ceremony after card unblocking.

### 10.3 Retry Floor Protection
Before transmitting any command that could decrement a PIN try counter, the Custodian **MUST** query the card's remaining try counter. If the counter indicates $\le 1$ attempt remaining, the Custodian MUST enforce the low-retry confirmation workflow (§10.2). If the try counter is 0 or unreadable, the Custodian **MUST** refuse the operation without transmitting verification commands to the card.

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
| `"unknown_operation"` | `1001` | Queried or committed `operation_id` is unknown or already terminal. | Class 3 |
| `"operation_expired"` | `1002` | Local monotonic operation deadline passed prior to commit. | Class 3 |
| `"user_cancelled"` | `1003` | User consciously declined or canceled the operation on the screen. | Class 3 |
| `"unauthorized"` | `1004` | Requested profile or action is not granted in active pairing. | Class 3 |
| `"unsupported_parameter"` | `1005` | Unsupported key profile, algorithm, or parameter value. | Class 3 |
| `"card_locked"` | `1006` | Card retry counter exhausted / PIN blocked (`SW 69 83`). | Class 4 |
| `"pin_blocked"` | `1007` | Specific PIN retry counter exhausted. | Class 4 |
| `"invalid_credential"` | `1008` | Incorrect PIN entered; retries remain (`SW 63 Cx`). | Class 3 |
| `"card_error"` | `1009` | APDU transmission failure, NFC loss, or smart card hardware fault. | Class 2 |
| `"operation_failed"` | `1010` | Consequential hardware execution or durable journal write failed. | Class 3 |
| `"duplicate_operation"` | `1011` | Non-idempotent attempt to execute an existing operation. | Class 3 |
| `"user_declined"` | `1012` | User declined proceeding under low-retry warning floor. | Class 3 |

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
| **Passive Eavesdropper** | Captures 2.4 GHz RF packets using SDR. | Zero hint in beacon. CPace provides mathematical resistance to offline dictionary attacks. Session encrypted with ChaCha20-Poly1305. |
| **Active MITM** | Injects, modifies, or drops BLE packets. | CPace authenticates possession of the pairing code only; with empty party identifiers it provides no endpoint identity binding (§6.1, draft-21 §10.1). Mutual endpoint identity authentication rests on Noise_XXpsk3 plus visual SAS confirmation (§4.5). Unmatched codes burn strikes and terminate the offer under rate-limiting. |
| **Disconnect Oracle** | Attacker tests $T_B$ and disconnects before $T_A$. | Atomic attempt reservation increments `attempts_admitted` *before* emitting $Y_B$ and $T_B$; disconnects do not refund the reserved attempt. |
| **Evil Twin / Rogue Beacon** | Attacker broadcasts identical Service UUID. | Requester requires matching code and post-handshake unbiased SAS device confirmation before dispatching operations. |
| **Transparent Wormhole / Relay** | Attacker relays RF traffic over WAN between distant devices. | Advisory proximity gate limits local discovery; explicit user consent on phone screen displays exact operation details; strict asymmetric ATT and CPace role separation structurally prevents relay loopback and reflection (§4.4, §5.2, §6.3). |
| **DoS Strike Burning** | Malicious central connects to phone to burn strikes. | Offers are open only upon explicit user trigger for 60 seconds; single-flight pre-authentication serialization limits concurrency. Fail-stop lockout imposes exponential backoff ($2^n$ seconds, up to 300 s) and alerts user with on-screen notification (§3.3.5). |
| **Rendezvous Token Replay / Presence Probing** | Attacker sniffs static rendezvous_token and replays preamble to probe presence or induce cryptographic work. | Preamble is unauthenticated routing metadata only; knowing rendezvous_token never authenticates caller. Handshake fails at message 1 (during DH computation, ML-KEM key decryption, or payload authentication). Timing difference between unknown token and known token is an accepted residual presence oracle for static tokens; mitigated by single-flight connection serialization and reconnect rate-limiting (§4.3.6). |

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

## 14. ReFineID Project Security Rules Compliance

1. **Inviolable Rule #1: Secret Exclusion over the Wire**:
   PIN1, PIN2, CAN, and PUK values **MUST NEVER** traverse the Bluetooth radio link. The RAPP GATT protocol wire format contains zero fields, messages, or representations for credential secrets.
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
