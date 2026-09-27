# Security and Usability Balance: The Refined Consensus

**Status:** Project Architectural Consensus  
**Date:** 2026-09-28  
**Applies to:** RefineID Core, RAPP Protocol, Apple, Unix, Windows platforms  
**Supersedes:** Prior draft iterations debating arbitrary PIN timeout windows  

---

## 1. Core Philosophy: Real Life Does Not Work in Extremes

Security engineering often falls into one of two damaging extremes:
1. **Security Theater & User Hostility:** Imposing arbitrary timers, repetitive confirmations, and friction that irritate users without actually stopping attackers. Users subjected to prompt fatigue end up approving prompts by reflex without reading them.
2. **Reckless Auto-Piloting:** Silently executing high-consequence operations (like legally binding Qualified Electronic Signatures) in the background without user awareness or consent.

RefineID rejects both extremes. Our goal is a **sane, refined balance of security and usability**:
- Make routine operations (web login, authentication) effortless, fast, and frictionless.
- Make consequential operations (contract signing, legal commitments) conscious, deliberate, and batch-efficient.
- Ground security in **verifiable physical and cryptographic boundaries**, rather than arbitrary time limits or superficial confirmation taps.

---

## 2. The Physical Air-Gap: The True Security Anchor

The fundamental security guarantee of a smart card is that **the private key never leaves the physical chip**.

### 2.1 The Myth of the 15-Minute Timer
Previous iterations debated whether PIN 1 should be cached for 15 minutes, 1 minute, or evicted immediately. In practice:
- If a card is resting in a reader or on a phone, an automated attacker with code execution on the host does not need 15 minutes—they can exploit the connected card in **15 milliseconds**.
- If the card is physically removed and placed back in the user's wallet or pocket, **an attacker can do nothing in 15 seconds or in 15 hours**. Without the physical silicon chip energized in the RF/contact field, the private key is physically unreachable.
- Evicting PIN 1 from secure local storage after an arbitrary countdown does not protect a connected card; it merely punishes the legitimate user who took a short coffee break by forcing them to re-type digits.

### 2.2 The Real-World Invariant: Detach the Card
The user discipline in RefineID is simple, physical, and absolute:
> **When you are done using your card, take it out of the reader or off the phone and put it in your wallet.**

The physical card detachment is the ultimate, unforgeable hardware air-gap.

---

## 3. PIN 1: Unattended, Seamless Web Authentication

PIN 1 protects the **Authentication Role** (identification, TLS client-certificate authentication, routine web logins).

### 3.1 Unattended Operation Model
- A user may explicitly choose to save PIN 1 in the device's hardware-backed secure store:
  - **iOS/macOS:** Apple Data Protection Keychain (`kSecAttrAccessibleWhenUnlockedThisDeviceOnly`, non-synchronizable, protected by Secure Enclave / Face ID / device passcode).
  - **Linux/BSD:** OS secret service / hardware keystore with user authorization.
  - **Windows:** Windows Credential Manager / DPAPI with user context isolation.
- There is **no arbitrary countdown timer** evicting PIN 1 from this store.
- When the user is sitting at their computer and clicks *"Log in with Identity Card"* on a website:
  - The click in the browser on the computer **is the human action and intent**.
  - If the card is present (in a reader or on the paired phone proxy) and PIN 1 is stored, the operation executes **unattended and seamlessly**.
  - Requiring a second, redundant "Approve" tap on a phone screen for every routine webpage login is security theater that adds friction without providing meaningful protection.

### 3.2 Invalidation Events
Stored PIN 1 is purged immediately upon:
- Explicit user deletion / logout;
- Card reporting a blocked, locked, or counter-decremented state;
- OS device lock or hardware container wipe.

---

## 4. PIN 2: Consequential Document Signing & Batch Flow

PIN 2 protects the **Qualified Signature Role** (creating Qualified Electronic Signatures / QES under eIDAS, with full legal equivalence to a handwritten signature).

### 4.1 No Silent Auto-Approvals
Unlike routine authentication, signing a document creates an irreversible, legally binding financial or legal commitment. A desktop application, browser tab, or malware must **never** be able to silently sign documents in the background without user awareness.

### 4.2 Solution A: Explicit Batch Signing
To completely eliminate prompt fatigue when signing multiple documents (e.g. 10 contracts or invoices) without sacrificing consent:
1. **Batch Request:** The requester submits a structured batch request containing the list of documents and their cryptographic digests:
   ```text
   Sign Batch: [ "Contract_Part1.pdf", "Contract_Part2.pdf", ... ] (10 documents)
   ```
2. **Single Batch Prompt on Proxy:** The phone displays the batch prompt, clearly showing the number of documents, the document names, and the requester identity.
3. **One PIN 2 Entry:** The user enters PIN 2 **once** for the entire batch.
4. **Sequential Card Execution:** The card signs each digest in the approved batch.
5. **Outcome:** Exactly **1 prompt** and **1 PIN entry** for 10 documents. Zero silent background execution, zero 10x typing friction.

---

## 5. RAPP Pairing: High Security with a 6-Digit Code (PAKE)

Pairing must be effortless for humans while cryptographically impenetrable to network eavesdroppers and untrusted relays.

### 5.1 No QR Code Gimmicks
RefineID prioritizes clean, accessible **6-digit numeric pairing codes** (formatted as two 3-digit groups: `123 456`) entered manually. QR codes are treated as optional shortcuts, never mandatory dependencies.

### 5.2 Elimination of Relay Brute-Force via PAKE
- Plain hashing of a 6-digit code (`SHA256(code)`) over an untrusted relay is vulnerable to instant offline dictionary attacks ($10^6$ combinations cracked in $<1\text{ ms}$ on a GPU).
- RAPP adopts **CPace (draft-irtf-cfrg-cpace-21, cipher suite `CPACE-RISTR255-SHA512`)** over Ristretto255 for 6-digit numeric pairing.
- **The PAKE Guarantee:** Mathematical immunity to offline dictionary attacks. The untrusted relay sees only uniform, random curve points. The relay learns zero bits of the PIN and cannot test guesses offline. An attacker can only test guesses through live, online attempts, which are strictly rate-limited and bounded by a short monotonic offer lifetime (60–120s).

### 5.3 Closing Local Network Backdoors
Pairing is an explicit, mutually authenticated ceremony. Direct unauthenticated LAN/mDNS record exchanges that automatically inject paired keys without user consent or pairing codes are prohibited.

---

## 6. Proportional Error Handling: No Nuclear Resets on Typos

Human users occasionally mistype digits. The security model must be resilient and forgiving of ordinary human error:
- A mistyped PIN or CAN fails the active transaction cleanly and reports the remaining card retry attempts.
- It **must not** trigger a nuclear response (destroying all stored pairings, wiping credentials, or factory-resetting the device).
- Permanent pairing tombstones and security shutdowns are reserved strictly for **hardware card lockouts** (retry counters reaching 0) or cryptographically verified protocol tampering.

---

## 7. Summary Matrix

| Domain | Mechanism | User Experience | Security Grounding |
| :--- | :--- | :--- | :--- |
| **Physical Security** | Card detachment | Card kept in wallet/pocket when idle | Hardware-level air gap; chip unpowered |
| **Authentication (PIN 1)** | Unattended Keychain store | Instant tap-and-go login from computer | Click on computer = user intent; no arbitrary timers |
| **Signing (PIN 2)** | Batch Signing (Solution A) | 1 PIN 2 entry per batch of documents | Conscious legal consent; zero prompt fatigue |
| **Relay Pairing** | CPace PAKE (draft-irtf-cfrg-cpace-21) | Clean 6-digit code (`123 456`) | Zero offline dictionary attacks; relay is blind |
| **Typo Resilience** | Proportional error return | Clean retry with counter feedback | Prevents self-inflicted Denial of Service |
