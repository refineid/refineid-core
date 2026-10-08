# RAPP v26.10.1 Implementation Notes

- **Status**: Informative. These notes do not amend `rapp-v26.10.1.md` or
  `rapp-transport-and-discovery-hierarchy.md`; a later stamped revision of
  those documents supersedes them.
- **Applies To**: `crates/rapp` and the independent Swift engine in
  `refineid-apple`, which agree on every point below.

The protocol document leaves a few points open or inconsistent. This file
records how the reference implementations resolve each one, so that every
peer resolves it the same way until a stamped revision settles it.

## 1. Offer bootstrap outside BLE

Section 4.2 defines the offer bootstrap only over the BLE Bootstrap
Characteristic and requires that `offer_id` is not derived from the pairing
code. The stream and Apple-peer tiers have no bootstrap.

On those tiers both peers derive the offer from the pairing code
(`derive_manual_offer_id`). Because a code-derived value would let a listener
search the code space offline, nothing derived from the code or the offer is
published: the pairing-mode advertisement carries only `v=1` and
`mode=pairing` under a fresh random instance name. The `offer=` TXT
attribute of hierarchy section 4.3 is not published. As written it also
describes a 16-byte identifier, while `offer_id` is 32 bytes.

## 2. CPace context on transports other than BLE

Section 6.1.1 fixes the context literals `fi.refineid.rapp.ble.v1` and
`ble-direct-1`. The CPace context binds these literals on every transport.
The Noise_XXpsk3 pairing prologue binds the transport profile actually in
use.

## 3. Error vocabulary

The section 10.4 table does not register every name the text uses. The
implementations send:

| Situation | Status | `error` |
| :--- | :--- | :--- |
| Blocked credential (section 10.2) | `credential_rejected` | `card_blocked` |
| Zero `expires_after_ms` (section 8.2.1) | `rejected` | `invalid_lifetime` |
| Retry floor refusal, zero or unreadable counter (section 10.3) | `rejected` | `operation_failed` |

A second request while one operation is live, the "busy session" of section
7.1, is refused with the `error` message named `operation_failed` (code
1010). A received `error_name` outside the table is handled as
`operation_failed`, as section 10.4 requires.

## 4. Close reason for a lost card

`close-reason-val` has no reason for a custodian that can no longer serve
the card. Such a custodian closes the session with `policy`.

## 5. Signature algorithms

Section 9.2 registers `ecdsa_sha256` and `rsa_pkcs1_sha256` only. A P-384
card that signs a TLS 1.3 handshake needs a SHA-384 digest, so custodians
also accept the earlier registry's `ecdsa_sha224`, `ecdsa_sha384`,
`ecdsa_sha512`, `rsa_pkcs1_sha384`, `rsa_pkcs1_sha512` and `rsa_pss_sha256`,
each with the digest length its hash fixes. Requesters send a section 9.2
name whenever the key and the relying party allow it.

## 6. `inspect_card` response fields

Section 9.1 lists `card_present`, `atr` and `supported_profiles`. The
implementations add `pin1_factory`, `pin2_factory`, `pin1_attempts`,
`pin2_attempts` and `puk_attempts` (an absent counter is `null`). A receiver
reads the section 9.1 fields and treats the others as optional.

The operation-message corpus `vectors/rapp-operation-v26.10.1.json` pins the
bytes of points 3 and 6.
