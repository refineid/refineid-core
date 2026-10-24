# Credential custody

This is the contract for PIN-bearing code. The public tree implements the
refined input types, the credential-command ownership types, and the PKCS#11
module's held PIN1 (`crates/pkcs11/src/pin_cache.rs`), which follows the rules
below.

See also [Security and Usability Balance](security-and-usability-balance.md) for
the architectural consensus on unattended PIN 1 authentication and explicit
batch signing for PIN 2.

## PIN2: every signature or batch

FINEID S4-1 v4.2 sections 4.1 and 8.1.7 require manual PIN entry for every
qualified-signature operation. PIN2 is entered for every signature, or once
for a batch the holder sees whole (RAPP v26.10.22 section 9.3); it is carried
only through that batch's signatures and destroyed at its end. It is never
kept between operations.

Each use is still reconstructed as `Pin2`, consumed by an at-most-once
credential command, and zeroized on every success or error path. PIN2 must
never be clonable, serializable, persisted, placed on a command line, stored
in an environment variable, or rendered by `Debug`, tracing, panic, or error
output.

## PIN1 authentication: held until the card leaves

FINEID S4-1 v4.2 sections 4.1 and 8.1.7 require user interaction and manual
PIN1 entry for every authentication-key signing operation. RefineID's explicit
product decision is to provide a convenience exception for PIN1
authentication operations, bounded by the card's presence, including TLS
client-auth signatures driven by CryptoTokenKit. The software re-presents PIN1
to the card for every operation; it does not treat card verification state as
persistent. This exception must be disclosed as a profile deviation in public
release documentation. It never extends to PIN2 or either qualified-signature
key. The current specification is published on the
[DVV FINEID specifications page](https://dvv.fi/en/fineid-specifications).

PIN1 is held in process memory from the first card-confirmed successful use
until one of the invalidation events below; there is no idle window or
countdown. It is never written to storage -- not to a keychain, a keystore, a
credential manager or a file -- so it never survives a restart (RAPP v26.10.22
section 11 item 2).

Reusable retention is allowed only when every live credential retry counter is
in its pristine state. The held entry is bound to the complete card token
identifier and the PIN1 authentication role. Its capability excludes PIN
management, PIN2, and qualified-signature operations.

Use is destructive checkout:

1. atomically remove the entry from the held state;
2. attempt one credential operation; and
3. restore it after the card confirms success, or after a transport failure
   or an unanswered command once the retry counter shows the card did not
   refuse it.

Dropping an in-flight checkout or losing the caller destroys the value rather
than resurrecting it. NFC glitches are common and are not removal, so a
transport failure keeps the value; the retry counter read before the next use
decides: a counter below the one read before the failed attempt means the card
refused the PIN, and the value is destroyed instead of sent again.

## Mandatory invalidation

Held PIN1 is destroyed on:

- card removal -- the card leaving the reader, or its holder removing it from
  the phone -- and token-identifier mismatch; on a PC/SC reader a card that
  left and came back between two uses is seen through the reader's card
  insertion and removal count, read in the card session of every use and
  compared with the count read when the card accepted the value;
- a wrong, blocked or malformed PIN response, or a retry counter that went
  down;
- process exit, device restart, or the user clearing it; and
- retry-counter state below pristine or unavailable counter state.

PIN2 is never held between operations, so it has nothing to invalidate.

Process-lifetime memory of card-rejected candidates may retain only a keyed,
constant-time-comparable fingerprint bound to the full card identifier and PIN
role. It must not retain the PIN or a reversible value. This negative memory is
not persisted.

## Card Access Number custody

The CAN is a different credential class from the PINs: printed on the card
face, it authenticates the terminal's visual access to the card, not the
user, and a wrong value costs a failed PACE handshake, not a retry counter.
Its threat model is the contactless attacker in radio range without sight
of the card -- for whom a software leak (a log line, a trace, a crash
report) is the only route to the value. Custody therefore still applies in
full: `Can` is non-clonable, zeroizing, redacted, and exports no raw value.

Remembering a CAN across sessions in an operating-system keystore, under
user consent, is a legitimate product choice for this class. Persistence
happens upstream of the border, never through it: the input surface that
collected the digits stores its own copy at collection time, and a keystore
read is another input surface -- its bytes re-enter through
`UnvalidatedCan` and `Can::reconstruct`, which rejects a corrupted or
foreign value. The sealed type never grows an export path to serve
storage; a client that needs the digits at some point keeps them upstream
of that point.

## Representation and transport

- Secret fields are private and zeroize on drop.
- PIN role types do not implement `Clone`, `Copy`, serialization, or raw
  `Debug`.
- Errors carry shape and state, never a rejected byte or credential value.
- A credential APDU is a separate zeroizing type, consumed by a transport API
  that cannot replay it.
- APDU tracing classifies and redacts before any hexadecimal formatting or sink
  call.
- UI entry uses an operating-system secure text field. CLI entry is echo-off
  and reads from a terminal, never argv or the environment.

These rules are release gates, not best-effort guidance.
