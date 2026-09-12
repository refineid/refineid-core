# Credential custody

This is the target contract for PIN-bearing code. The public tree currently
implements the refined input types and the credential-command ownership types;
it does not yet build a credential APDU flow or cache a PIN.

## PIN2 qualified-signature convenience window

FINEID S4-1 v4.2 sections 4.1 and 8.1.7 require manual PIN entry for every
qualified-signature operation. RefineID's explicit product decision is to give
PIN2 a bounded one-minute convenience window so that one signing session --
for example, a document set signed in a single user action -- does not prompt
for every signature. This exception must be disclosed as a profile deviation
in public release documentation.

The default maximum is a one-minute idle window measured by a monotonic clock
from the last card-confirmed successful use. The cache design constraints,
destructive-checkout discipline, and mandatory invalidation triggers defined
below for PIN1 apply to PIN2 identically; only the window length differs. The
cached entry is bound to the complete card token identifier and the PIN2
qualified-signature role. Its capability excludes PIN management and every
PIN1 operation.

Each use is still reconstructed as `Pin2`, consumed by an at-most-once
credential command, and zeroized on every success or error path. PIN2 must
never be clonable, serializable, persisted, placed on a command line, stored
in an environment variable, or rendered by `Debug`, tracing, panic, or error
output.

## PIN1 authentication convenience window

FINEID S4-1 v4.2 sections 4.1 and 8.1.7 require user interaction and manual
PIN1 entry for every authentication-key signing operation. RefineID's explicit
product decision is to provide a bounded convenience exception for PIN1
authentication operations, including TLS client-auth signatures driven by
CryptoTokenKit. The software re-presents PIN1 to the card for every operation;
it does not treat card verification state as persistent. This exception must be
disclosed as a profile deviation in public release documentation. It never
extends to PIN2 or either qualified-signature key; PIN2 has its own, shorter
window above. The current specification is published on the
[DVV FINEID specifications page](https://dvv.fi/en/fineid-specifications).

The default maximum is a 15-minute idle window measured by a monotonic clock
from the last card-confirmed successful use. It is not a wall-clock lifetime
from entry and it is not refreshed by checkout, prompt display, local parsing,
or a failed operation. A host with a scheduler actively releases the resident
entry at the deadline; every lookup independently rejects an expired entry.

Reusable retention is allowed only when every live credential retry counter is
in its pristine state. The cached entry is bound to the complete card token
identifier and the PIN1 authentication role. Its capability excludes PIN
management, PIN2, and qualified-signature operations.

Use is destructive checkout:

1. atomically remove the entry from the cache;
2. attempt one credential operation;
3. restore it only after the card confirms success; and
4. set `last_successful_use` to that confirmed monotonic instant.

Dropping an in-flight checkout, receiving a card error, or losing the caller
must destroy the value rather than resurrect it.

## Mandatory invalidation

Positive PIN1 or PIN2 state is destroyed on:

- card removal, reader loss, or token-identifier mismatch;
- wrong-PIN, blocked-PIN, malformed-response, or transport failure;
- screen lock, logout, process exit, system sleep, or explicit lock;
- retry-counter state below pristine or unavailable counter state; and
- any generation change while a checked-out value is in flight.

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
