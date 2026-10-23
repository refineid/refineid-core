# refineid-auth

Reviewed FINEID PIN role types and verification.

Raw input exists only in `UnvalidatedSecret`; consuming construction
validates once and reconstructs the non-clonable, zeroizing `Pin1` and
`Pin2` role types. `verify_pin1` and `verify_pin2` consume a validated
PIN through a crate-private path, pad it to the stored length, and ship
it only as a credential command, consumed exactly once; the slot is
fixed by the argument type. The counter-safe status probe reads the
retry state without spending a counter, and the retry-risk policy maps
the live counter to the safety floors different surfaces stop at.

Both citizen and organizational cards are supported.
`resolve_pin_reference_scheme` settles which credential numbering the card
uses with the counter-safe probe, and the `_with_scheme` entry points act
under an already-resolved numbering. The organizational card compares the
typed PIN at its own length under its own references, with no padding, and
a PIN longer than the organizational maximum is refused locally before any
command spends a retry.

`PinManageOps` adds the card-mutating chains: `change_pin1`/`change_pin2`
(CHANGE REFERENCE DATA) and `unblock_pin1`/`unblock_pin2` (RESET RETRY
COUNTER). Unblocking presents a `Puk` -- its own non-clonable,
zeroize-on-drop role type, which never authorises an operation and spends
its own counter. The citizen card unblocks in one command; the
organizational card verifies the PUK as its own object and then resets
with only the new PIN. A wrong current PIN or PUK is reported as a typed
outcome, not an error.

No verification, change, or unblock path is described as working against a
real card until it is observed on hardware with the retry counter checked.
The change and unblock chains are card-mutating and PUK-consuming -- and
exhausting the PUK is terminal -- so they were not run to exhaustion on
hardware; together with the organizational numbering, which no card was
available to exercise, they rest on the specification and the behaviour
reference.

Constants are traced to the
[DVV FINEID specifications](https://dvv.fi/en/fineid-specifications) (S1
sections 3.5, 3.11, and 3.12, and S4-2) and ISO/IEC 7816-4 and -8. See the
repository's
[credential custody contract](../../doc/security/credential-custody.md).
