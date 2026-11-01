# refineid-auth

Reviewed FINEID PIN role types and verification.

Raw input exists only in `UnvalidatedSecret`; consuming construction
validates once and reconstructs the non-clonable, zeroizing `Pin1` and
`Pin2` role types. `verify_pin1` and `verify_pin2` consume a validated
PIN through a crate-private path, pad it to the stored length on a
citizen card, and ship it only as a credential command, consumed exactly once; the slot is
fixed by the argument type. The counter-safe status probe reads the
retry state without spending a counter, and `check_retry_floor` serves a
PIN 1, PIN 2 or PUK attempt only at five, four or three tries left -- the
one floor every surface stops at. Setting a new PIN with the PUK is gated
by the PUK's own counter, not the target PIN's.

Both citizen and organizational cards are supported.
`resolve_pin_reference_scheme` settles which credential numbering the card
uses with the counter-safe probe, and the `_with_scheme` entry points act
under an already-resolved numbering. The organizational card compares the
typed PIN at its own length under its own references, with no padding.
Organization PINs have the same bounds as citizen PINs -- PIN 1 4–12
digits, PIN 2 6–12 -- held by the `Pin1` and `Pin2` role types, so a PIN
outside them is refused at construction, before any command.

`PinManageOps` adds the card-mutating chains: `change_pin1`/`change_pin2`
(CHANGE REFERENCE DATA) and `unblock_pin1`/`unblock_pin2` (RESET RETRY
COUNTER). Unblocking presents a `Puk` -- its own non-clonable,
zeroize-on-drop role type, which never authorises an operation and spends
its own counter. Every unblock, and an activation that presents the
activation code as the PUK, reads the PUK's counter first and refuses
below the floor before anything carrying the PUK is sent. The citizen
card unblocks in one command; the
organizational card verifies the PUK as its own object and then resets
with only the new PIN. A wrong current PIN or PUK is reported as a typed
outcome, not an error.

No verification, change, or unblock path is described as working against a
real card until it is observed on hardware with the retry counter checked.
The change and unblock chains are card-mutating and PUK-consuming -- and
exhausting the PUK is terminal -- so they are not run to exhaustion on
hardware and rest on the specification and the behaviour reference. The
organizational numbering resolution is observed on an Idemia Cosmo X
organization card.

Constants are traced to the
[DVV FINEID specifications](https://dvv.fi/en/fineid-specifications) (S1
sections 3.5, 3.11, and 3.12, and S4-2) and ISO/IEC 7816-4 and -8. See the
repository's
[credential custody contract](../../doc/security/credential-custody.md).
