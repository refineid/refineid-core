# PACE on FINEID cards

Every FINEID certificate card seals its applications behind PACE on the
contactless interface. `refineid-pace` runs one PACE mechanism,
`id-PACE-ECDH-GM-AES-CBC-CMAC-256` (generic mapping, AES-256 secure
messaging), and takes the password and the domain parameter from the
card in hand.

## The suite comes from EF.CardAccess

`read_card_access` selects EF.CardAccess in the master file and reads
its `SecurityInfos` (BSI TR-03110-3 §A.1.2.1, table 2). `CardAccess`
keeps the `PACEInfo` entries the crate implements: generic or
integrated mapping with AES-256, version 2, over a standardized domain
parameter of BSI TR-03110-3 table 4. Other entries -- chip-authentication
mapping, other ciphers, explicit domain parameters -- are skipped; a
malformed entry fails the parse. `run_pace` runs generic mapping over
the most preferred listed domain:

| Preference | Domain parameter | Table 4 identifier |
| --- | --- | --- |
| 1 | NIST P-384 (`secp384r1`) | 15 |
| 2 | brainpoolP384r1 | 16 |
| 3 | NIST P-256 (`secp256r1`) | 12 |

What the cards publish:

| Card | EF.CardAccess | Suite run |
| --- | --- | --- |
| Citizen cards | GM and CAM, AES-256, brainpoolP384r1 (FINEID S4-1 v4.2 §3.2) | GM over brainpoolP384r1 |
| Idemia Cosmo X organization card | GM and IM, AES-256, each over P-256 and P-384 (FINEID S4-2 v4.0 §6; the observed file lists these four entries) | GM over P-384 |

The curve arithmetic is the RustCrypto `p256`, `p384` and `bp384`
crates, with constant-time scalar multiplication.

## The nonce

The card chooses the length of its nonce `s`, a multiple of the cipher's
block size (ICAO Doc 9303 Part 11 §4.4.3.3), and sends it encrypted
under `K_pi` in CBC mode with the all-zero IV. The citizen cards send
one AES block; the Idemia Cosmo X organization card sends two, 32
bytes, observed on hardware. `run_pace` accepts one to four whole
blocks, decrypts every block, and maps with `s` read as a big-endian
integer reduced modulo the curve order: the generic mapping multiplies
the generator by `s` (§4.4.3.3.1), and `s * G` equals `(s mod n) * G`.
Any other length is refused before the next command.

## The password

`PacePassword` names the password, and `MSE:Set AT` its reference (BSI
TR-03110-3 §B.14.1):

| Card | Password | Reference |
| --- | --- | --- |
| Citizen cards | the Card Access Number printed on the card | 2 (CAN) |
| Organization cards | PIN 1 | 3, the PIN AUTH security data object |
| Organization cards | PIN 2 | 4, the PIN SIG security data object |
| Organization cards | the PUK | 18, the PIN PUK security data object (identifier `12`) |

The organization cards authenticate PACE with PIN 1 or PIN 2 in place of
the CAN (FINEID S1 v4.0, organizational cards, §2.1; FINEID S4-2 v4.0
§6), and with the PUK to set a blocked PIN (BSI TR-03110-3 §B.7.1,
§B.14.1). The references are the card's own security-data-object
identifiers, the ones its VERIFY uses (FINEID S4-2 v4.0 §4.2, §4.3);
the PUK has one only under the organization numbering. On the Idemia
Cosmo X organization card, `MSE:Set AT` naming the PUK reference over
GM-AES-256 and NIST P-384 answers `9000`, observed on hardware; a
neighbouring reference with the high bit set answers `6A88`.

The password never travels. Both sides derive the nonce key
`K_pi = SHA-256(password || 00000003)` (BSI TR-03110-3 §A.2.3), and the
password is encoded as its character string, one ISO/IEC 8859-1 octet
per character (table 5, appendix D.2.1.4). The CAN and a PIN are both
ASCII digits, which are their own ISO/IEC 8859-1 octets, so both are
encoded as the digits as they stand. A PIN's key is derived in
`refineid-auth`, which owns the digits; the handshake receives the key.

## The channel knows its password

`run_pace` returns a `PaceSession<O>`, and `SmTransport<T, O>` keeps
`O`, the proof of the password that opened the session: `OpenedByCan`,
`OpenedByPin1`, `OpenedByPin2` or `OpenedByPuk`. Only the handshake mints one, and the
session is not clonable, so the proof cannot be copied or relabelled.
The organization card counts the PACE password verified on the channel
(FINEID S4-2 v4.0 §6), observed on hardware for both PINs. A channel PIN
2 opened therefore reaches the qualified-signature key without a VERIFY
(`refineid-sign`, `qualified_key_after_pin2_pace`). Its proof carries
one PIN 2 presentation, spent by the one qualified key it unlocks and
kept spent across `into_parts` and `SmTransport::new`: PIN 2 is entered
for every signature (FINEID S4-1 v4.2 §4.1, §8.1.7), so a second
signature on the channel takes a VERIFY.

## PIN management on a PUK or PIN 1 channel

On the contactless interface the organization card answers nothing
before PACE, and its PINs ship blocked (FINEID S4-1 v4.2 §4.6.1), so
PACE with the PUK is the one way to activate or unblock it there. BSI
TR-03110-3 §B.7.1 has the terminal unblock or change the PIN after PACE
with the PUK or the PIN by RESET RETRY COUNTER carrying only the new PIN
(§B.14.11). FINEID S4-2 v4.0 §4.3 states the reset's contactless access
condition as the PUK's security environment together with PACE, and the
change's as PACE alone with the current PIN in the command (IAS ECC
v1.0.1 §9.4.2 allows no other form). Whether the card counts a completed
PACE with the PUK, or with PIN 1, as the authorisation its reset needs is
not stated, so each operation takes `ChannelProof`, named at every call:

| Operation | Channel | `PaceHandshake` | `PresentAgain` |
| --- | --- | --- | --- |
| `reset_pin1_after_puk_pace`, `reset_pin2_after_puk_pace` | `OpenedByPuk` | RESET RETRY COUNTER with the new PIN only | VERIFY the PUK (`12`), then the same reset |
| `change_pin1_after_pin1_pace` | `OpenedByPin1` | RESET RETRY COUNTER with the new PIN only | CHANGE REFERENCE DATA with the current and new PIN |

`PaceHandshake` presents no credential and spends no try; a card that
does not count the handshake answers it with a refusal such as `6982`.
`PresentAgain` presents the credential under the retry floor. Its input
is the channel's own record of the counter, because the counter-safe
empty VERIFY is not answered with a counter over secure messaging on
this card: the record starts at the `MSE:Set AT` answer the floor
served, every refusal lowers it, nothing raises it, and an answer whose
effect is unknown ends presentations on the channel. Only the channel
the matching password opened has these methods.

On the Idemia Cosmo X organization card, contactless, observed on
hardware: both resets are accepted under `PaceHandshake`, and the PUK's
counter is unchanged afterwards. The PIN 1 change under `PaceHandshake`
is refused with `6982` and accepted under `PresentAgain`; the PIN 1
counter is unchanged after either. A caller resets with `PaceHandshake`
and changes PIN 1 with `PresentAgain`. PIN 2's reset needs DF.ESIGN
selected, where its reference is local.

## A PIN or PUK password and the retry floor

A failed PACE with a PIN spends one of the PIN's tries, and with the
PUK one of the PUK's, whose exhaustion cannot be recovered. The organization
card takes the try at the first `GENERAL AUTHENTICATE` and gives it
back only when the handshake completes, so a handshake abandoned after
that command costs a try, observed on hardware. `MSE:Set AT`
answers with the PIN's state before any try is spent (BSI TR-03110-3
§B.14.1):

| Answer | Meaning | Handshake |
| --- | --- | --- |
| `9000` | the credential has its initial tries, five for each PIN and the PUK on the organization card (FINEID S4-2 v4.0 §4.3) | served |
| `63C4`, `63C3` | four or three tries left | served |
| `63C2` | two tries left | refused |
| `63C1` | one try left; the PIN is suspended | refused |
| `63C0` | the PIN is blocked | refused |
| `6283` | the PIN is deactivated | refused |

The rule is `check_retry_floor` from `refineid-auth`, the one floor
every surface applies (see
[credential custody](../security/credential-custody.md)). On a refusal
nothing after `MSE:Set AT` is sent. A `63CX` answer to a `GENERAL
AUTHENTICATE` is a wrong PIN or a wrong PUK, reported with the tries
left (BSI TR-03110-3 §B.14.2).

PACE with a PIN is covered by scripted tests over all three curves.
The handshake with a CAN over brainpoolP384r1 on the citizen cards is
hardware-validated (see [core migration](../architecture/core-migration.md)).
On the organization card, over the contact interface, the EF.CardAccess
read, the choice of generic mapping over P-384, `MSE:Set AT` with PIN 1
and the two-block nonce are observed on hardware; a completed PACE with
a PIN, the NIST curve arithmetic against a card, and the EF.CardAccess
read on the citizen cards are not. A completed PACE with the PUK has not
run on hardware; it is covered by scripted tests.
