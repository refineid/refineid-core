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

The organization cards authenticate PACE with PIN 1 or PIN 2 in place of
the CAN (FINEID S1 v4.0, organizational cards, §2.1; FINEID S4-2 v4.0
§6). The PIN references are the card's own security-data-object
identifiers, the ones its VERIFY uses (FINEID S4-2 v4.0 §4.3).

The password never travels. Both sides derive the nonce key
`K_pi = SHA-256(password || 00000003)` (BSI TR-03110-3 §A.2.3), and the
password is encoded as its character string, one ISO/IEC 8859-1 octet
per character (table 5, appendix D.2.1.4). The CAN and a PIN are both
ASCII digits, which are their own ISO/IEC 8859-1 octets, so both are
encoded as the digits as they stand. A PIN's key is derived in
`refineid-auth`, which owns the digits; the handshake receives the key.

## A PIN password and the retry floor

A failed PACE with a PIN spends one of the PIN's tries. The organization
card takes the try at the first `GENERAL AUTHENTICATE` and gives it
back only when the handshake completes, so a handshake abandoned after
that command costs a try, observed on hardware. `MSE:Set AT`
answers with the PIN's state before any try is spent (BSI TR-03110-3
§B.14.1):

| Answer | Meaning | Handshake |
| --- | --- | --- |
| `9000` | the PIN has its initial tries, five on the organization card (FINEID S4-2 v4.0 §4.3) | served |
| `63C4`, `63C3` | four or three tries left | served |
| `63C2` | two tries left | refused |
| `63C1` | one try left; the PIN is suspended | refused |
| `63C0` | the PIN is blocked | refused |
| `6283` | the PIN is deactivated | refused |

The rule is `check_retry_floor` from `refineid-auth`, the one floor
every surface applies (see
[credential custody](../security/credential-custody.md)). On a refusal
nothing after `MSE:Set AT` is sent. A `63CX` answer to a `GENERAL
AUTHENTICATE` is a wrong PIN, reported with the tries left (BSI
TR-03110-3 §B.14.2).

PACE with a PIN is covered by scripted tests over all three curves.
The handshake with a CAN over brainpoolP384r1 on the citizen cards is
hardware-validated (see [core migration](../architecture/core-migration.md)).
On the organization card, over the contact interface, the EF.CardAccess
read, the choice of generic mapping over P-384, `MSE:Set AT` with PIN 1
and the two-block nonce are observed on hardware; a completed PACE with
a PIN, the NIST curve arithmetic against a card, and the EF.CardAccess
read on the citizen cards are not.
