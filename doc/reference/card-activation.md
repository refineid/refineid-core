# Card activation

How a FINEID card waiting to be taken into use is recognised and
activated, and which signals decide it. Activation happens once in a
card's life, so every rule below is about never guessing.

## The two citizen schemes

FINEID S4-1 v4.2 §4.6 defines two procedures:

| Scheme | Cards | Factory state | Activation |
| --- | --- | --- | --- |
| §4.6.1, activation code is the PUK | issued before 13 January 2026 | PIN 1 and PIN 2 blocked | RESET RETRY COUNTER with the 8-digit code (the PUK) for each PIN |
| §4.6.2, preset activation PIN | issued from 13 January 2026 | PIN 1 and PIN 2 set to one 7-digit activation PIN | CHANGE REFERENCE DATA from the activation PIN for each PIN |

The wrong digit count burns a try, and the wrong command is refused, so
the scheme must be known before the form opens.

## What decides the scheme

**The authentication certificate's validity start, and nothing else.**
DVV names the cutover by date; a certificate issued from 13 January 2026
is §4.6.2, one issued before it §4.6.1. An organizational issuer, or a
certificate whose validity start cannot be read, gives no scheme and no
activation decision.

Signals that do **not** decide it, each disproven by a real card:

| Signal | Why it fails |
| --- | --- |
| Chip generation in the ATR or NFC historical bytes | DVV H6 cards (produced 2023 – mid 2025, §4.6.1) and H8 cards (2026, §4.6.2) are both Thales MultiApp v5.0 with the same ATR |
| Certificate key family / issuer suffix ("…E" for ECC, "…R" for RSA) | H6 cards carry ECC certificates from an "…E" issuer and still use §4.6.1 |
| Issuer name containing "Organisational" | test organization cards are issued by "DVV TEST Certificates - G5R", the same naming as citizen cards |

## Whether a PIN still awaits activation

Judged per PIN, because an interrupted activation leaves one PIN set and
the other waiting.

- The **PIN changed flag** (GET DATA PIN container, FINEID S1 v4.2
  §3.15.3) decides under both schemes: unchanged means the PIN awaits
  activation, changed means the holder has set it.
- A §4.6.1 PIN blocked at the factory answers the counter-safe VERIFY
  probe with an exhausted counter (`63C0`, "0 tries left"), not only with
  "blocked" (`6983`); both mean the same here.
- When the flag cannot be read, §4.6.1 falls back to the counter: a
  blocked, invalidated or exhausted PIN awaits activation (the same PUK
  reset recovery would send). §4.6.2 makes no activation decision without
  the flag.

## Organization cards

Observed on a DVV O6 organization card (Idemia Cosmo X, see
[supported cards](supported-cards.md)):

- The card answers the citizen PIN reference with "reference data not
  found" and the FINEID S4-2 v4.0 §4.2 references (PIN 1 `03`, PIN 2
  `04`, PUK `12`), so the reference numbering resolution identifies it
  as an organization card. Its EF.TokenInfo label reads
  "Organisaatiokortti" (citizen cards: "HENKILOKORTTI").
- Activation follows the §4.6.1 procedure under the organization
  numbering: the 8-digit activation code from the letter is the PUK, and
  RESET RETRY COUNTER sets PIN 1 and PIN 2. Both PINs ship blocked
  (`63C0`), the PUK has 5 tries, and the PIN changed flag cannot be read,
  so the counter fallback above applies.
- The organization numbering, not the certificate date or issuer name,
  is what makes a card an organization card.

## PIN lengths

The card's PKCS#15 EF.AOD (`4401`) gives each PIN's minimum and maximum
length, and it is the authority: the O6 organization card's EF.AOD lists
PIN 1 as 4–12 digits, where FINEID S4-2 v4.0 tables say 4–8. EF.AOD is
read only where PINs are set (activation, change, reset); signing and
login never need it.
