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

The card's credential numbering first, then the authentication
certificate's validity start:

1. **Organization numbering** (FINEID S4-2 v4.0 §4.2, see
   [organization cards](#organization-cards)) means §4.6.1, whatever the
   certificate date.
2. **Citizen numbering** (FINEID S1 v4.2): the authentication
   certificate's validity start decides. DVV names the cutover by date; a
   certificate valid from 13 January 2026 is §4.6.2, one valid from
   before it §4.6.1.
3. A citizen-numbered card whose validity start cannot be read gives no
   scheme and no activation decision.

`refineid_auth::ActivationScheme::from_numbering_and_validity_start`
takes the resolved `PinReferenceScheme` and the validity start (epoch
seconds, `None` when unread) and returns the scheme or `None`; it is the
one place the decision is made. `PinManageOps::probe_credential_health`
takes the validity start, resolves the numbering, and reports the
decided scheme with the activation needs under it. An `ActivationCode`
is validated against a scheme and carries it, so
`PinManageOps::activate_card` runs the command chain of the scheme its
digit count was checked for.

Signals that do **not** decide it, each disproven by a real card:

| Signal | Why it fails |
| --- | --- |
| Chip generation in the ATR or NFC historical bytes | Thales MultiApp v5.0 citizen cards issued before 13 January 2026 (§4.6.1) and from that date (§4.6.2) present the same ATR |
| Certificate key family / issuer suffix ("…E" for ECC, "…R" for RSA) | Thales MultiApp v5.0 citizen cards issued before 13 January 2026 carry ECC certificates from an "…E" issuer and use §4.6.1 |
| Issuer name containing "Organisational" | test organization cards are issued by "DVV TEST Certificates - G5R", the same naming as citizen cards |

## Whether a PIN still awaits activation

Judged per PIN, because an interrupted activation leaves one PIN set and
the other waiting.

- The **PIN changed flag** (GET DATA PIN container, FINEID S1 v4.2
  §3.15.3) decides under both schemes: unchanged means the PIN awaits
  activation, changed means the holder has set it.
- The flag is optional: the card returns it only if "Return PIN changed
  flag" was set when the applet was personalized (FINEID S1 v4.2
  §3.15.2, §3.15.3). A card without it is judged by the counter fallback
  below.
- A §4.6.1 PIN blocked at the factory answers the counter-safe VERIFY
  probe with an exhausted counter (`63C0`, "0 tries left"), not only with
  "blocked" (`6983`); both mean the same here.
- When the flag cannot be read, §4.6.1 falls back to the counter: a
  blocked, invalidated or exhausted PIN awaits activation (the same PUK
  reset recovery would send), and a usable or verified PIN does not.
- When the flag cannot be read under §4.6.2, no activation decision is
  made: `pin_awaits_activation` answers `false` whatever the counter, so
  the activation PIN is never presented to a PIN the holder may already
  have set.

## Organization cards

Observed on an Idemia Cosmo X organization card (see
[supported cards](supported-cards.md)):

- The card answers the citizen PIN reference with "reference data not
  found" and the FINEID S4-2 v4.0 §4.2 references (PIN 1 `03`, PIN 2
  `04`, PUK `12`), so the reference numbering resolution identifies it
  as an organization card. Its EF.TokenInfo label reads
  "Organisaatiokortti" (citizen cards: "HENKILOKORTTI").
- Activation follows the §4.6.1 procedure under the organization
  numbering: the 8-digit activation code from the letter is the PUK, and
  RESET RETRY COUNTER sets PIN 1 and PIN 2. Both PINs ship blocked
  (`63C0`) and the PUK has 5 tries. The card does not support the
  FINEID S1 GET DATA PIN container: it answers `6A86` under every
  organization and citizen PIN reference, so the PIN changed flag is not
  available and the counter fallback above applies.
- The organization numbering, not the certificate date or issuer name,
  is what makes a card an organization card.
- No FINEID S1 document for the Idemia Cosmo X is published: the DVV ATR
  technology note names "FINEID S1 v5.0" for it, and the newest published
  FINEID S1 is v4.2, for citizen cards. The card itself -- its EF.AOD and
  the counter-safe probes -- is the authority for this card.
- The published FINEID S1 v4.0 for organizational cards covers the Idemia
  ID.me IDeal Citiz 2.17-i, not the Cosmo X. On those cards PACE
  authenticates the holder with PIN 1 or PIN 2 instead of the CAN
  (FINEID S1 v4.0, organizational cards, §2.1).

## PIN lengths

Organization PINs follow the same bounds as citizen PINs: PIN 1 is 4–12
digits and PIN 2 is 6–12. They are sent as the bare typed digits, with
no padding. The Idemia Cosmo X organization card's EF.AOD lists PIN 1
as 4–12 digits, where FINEID S4-2 v4.0 tables say 4–8, and DVV's
organization card letter gives PIN 1 4–12 and PIN 2 6–12.

The card's PKCS#15 EF.AOD (`4401`) gives each PIN's minimum and maximum
length, and it remains the authority. The GET DATA PIN container also
carries a PIN policy with the minimum and maximum length (each within
4–64) and the try limit (FINEID S1 v4.2 §3.15.3). Reading them where
PINs are set (activation, change, reset) is planned work; signing and
login never need them.
