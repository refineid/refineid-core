# Card activation

How a FINEID card waiting to be taken into use is recognised and
activated, and which signals decide it. Activation happens once in a
card's life, so every rule below is about never guessing.

## The two citizen schemes

FINEID S4-1 v4.2 §4.6 defines two procedures:

| Scheme | Cards | Factory state | Activation |
| --- | --- | --- | --- |
| §4.6.1, activation PIN is the PUK | issued before 13 January 2026 | PIN 1 and PIN 2 blocked | RESET RETRY COUNTER with the 8-digit code (the PUK) for each PIN |
| §4.6.2, preset activation PIN | issued from 13 January 2026 | PIN 1 and PIN 2 set to one 7-digit activation PIN | CHANGE REFERENCE DATA from the activation PIN for each PIN |

The wrong digit count burns a try, and the wrong command is refused, so
the scheme must be known before the form opens.

Under both schemes the credential in the activation letter carries
DVV's official name from the letters: "Activation PIN", Finnish
"aktivointitunnusluku", Swedish "aktiveringskod". User-facing text uses
these terms for either scheme.

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
  numbering: the 8-digit activation PIN from the letter is the PUK, and
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

The card is the authority on its PIN and PUK lengths. The `Pin1` and
`Pin2` role types accept 4–12 digits and `Puk` 8–12: every length a
FINEID card may list, up to the 12-digit stored length the commands
carry. Signing and login do not read the card's lengths, so they send any
4–12-digit PIN 1 or PIN 2 to the card, which decides. Organization PINs
are sent as the bare typed digits, with no padding.

Where PINs are set -- activation, change and reset -- the card's lengths
are read once per session with `PinManageOps::read_card_pin_lengths`:

1. **EF.AOD** (`4401`, FINEID S4-1 v4.2 §8.1.5; FINEID S4-2 v4.0
   §4.6.10, §4.7.10) is the authority. Each password object's
   `pwdReference` is mapped to PIN 1, PIN 2 or the PUK under the card's
   resolved numbering, with or without the local high bit; a reference
   no numbering uses is not consulted, and a credential listed twice is
   not listed. The range is `minLength` to `maxLength`, or to
   `storedLength` when `maxLength` is absent.
2. **The PIN policy** in the GET DATA PIN container (FINEID S1 v4.2
   §3.15.3, minimum and maximum each within 4–64) is read only on a
   citizen card, and only for a credential EF.AOD does not list. The
   organization card answers `6A86` to that GET DATA and is not asked.
3. **The FINEID bounds** -- PIN 1 4–12 digits, PIN 2 6–12, PUK 8–12
   (FINEID S4-1 v4.2 §4.1, §8.1.5) -- apply to a credential neither
   source lists, including when EF.AOD cannot be selected, read or
   decoded.

A listed range is used as the card lists it, within what the role type
carries: a listed maximum above 12 is taken as 12, and a listed minimum
below the role type's minimum as that minimum. A card listing PIN 1 up
to 8 digits takes 4–8; a card listing PIN 2 from 4 digits takes 4–12.
The change, unblock and activation operations check every entry -- the
current PIN, the PUK, the activation PIN in the role it is presented
as, and each new PIN -- against these lengths before any command.

The Idemia Cosmo X organization card's EF.AOD lists PIN 1
("perustunnusluku") with `minLength` 4, `storedLength` 12, `maxLength`
12 and `pwdReference` 3, so its PIN 1 takes 4–12 digits. DVV's
organization card letter gives PIN 1 4–12 and PIN 2 6–12, where the
FINEID S4-2 v4.0 tables say 4–8 for PIN 1.
