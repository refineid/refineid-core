# Certificate custody

This is the contract for code that keeps a certificate read from the
card. It is a settled product decision of 2026-11-07, recorded here so
that every platform follows the same rule and a review that proposes
another is answered by reference to this document. Secrets are the
subject of [credential custody](credential-custody.md); certificates are
not secrets, but some of them are personal data, and this document says
what each platform may keep of them, where, and for how long.

The card carries three kinds of certificate: the holder's own
(authentication in EF.4331, qualified signature in EF.4332, the
alternative authentication certificate in EF.4333), the issuing CA that
signed them (EF.4336), and the root the issuing CA chains to (EF.4334).
The issuing CA and the root are public certificates that every card of
the same generation carries; the holder's certificates carry the
holder's name and electronic identification number.

## CA certificates: cached until they expire

The issuing CA and the root are cached on every platform until their own
validity ends, in storage only the owner can read (the per-user cache
directory on Unix with owner-only modes, the keychain on Apple
platforms, the application's private storage on Android), and purged
when they expire. They are read from the card only when the cache holds
no unexpired issuer for the chain at hand, or when a chain cannot be
built from what the cache holds. In particular, priming a card over NFC
reads no CA certificate while the cache holds an unexpired issuer for it.

Nothing of these certificates is personal, so the cache has no retention
bound shorter than the certificates' own lives. A certificate the card
supplies is admitted to the cache only when it is a CA certificate within
its validity and, for a root, self-signed and the verified issuer of the
issuing CA beside it. Privileged processes (a PAM module, a display
manager, anything running as root) read from the card and write no
cache.

## Personal certificates: memory only, one bounded exception

The holder's certificates are held in memory while the card is in the
reader or the phone session is open, and dropped when the card leaves,
the session ends or the process exits. No platform writes them to any
store that survives the process, with one exception.

The exception is the pairing record of a computer paired with a phone
(RAPP). A browser asks the PKCS#11 token for certificates at its first
TLS handshake, and a browser offered none resumes that handshake and
never asks again, so the identity must be offered before the phone has
answered. The record therefore keeps the paired card's authentication
certificate, under these bounds:

- a computer holds at most one pairing per operating-system user, and
  pairing another phone replaces it, so the record never accumulates a
  history of people;
- the certificate is dropped from the record after 7 days without a
  session (`CERTIFICATE_RETENTION_DAYS`), while the pairing itself lives
  on to the protocol's 30-day expiry and the certificate is read again
  from the phone at the next session;
- the record is erased when the holder forgets the pairing, when the
  pairing is revoked, and when it expires.

The reason for the bound is the shared computer: nobody should be able
to read from it who has ever used an identity card there. Seven days
keeps the browser working for a card in weekly use and leaves nothing
behind for one that is not.

## What the card is asked for

A session that has unexpired CA certificates cached and, for a paired
phone, the authentication certificate in the record, reads no
certificate from the card until an operation needs one the cache lacks.
A signature always reads what it signs with from the card; the
certificate it embeds is the one the card holds at that moment, never a
cached copy.
