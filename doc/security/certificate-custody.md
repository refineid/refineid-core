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

## Personal certificates: memory only, no exception

The holder's certificates are on a computer only while the card is in a
reader there or the paired phone is reachable. They are held in memory,
and dropped when the card leaves, when the phone is no longer reachable
or its session's grace ends (RAPP v26.11.8 section 8.4 item 3), and when
the process exits. No platform writes them to any store that outlives
that: no file, no keychain item, no pairing record, no cache. There is
no exception.

A browser asks a PKCS#11 token for certificates at its first TLS
handshake and does not ask again, so a token for a paired phone that
holds no certificate yet wakes the phone and waits a bounded time for a
session to read one. It never offers a stored copy instead.

The owner decided this on 2026-11-08, replacing a 7-day retention in the
pairing record: a retained certificate lists people who are not there
and offers an identity nobody can use.

## What the card is asked for

A session that has unexpired CA certificates cached reads no CA
certificate from the card until an operation needs one the cache lacks.
The holder's authentication certificate is read once per presence: when
the card enters the reader, or on the first session after the phone
became reachable, and kept in memory while that presence lasts.
A signature always reads what it signs with from the card; the
certificate it embeds is the one the card holds at that moment, never a
cached copy.
