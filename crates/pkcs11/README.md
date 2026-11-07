# refineid-pkcs11

A minimal, read-only, sign-only PKCS#11 v2.40 (cryptoki) module for FINEID cards.
It builds as a C ABI shared library (`librefineid_pkcs11.so` on Linux, `.dylib` on macOS) plus an `rlib` for tests.

Its single job is Firefox / NSS client-certificate TLS authentication:
it exposes the card's authentication certificate and its private key, takes PIN1 through `C_Login`,
and signs the TLS `CertificateVerify` digest on the card.
The same module also drives OpenSSL through the `pkcs11-provider` bridge once registered with p11-kit.

## Scope

Deliberately small.
Implemented:

- Discovery: `C_Initialize`, `C_Finalize`, `C_GetInfo`, `C_GetFunctionList`, `C_GetSlotList`, `C_GetSlotInfo`,
  `C_GetTokenInfo`, `C_GetMechanismList`, `C_GetMechanismInfo`, `C_WaitForSlotEvent` (non-blocking: reports card insertion / removal events, so NSS notices a card without a browser restart).
- Sessions: `C_OpenSession` (serial, read-only), `C_CloseSession`, `C_CloseAllSessions`, `C_GetSessionInfo`.
- Login: `C_Login` (`CKU_USER` only), `C_Logout`.
  PIN1 is validated as 4..=12 ASCII digits and verified on the card.
  Once the card accepts it under a pristine retry counter, it is held in this process's memory with no idle window,
  until the card is removed or replaced, the card refuses it, its retry counter reads below pristine,
  or `C_Logout`, the last `C_CloseSession` or `C_Finalize` ends the login;
  under a counter below pristine it only bridges to the next operation.
  It is presented to the card inside each sign, never logged, and never written to storage
  (see [credential custody](../../doc/security/credential-custody.md)).
- Objects: `C_FindObjectsInit` / `C_FindObjects` / `C_FindObjectsFinal` and `C_GetAttributeValue` over
  the authentication certificate (`CKO_CERTIFICATE`, `CKC_X_509`),
  its public key (`CKO_PUBLIC_KEY`, from the certificate SPKI, for
  consumers such as p11tool / libp11 that enumerate public keys),
  its private key (`CKO_PRIVATE_KEY`, `CKK_RSA` or `CKK_EC`),
  the CA certificates the card carries (`CKO_CERTIFICATE`,
  `CK_CERTIFICATE_CATEGORY_AUTHORITY`), and one NSS trust record
  (`CKO_NSS_TRUST`) per CA certificate -- see
  [NSS trust records](#nss-trust-records).
  The three authentication objects share one `CKA_ID` so NSS pairs them.
  The private key answers `CKA_EXTRACTABLE` false and
  `CKA_NEVER_EXTRACTABLE` / `CKA_ALWAYS_SENSITIVE` true -- the FINEID
  key never leaves the card.
  On a card in a local reader the private key is a private object
  (`CKA_PRIVATE` true) and the token reports `CKF_LOGIN_REQUIRED`.
  On a card served by a paired phone the phone verifies PIN 1 and asks
  the holder for each signature, so the token reports
  `CKF_PROTECTED_AUTHENTICATION_PATH` without `CKF_LOGIN_REQUIRED`, every
  object is public, `C_Sign` needs no login, and `C_Login` (null PIN)
  succeeds without contacting the phone.
- Signing: `C_SignInit` / `C_Sign` (single-part).
  `CKM_RSA_PKCS` takes a DER `DigestInfo` (SHA-256 only) on the RSA-3072 card;
  `CKM_ECDSA` takes a raw digest of any hash on the ECC P-384 card and returns raw `r || s`.
  The card slot is exactly 48 bytes,
  so shorter digests (TLS 1.2 commonly negotiates ECDSA+SHA-256) are left-padded with zeros
  and longer ones truncated to the leftmost 384 bits,
  per the PKCS#11 v2.40 s6.4.1 ECDSA rule -- see `doc/bugs/2026-07-07-ckm-ecdsa-digest-len.md`.
  The two-call length query works without touching the card.
- Verifying: `C_VerifyInit` / `C_Verify` (single-part), pure
  software against the cached certificate public key -- no card
  IO, no PIN. Same input shapes as signing.

Everything else in the v2.40 function list is present but returns `CKR_FUNCTION_NOT_SUPPORTED`,
except where the spec names a more specific code for a permanent refusal:
`C_InitToken` returns `CKR_TOKEN_WRITE_PROTECTED`,
`C_SignRecoverInit` / `C_UnwrapKey` return `CKR_KEY_FUNCTION_NOT_PERMITTED`,
`C_DigestKey` returns `CKR_KEY_INDIGESTIBLE`,
`C_SeedRandom` returns `CKR_RANDOM_SEED_NOT_SUPPORTED`,
and the legacy `C_GetFunctionStatus` / `C_CancelFunction` return `CKR_FUNCTION_NOT_PARALLEL` as v2.40 mandates.
There is no object creation, no key generation, no encryption / decryption / digesting, no write path;
verification is software-only (above);
the token reports `CKF_WRITE_PROTECTED`.

## Diagnostics

Off by default. `REFINEID_PKCS11_LOG=<path>` appends the NSS call
sequence (function names, handles, byte lengths -- never PIN bytes or
attribute values) to an operator-named file; without it,
`REFINEID_DEBUG=1` writes the same lines to stderr. There is
deliberately no default log path: the module runs inside the
browser's address space, and an implicit file in a world-writable
directory would be a symlink-attack surface. The environment is read
once per process.
On Unix a log file the module creates gets mode 0600; an existing file
keeps its mode, and the path is opened as given, following symlinks.
A privileged Unix process -- effective uid root, or an effective user or
group id that differs from the real one -- ignores `REFINEID_PKCS11_LOG`,
because its environment may come from an unprivileged caller; there
`REFINEID_DEBUG=1` still writes to stderr, a descriptor the host already
holds rather than a path the environment names.

## CA certificate cache

CA certificates read from the card are kept, as untrusted intermediates
(`CKA_TRUSTED` false), in a per-user cache directory so later sessions
can serve them without reading them again: `REFINEID_CA_CACHE_DIR`,
else `XDG_CACHE_HOME/refineid/ca-certificates` or
`~/.cache/refineid/ca-certificates` on Linux and BSD,
`~/Library/Caches/fi.refineid/ca-certificates` on macOS, and
`LOCALAPPDATA` or `APPDATA` under `refineid\ca-certificates` on Windows.
On Unix the module creates missing cache directories with mode 0700 and
cache files with mode 0600, and leaves existing directories as they are.
A privileged Unix process -- effective uid root, or an effective user or
group id that differs from the real one, such as a PAM stack under
`sudo` or a display manager -- has no persistent cache and reads the CA
certificates from the card each time, because its environment may come
from an unprivileged caller.

## NSS trust records

A FINEID card carries the certificates of its issuing CA (EF.4336)
and of the DVV root (EF.4334), and the module presents both as
certificate objects. NSS trusts a certificate on a token only when the
token also presents a trust record for it, so the module presents, next
to each CA certificate object, one object of NSS's vendor class
`CKO_NSS_TRUST` (NSS `lib/util/pkcs11n.h`; the standard `CKO_TRUST`
class of PKCS#11 v3.2 applies only to modules reporting that version,
and this one reports 2.40). NSS finds the record by `CKA_CLASS`,
`CKA_ISSUER` and `CKA_SERIAL_NUMBER` (NSS `lib/dev/devtoken.c`,
`nssToken_FindTrustForCertificate`), the same issuer and serial the
certificate object answers, and reads from it the label, the
certificate's SHA-1 and MD5 digests (`CKA_NSS_CERT_SHA1_HASH`,
`CKA_NSS_CERT_MD5_HASH`; the MD5 is a lookup key every NSS trust record
carries, never a decision), the subject, and one trust level per
purpose:

| Purpose | Attribute | Level |
| --- | --- | --- |
| TLS client authentication | `CKA_NSS_TRUST_CLIENT_AUTH` | `CKT_NSS_TRUSTED_DELEGATOR` |
| Email protection (S/MIME) | `CKA_NSS_TRUST_EMAIL_PROTECTION` | `CKT_NSS_TRUSTED_DELEGATOR` |
| TLS server authentication | `CKA_NSS_TRUST_SERVER_AUTH` | `CKT_NSS_MUST_VERIFY_TRUST` |
| Code signing | `CKA_NSS_TRUST_CODE_SIGNING` | `CKT_NSS_MUST_VERIFY_TRUST` |

`CKT_NSS_TRUSTED_DELEGATOR` makes the CA a trust anchor for the
purpose: NSS accepts a chain that ends at it. `CKT_NSS_MUST_VERIFY_TRUST`
asserts nothing for the purpose: a chain through the CA must reach some
other anchor, so a web site or a signed program chaining to the DVV root
is no more trusted than before. It is not `CKT_NSS_NOT_TRUSTED`, which
would be an active distrust. `CKA_NSS_TRUST_STEP_UP_APPROVED` is false,
the record is a public, unmodifiable token object, and `certutil -L`
shows the pair as the trust string `T,C,` (trusted client CA for TLS,
trusted CA for email, nothing for object signing).

The purposes follow the card: the holder uses it to authenticate as a
TLS client and to sign and encrypt mail. The DVV roots are in no
Mozilla-derived root store (DVV has not applied to Mozilla's root
program), and this module does not put them in one.

A trust record exists exactly while its CA certificate object does: it
is built with the token's objects and dropped with them when the card
leaves the reader, with the certificate objects, the private key and
the held PIN. A CA certificate served from the per-user cache (above)
gets the same record as one just read from the card, since the cache
only ever holds certificates read from a card, so Firefox trusts the
DVV root while a FINEID card is in the reader and at no other time.
Nothing is written to the NSS database and no policy file or root
privilege is involved.

## Example programs and hardware rigs

This repository carries no example programs or hardware rigs for the
module. The [refineid-unix](https://github.com/refineid/refineid-unix)
repository builds this crate into its host library and keeps them in
`crates/refineid-pkcs11/`: `examples/nss_debug.rs`, which replays NSS's
discovery probes against the built module without launching Firefox,
and the operator-run scripts under `test/`, gated on
`REFINEID_HARDWARE_TEST=1`.

## Card access

The module opens the reader itself through `refineid-lib-pcsc` (`PcscBackend::open_session`),
reads what it needs, and drops the transport immediately.
PIN-bearing opens use `ReaderAccessCap::PinSequence`: the whole
SELECT -> VERIFY -> operation span runs inside one held PC/SC
transaction, so a concurrent card consumer can neither interleave
an APDU mid-sequence nor consume the card's verified state.
It never holds the card open across PKCS#11 calls, and it does not hold the module lock across card IO,
so a shared desktop reader stays usable.

## Versions

- Library and token hardware version: `YY.M` of the workspace version
  `YY.M.D` ([README](../../README.md#version)).
- Token firmware version: `M.D` of the workspace version.
- Cryptoki version: `2.40`.

## Register with p11-kit

Install the built library somewhere on the system module path (for example `/usr/lib64/pkcs11/librefineid_pkcs11.so`)
and drop a p11-kit module file, e.g. `/usr/share/p11-kit/modules/refineid.module`:

```
module: librefineid_pkcs11.so
critical: no
```

Use an absolute path if the library is not on the default module search path:

```
module: /usr/lib64/pkcs11/librefineid_pkcs11.so
critical: no
```

Firefox / NSS then load the module through p11-kit,
or you can add it directly with `modutil -dbdir sql:$HOME/.pki/nssdb -add "RefineID" -libfile /usr/lib64/pkcs11/librefineid_pkcs11.so`.
OpenSSL reaches the same module through `pkcs11-provider`, which also enumerates p11-kit modules.

This README documents the file content only; it installs nothing.

## Build

```
cargo build -p refineid-pkcs11
```

The `cdylib` builds on both Linux and macOS; PC/SC access is cross-platform through `refineid-lib-pcsc`.
