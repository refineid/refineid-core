# Common-core migration policy

This repository receives reviewed snapshots, not a dump of the original
development tree or its history. Each slice must be independently buildable,
licensed, scrubbed, and understandable without private context.

The core is split into small crates so each unit can be audited alone and so
every crate's dependency set stays minimal. A crate is admitted with only the
modules its slice has passed review for; the rest of its charter arrives in
later slices.

## Trust by construction

Boundary data starts in an explicitly unvalidated type. A constructor then:

1. deconstructs the raw representation;
2. checks every structural invariant once;
3. reconstructs a domain type with private fields; and
4. destroys the raw secret-bearing representation.

Downstream code accepts the reconstructed type. It must not repeat scattered
"just in case" validation or keep the raw representation beside the typed one.
If another invariant becomes necessary, it belongs in a new constructor or a
new type-state transition.

## Numeric policy

Anonymous domain numbers are forbidden in production and ordinary tests.
Changing a hexadecimal value to decimal does not name its meaning.

Hand-typed hexadecimal arrays are not permitted anywhere in the core, not
even in tests. Every byte of protocol structure is a named constant, and a
wire buffer -- a command, an expected fixture -- is assembled from those
names, so a reader (human or machine) sees the meaning rather than a row of
opaque bytes. An expected-wire fixture is built from the same named header,
tag, and length constants the serialiser uses; a synthetic test payload is
an ASCII byte string, and a well-known identifier is the single value the
specification prints (for example a file identifier built from its 16-bit
number, or an application identifier whose ASCII name is written as
character literals).

Raw wire values then have only two legitimate homes:

- the initializer or discriminant of a truthful named protocol constant; or
- a single named constant holding an opaque, externally specified block whose
  bytes carry no separable per-byte meaning -- an independently audited
  known-answer vector, a registered application-provider identifier, or a
  DER object identifier -- carrying a citation to the source it locks.

The AST-based `xtask` walks integer and floating-point literals, numeric byte
escapes, radix spellings embedded in strings or documentation, patterns,
attributes, and macro token streams. Anonymous constants are not names, and
opaque macro arguments or delayed executable bodies never inherit a constant's
name. Only small reviewed sets of function-like macros, inert attributes, and
derive names may be used; other opaque macros, macro glob imports, `macro_use`,
and rebinding a trusted function-like macro name are rejected. The locked
`zeroize` derive implementation is an explicit dependency trust boundary: its
version, import, and generated drop behavior remain part of dependency and
code review. Source indirection through
symlinks, `include!`, `#[path]`, alternate Cargo target extensions, or
out-of-tree target roots is prohibited. Only the workspace-root build
directory is skipped; a source directory merely named `target` remains in
scope. Ordinary Rust comments are checked lexically. All bytes in non-Rust
files are checked for radix-prefixed values and common numeric escape forms,
even when a file is not valid UTF-8; those spellings remain prohibited until a
language-aware named-value checker exists.
Executable doctests are disabled and rejected in Cargo metadata because their
generated source is opaque to this gate. Security-sensitive negative API
contracts use checked compile-fail consumer fixtures instead.
There is no aggregate baseline: a new offender cannot be traded for an old
one. Dedicated wire-fixture support will be added only with an exact path,
symbol, reason, and primary specification citation.

## Admitted slices

The first slice admits the refined input types, each in the crate that will
own its consuming protocol:

- `refineid-pace`: `UnvalidatedCan` and an opaque, zeroizing `Can` for
  sensitive PACE access data;
- `refineid-auth`: `UnvalidatedSecret`, the zeroize-on-drop raw input
  boundary, and the non-clonable, non-copyable `Pin1` and `Pin2` role types;
- the repository policy checker and CI gate.

The second slice admits the APDU foundation in `refineid-apdu`:

- typed ISO 7816-4 command builders and validated primitives, every wire
  value a named constant;
- the decoded status word;
- the two command ownership paths: a debuggable public command with no
  raw-bytes constructor and no `Clone`, and a zeroizing, non-clonable,
  redacted credential command assembled from a custody-taking body and
  consumed exactly once; and
- the typed-only transport port, with no byte-slice transmit, so a
  builder-granted permission such as the single wrong-Le correction
  survives to the adapter.

The third slice admits the read path:

- `refineid-ber`: the minimal BER-TLV encoder and decoder with the typed
  tag layer; the encoder is fallible rather than panicking;
- `refineid-pkcs15`: PKCS#15 application and file selection with the
  per-generation fallback variants, bounded chunked reads, certificate
  retrieval sized by the DER header and returned as plain DER,
  EF.TokenInfo parsing, and the typed chip-serial forms. Reader
  discovery and generation classification from certificate contents
  stay outside the core.

The fourth slice admits the PACE secure channel in `refineid-pace`:

- the `id-PACE-ECDH-GM-AES-CBC-CMAC-256` handshake over brainpoolP384r1
  with the Card Access Number as the password, and the
  secure-messaging layer that is itself a card transport;
- the supporting primitives: brainpoolP384r1 field and point
  arithmetic over fixed-width Montgomery form with no code-generating
  macro, AES-CBC/ECB and AES-CMAC with the ICAO key derivation, the
  algorithm-typed cipher and message-authentication containers, and the
  single fail-closed random seam.

The `refineid-apdu` credential command grew its storage ceiling in this
slice so a secure-messaging wrap of the largest credential command still
fits the fixed, off-heap buffer; the wrapping path takes custody of the
wrapped wire and remains consumed exactly once. The handshake and its
cryptography are covered by known-answer, property, and synthetic-peer
tests; the full four-round wire choreography and any card-touching
behaviour are validated on hardware before being described as working,
per the admission checklist. PACE consumes no retry counter, so it is
admitted without a retry-consuming hardware gate.

The fifth slice admits PIN verification in `refineid-auth`:

- `verify_pin1` and `verify_pin2` consume a validated `Pin1` or `Pin2`
  through a crate-private path, pad it to the stored length, and ship it
  only as a credential command; the slot is fixed by the argument type,
  so a PIN2 can never reach the PIN1 slot;
- the counter-safe status probe reads the retry state without spending a
  counter, on the plain path with no credential;
- the typed outcomes and status-word classifiers, and the retry-risk
  policy that maps the live counter to the safety floors different
  surfaces stop at.

VERIFY is retry-consuming: the classifiers, the credential-command wire,
and the retry-risk policy are covered by scripted-transport and unit
tests, but no path is described as working against a real card until it
is observed on hardware with the retry counter checked before and after,
and PIN2 and card-mutating tests stay off automation, per the admission
checklist and the Apple release plan.

The sixth slice admits card-side signing in `refineid-sign`:

- `sign_prehashed_sha256_rsa`, `sign_prehashed_sha256_ecdsa`, and
  `sign_prehashed_sha384_ecdsa` drive the
  MANAGE SECURITY ENVIRONMENT / PERFORM SECURITY OPERATION choreography:
  MSE:SET pins the key and algorithm in the digital-signature template --
  the only template the specification sets for PSO:COMPUTE DIGITAL
  SIGNATURE, for the authentication key and the qualified-signature key
  alike -- and PSO:HASH loads the host-computed digest before an empty
  PSO:CDS returns the signature;
- the typed algorithm references, external-hash values, and the
  algorithm-typed signature container.

The card holds the private key and performs the private-key operation;
these commands carry no credential material and use the plain transport
path, so signing composes over the PACE secure-messaging transport
unchanged once the gating PIN is verified. The pre-hashed chains fit the
short form. An RSA-3072 signature exceeds the short response, so PSO:CDS
uses the maximum-length encoding and the adapter chains the 61xx
response; a P-384 ECDSA signature fits, so PSO:CDS carries its exact
length as Le, which a T=0 card requires to answer the short response
directly. So no extended-length support is needed. RSASSA-PSS follows in a
later slice,
and PSO:DECIPHER -- whose modulus-wide ciphertext needs command chaining
-- after that. The wire, algorithm references, and length checks are
covered by
scripted-transport tests and cross-checked against the specification;
no signing path is described as working against a real card until it is
observed on hardware.

The seventh slice admits organizational card support across
`refineid-auth` and `refineid-sign`:

- credential-numbering resolution: rather than trust a specification
  sample whose printed references contradict its own tables and shipped
  cards, the numbering is resolved by the counter-safe VERIFY probe --
  the citizen numbering is tried first, and a reference-not-found answer
  re-probes under the organizational numbering -- so a session drives the
  numbering the card in hand actually uses;
- organizational VERIFY: the typed PIN is compared at its own length with
  no padding and under the organizational references, and a PIN longer
  than the organizational maximum is refused locally, before any command
  spends a retry learning it;
- organizational signing: the qualified key is named by its local
  DF.ESIGN reference, and the digest rides inline in a single PSO:CDS with
  no PSO:HASH step -- the shape the organizational card requires and the
  citizen card refuses, which is why the resolved numbering picks the
  chain.

This slice also corrects the signing environment admitted in the sixth:
PSO:COMPUTE DIGITAL SIGNATURE runs under the digital-signature template
for the authentication key as well as the qualified-signature key,
matching the specification -- which defines only hash, digital-signature,
and confidentiality templates for the operation, no authentication one --
and the behaviour reference. The organizational reconstruction is traced
to the FINEID S4-2 and S4-1 specifications and cross-checked against the
country-neutral behaviour reference that is exercised against live
organizational cards. No organizational path is described as
hardware-validated here: no organizational card was available for
verification, so the organizational VERIFY and signing chains rest on the
specification and the behaviour reference rather than an observed card.

The eighth slice admits PIN change and unblock in `refineid-auth`:

- a `Puk` role type, reconstructed from unvalidated input like the PIN
  roles: non-clonable, zeroize-on-drop, redacted, with no raw accessor
  and no cache path. It never authorises an operation; it resets a
  blocked PIN and spends its own counter;
- `change_pin1` and `change_pin2` drive CHANGE REFERENCE DATA, presenting
  the current value and the new one in one command; `unblock_pin1` and
  `unblock_pin2` drive RESET RETRY COUNTER. The citizen card unblocks in
  one command carrying the PUK and the new PIN; the organizational card
  verifies the PUK as its own object first and then resets with only the
  new PIN, and a refused PUK ends the flow before the reset;
- each resolves the credential numbering first, refuses an over-length
  organizational credential before any command, and reports a typed
  outcome that names a wrong current-PIN-or-PUK separately from a locked
  method.

Every credential travels only as a credential command, consumed exactly
once, so a change or unblock can never be replayed. These commands are
card-mutating and retry-consuming, and exhausting the PUK is terminal.
The change path has been observed on a real citizen card: `change_pin1`
and `change_pin2` each round-tripped the current value to a temporary
one and back, every change confirmed by an intervening VERIFY, with the
retry counters at their maximum throughout and the card restored to its
starting state. The unblock path is deliberately not run on hardware --
it spends the PUK counter, whose exhaustion is terminal -- so it rests
on scripted-transport tests traced to the FINEID S1 (sections 3.11 and
3.12) and S4-2 specifications, and no counter-consuming path was run to
exhaustion on hardware.

The ninth slice admits RSASSA-PSS signing in `refineid-sign`:
`sign_prehashed_sha256_rsa_pss` drives the same pre-hashed choreography as
the PKCS#1 chain with the PSS algorithm reference, and returns a
PSS-typed signature. PSS is a card-native scheme -- the card applies the
padding from the host digest and draws the salt itself, so no host-side
encoding and no command chaining are involved, and two signatures over
one digest differ. The reference and the specification's algorithm-
reference table agree on the scheme byte; the wire is covered by
scripted-transport tests, and the RSA keys live on the older card
generation. This slice is hardware-validated (see below).

The tenth slice admits RSA decipher in `refineid-sign`, and the outgoing
command chaining it needs in `refineid-apdu`:

- `CommandApdu::command_chain` splits a data field larger than the short
  form into a command-chained sequence, setting the chaining class on
  every command but the last;
- `decipher_rsa` sets the confidentiality template and ships the
  modulus-wide cryptogram -- the padding-content indicator followed by
  one modulus block -- through that chaining, returning the plaintext the
  card recovers; `DecipherAlgRef` names the padding (PKCS#1 v1.5 or
  RSAES-OAEP-SHA256).

Unlike the other card private-key operations, decipher has no behaviour
reference; its wire is traced to the FINEID S1 specification (section 3.9
and the confidentiality-template table) and covered by scripted-transport
tests. This slice is hardware-validated (see below).

The eleventh slice admits a SubjectPublicKeyInfo layer in
`refineid-x509`: a certificate enters as an `UnvalidatedCertificate` (raw
DER), and `PublicKey::from_certificate` navigates it to the public key and
reconstructs a typed value -- an `RsaPublicKey` with a validated modulus
and exponent, or an `EcPublicKey` with its NIST curve and coordinates --
checking each invariant once at that boundary. No raw DER survives;
`to_spki_der` re-serialises the SubjectPublicKeyInfo from the typed key for
a host verifier, and the typed key pairs a certificate the read path
returns with the right signing chain. It parses only the
SubjectPublicKeyInfo; full X.509 -- validity, extensions, chains, and
revocation -- stays out of the core, and the DER walk is built on
`refineid-ber`, not a general parser, so no dependency is added.
It is covered by unit tests over synthetic RSA-3072, P-384, and P-256
certificates, and is hardware-validated (see below). Constants are traced
to RFC 5280, PKCS#1, and the object identifiers in RFC 5480 and RFC 8017.

The twelfth slice extends the RSA signing vocabulary to every SHA-2 hash used
by current browser TLS client authentication: RSASSA-PKCS1-v1_5 and
RSASSA-PSS over SHA-256, SHA-384, and SHA-512. Each entry point takes the digest as a
fixed-size array, selects the algorithm reference whose high nibble names that
hash and whose low nibble names PKCS1 or PSS, and returns a distinct
algorithm-typed RSA-3072 signature. FINEID S1 v4.2 section 3.6.3 Table 6 fixes
the reference construction; S4-1 v4.2 section 8.1.3 publishes all six
algorithms as compute-signature operations and fixes each PSS hash, MGF1 hash,
and salt length. The added SHA-384 and SHA-512 chains are covered by scripted
transport tests and are not recorded as hardware-validated.

The thirteenth slice admits the remote-operation vocabulary in
`refineid-remote`: the closed credential-profile, action, key-profile, and
signature-algorithm registries of the Remote Authorization Proxy Protocol
(RAPP), review draft 26.8.17.135 section 13.2.1, as nominal types with their
invariants carried by construction. A `SignatureRequest` cannot exist with a
digest of the wrong length or an algorithm its key profile does not support;
consent display text is bounded and non-empty at its boundary; certificate
reads are owned by the profile whose key the certificate serves. The crate
holds names and invariants only -- RAPP's wire encoding, Noise channels,
transports, engines, and stores all stay outside the core, and no CAN, PIN,
or PUK value has any representation, because RAPP never transports them.
Digest lengths reuse the named constants of `refineid-digest`; only the
SHA-224 length is added, cited to FIPS 180-4. Covered by unit tests over the
complete registries; nothing here touches a card, so no hardware validation
applies.

The fourteenth slice admits the paired phone as a PKCS#11 slot in
`refineid-pkcs11`, behind one seam: a host installs a `RemoteTokenSource`
before it hands out the function list, and the module reads from it, at
every slot refresh, the one pairing offered right now. An offer carries a
certificate only while the source holds an open session on which the
phone reports a card, and it is the certificate the source read from that
card on that session; the token exists exactly then, its objects are
built from that certificate and the persisted CA certificates, and its
serial names the pairing. A withdrawn or replaced token is a new token
when it reappears: every raised token takes its own object-handle range,
so a handle of a withdrawn token names nothing. `C_Login` on a remote
slot reads no PIN and succeeds only while the token is present, since
the phone verifies PIN 1 itself; `C_Sign` builds one typed
`SignatureRequest` from the caller's input -- the `DigestInfo` names the
hash for RSA, the digest's length names it for ECDSA -- and makes one
call to the source with the module's deadline and the text naming this
computer, checks the signature's length against the key, and never
retries; every outcome of the source maps through one table to a PKCS#11
return value. The exported `C_GetFunctionList` is behind a default-on
feature so a host library can own the symbol. RAPP's wire, channels,
transports and stores stay outside the core. Covered by unit tests over a
scripted source; the phone path is not recorded as hardware-validated.

## Hardware validation

Slices two through five have been exercised against two citizen card
generations -- the Gemalto MultiApp v4.2 (FINEID S4-1 v3.1) and the
Thales MultiApp v5.0 (FINEID S4-1 v4.0), the "older" and "newer" cards
this record names -- over both the contact and the contactless
interfaces: the PACE handshake and secure messaging, which the card
accepts on
contact and requires on contactless; certificate reads, EF.TokenInfo
parsing, and the status classifiers; and a PIN VERIFY over both the
plain and the secure-messaging credential paths. Every VERIFY was framed
by the counter-safe status probe and run with the correct PIN, so no
retry counter was consumed and no credential was locked. The counter
read as pristine before each verification and as verified after. The
reconstruction required no change to pass on either generation or
either interface. The earlier Gemalto MultiApp v3.0 (FINEID S4-1 v3.0)
citizen generation and the organizational cards were not available; the
[supported cards](../reference/supported-cards.md) reference lists the
FINEID certificate cards with their answer-to-reset identifiers.

Three behaviours the validation recorded, for the transport adapters
that remain outside this tree: the newer card requires the PKCS#15
application selected before a VERIFY, where the older card is more
permissive; a card may answer a credential command with a chained "more
data" response, so the adapter settles it on the credential path as
well as the plain one; and on the contactless interface the card
refuses the application selection before PACE, so the reset that
precedes PACE on a dirty contact context is best-effort there.

The ninth slice, RSASSA-PSS signing, has also been exercised on the
older card over the contact interface: the authentication key produced a
PSS signature over a SHA-256 digest that verified against the
authentication certificate's RSA-3072 public key. This exercises the
whole citizen signing choreography -- MSE:SET in the digital-signature
template, PSO:HASH of the external SHA-256 digest, an empty PSO:COMPUTE
DIGITAL SIGNATURE, and the modulus-wide signature returned through the
adapter's response chaining -- which the PKCS#1 chain shares byte for
byte but for the algorithm reference. The other signing chains (PKCS#1,
ECDSA, and the organizational inline-digest form) remain covered by
scripted-transport tests.

RSA decipher (tenth slice) has also been exercised on the older card over
contact: a message encrypted to the authentication certificate's public
key was recovered by the card's decipher key, which validates the
PSO:DECIPHER chain together with the command chaining that carries the
modulus-wide cryptogram.

The newer card, a dual-algorithm card, exercised the SubjectPublicKeyInfo
layer and the SHA-384 ECDSA signing chain over contact. The SHA-256 ECDSA
chain remains covered by scripted-transport tests. Its certificate slots
classified as expected -- P-384 elliptic-curve keys for the primary
authentication, signature, and CA certificates, and RSA-3072 and RSA-4096
keys in the alternate slots -- confirming both the elliptic-curve and the
RSA paths of the parser against issued certificates. The authentication
key then produced a P-384 ECDSA signature over a SHA-384 digest that
verified against that certificate. That run first caught a defect the
scripted tests could not: the card, being T=0, rejected the maximum-
length Le with a wrong-length status for the short ECDSA response, so the
signing chain now sends the exact short-form length as Le for a signature
that fits it, and the maximum encoding only for the wider RSA response.

## Quarantined until redesigned

The admitted APDU slice replaces the quarantined designs from the private
development tree: an unrestricted raw command constructor, command buffers
deriving `Clone`, a byte-slice transport path that silently copied buffers
and dropped builder permissions, and credential bytes travelling through
generic command types do not enter the public tree in any form.

Still outside the public tree:

- transport adapters until their custody and fault paths pass review;
- automatic retry paths of any kind around credential commands; and
- the legacy PIN cache.

A credential command must never enter generic tracing before redaction.

## Admission checklist

Every later slice must pass:

- copyright and contribution provenance review;
- public-information and secret scanning;
- domain-type and ownership review against the
  [refinement-types policy](refinement-types.md);
- zero anonymous numeric literals;
- formatting, tests, Clippy with warnings denied, and rustdoc with warnings
  denied;
- focused adversarial tests for parser and state-machine boundaries; and
- observed hardware validation before a card-mutating or retry-consuming path
  is described as working.

## Provenance

Each slice's publication authorization and reconstruction record are in
[public provenance](../governance/public-provenance.md). Later migrations stop
at any file whose authorship or publication rights are not explicit.
