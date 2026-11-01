# Document verification

How `refineid-doc-sign` judges a signed document and what it reports.
The verifier is shared by every RefineID application built on this
core; the Swift application keeps its own implementation of the same
design.

## Scope

Input is one file: a PDF carrying PAdES signatures, an ASiC-E or BDOC
container carrying XAdES or CAdES signatures, or a single CMS file with
attached content. The verifier reads the file, every signature in it,
and every piece of validation evidence the file carries, and returns a
report. It never writes, never prompts, and never touches a card.

The levels verified are the baseline levels of ETSI EN 319 142-1 and
142-2 (PAdES), EN 319 122-1 (CAdES) and EN 319 132-1 (XAdES), inside
EN 319 162-1 containers, with the long-term-with-archive level as the
target the signing side produces. The validation process follows
EN 319 102-1.

Out of scope, reported as unsupported rather than judged: encrypted
PDFs, XFA and XAdES signatures inside PDFs, and signatures over MD5 or
SHA-1.

## Trust origins and borders

Every input has one origin, one border and one constructor.

| Origin | Border | Meaning after the border |
|---|---|---|
| The file | `DocumentFile::from_file` | Bytes of a known shape: PDF, ZIP, or DER SEQUENCE. Nothing else passes. |
| Trust anchors | `TrustAnchors` | Certificates the relying party trusts for a role (certificate issuing or time-stamping) during granted periods, and when the lists they came from were fetched. |
| The clock | `now` passed by the caller | The current time, used only where no proven time exists. |
| Validation evidence inside the file | `MaterialPool` | Parsed certificates, OCSP responses and CRLs from the DSS, the CMS, or the container. Each is parsed once, at the border. |

Trust anchors come from two sources `TrustAnchors::from_trusted_lists`
combines: the pinned roots the core ships (the DVV roots and the
time-stamping root the signing side uses), and the EU trusted lists
(see Trusted lists). The lists are fetched and cached by the shell; a
verdict uses the cached lists and the report says when they were
fetched and whether one of them is stale. The verifier itself does no
network access.

An anchor is the subject name and public key of its certificate (RFC
5280 sec.6.1.1): a path ends at the first certificate that carries an
anchor's name and key, for the role the path needs, at a time inside
one of the anchor's granted periods. The anchor certificate's own
validity and extensions are not consulted; its granted periods are.
Any certificate can be an anchor: a root, an issuing CA a trusted list
names, or a time-stamping unit's own certificate. `TrustAnchors::pinned`
gives the core's pinned roots, each granted without bounds.

## Trusted lists

The EU trusted lists (ETSI TS 119 612) are a trust input: what they
name as a qualified service becomes an anchor. They enter through one
border, `verification::trusted_list::TrustedList::read`, which takes
the bytes of one list and the certificates entitled to sign it, and
hands out typed facts or a typed refusal.

A list is read only when its enveloped XAdES signature verifies. The
`ds:SignedInfo` carries exactly two references (annex B): one to the
list and one to the signed properties; any other count is refused
before anything is computed. The `ds:KeyInfo` certificate the
`SigningCertificate` property names is one of the entitled
certificates, byte for byte (TS 119 612 annex A.1 authenticates a list
by the digest of its signer certificate), and the `ds:SignedInfo`
signature verifies under it before any reference digest is computed,
so a forged list costs one signature verification, not a
canonicalisation of the list. Then the reference to the list carries
the enveloped-signature transform and a canonicalisation and digests
the list without its signature (annex B.1), and the reference of the
`SignedProperties` type digests this signature's signed properties; a
reference the verifier cannot recompute, or a digest or signature value
that does not match, refuses the list. The signer
certificate's own validity and revocation are not consulted: the lists
are a direct trust model in which issuing a new list deprecates the
old one (annex A.2).

The list of the lists is read under the Commission certificates the
core pins (`trust::LOTL_SIGNER_DER`), the ones the Official Journal
notice named by the list's scheme information URI publishes: OJ C,
C/2026/1944 (`https://eur-lex.europa.eu/eli/C/2026/1944/oj`). The
notice lists six certificates by SHA-256 and SHA-1 digest, and the
SHA-256 digest of each pinned certificate equals one of them; the
notice's electronic edition is authenticated by the Publications
Office's XAdES seal over a manifest of its language versions. A future
set is re-checked the same way: compare the SHA-256 digests the new
notice lists with the certificates the list of the lists carries in its
pointer to itself. Each
national list is read under the certificates the list of the lists
carries in the pointer to it. Pointers are followed one level, from the
list of the lists to the national lists: a national list's own pointers
are read and never fetched. Only pointers that declare the EU member
state list type and the machine-processable media type are followed;
the pointer to the list of the lists itself and to human-readable forms
are not. A national list that does not arrive, does not read, is not
signed by a pointer certificate or is not a member state list is
reported with its reason beside the lists that read, and yields no
anchor. Bounds are named constants in `verification::trusted_list`:
the size of a list, the pointers and services of a list, the history
entries of a service, the certificates of an identity and of a pointer;
a list beyond one is refused.

A service of type `CA/QC` yields certificate-issuing anchors, one of
type `TSA/QTST` time-stamping anchors: one anchor per certificate of
its digital identity (TS 119 612 clause 5.5.3: the certificates
represent one public key). A certificate that is base64 but not a
certificate this core reads (the national lists carry some from the
1990s) is counted and left out, since nothing can be anchored on it; a
service none of whose certificates read yields no anchor and the count
says why. Its granted periods come from its status
and status history (clauses 5.5.4, 5.5.5, 5.5.10 and 5.6), every entry
walked in time order: a period opens at a status that grants and
closes at the next that does not, open-ended while the current status
grants. An entry recorded under another service type does not grant
and closes an open period, so a time the service was of another type
is never bridged. Of entries starting at one instant the most recent
fact counts last: the history, listed newest first, from its last entry
to its first, then the current status; a period that closes at the
instant it opened is left out. `granted` grants for both types. For a
certificate service `undersupervision`, `accredited` and
`supervisionincessation`, the statuses held under Directive 1999/93/EC,
grant too, until 1 July 2016 00:00 UTC at the latest: the Regulation
applies from then (its article 52(2)) and annex J moved every such
service to `granted` or `withdrawn`, so a period one of them opens
closes then, and one starting later grants nothing; after that only
`granted` opens a period. A certificate issued under supervision in
2015 is as qualified as one issued under a granted status. For a time-stamping service they grant
nothing: annex J turned them into `withdrawn`, since qualified
time-stamps did not exist before the Regulation. Every other status,
`withdrawn` first among them, grants nothing. A service of another type
yields no anchor.

A list past its `NextUpdate` is stale (clause 5.3.15). The anchors
taken from a stale list still count: a stale list is the last one its
operator published, the statuses in it were granted when it was issued,
and un-anchoring every qualified signature of a territory because a
cache aged is a loss no relying party expects. The report says so
instead (`DocumentReport::anchors_stale`, judged against the verifier's
clock from the earliest `NextUpdate` of the lists the anchors came
from), beside the fetch time, and the shell shows both and fetches
again. A closed list, one without a `NextUpdate`, never goes stale.

Fetching and caching are the shell's. `TrustedLists::fetch` fetches the
list of the lists from its published location and the national lists
over the crate's HTTP transport, and returns beside the lists one
`CachedList` per list that read: the location, the fetch time, the
list's next update and its bytes. The shell stores the records and
hands them back to `TrustedLists::from_cache`, which verifies every
signature again; it fetches again once a record's next update has
passed or on its own schedule. The core writes no file.

## What is judged, per signature

For each signature the report carries independent facts:

- **Document intact.** Every byte the signature claims to cover digests
  to the value the signature states, and no later revision changes the
  document (see Revisions after signing). For PDFs this is the ByteRange,
  whose hole must be exactly this dictionary's own Contents, whose
  trailing bytes must be zero padding, and which must end where a
  revision ends, just after an `%%EOF` marker and its end-of-line; a
  range cut elsewhere signs part of a revision and is an unsupported
  row. Signature dictionaries are found in every cross-reference
  section, so a signature a later revision freed or replaced is still
  a row. For XAdES, every Reference recomputes, the SignedProperties
  reference resolves to this signature, and every data file in the
  container is covered; a reference URI names an entry percent-decoded
  or as written. A same-document reference digests the subtree its
  `Id` names, under its canonicalisation transform or, without one,
  Canonical XML 1.0. For an XAdES counter-signature, the data files
  are not required; instead a reference whose `Type` is
  `CountersignedSignature` must resolve to the `ds:SignatureValue` of
  the signature the counter-signature is embedded in. One without that
  `Type` is an ordinary reference and covers nothing, and one with it
  that resolves elsewhere, another signature's value included, fails. For CAdES in a container, the ASiCManifest that binds
  the signature (one manifest with exactly one SigReference naming it)
  references every data file and at least one, and each digest
  recomputes. A reference the verifier cannot resolve fails this fact;
  it never passes.
- **Signature valid.** The CMS or XML signature verifies under the
  signer's public key, with the digest algorithm taken from the
  SignerInfo, the signature algorithm's hash equal to it, algorithm
  parameters of the shape RFC 5754 and RFC 5758 allow, exactly one
  message-digest attribute of the digest's length, and a signature
  value whose shape fits the key. The ESS signing-certificate binding
  is required for `ETSI.CAdES.detached` and XAdES, and not required for
  `adbe.pkcs7.detached`. A PAdES baseline signature
  (`ETSI.CAdES.detached`) carrying a signing-time attribute is not
  valid. Digests are SHA-256, SHA-384 or SHA-512: for CMS signatures,
  timestamp imprints, XAdES references and ASiC manifests alike; MD5
  and SHA-1 are refused. ECDSA over the named curves P-256 and P-384
  and RSASSA-PKCS1-v1_5 are accepted with each of the three, and in
  XAdES also RSASSA-PSS with SHA-256, MGF1 with SHA-256 and a 32-octet
  salt (RFC 6931 `sha256-rsa-MGF1`); explicit
  curve parameters are refused everywhere, including in timestamp,
  OCSP and CRL signers. A signature algorithm whose hash differs from
  the digest algorithm, or whose parameters break RFC 5754 or RFC
  5758, makes the signature unsupported; a scheme that does not fit
  the signer key makes it not valid. The content-type signed
  attribute must be present once and name `id-data`: absent, the CMS
  structure is refused as unsupported; another type is not valid. In
  XAdES a SignatureMethod or DigestMethod the verifier does not know,
  a canonicalisation other than Canonical XML 1.0, Canonical XML 1.1
  or Exclusive XML Canonicalization 1.0 (each with or without
  comments; an exclusive `InclusiveNamespaces` prefix list is applied,
  and the inclusive algorithms take no parameter), and a Reference
  with more than one transform, a transform other than these, or a
  transform over a data file make the signature unsupported. The
  canonicalised subtree is the apex of its node set: the inclusive
  algorithms render on it every namespace in scope and the `xml:`
  attributes it inherits from its ancestors (all of them for 1.0;
  `xml:lang` and `xml:space`, with `xml:base` joined from the
  ancestors' values, for 1.1), the exclusive one renders only what
  each element visibly uses. A signature file that declares a relative
  namespace URI does not read, since Canonical XML 1.0 sec.2.1 makes
  canonicalising it an error. A SigningCertificate
  binding that names a certificate the signature does not carry leaves
  it without a signer, and an unsupported row.
- **Chain verified.** A path from the signer certificate to a trust
  anchor whose role is certificate issuing and whose granted period
  covers the validation time, built offline from the material pool:
  name chaining, signatures, validity at the validation time, basic
  constraints, key usage, path length, no name constraints, no critical
  extension the verifier does not process, depth bound. The signer
  itself must be no CA, with a Key Usage that, when present, asserts
  digitalSignature or nonRepudiation. Every anchored path is judged and
  the best revocation outcome kept, good before unavailable before
  revoked (RFC 5280 sec.6 accepts any valid path). Every certificate
  below the anchor is checked for revocation. The report carries the
  path as certificates, the signer's issuer first: anchored, ending in
  the anchor, exactly when the chain is verified; otherwise partial,
  as far as verifiable issuers in the evidence reach, which may be
  empty. A signer that is itself not valid at the validation time or
  not fit to sign has a partial path even when its issuers reach an
  anchor; the path is then the one to that anchor.
- **Proof of existence.** The earliest time proven by a timestamp whose
  authority chains to a trust anchor with the time-stamping role: a
  signature-time-stamp attribute over the signature value, a XAdES
  SignatureTimeStamp over the canonicalised SignatureValue, or a PDF
  document timestamp whose ByteRange covers this signature. A token
  verifies under its own TSTInfo imprint algorithm and its signer must
  carry the time-stamping extended key usage, not be a CA, and be valid
  at the token's time. Its path to the anchor is judged at the token's
  time from the document's evidence and the token's own certificates
  and revocation answers; an authority revoked at or before that time
  is not anchored, and one whose revocation is unavailable is
  anchored, the same rule a signature follows. A token
  whose authority is not anchored is shown with its claimed time and
  marked unproven; it moves nothing and blocks nothing. Only the
  `signature-time-stamp` attribute counts as a CAdES signature
  timestamp. An anchored archive timestamp is a proof of existence too:
  it covers the signature with its validation material (EN 319 122-1
  clause 5.5.3, EN 319 132-1 clause 5.5.2), so when the signature
  timestamp's authority can no longer be anchored, the archive time is
  the proof the signer's chain and revocation are judged at. A CAdES
  `archive-time-stamp-v3` attribute holds exactly one value, else it
  is invalid as malformed, and first has its `ats-hash-index-v3`
  validated: the token carries exactly one, its `AlgorithmIdentifier`
  SHA-256, SHA-384 or SHA-512 with parameters absent or NULL, each
  hash a primitive OCTET STRING of that length, each list bounded; and
  every hash it lists must be that of a complete `CertificateChoices`
  in `SignedData.certificates`, a complete `RevocationInfoChoice` in
  `SignedData.crls`, or an unsigned attribute's type followed by one of
  its values, each as encoded; a hash naming nothing present makes the
  token invalid. A present value the index does not list, this token's
  own attribute and later archive timestamps among them, is not
  protected by it. A signature declared attached whose content is
  absent is refused, never hashed as empty. Its imprint is then
  recomputed over the `eContentType`, the hash of the signed data under
  the index's algorithm, the `SignerInfo` fields `version` through
  `signature` and the index, each as encoded, and the token must
  imprint under that same algorithm. The token's authority is judged
  from the document's evidence and the certificates and revocation
  values of the token's own `SignedData`; certificate and revocation
  values in the token's unsigned attributes are not consulted. An
  archive timestamp is judged, and when its time is the earliest proof
  of existence the signer's chain and revocation are judged, only from
  the anchors, the token and the material it covers: for CAdES the
  certificates and revocation values its index lists, for XAdES the
  `ds:KeyInfo` certificates and the `CertificateValues`,
  `RevocationValues` and `TimeStampValidationData` before it in
  document order. Material it does not cover, appended after it, is
  left out; when the signer is judged at the archive time, the
  material of every anchored archive timestamp is pooled. One
  exception serves the XAdES timestamp's own authority: a
  `TimeStampValidationData` after it that names it by `URI`, or has no
  `URI` and follows it as the nearest archive timestamp before it
  (EN 319 132-1 clause 5.5.1), may be used to judge that timestamp's
  authority path and revocation, never the signer's chain or an
  earlier timestamp; a later archive timestamp covers it for the long
  term like any material before it. An XAdES `ArchiveTimeStamp` in
  the 1.4.1 namespace imprints, under its canonicalisation (Canonical
  XML 1.0 when it names none), the octets every reference digests, in
  order, then `ds:SignedInfo`, `ds:SignatureValue`, `ds:KeyInfo`, each
  unsigned signature property before it in document order (a
  `TimeStampValidationData` among them) and each `ds:Object` but the
  one holding the qualifying properties (clause 5.5.2.3). The
  certificates and revocation values of a `TimeStampValidationData`
  join the evidence. A CAdES `archive-time-stamp` of version 2, an
  XAdES `ArchiveTimeStamp` in the 1.3.2 namespace, one with
  `xades:Include` children in either namespace (time-stamped
  properties not sharing its parent, clause 5.5.2.4), and one under a
  canonicalisation or over a reference the verifier does not compute
  are reported unsupported. The octets of a reference are those its
  verification digests; a data file is never under a transform, since
  a transform over one makes the signature unsupported.
- **Timestamps.** Each signature timestamp, and each archive
  timestamp with its form (CAdES v3, CAdES v2, XAdES), is reported as anchored
  (with the time it proves), claimed (verified under an authority that
  is not anchored, with the time it claims), invalid (with the reason
  the token failed), or unsupported (an XAdES timestamp whose imprint
  needs a canonicalisation the verifier does not compute, an archive
  timestamp of a form not judged, or a document timestamp whose range
  does not end a revision). An invalid or unsupported token also
  carries the `genTime` it claims when it parses as far as its
  `TSTInfo`, read without verification and proving nothing, so the
  shell can show the time beside the word that it is unproven. An XAdES
  timestamp that names no canonicalisation imprints the
  `ds:SignatureValue` under Canonical XML 1.0 (EN 319 132-1 clause
  4.5). An anchored or claimed token is reported with its signer and
  the path above it, as for the signer's chain: issuer first, anchor
  last when anchored, as far as it was built when not.
  A timestamp that is invalid, unsupported, or verified under an
  authority that is not anchored is reported and decides nothing: it
  sets no proof of existence and does not make the signature or the
  document not valid (EN 319 102-1 clauses 5.4 and 5.6). Timestamps
  sit in unsigned attributes or later revisions anyone can append, so
  only the facts of the signature itself decide its verdict.
- **Validation time.** The proof of existence when there is one,
  otherwise now. Chain validity and revocation are judged at this time.
- **Claimed signing time.** The time the signer's own clock wrote into
  the signature, reported as a claim that proves nothing and decides
  nothing: the CMS `signing-time` signed attribute when exactly one
  holds exactly one `UTCTime` or `GeneralizedTime` (RFC 5652
  sec.11.3), else for a PDF signature its `/M` entry; for XAdES the
  `SigningTime` property, an `xsd:dateTime` with a time zone (EN 319
  132-1 clause 5.2.1). Absent or unreadable, the report says none.
- **Revocation.** From the evidence in the file first: OCSP responses
  and CRLs that verify under an authorised responder or the issuer and
  whose window covers the validation time per EN 319 102-1 clause
  5.2.5; an answer dated later than the verifier's clock, beyond five
  minutes of skew, speaks for nothing. An OCSP answer matches its
  certificate by a SHA-1 or SHA-256 CertID whose issuer hashes are
  those of the issuer the path names, and a CRL issuer must be a CA
  whose Key Usage, when present, asserts cRLSign. The states are Good
  with the evidence time, Revoked with the revocation time and the
  CRLReason when the evidence gives one, and Unavailable. A
  certificate revoked before the proof of existence makes the
  signature not valid; one revoked after it does not, because the
  signature was proven to exist while the certificate was good, unless
  the reason is keyCompromise, cACompromise or aACompromise: a
  compromised key proves nothing about when it signed, so those
  invalidate whatever the proof of existence. Without a proof of
  existence any revocation counts. OCSP and CRL answers are weighed
  together: any verified revoked answer outweighs good ones, a
  compromise is reported before other reasons, and otherwise the
  earliest revocation time on the path. The shell may ask the network only for a
  signature still Unavailable on a verified chain, and that answer is
  judged at now: `DocumentReport::with_live_revocation` calls the
  shell's closure for exactly those signatures and applies the answer
  it returns, and `SignatureReport::with_live_revocation` does the same
  for one report. `live::live_revocation` is that closure's body: for
  each certificate below the anchor on the signature's anchored path
  it asks the OCSP responders the certificate names (with a nonce,
  RFC 6960) and, without an answer, its CRL distribution points, at
  most three addresses of each kind, over the crate's HTTP transport;
  the answers join a pool with the path and the anchors, and the
  signer is judged again at now under the same rules as the file's
  own evidence. A responder that does not answer, or an answer that
  does not hold up, leaves the status Unavailable. Every other fact is fixed when the report is made.
- **Revisions after signing.** For a PDF signature, what the
  revisions after the one it signs do to the document (ISO 32000-1
  sec.12.8.2.2 and sec.12.8.2.4): none follow; later revisions are
  harmless; or the document was changed after signing, with the kind
  of change. The signed revision is indexed on its own, each live
  object of both views parsed once, values compared by meaning
  (dictionaries by key, spacing ignored), objects matched by number;
  the comparison is bounded by the index's entry ceiling and a ceiling
  on the octets read, and a document past them does not end a
  judgeable revision. A later revision is harmless when, and only
  when, everything it adds or rewrites is one of these: signature
  fields and widgets that carry a signature (`/V`), attached to the
  field tree and, for a widget (its own `/Subtype /Widget`), to a
  page's `/Annots` after the annotations already there; the signature
  and document timestamp dictionaries those fields name; new objects
  the `/AP` of those fields reaches; an existing signature field that
  had no value gaining `/V`, `/AP` and `/AS`; the `/DSS` growing (new
  streams in `/Certs`, `/OCSPs` and `/CRLs`, new `/VRI` entries, old
  ones kept); cross-reference and object streams; the document
  information dictionary and the catalog's `/Metadata` stream (signing
  tools update both, and neither changes what is rendered); the
  catalog rewritten only in `/DSS`, `/AcroForm`, `/Extensions` and
  `/Metadata`; the interactive form only in `/Fields`, whose order is
  free, and `/SigFlags`; and the trailer anywhere but `/Root` and the
  first, permanent `/ID` element. `/Annots` and `/Fields` are resolved
  on both sides whether inline or indirect, and the field tree is
  walked through `/Kids` once per node and to a bounded depth. Anything
  else is a change after signing, a new object that is none of these
  included: a reordered `/Annots`, a changed `/Perms`, `/DA` or `/DR`,
  a rewritten signed widget, a replaced store object, an unattached
  signature field and what it reaches, an object whose generation rose
  (the signed revision's references to it no longer resolve). It is
  typed as the page tree, a form field, an annotation, the catalog,
  the trailer, or content (a content stream, a resource, the store
  beyond growing, any other object), the first of these when several
  change. A change after signing makes the document not intact, since
  the document the signer saw is not the one the reader sees; harmless
  later revisions keep it intact. A range whose bytes do not index as
  a document of their own does not end a revision. Outside a PDF the
  signature always covers the whole document.

An XAdES `CounterSignature` in a signature's unsigned properties
holds a complete `ds:Signature` over that signature's
`ds:SignatureValue` (EN 319 132-1 clause 5.2.7). It is judged as a
signature in its own right: its references recomputed, its
SignedProperties reference required, its SigningCertificate binding
required, its chain, revocation and timestamps judged as any
signature's, with the evidence of every signature it is nested in
added to its own, since their `CertificateValues` may carry its path
(clause 5.4.2). It is its own row, placed after the row of the
signature it counter-signs and naming that row; a counter-signature
of a counter-signature names the counter-signature. Counter-signatures
are judged four levels deep below a signature over the document; a
deeper one is an unsupported row and nothing below it is read. A
counter-signature that does not read is an unsupported row naming the
signature it counter-signs. A counter-signature sits in unsigned
properties anyone can append to, so, like a timestamp, it decides
nothing: whatever its own verdict, it changes neither the verdict of
the signature it counter-signs nor the document's.

A signature is valid when the document is intact, the signature is
valid, the chain is verified at the validation time, and no revocation
that invalidates it is known (see Revocation). A signature the verifier
cannot read (unsupported profile, algorithm or structure) gets its own
row saying so, with a typed reason: a PDF subfilter other than the two
above, a PDF range that does not end a revision, a CMS structure the
CMS border refuses, a CAdES signature no `ASiCManifest` binds, an
XAdES feature outside the scope, an XAdES signature without a carried
signer, one XAdES signature or counter-signature that does not read
(its neighbours in the same file are still judged), or XAdES
signature files that do not read.

Each PDF document timestamp is reported with what its token was found
to be and how far into the file its range reaches. A document
timestamp covers the signatures whose revision ends where its own
range starts or earlier. Each judged signature names the document
timestamps that cover it, in document order and whatever each was
found to be; the anchored ones count toward its proof of existence.

A signature row not judged names the signer its certificate
identifies when one does: a PDF signature under another subfilter or
over a range that does not end a revision whose CMS structure still
parses, a CAdES signature no manifest binds, and an XAdES signature
with a feature the verifier does not implement or nested too deep.
The name is what the certificate says, unverified, since nothing was
judged.

The document is valid when it has at least one signature over the
document, every such signature is valid, and none of them is
unsupported; counter-signature rows are reported and do not count.

## Signer identity

The name is the subject's `commonName` exactly as the certificate
carries it, never recomposed from `givenName` and `surname` and never
case-changed; a FINEID certificate's reads surname, given names and
identifier. A subject without a `commonName` is named by the whole
subject as RFC 4514 writes it. The `serialNumber` attribute, when it
has the shape of a Finnish electronic user identifier, is the
identifier for machine use, and is not appended to the name. The
identifier is a type, never a string beside a flag.

## Failures

A file the verifier cannot judge is a typed failure, not a report: not
a signed document (neither a PDF, a ZIP archive nor a DER SEQUENCE),
unreadable with the reader's reason, no signatures, or an unsupported
profile with the reason (a PDF or ZIP feature outside the readers,
encryption in any revision, an archive that is not an ASiC-E or BDOC
container, a META-INF entry the reader does not name or a
subdirectory of META-INF, or a DER file that is not a CMS signature
with attached content). A container without a data object, and one
whose manifests bind a signature it does not hold or bind one
signature twice, is unreadable. The META-INF entries a container may
carry are signature files, ASiC manifests, archive manifests and
their timestamp tokens, and the OpenDocument `manifest.xml` and
`container.xml`, which pass unexamined. A negative verdict is a
report.

## STPA

The record in [stpa-rapp.md](../security/stpa-rapp.md) covers card
operations. Verification adds one loss and one hazard.

| Id | Statement |
|---|---|
| L-6 | A relying party acts on a document as validly signed when it is not, or rejects one that is. |
| H-8 | The verifier reports a fact it has not established, or hides a signature or timestamp it has not judged. |

Control structure: the relying party reads the report the application
shell renders from the verifier's facts. The shell supplies the file,
the anchors and the clock, and may fetch live revocation. The anchors
are themselves fed by the trusted lists the shell fetches and the
reader verifies, so the lists are a trust input whose forgery or age
reaches every verdict. Feedback the relying party needs: which facts
hold, at which time they were judged, how fresh the anchors and
evidence are, and which signatures were not judged.

| Id | Controller | Unsafe control action | Hazard | Constraint |
|---|---|---|---|---|
| UCA-105 | Verifier | Uses a timestamp's time as the validation time when the timestamp's authority is not anchored. | H-8 | CC-109: only an anchored token sets the validation time; others are reported unproven. |
| UCA-106 | Verifier | Omits a signature or document timestamp it could not read from the report. | H-8 | CC-110: every signature dictionary, XAdES signature and counter-signature, signature timestamp and document timestamp found is reported. A signature the verifier cannot read is a row marked unsupported and blocks the document verdict; a counter-signature, of any verdict, is a row that decides nothing. A signature timestamp, archive timestamp or document timestamp that fails verification, cannot be computed, or is not anchored is reported with what it was found to be and decides nothing: no proof of existence, no verdict. |
| UCA-107 | Verifier | Reports revocation Good from a live answer while the chain is not verified, or Revoked without the revocation time. | H-8 | CC-111: revocation is reported with its evidence time and judged against the proof of existence; a live answer never upgrades a chain the pool did not verify. |
| UCA-108 | Verifier | Reports a document intact when a reference could not be resolved or canonicalised. | H-8 | CC-112: an unresolvable reference fails the fact. |
| UCA-109 | Shell | Renders a verdict from anchors or lists that are stale without saying so. | H-8 | CC-113: the report carries the anchors' fetch time; the shell shows it. |
| UCA-110 | Verifier | Judges a signature under a trust anchor outside the period its service status was granted. | H-8 | CC-114: anchors carry granted periods and are matched at the validation time. |
| UCA-111 | Shell | Renders a claimed signing time, a claimed timestamp time, or the signer an unjudged row names as established. | H-8 | CC-115: claims are typed apart from proofs: the claimed signing time and a token's claimed time are their own accessors, never the proof of existence, and an unjudged row's signer sits only in the unsupported outcome; the shell labels each a claim. |
| UCA-112 | Trusted-list reader | Takes anchors from a list whose signature is not by a certificate entitled to sign it: a forged or substituted list of the lists or national list. | H-8 | CC-116: a list yields nothing until its enveloped signature verifies under the pinned Commission certificates (the list of the lists, as the Official Journal notice publishes them) or the pointer's certificates (a national list), the signer compared byte for byte; the list of the lists is the only source of a national list's signers. The `ds:SignedInfo` carries exactly two references, any other count refused before anything is computed, and its signature is verified before any reference digest, so a forged list costs one signature verification. |
| UCA-113 | Shell | Renders a verdict from anchors taken from a list past its next update without saying so. | H-8 | CC-117: the reader types staleness from `NextUpdate`; the anchors carry the earliest one and the report says whether it has passed; the shell shows it with the fetch time and fetches again. |
| UCA-114 | Trusted-list reader | Anchors a service at a time its status did not grant: a withdrawn service, or one before it was granted. | H-8 | CC-118: the granted periods are derived from the current status and the whole history in time order, closed at the first status that does not grant, an entry of another service type included; at one instant the most recent status counts last; a Directive 1999/93/EC status grants only a certificate service and only until 1 July 2016; a status that grants is named per service type, and a service never granted yields no anchor. |
| UCA-115 | Trusted-list reader | Follows pointers from list to list, or reads a list without bound, so one list controls what is fetched and how much is parsed. | H-8 | CC-119: the list of the lists is followed one level to the national lists and no further; size, pointers, services, history and identity certificates are bounded by named constants and a list beyond one is refused whole. |

Loss scenario: a document carries a self-made timestamp token whose
time lies inside the signer certificate's validity, while the
certificate is in fact revoked since. Without CC-109 the verifier judges
the chain at the token's time and reports valid; with it the token is
unproven, the signature is judged at now, the revocation is found, and
the report says not valid.

Loss scenario: a trusted list is substituted on the wire for one that
lists an attacker's CA as a qualified certificate service. Without
CC-116 the attacker's CA anchors every signature it issues; with it
the substituted list is not signed by a pointer certificate, is
reported unreadable, and the anchors are those of the lists that read.

## References

- ETSI EN 319 102-1 V1.3.1, Procedures for creation and validation of
  AdES digital signatures.
- ETSI EN 319 122-1 V1.3.1, CAdES baseline signatures.
- ETSI EN 319 132-1 V1.3.1, XAdES baseline signatures.
- ETSI EN 319 142-1 V1.2.1 and 142-2 V1.2.1, PAdES.
- ETSI EN 319 162-1 V1.1.1, ASiC baseline containers.
- ETSI TS 119 612, Trusted lists.
- W3C Canonical XML 1.0, Canonical XML 1.1, Exclusive XML
  Canonicalization 1.0, XML Signature Syntax and Processing 1.1.
- RFC 3161, RFC 5652, RFC 5280, RFC 6960, RFC 5754, RFC 5758, RFC 5480,
  RFC 4514, RFC 3986.
- ISO 32000-1, Document management, Portable document format.
