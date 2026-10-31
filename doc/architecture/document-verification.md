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
PDFs, XFA and XAdES signatures inside PDFs, counter-signatures,
inclusive canonicalisation of SignedInfo, and signatures over MD5 or
SHA-1.

## Trust origins and borders

Every input has one origin, one border and one constructor.

| Origin | Border | Meaning after the border |
|---|---|---|
| The file | `DocumentFile::from_file` | Bytes of a known shape: PDF, ZIP, or DER SEQUENCE. Nothing else passes. |
| Trust anchors | `TrustAnchors` | Certificates the relying party trusts for a role (certificate issuing or time-stamping) during a time range. |
| The clock | `now` passed by the caller | The current time, used only where no proven time exists. |
| Validation evidence inside the file | `MaterialPool` | Parsed certificates, OCSP responses and CRLs from the DSS, the CMS, or the container. Each is parsed once, at the border. |

Trust anchors come from two sources the application shell combines
before calling the verifier: the pinned roots the core ships (the DVV
roots and the time-stamping root the signing side uses), and the EU
trusted lists. The list of the lists is verified under the Commission's
list-signing certificates the core pins; each national list is verified
under the certificate the list of the lists names for it; the qualified
certificate-issuing and time-stamping services in each list become
anchors for the periods in which their status was granted. The lists are
fetched and cached by the shell; a verdict uses the cached lists and the
report says when they were fetched. The verifier itself does no network
access.

## What is judged, per signature

For each signature the report carries independent facts:

- **Document intact.** Every byte the signature claims to cover digests
  to the value the signature states. For PDFs this is the ByteRange,
  whose hole must be exactly this dictionary's own Contents and whose
  trailing bytes must be zero padding. For XAdES, every Reference
  recomputes, the SignedProperties reference resolves to this
  signature, and every data file in the container is covered. For
  CAdES in a container, the ASiCManifest references every data file
  and each digest recomputes. A reference the verifier cannot resolve
  or canonicalise fails this fact; it never passes.
- **Signature valid.** The CMS or XML signature verifies under the
  signer's public key, with the digest algorithm taken from the
  SignerInfo, the signature algorithm's hash equal to it, algorithm
  parameters of the shape RFC 5754 and RFC 5758 allow, exactly one
  message-digest attribute of the digest's length, and a signature
  value whose shape fits the key. The ESS signing-certificate binding
  is required for `ETSI.CAdES.detached` and XAdES, and not required for
  `adbe.pkcs7.detached`. A PAdES signature carrying a signing-time
  attribute is not valid. Named curves P-256 and P-384 and RSA with
  SHA-256 or SHA-384 are accepted; explicit curve parameters are
  refused everywhere, including in timestamp, OCSP and CRL signers.
- **Chain verified.** A path from the signer certificate to a trust
  anchor whose role is certificate issuing and whose granted period
  covers the validation time, built offline from the material pool:
  name chaining, signatures, validity at the validation time, basic
  constraints, key usage, path length, no name constraints, depth
  bound. Every certificate below the anchor is checked for revocation.
- **Proof of existence.** The earliest time proven by a timestamp whose
  authority chains to a trust anchor with the time-stamping role: a
  signature-time-stamp attribute over the signature value, a XAdES
  SignatureTimeStamp over the canonicalised SignatureValue, or a PDF
  document timestamp whose ByteRange covers this signature. A token
  verifies under its own TSTInfo imprint algorithm and its signer must
  carry the time-stamping extended key usage, not be a CA, and be valid
  at the token's time. A token whose authority is not anchored is shown
  with its claimed time and marked unproven; it moves nothing.
- **Validation time.** The proof of existence when there is one,
  otherwise now. Chain validity and revocation are judged at this time.
- **Revocation.** From the evidence in the file first: OCSP responses
  and CRLs that verify under an authorised responder or the issuer and
  whose window covers the validation time per EN 319 102-1 clause
  5.2.5. The states are Good with the evidence time, Revoked with the
  revocation time, and Unavailable. A certificate revoked before the
  proof of existence makes the signature not valid; one revoked after
  it does not, because the signature was proven to exist while the
  certificate was good. Without a proof of existence any revocation
  counts. The shell may ask the network only for a signature still
  Unavailable, and that answer is judged at now.
- **Covers whole document.** Whether bytes follow the signed revision.
  Reported, not judged.

A signature is valid when the document is intact, the signature is
valid, the chain is verified at the validation time, and no revocation
before the proof of existence is known. A signature the verifier cannot
read (unsupported profile, algorithm or structure) gets its own row
saying so.

The document is valid when it has at least one signature, every
signature is valid, and no signature is unsupported.

## Signer identity

Given names and surname from the subject, else the common name, with
the serial-number attribute as the identifier when it has the shape of
a Finnish electronic user identifier. The identifier is a type, never a
string beside a flag.

## Failures

A file the verifier cannot judge is a typed failure, not a report: not
a signed document, unreadable with the reason, no signatures, or an
unsupported profile with the reason. A negative verdict is a report.

## STPA

The record in [stpa-rapp.md](../security/stpa-rapp.md) covers card
operations. Verification adds one loss and one hazard.

| Id | Statement |
|---|---|
| L-6 | A relying party acts on a document as validly signed when it is not, or rejects one that is. |
| H-8 | The verifier reports a fact it has not established, or hides a signature or timestamp it has not judged. |

Control structure: the relying party reads the report the application
shell renders from the verifier's facts. The shell supplies the file,
the anchors and the clock, and may fetch live revocation. Feedback the
relying party needs: which facts hold, at which time they were judged,
how fresh the anchors and evidence are, and which signatures were not
judged.

| Id | Controller | Unsafe control action | Hazard | Constraint |
|---|---|---|---|---|
| UCA-105 | Verifier | Uses a timestamp's time as the validation time when the timestamp's authority is not anchored. | H-8 | CC-109: only an anchored token sets the validation time; others are reported unproven. |
| UCA-106 | Verifier | Omits a signature or document timestamp it could not read from the report. | H-8 | CC-110: every signature dictionary and timestamp found is a row; an unjudged one is marked unsupported and blocks the document verdict. |
| UCA-107 | Verifier | Reports revocation Good from a live answer while the chain is not verified, or Revoked without the revocation time. | H-8 | CC-111: revocation is reported with its evidence time and judged against the proof of existence; a live answer never upgrades a chain the pool did not verify. |
| UCA-108 | Verifier | Reports a document intact when a reference could not be resolved or canonicalised. | H-8 | CC-112: an unresolvable reference fails the fact. |
| UCA-109 | Shell | Renders a verdict from anchors or lists that are stale without saying so. | H-8 | CC-113: the report carries the anchors' fetch time; the shell shows it. |
| UCA-110 | Verifier | Judges a signature under a trust anchor outside the period its service status was granted. | H-8 | CC-114: anchors carry granted periods and are matched at the validation time. |

Loss scenario: a document carries a self-made timestamp token whose
time lies inside the signer certificate's validity, while the
certificate is in fact revoked since. Without CC-109 the verifier judges
the chain at the token's time and reports valid; with it the token is
unproven, the signature is judged at now, the revocation is found, and
the report says not valid.

## References

- ETSI EN 319 102-1 V1.3.1, Procedures for creation and validation of
  AdES digital signatures.
- ETSI EN 319 122-1 V1.3.1, CAdES baseline signatures.
- ETSI EN 319 132-1 V1.3.1, XAdES baseline signatures.
- ETSI EN 319 142-1 V1.2.1 and 142-2 V1.2.1, PAdES.
- ETSI EN 319 162-1 V1.1.1, ASiC baseline containers.
- ETSI TS 119 612, Trusted lists.
- RFC 3161, RFC 5652, RFC 5280, RFC 6960, RFC 5754, RFC 5758, RFC 5480.
- ISO 32000-1, Document management, Portable document format.
