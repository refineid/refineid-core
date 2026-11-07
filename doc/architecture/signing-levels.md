# Signing levels in release and development builds

The owner's rule, for every platform: a development build may make a
document without long-term validation material; a release build makes
only the long-term level its request asks for, `B-LTA` where the format
has an archive construction (`PAdES`, `ASiC-E` with `CAdES`) and `B-LT`
where it does not yet (`CAdES`, `XAdES`, `ASiC-E` with `XAdES`).

## The switch

`refineid_doc_sign::service::SigningBuild` carries the rule into every
`DocumentRequest`. It is fixed by `debug_assertions`, the build
profile's, and never by a setting, a flag or the environment:

- `SigningBuild::THIS` is `Development` in a build with debug
  assertions and `Release` in one without. A shell passes it in every
  request it builds.
- `SigningBuild::Development` does not exist without debug assertions,
  so release code cannot name it. `Release` is the default.
- Release packaging builds with the release profile and never turns
  debug assertions on for it.

## Release builds

A signature whose requested level cannot be reached is refused with the
reason, and nothing is saved.

- Before the private-key operation, and so before the PIN 2 prompt or
  the phone's consent, `DocumentRequest::check_signer_path` judges the
  signer's certificate path offline at the claimed signing time
  (`material::check_path_reachable`). A path whose next link is neither
  among the request's signer anchors nor behind a CA Issuers address
  can never be completed, and is refused:
  `validation material: signer path: no issuer certificate: certificate
  has no CA Issuers address and is not an approved anchor`. A request
  with no signer anchor at all is refused earlier, by the request
  policy.
- A link behind a CA Issuers address is fetched only after signing,
  with the revocation answers. If that collection, the timestamps or the
  archive timestamp fail then, the signing is refused the same way and
  nothing is written.

## Development builds

The document is saved at the highest level actually reached:

- LTA requested and the archive timestamp lost: `B-LT`.
- The signer's material cannot be collected: `B-T`.
- No timestamp authority answered: `B-B`.

Only a failure to obtain a level's material lowers the level: a
timestamp that cannot be had, or validation material that cannot be
collected. A verified answer that a certificate is revoked is refused
as in a release build, and so is every other failure.

The saved document says what it is in two places:

- The file name carries `-dev-<level>` before its extension
  (`BelowRequestedLevel::file_suffix`), for example
  `report-signed-2026-11-08T10-00-00Z-dev-B-T.pdf`, so it cannot pass
  for a release build's signature. A path the holder chose is marked
  the same way.
- `SignReport::below_requested_level` names the format, the level
  reached, the level a release build requires and the reasons each
  higher level failed. Its display is the line shells show the holder:
  `development build: saved as PAdES B-T, without long-term validation
  material, not the B-LTA a release build requires: <reason>`.

A development build that reaches the requested level saves the
document under its ordinary name, with no such report.

## STPA

Losses and hazards from the record: L-3 (the holder cannot sign and
cannot tell why), L-6 (a relying party acts on a document as validly
signed when it is not), H-5 (a person is shown a state that is not the
system's).

Control structure: the shell asks the signing service for a document at
a level; the service drives the card or the phone, then the timestamp
authorities and the evidence responders, and reports back what it
wrote.

- Unsafe control action: a release build saves a document below the
  requested level, which fails later at archival with no feedback at
  signing time (L-6, H-5). Constraint: in `Release` the service writes
  only at the requested level and otherwise returns the reason.
- Unsafe control action: the holder enters PIN 2 for a signature that
  can never be finished (L-3). Constraint: the offline path check runs
  before the private-key operation.
- Unsafe control action: a development build's document is taken for a
  release build's (L-6, H-5). Constraint: the file name and the report
  both carry the level reached and say development build.
- Unsafe control action: the level rule is changed at runtime
  (L-6). Constraint: the rule is the build profile's, and the
  development variant does not compile into a release build.
