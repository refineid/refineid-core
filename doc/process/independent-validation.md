# Independent validation gate

Our own tests ask our own code what level it made, so a wrong rule in
the code passes them. This gate asks someone else: every document format
the core writes is signed the way a release build signs it, and the EU
DSS library, the European Commission's reference validator and the one
behind DVV's validation service, judges the result.

## The rule it enforces

The owner's rule: a release build saves only a long-term archival
signature. For every format the gate requests `B-LTA` with
`SigningBuild::Release` and requires DSS to report

| Format | DSS signature format | DSS container |
|--------|----------------------|---------------|
| `PAdES` | `PAdES-BASELINE-LTA` | none |
| `ASiC-E` with `XAdES` | `XAdES-BASELINE-LTA` | `ASiC-E` |
| `ASiC-E` with `CAdES` | `CAdES-BASELINE-LTA` | `ASiC-E` |
| `CAdES`, content attached | `CAdES-BASELINE-LTA` | none |
| `CAdES`, detached | `CAdES-BASELINE-LTA` | none |

with indication `TOTAL_PASSED` under DSS's default validation policy.
It then requires this crate's verifier to agree: one valid signature,
an anchored signature timestamp, and an anchored archive timestamp (a
`PAdES` document timestamp over the signature, or the `CAdES` or `XAdES`
archive timestamp). The detached `CAdES` file has no entry point in this
crate's verifier, so DSS alone judges it.

A release build that refuses the request fails the gate as surely as a
document DSS grades lower: a format is done only when DSS reports its
`B-LTA` level. Where [signing-levels.md](../architecture/signing-levels.md)
still names `B-LT` for a format, the gate stays red for it until the
format reaches `B-LTA`. Do not weaken the expectation to make it pass.

## What runs

- `crates/doc-sign/tests/dss_gate.rs`, one test per format. The signer
  is a scripted paired phone holding a synthetic card key, through
  `remote::sign_on_phone` and the finish every shell shares. A synthetic
  PKI answers every request in memory through `http::set_http_transport`:
  a root, an issuing CA with an OCSP responder that echoes the nonce, a
  timestamp authority, the root's CRL and the issuing CA's certificate
  behind the signer's CA Issuers address. Its host is under `.test`; no
  request leaves the process.
- `tools/dss-gate/DssGate.java`, a small validator on `dss-validation`:
  the synthetic root is its only trusted certificate, no trusted list is
  loaded, and its AIA, OCSP and CRL sources are off, so DSS judges only
  what the document carries. It prints the format, indication,
  sub-indication, errors and warnings of each signature and the
  container type.
- `tools/dss-gate/dss.lock` pins DSS 6.5.1 (Maven Central, group
  `eu.europa.ec.joinup.sd-dss`, released 2026-10-14) and its runtime
  closure, one SHA-256 per jar.
- `scripts/dss-gate.sh` fetches any jar the cache lacks from Maven
  Central and refuses it unless its SHA-256 matches the lock, compiles
  the validator into `target/dss-gate/`, and runs the tests with
  `REFINEID_DSS_JAVA` and `REFINEID_DSS_CLASSPATH` set. Without those
  variables every test fails; plain `cargo test` does not build the file
  at all (it needs the `testkit` feature).

## Running it

```sh
sh scripts/dss-gate.sh
```

It needs a JDK 17 or later (`JAVA_HOME`, `/usr/libexec/java_home`,
Homebrew's `openjdk`, or `javac` on `PATH`) and, the first time only,
network access to Maven Central; the jars are kept under
`${XDG_CACHE_HOME:-$HOME/.cache}/refineid/dss-gate`, or
`REFINEID_DSS_CACHE`. After that it runs offline. Arguments go to the test binary, so one
format runs alone:

```sh
sh scripts/dss-gate.sh pades
```

A failure carries DSS's whole report for that document.

## Where it gates

The pre-push floor (`scripts/verify-push.sh`) runs Clippy on the test
target and then the gate. It is not in the pre-commit hook: it starts a
Java runtime per format and the first run downloads the validator, which
the commit gate's fast source checks must not depend on.

## Updating DSS

Resolve the new release's runtime closure for the modules the lock
header names, check each jar against the SHA-1 Maven Central publishes
beside it, and replace the lock's lines and its header's version and
date in one change. Never edit a digest by hand to match a download.
