# Two reference implementations, one document

RefineID is deliberately bilingual. The card stack and the RAPP protocol
exist twice: in Rust, in this repository, and in Swift, in
`refineid-apple` (`CardCore`, `RappEngine`). This is a design decision
of the maintainer (recorded 2026-11-07), not an accident of history, and
a reviewer who finds "the same thing implemented twice" there has found
the design working.

## Why

A protocol that exists as one codebase is defined by that code,
accidents included. A second implementation in a different language is
the cheapest way to find out which parts of a protocol are
specification and which are habit: every place the two engines disagree
is a sentence the document had not nailed down. Standards bodies ask for
two interoperating implementations before a protocol is called done for
this reason. Developing against two implementations also generalises the
ideas: what survives translation into both languages is the design, the
rest was an idiom.

## What makes it an asset rather than a cost

- **The document and the vectors are the source of truth, not either
  engine.** The RAPP document (`doc/protocols/rapp-v26.11.2.md`) and
  the FINEID card specifications define the behaviour. The conformance
  corpora under `doc/protocols/vectors/` are derived by
  `tools/rapp-vectors/generate.py` from standard-library primitives,
  never from an engine, and both engines are tested against the same
  files. The Apple repository keeps a byte-identical copy under
  `Documentation/rapp-conformance/`.
- **A wire change is finished when both engines pass the regenerated
  vectors.** Same change, same day, one definition of done. The wire
  version triple is bumped with every change of wire vocabulary (RAPP
  section 10.1 item 4) so that an engine left behind fails at the
  handshake, loudly, instead of half-working.
- **Bilingual where it pays.** The protocol, the cryptography and the
  card commands are implemented twice. Platform glue (user interface,
  key storage, system services) is per platform anyway and gains nothing
  from a second implementation.

## What is not a reference implementation

The Windows repository carries Rust duplicates of the card stack in
`refineid-lib-core` and C# glue for the system APIs. The Rust
duplication is drift without a document behind it, not a second
reference implementation, and it is being retired in favour of these
crates (refineid-windows#212). C# is not a target for a third
implementation of anything the Rust core or the Swift engine already
provides; it stays the thinnest possible layer over the Windows APIs.

Unix and Android build on these crates directly and are not
implementations of the protocol or the card stack in their own right.
