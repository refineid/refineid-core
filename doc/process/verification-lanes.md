# Verification lanes

The checks that run beyond the floor: bounded proofs, fuzzing, refinement
types and symbolic protocol models. They run nightly on the build server,
never in the commit or push hooks, and report on the dashboard and by mail.
A red lane is fixed in the next change that touches the code, like any
other defect; it does not hold a merge on its own.

## Lanes

| Lane | Tool | Input in this repository | Claim it checks |
|------|------|--------------------------|-----------------|
| miri | `cargo +nightly miri test` | the pure parsing crates | the tests execute without undefined behaviour under the interpreter |
| fuzz | cargo-fuzz (libFuzzer) | `fuzz/` targets, one per border constructor | arbitrary bytes never make a constructor panic; round trips hold |
| kani | Kani bounded model checker | `#[cfg(kani)]` harnesses beside each border constructor | the same claims as fuzzing, proved for every input up to a named bound |
| proverif | ProVerif | `doc/protocols/models/*.pv` | RAPP secrecy and authentication properties, each tied to the STPA record |
| tamarin | Tamarin | `doc/protocols/models/*.spthy` | the same properties under a second prover |
| flux | Flux refinement types | `#[cfg_attr(flux, flux::...)]` signatures on border types | the predicate a refinement type carries is enforced by its constructor |

The lane runner, its budgets and the dashboard live in the release
repository's build-server scripts; the provisioning script there installs
every tool under the builder's home. Each tool brings its own pinned
nightly compiler; this repository stays on stable.

## Writing for the lanes

- A Kani harness or fuzz target states one claim about one border
  constructor. Bounds are named constants with a comment saying what they
  bound; the loop unwinding depth is the crate's `default-unwind` in its
  manifest, with a comment naming the bound it derives from, and
  `cargo kani` runs from the crate's directory so that setting is read.
  No example bytes: inputs are `kani::any()` or the fuzzer's.
- Flux is the only in-source annotation dialect. Its attributes are gated
  with `cfg_attr(flux, ...)` so stable rustc never sees them, and a crate
  opts in with `[package.metadata.flux] enabled = true`. Verus (code must
  live inside its macro, a second copy of every function) and Prusti
  (dormant) are not used; Creusot is considered later only if Flux cannot
  express a needed predicate.
- A protocol model follows the stamped specification. Where the engine
  and the specification disagree, the model follows the specification
  and the disagreement is a defect to fix in the engine or a change for
  the owner to stamp.
- A lane that finds a real defect is answered by fixing the constructor
  or the engine in the same change, not by loosening the harness.
