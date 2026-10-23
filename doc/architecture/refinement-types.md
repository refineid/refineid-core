# Refinement types

This is the type discipline of the core: what a refinement type is, what
a byte buffer may and may not be, and how data from outside the trust
domain becomes typed meaning. The [migration policy](core-migration.md)
defines trust by construction and the numeric policy; this document
rationalizes them into principles a designer can apply and a reviewer can
check. Where the two disagree, the migration policy wins and this
document has a bug to fix.

## A type is a predicate

A refinement type is a base type together with a predicate that holds for
every value of the type. Rust has no predicate language, so the core
encodes the predicate as a smart constructor: the predicate is checked
once, at construction, and privacy makes the encoding sound -- fields are
private, there is no other constructor, so no value of the type exists
that did not pass the check. Every value is therefore a proof that its
predicate holds, and holding one is the only authorization downstream
code needs.

The contrapositive matters just as much: a wrapper whose constructor
cannot fail asserts the empty predicate. It refines nothing, proves
nothing, and is not a refinement type -- it is ceremony, and ceremony is
reviewed as a defect exactly like rawness.

The aim is Milner's: a well-typed program cannot "go wrong" -- extended
here from memory safety to protocol safety. In Saraswat's phrasing, a
language is type-safe when the only operations that can be performed on
data are those sanctioned by the type of the data; the core designs every
type so that the sanctioned operations are exactly the safe ones. A PIN2
cannot reach the PIN1 slot because no function accepts it there; a
credential command cannot be replayed because transmitting it consumes
it; a certificate's raw bytes cannot be consulted past the border because
no accessor returns them. When the sanctioned set equals the safe set,
the compiler carries the security argument, and a whole class of protocol
mistakes stops being a runtime risk and becomes a build failure.

## Validated at the border, trusted after

Data is validated where it crosses the trust border, once, and is trusted
totally thereafter. No sprinkled re-checks, no defensive re-validation,
no "just in case" -- downstream code computes with the typed value as
proven fact.

This total trust is not optimism; it is what licenses the border to be
strict, and it cuts both ways:

- The border validator must be total. It checks every invariant the
  specification states for the data, because every consumer everywhere is
  entitled to rely on all of them. Rigor concentrates at one point
  instead of diffusing into scattered checks that each cover a fraction.
- A downstream check of an already-validated value is a policy violation,
  whichever way it resolves. Either it duplicates a perfect validator --
  noise that misleads a reader about where trust begins -- or it reveals
  the validator has a hole, which is a border defect to fix at the
  border, not to patch at the point of use.

When a validator turns out to be incomplete, the fix goes into the
constructor, and the type system guarantees the fix covers every value in
the program: there is no other way to become one.

## Every byte is meaning, transit, or citation

All bytes in the core are in exactly one of three states:

- **Meaning.** Deconstructed into a domain type whose fields are typed
  values with checked predicates. This is the resting state: what the
  rest of the program computes with.
- **Transit.** Raw bytes moving between the outside world and exactly one
  constructor or one serializer: a response body still in flight, an
  `Unvalidated*` input awaiting its constructor, a wire buffer just
  assembled for the transport. Transit is short-lived and directional; it
  is never stored inside a domain type and never flows back out of one.
- **Citation.** A single named constant holding an opaque, externally
  specified block -- a known-answer vector, a registered identifier, an
  object identifier -- with the source it locks. Its bytes have no
  separable per-byte meaning for this software, which is the only reason
  they may stay a block.

A public field or accessor that exposes a byte buffer fitting none of
these states is a defect. "It is just bytes" is never true of protocol
data: a certificate, an answer-to-reset, a command, a key are structures
whose every byte the specification assigns meaning, and the type must
carry the meaning, not the buffer.

## Nothing raw beside the typed

A domain type does not retain the bytes it was parsed from -- not
borrowed, not copied, not "for convenience". Keeping the input beside the
meaning stores an unaudited copy of the outside world inside the trust
domain and invites downstream code to reach past the proof back into the
raw.

When a consumer needs the wire form of a validated value, it is
re-serialized from the typed meaning. Canonical encodings make this
exact, and a round-trip test pins it. The unvalidated input is consumed
by its constructor and destroyed.

## Deconstruct to the depth of meaning

The right depth is set by two questions: which invariants does the
specification state, and which decisions does this software take on the
inner structure. Both set a floor; neither excuses going shallower, and
going deeper than either requires is ceremony.

- An RSA public key is consulted -- its modulus width sizes buffers, its
  integers build platform key blobs -- so it deconstructs to a typed
  modulus and exponent whose predicates (minimal, positive, an odd
  exponent) are checked at the border.
- A signature the card produces travels outward to a verifier and is
  never consulted, so its refined form is an algorithm-typed container
  whose one predicate -- the length the algorithm fixes -- is checked.
  Splitting it further would assert nothing this software relies on.
- Parsing machinery -- the BER walker and its borrowed views -- is not a
  domain type and may traverse raw bytes internally. What machinery emits
  to a consumer must be reconstructed meaning.

## Types may depend on values -- with reason

A dependent type lets a type mention a value. Rust approximates the idea
three ways, and the core uses all three where they carry weight: an array
sized by a named constant, so a length lives in the type; a marker
parameter standing for a domain value, as in an algorithm-typed
container, so mixing algorithms is a compile error; and typestate, where
an operation exists only on the state that permits it, as in the
consumed-once credential command.

The judgment line is where the value is decided:

- **Fixed by the specification at design time** -- a digest width, a
  curve's coordinate width, a template byte per algorithm. Lift it into
  the type. A SHA-256 digest is an array of its named width, not a vector
  with a length check; handing the wrong algorithm's value to a consumer
  should fail to compile, not fail at runtime. Leaving a statically-known
  value dynamic discards a free proof and re-scatters the checks this
  discipline exists to concentrate.
- **Decided by the world at runtime** -- a modulus width the card chose,
  a counter the card reports. Keep it a field whose predicate the border
  constructor checked. Forcing runtime-varying values to the type level
  multiplies the API into generic machinery that proves nothing the
  software relies on.

Overkill and undercooking are the same mistake in opposite directions:
type-level machinery nothing depends on is ceremony, and a runtime check
for a value the specification fixed is a proof thrown away.

## No ducks at the border

Duck typing admits any value that has the right shape -- if it walks
like a duck and quacks like a duck, it is a duck. This discipline is its
negation: suitability is proven by identity, not by shape, because at a
trust border the dangerous impostors quack perfectly. A PIN, a serial,
a digest, and a certificate all quack alike -- they are all byte-like --
and a shape-typed API cannot tell them apart.

The Rust spelling of a duck at the border is a byte-likeness bound: a
border or domain function generic over anything convertible to bytes,
where a nominal type belongs. Such a signature says "any duck welcome"
and erases exactly the provenance the refinement types exist to carry. A
border function takes the explicitly unvalidated boundary type; a domain
function takes the refinement type whose predicate it relies on. Then a
wrong argument is a compile error and the proof-of-origin travels with
the value.

Genericity is not the enemy -- shape is. A trait in Rust is nominal: a
transport implements the card-transport port by declaration, and that is
a designed contract, not a duck. Machinery below the domain layer may be
generic over raw bytes it is deconstructing. The rule bites exactly at
the border and in the domain, where what a value *is* matters more than
what it can be converted into.

## Secrets are custody, not data

A secret's type is a custody contract, defined in
[credential custody](../security/credential-custody.md): private fields,
zeroize on drop, no clone, no copy, no serialization, no raw debug
rendering, and consumption through an at-most-once path to the wire.
After reconstruction a secret has no raw accessor at all. Anything
derived from a secret -- a fingerprint, a padded block, a wire form -- is
produced inside the crate that owns the secret, through a crate-private
path, never by exporting the bytes for someone else to process.

## The checker is a floor

The magic-number gate, the compiler, clippy, and the tests detect
mechanical failures. Passing them is necessary and never sufficient: none
of them can tell a predicate-carrying type from a costume. When a rule in
this document seems to block a sensible design, the resolution is to
re-derive the design from the specification and the trust topology --
never to find a rename, wrapper, encoding, or attribute that quiets the
check while keeping the design. A change that satisfies a rule's letter
against its purpose is a defect, and openly stating the tension is always
the right move when the policy itself seems wrong.

## Review questions

Asked of every public type and function in a slice, at design time and at
review:

1. Where do these bytes come from, and where is that border's single
   constructor?
2. Which specification sentence states each predicate the constructor
   checks -- and is each checked exactly once, nowhere else?
3. Does any field or accessor expose raw bytes? Which of the three states
   is that buffer in -- and if transit, who consumes it, exactly once?
4. Does the type retain what it was parsed from, or can it re-serialize
   from meaning?
5. Can a consumer construct or mutate the type without passing the
   constructor?
6. For a secret: clone, copy, debug, serialization, raw accessor -- all
   absent? Zeroized on drop? Consumed once on its way to the wire?
7. Is anything here ceremony -- a constructor that cannot fail, a type
   that asserts the empty predicate?
8. Is a value the specification fixes carried as a runtime check that
   could be a compile-time proof -- or is there type-level machinery
   proving something nothing relies on?
9. Does any border or domain signature accept byte-likeness -- a
   conversion bound, a generic byte parameter -- where a nominal
   unvalidated or refinement type belongs?

## Case studies

- [Why `<alloc::vec::Vec>::insert` is bad code in high-assurance systems](case-study-refinement-types-vec-insert.md)
  -- detailed analysis of partial functions, operational semantics (progress & preservation),
  eliminating unit/semantic mismatches, and refined collections.
