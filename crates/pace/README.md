# refineid-pace

The PACE secure channel for FINEID cards.

The handshake authenticates the channel with a `PacePassword`: the Card
Access Number of a citizen card, or PIN 1 or PIN 2 of an organizational
card. A CAN is printed on the card, but it is sensitive access data
because it enables PACE access to the chip; the validated `Can` is
opaque, non-clonable, and zeroizing, and the handshake consumes it
through a crate-private path. A PIN's PACE key is derived in
`refineid-auth`, which owns the digits, and a PIN password passes the
retry floor before any try can be spent.

`read_card_access` parses EF.CardAccess into the PACE suites the card
publishes. `run_pace` drives `id-PACE-ECDH-GM-AES-CBC-CMAC-256` over the
domain parameter it picks there -- NIST P-384, brainpoolP384r1, or NIST
P-256 -- and returns the session keys; `SmTransport` wraps a raw
transport with those keys and is itself a card transport, so the layers
above it stay unaware of the protection and credential commands stay
consumed exactly once end to end.

The curve arithmetic comes from the RustCrypto `p256`, `p384` and
`bp384` crates, whose scalar multiplication is constant time; the crate
here holds only the SEC1 encoding border and the handshake's use of it.
The symmetric primitives carry the NIST AES and CMAC known-answer
vectors. The suites, passwords and retry floor are in
[PACE](../../doc/reference/pace.md). The full four-round handshake is
validated on hardware before being described as working.

Constraints and flow are traced to BSI TR-03110-3,
[ICAO Doc 9303](https://www.icao.int/publications/doc-series/doc-9303),
RFC 5639, NIST SP 800-186, and the
[DVV FINEID specifications](https://dvv.fi/en/fineid-specifications).
