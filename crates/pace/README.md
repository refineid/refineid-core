# refineid-pace

The PACE secure channel for FINEID cards.

A CAN is printed on the card, but it is sensitive access data because it
enables PACE access to the chip; the validated `Can` is opaque,
non-clonable, and zeroizing, and the handshake consumes it through a
crate-private path. `run_pace_with_can` drives
`id-PACE-ECDH-GM-AES-CBC-CMAC-256` over brainpoolP384r1 and returns the
session keys; `SmTransport` wraps a raw transport with those keys and is
itself a card transport, so the layers above it stay unaware of the
protection and credential commands stay consumed exactly once end to end.

The brainpoolP384r1 arithmetic comes from the RustCrypto `bp384` crate,
whose scalar multiplication is constant time; the crate here holds only
the SEC1 encoding border and the handshake's use of it. The symmetric
primitives carry the NIST AES and CMAC known-answer vectors.
The full four-round handshake is validated on hardware before being
described as working.

Constraints and flow are traced to BSI TR-03110-3,
[ICAO Doc 9303](https://www.icao.int/publications/doc-series/doc-9303),
RFC 5639, and the
[DVV FINEID specifications](https://dvv.fi/en/fineid-specifications).
