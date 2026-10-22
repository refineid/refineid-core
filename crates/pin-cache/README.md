# refineid-pin-cache

Process-lifetime negative PIN cache.

A PIN a card has already rejected must never be offered to it again: a
second attempt spends another of the card's few retries toward a lock, for
no new information. `PinSafetyCache` remembers, for the life of the
process, which PIN values a given card rejected, and answers `is_rejected`
before software re-offers one -- so a known-bad value is refused locally,
off the card.

The cache never stores a raw PIN. A rejected value is kept only as an
HMAC-SHA-256 fingerprint keyed with fresh per-process random material, so
the marks cannot be correlated across runs and a mark reveals nothing about
the PIN it stands for. Membership is tested in constant time, and the whole
cache -- and each fingerprint -- erases on drop.

The borders are typed. A rejection is keyed by the card's `TokenSerial` and
a `CachedPin`: a sealed trait implemented only for `Pin1` and `Pin2`, so
the PUK is excluded by construction, matching its no-cache-path contract. A
PIN's digits are absorbed into the fingerprint through a scoped borrow,
never handed out, so the cache adds no raw-bytes accessor to a PIN role.

This crate keeps no positive cache and performs no card I/O. Holding a PIN1
the card accepted is the host's, under the
[credential custody](../../docs/security/credential-custody.md) contract: in
process memory from the first card-confirmed success until an invalidation
event, with no idle window or countdown. PIN2 is never held between
operations.
