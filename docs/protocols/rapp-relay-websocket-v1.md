# RAPP Transport Profile: `relay-websocket-v1`

Status: Companion draft to RAPP 26.9.13 (external-review draft)
Intended status: Experimental
Document version: 26.9.26
Date: 2026-09-26
Change controller: RefineID project

## 1. Overview

`relay-websocket-v1` carries RAPP frames between a requester and a proxy
that cannot reach each other directly. Both peers open a WebSocket leg to
an untrusted relay; the relay joins the two legs by a token and then
forwards opaque frames. It is the first RAPP profile reachable from a web
browser, which can only dial out: the implemented `fi.refineid.stream.v1`
profile requires the requester to run a listener, which a page or an
extension cannot do.

This document is read together with the base draft
(`rapp-v26.9.13.md`). Section numbers below without a document name refer
to it. On the next base-draft revision this profile folds into Section 16
as Section 16.2; until then the Section 16 registry points here.

The key words MUST, MUST NOT, REQUIRED, SHALL, SHALL NOT, SHOULD, SHOULD
NOT, RECOMMENDED, NOT RECOMMENDED, MAY, and OPTIONAL are to be interpreted
as described by BCP 14 when they appear in capitals.

## 2. Underlay

The underlay is WebSocket as defined by RFC 6455. Legs MUST use `wss`
(TLS); plain `ws` MUST NOT be used. TLS contributes no RAPP security
(Section 5): it hides frame contents from passive network observers and,
decisively for browser requesters, a secure-context page cannot open
plain `ws://` legs at all, since blockable mixed content is defined as
all mixed content that is not upgradable.

One RAPP frame travels as exactly one WebSocket binary message. A binary
message larger than `NOISE_MAX_MESSAGE` (65,535 bytes) is malformed. A
WebSocket text message, ping/pong aside (handled by the underlay
automatically), is malformed input. Message boundaries carry no meaning
beyond framing: segmentation or coalescing by any party except the
one-frame-per-message rule is a violation.

## 3. Candidate parameters

The offer's `transport-candidate.parameters` map for this profile is:

```cddl
relay-parameters = {
  "relay_url": tstr    ; wss:// URL of the relay, no query or fragment
}
```

`candidate_id` is chosen by the requester per offer (Section 9.2) and
stored with the pairing. The proxy stores the selected candidate,
including `relay_url`, at pairing confirmation and dials it for later
sessions. A requester whose relay URL has changed since pairing is
unreachable until the user pairs anew; the profile prefers breakage to
silent endpoint changes, as in Section 16.1.

## 4. Leg lifecycle

Each peer opens one WebSocket leg to `relay_url` and then:

1. Sends exactly one join frame as its first binary message, the
   deterministic-CBOR encoding of:

   ```cddl
   relay-join = [
     "RAPP-relay-v1",
     tstr,    ; purpose: "pairing" / "session"
     tstr,    ; role: "requester" / "proxy"
     bstr     ; purpose "pairing": offer_id, Section 9.2 (16 bytes)
              ; purpose "session": rendezvous_token, Section 8.5 (16 bytes)
   ]
   ```

2. Waits for exactly one joined signal, the binary message carrying the
   deterministic-CBOR encoding of `["RAPP-relay-joined-v1"]`. The relay
   sends it to each leg once the legs are matched (Section 7). A leg
   MUST NOT send anything after its join frame until it has received the
   joined signal.

3. After the joined signal, sends RAPP handshake and envelope frames as
   binary messages and receives the peer's. The relay forwards bytes
   verbatim in both directions and MUST NOT parse post-join frame
   contents.

4. On close of either leg the relay closes the other leg and deletes all
   token state for the match (Section 7).

Logical Noise roles are unchanged: the requester initiates every
handshake over the joined pipe, regardless of which leg connected first.

## 5. Pairing over the relay

For purpose `pairing`, both peers dial with `offer_id` derived from the
6-digit code (Section 9.2). The relay joins the two legs whose join
frames carry equal `offer_id` values with complementary roles. The peers
then run the pairing Noise handshake of Section 9.3 with the code-derived
`pairing_secret` as `psk3`, the Section 8.3 prologue naming transport
profile `relay-websocket-v1`, and empty handshake payloads.

### 5.1 Manual-code pairing without URI transport

Section 9.2 permits the offer to travel as a `rapp:` URI. Deployments
that pair from the 6-digit code alone (no URI, no QR) cannot learn the
offer map out of band, yet both peers must construct the identical
`pairing-offer` map for `offer_hash`. Such deployments MUST use this
fixed offer template, with only `offer_id` varying per pairing:

```cddl
relay-offer-template = {
  "scheme": "rapp",
  "version": [uint, uint, uint],   ; current wire version triple
  "offer_id": bstr .size 16,       ; derived from the code, Section 9.2
  "pairing_secret": bstr .size 32, ; derived from the code, Section 9.2
  "suites": ["Noise_XXpsk3_25519_ChaChaPoly_SHA256"],
  "profiles": [                    ; fixed login + signing set
    "fi.refineid.authentication.v1",
    "fi.refineid.document-signing.v1"
  ],
  "transports": [{
    "profile": "relay-websocket-v1",
    "candidate_id": "relay",
    "parameters": { "relay_url": tstr }  ; deployment default, both peers
  }],
  "offer_ttl_ms": 120000
}
```

`offer_ttl_ms` (120,000) is within `OFFER_TTL_MAX` (180,000). Both peers
clamp it to local policy per Section 9.2. The `relay_url` is a
deployment-configured default known to the requester (site or extension
configuration) and the proxy (application configuration).

NOTE: the Section 9.2 CDDL shows `"version": [uint, uint]`, while the
26.9.13 vectors and the Rust engine encode three components (e.g.
`[26, 9, 13]`). The template follows the vectors. This discrepancy needs
a draft-maintainer ruling at rollup.

A deployment needing other suites, profiles, relay URLs, or TTLs MUST
transfer the full `rapp:` URI (Section 9.2) instead of relying on this
template. Grant selection at confirmation (Section 9.3, step 7) is
unaffected: the template fixes what is offered, the proxy user still
chooses what is granted.

## 6. Session over the relay

For purpose `session`, both peers dial with the stored
`rendezvous_token`. The relay joins complementary-role legs with equal
tokens. The requester then initiates the mandatory `Noise_KK` handshake
(Section 10) with the session prologue naming `relay-websocket-v1`.

The requester initiates the session leg only after explicit user or
application action (Section 10). The proxy learns of a pending session
only through its own explicit action or an opaque push wake hint (Section
17); the relay MUST NOT encode pairing, peer, or operation identity in
the hint. The single-session `busy` rule of Section 10 applies unchanged:
a second session attempt for a pairing with a live session completes its
handshake and receives an authenticated `error` named `busy`.

## 7. Relay behavior

The relay implements Section 17 and additionally MUST:

- match legs only on exact token equality with complementary roles and
  equal purpose; compare tokens in constant time;
- hold an unmatched leg until `JOIN_TIMEOUT_MS` (60,000) and then close
  it with no signal; behave identically whether or not a counterpart
  exists, so the relay is not an existence oracle for tokens;
- close a newcomer leg with no signal when its token already has two
  legs or a same-role leg;
- send exactly one joined signal per leg upon matching, then forward
  every subsequent binary message on each leg to the other leg,
  unmodified and in arrival order per leg;
- enforce deployment-configured limits before buffering: joins per
  source, concurrent legs per token and total, and maximum message size;
- close both legs when either closes, and delete all state for the
  match (tokens, leg bindings, counters) on close or expiry;
- never emit bytes on a leg except the single joined signal; in
  particular never signal why a leg was closed.

The relay never interprets post-join frames and holds no RAPP keys, so
it cannot emit authenticated errors: all failure signaling happens
between the peers inside the Noise channel or by leg closure.

## 8. Error mapping

The following are pre-authentication invalid input (Section 14.5,
class 1): the relay closes only the offending leg and changes no stored
state (its own or any peer's): malformed CBOR, unknown purpose or role,
wrong token length, a second join frame, any frame before the joined
signal other than the join frame, a text message, or an oversize binary
message.

Post-join byte corruption surfaces at the endpoints as established-channel
integrity failure (Section 14.5, class 2), exactly as on any transport.
Classes 3 through 6 are transport-independent and unchanged.

## 9. Security considerations

- The pairing token `offer_id` derives from a 6-digit code: about 20
  bits, enumerable offline. Security rests on online-only verification:
  testing a guess requires a full handshake attempt through the relay,
  the requester processes at most one handshake per offer at a time
  (Section 9.3), and the relay MUST rate-limit joins per source and per
  token. Short offer TTLs keep the guessing window small.
- Possession of a token lets an attacker hold a relay leg and elicit at
  most the first handshake message of the corresponding pattern (an
  ephemeral public key for `Noise_KK`; nothing peer-identifying), and
  lets a network observer link the two legs of one match. It enables
  nothing else. Tokens are computationally unlinkable to `pair_id`
  without the handshake hash (Section 8.5).
- End-to-end encryption does not hide timing, endpoints, connection
  duration, or approximate message size from the relay (Section 17).
  TLS hides frame contents from passive network observers only.
- The fixed offer template (Section 5.1) binds every pairing to the
  mandatory suite and the login + signing profile set through
  `offer_hash`. Downgrade to weaker suites or narrower profiles through
  template confusion is impossible without breaking the handshake.

## 10. Conformance and vectors

An implementation claiming this profile MUST implement Sections 2
through 9, the mandatory suite (Section 8.1), and at least the
authentication and document-signing credential profiles (Section 13.2).
It MUST identify itself as experimental, as the base draft requires.

The following vectors are REQUIRED before interoperability claims and
will ship with the implementation phase: join/joined encodings (pairing
and session), fixed-template offer reconstruction for a reference code,
`offer_hash` over the template, relay join/timeout/role-collision
behavior, and oversize/text-message rejection. The Section 14 state
machine needs no new states: relay legs are transport connections, and
all listed anomalies map to existing policy classes.

## 11. Rollup

On the next base-draft revision this document folds into Section 16 as
Section 16.2, the Section 16 registry row flips from "defined here" to
"defined in Section 16.2", and the vectors of Section 10 join the
conformance corpus.
