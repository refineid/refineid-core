#import "style.typ": *
// Pairing, both sides (rapp-state-machine-v26.11.8.yaml, `pairing`).
#set text(font: ("Helvetica Neue", "Helvetica", "Arial"))
#let w = 34mm
#diagram(
  spacing: (22mm, 14mm),
  st((0, 0), <unpaired>, [unpaired], width: w),
  st((1, 0), <offering>, [offering], sub: [custodian only], width: w),
  st((2, 0), <exch>, [exchanging], sub: [CPace], width: w),
  st((2, 1), <hs>, [handshaking], sub: [Noise_XXpsk3], width: w),
  st((2, 2), <conf>, [confirming], sub: [hello, confirm], width: w),
  st((1, 2), <store>, [storage\_confirming], sub: [awaiting the peer's], width: w),
  st((0, 3), <pd>, [paired\_disconnected], width: w),
  st((2, 3), <pc>, [paired\_connected], width: w),
  st((0, 4), <rk>, [revoking], sub: [key kept for the close], width: w),
  st((2, 4), <rd>, [revoked], width: w),
  tr(<unpaired>, <offering>, [start], shift: 3pt, label-side: left),
  tr(<offering>, <unpaired>, [expired], shift: 3pt, label-side: left),
  tr(<offering>, <exch>, [attempt], shift: 3pt, label-side: left),
  tr(<exch>, <offering>, [failed], shift: 3pt, label-side: left),
  tr(<unpaired>, (0, -0.65), (2, -0.65), <exch>, [requester: code typed], label-pos: 0.5, label-side: left),
  tr(<exch>, <hs>, [key confirmed], label-side: right),
  tr(<hs>, <conf>, [authenticated], label-side: right),
  tr(<conf>, <store>, [both confirmed], label-side: right),
  tr(<store>, <pd>, [peer stored], label-side: left, label-pos: 0.55),
  tr(<store>, (1, 1), (0, 1), <unpaired>, [another pair\_id, deadline], label-pos: 0.5, label-side: right),
  tr(<conf>, (2.55, 2), (2.55, -0.95), (-0.5, -0.95), (-0.5, 0), <unpaired>, [abort, deny, timeout, store failed], label-pos: 0.5, label-side: right),
  tr(<pd>, <pc>, [session healthy], shift: 3pt, label-side: left),
  tr(<pc>, <pd>, [session closed], shift: 3pt, label-side: left),
  tr(<pd>, <rk>, [forget, idle expiry], label-side: right),
  tr(<pc>, <rd>, [custodian forget: close now], label-side: left),
  tr(<rk>, <rd>, [close sent or echoed; time bound], label-side: left),
)
#align(center, text(6.8pt)[
  _both confirmed_: the record is stored and `pairing.stored` sent. A failed handshake also returns `handshaking` to `unpaired`.\
  _close sent or echoed_: a custodian once its close was sent and the wait for the echo ended, a requester on the echo alone.\
  _time bound_: on a custodian `revocation_notice_days` after the forget, on a requester `pairing_idle_expiry_days` after the latest session.\
  A requester's forget in session goes to `revoking` too, with the close sent at once.
  _idle expiry_ leads to `revoking` on a custodian only; a requester's goes straight to `revoked`, silently.
  A peer's `pairing_revoked` moves any paired state to `revoked`.
])
