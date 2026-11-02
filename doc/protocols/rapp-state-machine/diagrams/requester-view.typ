#import "style.typ": *
// requester_view_of_custodian (section 5).
#set text(font: ("Helvetica Neue", "Helvetica", "Arial"))
#diagram(
  spacing: (34mm, 22mm),
  st((0, 0), <idle>, [idle], sub: [no session, no window]),
  st((1, 0), <conn>, [connecting], sub: [dial running or due;\ redial\_window\_ms]),
  st((2, 0), <connected>, [connected], sub: [the remote card]),
  st((1, 1), <withdrawn>, [withdrawn], sub: [no dial, no offer]),
  st((2, 1), <ended>, [ended], kind: "quiet"),
  tr(<idle>, <conn>, [appeared,\ consumer request], shift: 4pt, label-side: left),
  tr(<conn>, <idle>, [window spent], shift: 4pt, label-side: left),
  tr(<conn>, <connected>, [ready], shift: 4pt, label-side: left),
  tr(<connected>, <conn>, [lost], shift: 4pt, label-side: left),
  edge(<conn>, <conn>, "-|>", lbl[due, failed in window,\ appeared again], bend: 130deg, stroke: 0.6pt + ink, label-fill: white),
  tr(<connected>, <withdrawn>, [withdrawn], label-pos: 0.45, label-side: left),
  tr(<withdrawn>, <conn>, [announced again], shift: 6pt, label-side: right, label-sep: 6pt),
  tr(<connected>, <ended>, [pairing\_revoked], label-side: left),
)
#align(center, text(6.8pt)[
  _lost_: a loss, or a close with `normal`, `complete`, `user_disconnect`, `policy` or `shutdown`; it opens the redial window at once.
  _window spent_: the window ended with no dial running, or a dial failed after it; a protocol violation also returns to `idle`, without redial.
  _withdrawn_: `service_withdrawn` or `card_unavailable` received; a withdrawn record matched in `idle` or `connecting` leads there too.\
  _announced again_: a `mode=session` record, or the BLE advertisement first seen after the withdrawal. A consumer request in `withdrawn` is refused.
  `pairing_left` ends every state.
])
