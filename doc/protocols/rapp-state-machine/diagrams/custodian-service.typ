#import "style.typ": *
// custodian_service (section 6).
#set text(font: ("Helvetica Neue", "Helvetica", "Arial"))
#diagram(
  spacing: (36mm, 24mm),
  st((0, 0), <off>, [switched\_off], sub: [pairings kept]),
  st((1, 0), <serving>, [serving], sub: [listener, mode=session,\ BLE; an offer may be up]),
  st((2, 1), <nr>, [not\_running], kind: "quiet"),
  st((0, 1), <wd>, [withdrawing], sub: [withdrawn record,\ 2 to 10 s]),
  st((1, 1), <lim>, [limited], sub: [BLE only (OS)]),
  tr(<off>, <serving>, [on: fresh instance], label-side: left),
  tr(<serving>, <wd>, [off: withdraw], label-side: left, label-pos: 0.35, shift: 5pt, label-sep: 5pt),
  tr(<wd>, <serving>, [on: fresh instance], label-side: left, label-pos: 0.35, shift: 5pt, label-sep: 5pt),
  tr(<wd>, <off>, [record elapsed:\ unregister], label-side: left),
  edge(<serving>, <serving>, "-|>", lbl[holder starts pairing (no offer up)], bend: 130deg, stroke: 0.6pt + ink, label-fill: white),
  tr(<serving>, <lim>, [limited by OS], shift: 4pt, label-side: left, label-pos: 0.3),
  tr(<lim>, <serving>, [restored: fresh instance], shift: 4pt, label-side: right, label-pos: 0.3),
  tr(<lim>, (1, 1.6), (-0.45, 1.6), (-0.45, 0), <off>, [off: withdraw BLE sessions], label-pos: 0.35),
  tr(<nr>, (2, 0), <serving>, [launch, remote access on], label-pos: 0.6, label-side: right),
)
#align(center, text(6.8pt)[
  Withdraw: cancel any offer, then `service_withdrawn` on every session, stop accepting, withdrawn TXT record in place, then unregister after 2 to 10 s (RAPP §4.5 item 3).\
  Being limited also cancels an offer; quitting withdraws as far as the platform lets it.
  A card available again after `card_unavailable` re-announces `serving` under a fresh instance name.
])
