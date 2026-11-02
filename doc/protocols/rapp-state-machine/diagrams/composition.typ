#import "style.typ": *
// How the machines compose (section 3).
#set text(font: ("Helvetica Neue", "Helvetica", "Arial"))
#let box2(pos, name, title, body) = node(pos,
  align(left)[#text(8pt, weight: "bold")[#title]\ #text(6.8pt)[#body]],
  name: name, shape: fletcher.shapes.rect, corner-radius: 4pt, inset: 6pt, width: 62mm,
  fill: fillstate, stroke: 0.7pt + accent)
#diagram(
  spacing: (40mm, 9mm),
  node((0, -0.7), text(9pt, weight: "bold", fill: accent)[REQUESTER (computer, iPad, Android tablet)], stroke: none),
  node((1, -0.7), text(9pt, weight: "bold", fill: accent)[CUSTODIAN (phone with NFC)], stroke: none),
  box2((0, 0), <ru>, [requester\_remote\_use — one], [switched\_off · switched\_on · searching · suspended · not\_running]),
  box2((1, 0), <c>, [custodian\_service — one], [switched\_off · serving · withdrawing · limited · not\_running]),
  box2((0, 1), <q>, [requester\_view\_of\_custodian — one, while on with a pairing], [idle · connecting · connected · withdrawn · ended]),
  box2((0, 2), <pr>, [pairing], [unpaired … paired\_disconnected · paired\_connected · revoking · revoked]),
  box2((1, 2), <pc>, [pairing — one per stored pairing; the holder's list], [unpaired … paired\_disconnected · paired\_connected · revoking · revoked]),
  box2((0, 3), <sr>, [session — one per connection], [absent · connecting · authenticating · healthy · closing · closed]),
  box2((1, 3), <sc>, [session — one per connection], [absent · authenticating · healthy · closing · closed]),
  edge(<ru>, <q>, "-|>"), edge(<q>, <pr>, "-|>"), edge(<pr>, <sr>, "-|>"),
  edge(<c>, <pc>, "-|>"), edge(<pc>, <sc>, "-|>"),
  edge(<c>, <q>, "-|>", text(6.6pt)[discovery records,\ BLE advertisement], stroke: (paint: silent, dash: "dashed"), label-side: left, label-pos: 0.5, label-sep: 8pt),
  edge(<pr>, <pc>, "<|-|>", text(6.6pt)[pairing channel], stroke: 1.4pt + ink),
  edge(<sr>, <sc>, "<|-|>", text(6.6pt)[Noise\_KK session], stroke: 1.4pt + ink),
)
