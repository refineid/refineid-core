#import "style.typ": *
// requester_remote_use (section 4).
#set text(font: ("Helvetica Neue", "Helvetica", "Arial"))
#diagram(
  spacing: (30mm, 22mm),
  st((0, 0), <off>, [switched\_off], sub: [local reader only]),
  st((1, 0), <on>, [switched\_on], sub: [code entry, or the\ pairing and its view]),
  st((2, 0), <search>, [searching], sub: [code being tried]),
  st((0, 1), <notrun>, [not\_running], kind: "quiet"),
  st((1, 1), <susp>, [suspended], sub: [local card; withdrew]),
  tr(<off>, <on>, [on], shift: 3pt, label-side: left),
  tr(<on>, <off>, [off: forget], shift: 3pt, label-side: left),
  tr(<on>, <search>, [code typed], shift: 3pt, label-side: left),
  tr(<search>, <on>, [stored, failed], shift: 3pt, label-side: left),
  tr(<on>, <susp>, [card in], shift: 6pt, label-side: left, label-sep: 6pt),
  tr(<susp>, <on>, [card out], shift: 6pt, label-side: left, label-sep: 6pt),
  tr(<search>, (2, 1), <susp>, [card in], label-pos: 0.25, label-side: left),
  tr(<off>, <susp>, [on, local card], label-pos: 0.35, label-side: right),
  edge(<on>, <on>, "-|>", lbl[last pairing ended], bend: 130deg, stroke: 0.6pt + ink, label-fill: white),
  tr(<notrun>, <off>, [launch, switch off], label-side: left),
  tr(<susp>, <notrun>, [quit], label-side: left),
)
#align(center, text(6.8pt)[
  _off: forget_ also leaves `searching` and `suspended`, each with the one bounded revocation attempt; a local card present does not stop it.\
  _quit_ leaves every running state for `not_running`; from `switched_on` it first sends `service_withdrawn`, waiting at most 1 s.
  A launch restores the stored switch: `switched_on` or `suspended` as the local card says, `switched_off` otherwise.
])
