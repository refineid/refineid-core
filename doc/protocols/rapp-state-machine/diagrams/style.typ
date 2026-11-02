// Shared drawing style for the lifecycle diagrams. A solid arrow is a
// transition of the formal machine; a grey dotted arrow is an event that
// arrives from another machine or from the peer.
#import "@preview/fletcher:0.5.8" as fletcher: diagram, node, edge

#let ink = rgb("#1d2733")
#let accent = rgb("#2f5d8a")
#let silent = rgb("#7a8794")
#let fillstate = rgb("#eef3f8")
#let fillquiet = rgb("#f6f6f6")

#let st(pos, name, label, sub: none, kind: "state", width: 30mm) = node(
  pos,
  align(center)[
    #text(8.5pt, weight: "bold")[#label]
    #if sub != none [\ #text(6.8pt, fill: rgb("#4a5561"))[#sub]]
  ],
  name: name,
  shape: fletcher.shapes.rect,
  corner-radius: 4pt,
  inset: 6pt,
  width: width,
  fill: if kind == "quiet" { fillquiet } else { fillstate },
  stroke: 0.7pt + accent,
)

#set text(font: ("Helvetica Neue", "Helvetica", "Arial"))
#let lbl(body) = text(6.6pt, fill: ink, body)

// Each helper takes the edge's vertices (node names or coordinates) and
// then its label as the last positional argument.
#let _edge(args, label, stroke) = {
  let p = args.pos()
  edge(..p.slice(0, -1), "-|>", label(p.last()), stroke: stroke, label-fill: white, ..args.named())
}
// A transition of the machine.
#let tr(..args) = _edge(args, b => lbl(b), 0.6pt + ink)
// An event raised elsewhere: another machine, the peer, the platform.
#let ev(..args) = _edge(args, b => text(6.6pt, fill: silent, b), (paint: silent, thickness: 0.6pt, dash: "dotted"))
