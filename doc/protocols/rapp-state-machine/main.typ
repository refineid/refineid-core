// Page and type settings for the human edition of
// doc/protocols/rapp-state-machine.md. The text comes from build/body.typ,
// which build.sh converts from the Markdown source.
#let ink = rgb("#1d2733")
#let accent = rgb("#2f5d8a")
#let muted = rgb("#5b6773")
#let rule = rgb("#c9d1d9")

#set document(title: "RAPP v26.11.8 state machine")
#set page(
  paper: "a4",
  margin: (x: 18mm, top: 20mm, bottom: 18mm),
  header: context {
    if counter(page).get().first() > 1 [
      #set text(8pt, fill: muted)
      RAPP v26.11.8 state machine #h(1fr) Stamped, reviewed by the owner
    ]
  },
  footer: context [
    #set text(8pt, fill: muted)
    #h(1fr) #counter(page).display() #h(1fr)
  ],
)
#set text(font: ("Helvetica Neue", "Helvetica", "Arial"), size: 9.5pt, fill: ink, lang: "en")
#set par(justify: false, leading: 0.62em, spacing: 0.9em)
#show raw: set text(font: ("Menlo", "Courier New"), size: 8pt)
#show raw.where(block: true): it => block(
  fill: rgb("#f4f6f8"), inset: 7pt, radius: 3pt, width: 100%, it,
)
#set heading(numbering: none)
#show heading.where(level: 1): it => {
  pagebreak(weak: true)
  block(below: 1em)[
    #set text(18pt, weight: "bold", fill: accent)
    #it.body
    #v(-0.4em)
    #line(length: 100%, stroke: 0.6pt + rule)
  ]
}
#show heading.where(level: 2): set text(13pt, weight: "bold", fill: accent)
#show heading.where(level: 3): set text(10.5pt, weight: "bold", fill: ink)
#show link: set text(fill: accent)

#set table(
  stroke: (x, y) => (
    top: if y == 0 { 0pt } else { 0.4pt + rule },
    bottom: 0.4pt + rule,
  ),
  inset: (x: 4pt, y: 3.5pt),
  fill: (x, y) => if y == 0 { rgb("#e8eef4") },
)
#show table: set text(7.6pt)
#show table: it => { show raw: set text(6.2pt); it }
#show table.cell.where(y: 0): set text(weight: "bold")
#show figure.where(kind: table): set block(breakable: true)

// Title page.
#page(header: none, footer: none)[
  #v(30mm)
  #text(30pt, weight: "bold", fill: accent)[RAPP v26.11.8\ state machine]
  #v(12mm)
  #line(length: 60%, stroke: 0.8pt + accent)
  #v(4mm)
  #text(10pt)[Stamped, reviewed by the owner]
]

#outline(depth: 2, indent: 1.2em)

#include "build/body.typ"
