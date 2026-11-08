#import "style.typ": *
// One session instance (rapp-state-machine-v26.11.8.yaml, `session`).
#set text(font: ("Helvetica Neue", "Helvetica", "Arial"))
#diagram(
  spacing: (13mm, 16mm),
  st((0, 0), <absent>, [absent]),
  st((1, 0), <connecting>, [connecting], sub: [requester only]),
  st((2, 0), <auth>, [authenticating], sub: [preamble, Noise_KK,\ session.ready]),
  st((3, 0), <healthy>, [healthy], sub: [ping after 5 s,\ 30 s silence limit]),
  st((1.5, 1.4), <closed>, [closed], sub: [terminal; keys erased]),
  st((3, 1.4), <closing>, [closing], sub: [close sent, or\ none possible]),
  tr(<absent>, <connecting>, [connect]),
  tr(<absent>, <auth>, [preamble routed (custodian)], bend: 28deg),
  tr(<connecting>, <auth>, [transport\ up]),
  tr(<auth>, <healthy>, [ready sent\ or verified]),
  tr(<connecting>, <closed>, [transport failed,\ withdrawn], label-side: right),
  tr(<auth>, <closed>, [candidate failure,\ revoking close,\ pairing close], label-side: left),
  tr(<auth>, <closing>, [protocol\ violation], label-side: left, label-pos: 0.35),
  tr(<healthy>, <closing>, [any close reason,\ silence, transport\ or AEAD failure], label-side: left),
  tr(<closing>, <closed>, [complete or deadline]),
  tr(<healthy>, <healthy>, [ping], bend: 130deg, loop-angle: 90deg),
)
