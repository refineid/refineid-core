#!/bin/sh
# Builds rapp-state-machine.pdf from ../rapp-state-machine.md and the
# drawings in diagrams/. Needs pandoc (3.x) and typst (0.13 or later);
# typst fetches the fletcher package on first use. qpdf packs every object
# into compressed object streams, so no plain-text run of the PDF looks like
# an identifier the repository hygiene gate refuses.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
cd "$here"
mkdir -p build
pandoc ../rapp-state-machine.md \
  --from gfm+tex_math_dollars \
  --to typst \
  --lua-filter figures.lua \
  --shift-heading-level-by=-1 \
  --output build/body.typ
typst compile --root "$here" main.typ build/rapp-state-machine.pdf
qpdf --object-streams=generate --compress-streams=y --recompress-flate \
  build/rapp-state-machine.pdf rapp-state-machine.pdf
echo "$here/rapp-state-machine.pdf"
