#!/bin/sh
# Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.
#
# Run the source-only checks shared by the commit and push gates.
set -eu

root=$(git rev-parse --show-toplevel)
cd "$root"

cargo fmt --check
cargo run -q -p xtask -- check-magic-numbers
"$root/scripts/verify-hygiene.sh"
PYTHONDONTWRITEBYTECODE=1 python3 "$root/scripts/test-check-receipt.py"
