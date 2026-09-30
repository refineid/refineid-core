#!/bin/sh
# Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.
#
# Fast source checks for the pre-commit hook. The full floor -- build,
# tests, Clippy with warnings denied, rustdoc, and the doctest ban -- runs
# in the pre-push gate via scripts/verify-push.sh.
set -eu

root=$(git rev-parse --show-toplevel)
cd "$root"

# Hooks may run from GUI clients whose PATH lacks the rustup shims.
if command -v brew > /dev/null 2>&1; then
    rustup_bin="$(brew --prefix rustup 2> /dev/null)/bin"
    if [ -d "$rustup_bin" ]; then
        PATH="$rustup_bin:$HOME/.cargo/bin:$PATH"
        export PATH
    fi
fi

python3 "$root/scripts/check-receipt.py" source-checks \
    --tool sh --tool cargo --tool rustc --tool rustfmt --tool cargo-fmt --tool git --tool grep \
    -- "$root/scripts/run-source-checks.sh"
echo "pre-commit gates passed"
