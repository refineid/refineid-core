#!/bin/sh
# Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.
#
# The full quality floor for the pre-push hook, exactly as AGENTS.md
# states it: formatting, build, tests, Clippy across every target with
# zero warnings, rustdoc with warnings denied, and the magic-number
# policy. Bypassing this gate is prohibited for every contributor,
# human or AI agent alike.
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
    -- sh "$root/scripts/run-source-checks.sh"
cargo build
cargo test
cargo clippy --all-targets -- -D warnings
# The library alone, without dev-dependencies: the RAPP crate's
# test-vectors feature stays off, as in every platform build.
cargo clippy -p refineid-rapp -- -D warnings
# The UniFFI surface is off by default; the platform apps build with it,
# library alone as above.
cargo clippy -p refineid-rapp --features bindings -- -D warnings
cargo clippy -p refineid-rapp --features bindings --all-targets -- -D warnings
cargo test -p refineid-rapp --features bindings
# The document-signing library as a platform without PC/SC builds it:
# the local-reader session off, the phone path and the shared finish on.
cargo build -p refineid-doc-sign --no-default-features
cargo clippy -p refineid-doc-sign --no-default-features --all-targets -- -D warnings
cargo test -p refineid-doc-sign --no-default-features
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps
RUSTDOCFLAGS="-D warnings" cargo doc -p refineid-rapp --features bindings --no-deps
RUSTDOCFLAGS="-D warnings" cargo doc -p refineid-doc-sign --no-default-features --no-deps
if command -v cargo-audit > /dev/null 2>&1; then
    cargo audit
fi
cargo vet --locked
git diff --exit-code --quiet || {
    echo "pre-push: working tree has unstaged modifications"
    exit 1
}
echo "pre-push gates passed"
