# Developing on Windows

Status: Active

Date: 2026-10-20

The quality floor is the same on Windows as on macOS and Linux: the hooks
run the same scripts and the same Cargo commands. This page lists what a
Windows machine needs for them and the two places where Windows differs.

## Prerequisites

- **Git for Windows**, whose Git Bash runs the hooks and the scripts under
  `scripts/`. Enable the hooks once per clone from Git Bash:
  `sh scripts/install-hooks.sh`.
- **Rust through rustup**, with the MSVC toolchain and the Visual Studio C++
  build tools and Windows SDK it links with. The refineid-windows repository's
  `scripts/setup-dev-tools.ps1` installs and updates all of them.
- **Python 3 with a `python3` command**, which the gate scripts call. Install
  it with the [Python Install Manager](https://docs.python.org/3/using/windows.html)
  (`pymanager install 3`); a per-version installer provides only `python`, and
  `python3` then resolves to the Microsoft Store placeholder.
- **cargo-vet** for the pre-push gate: `cargo install cargo-vet --locked`.
  `cargo audit` runs when `cargo-audit` is installed.

## Line endings

The repository stores text with LF line endings, and `rustfmt.toml` sets
`newline_style = "Unix"`. The Git for Windows installer sets
`core.autocrlf=true` in its system configuration by default, which converts
text to CRLF on checkout; `cargo fmt --check` then rejects every Rust file.
The tracked `.gitattributes` sets `* text=auto eol=lf`, which takes precedence
over `core.autocrlf`, so a checkout made with it is LF on every platform. No
local Git setting is needed, and none should be changed to work around it.

A checkout made before `.gitattributes` existed keeps its CRLF files until
they are written again. `git ls-files --eol` shows them as `w/crlf`. To
rewrite them, commit or stash any work first, since this replaces every
tracked file from the index, and close editors and build servers that hold
files open, then run in Git Bash:

```sh
cd "$(git rev-parse --show-toplevel)"
git ls-files -z | xargs -0 rm -f
git checkout -- .
git ls-files --eol | grep -c w/crlf   # 0
```

## Check receipts

`scripts/check-receipt.py` reuses a successful source-check run for an
identical indexed tree only when the receipt's file and directory are private
to the user, which it checks with POSIX ownership and modes. Windows has
neither, so there every commit and push runs the source checks in full and
reports `check receipt disabled`. Nothing is skipped; only the shortcut is.
