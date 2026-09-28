#!/usr/bin/env bash
# Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.
#
# Repository hygiene checks: rejects private or operational path names,
# credential-shaped strings, PIN/PUK assignment patterns, and Finnish personal
# identity code (HETU/PIC) patterns.

set -euo pipefail

root="$(git rev-parse --show-toplevel)"
cd "$root"

failed=0

private_paths=$(git ls-files | grep -E '(^|/)(\.codex|\.idea|private|internal|operations?)(/|$)' || true)
if [[ -n "$private_paths" ]]; then
  echo "Private or operational path names are not allowed:"
  printf '%s\n' "$private_paths"
  failed=1
fi

whatsup_files=$(git ls-files | grep -i -E '(^|/)WHATSUP\.md$' || true)
if [[ -n "$whatsup_files" ]]; then
  echo "WHATSUP.md files are forbidden:"
  printf '%s\n' "$whatsup_files"
  failed=1
fi

secret_files=$(git grep -I -l -E \
  'BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY|AKIA[0-9A-Z]{16}|github_pat_[A-Za-z0-9_]{20,}|gh[pousr]_[A-Za-z0-9_]{20,}|xox[baprs]-[A-Za-z0-9-]{10,}|sk-[A-Za-z0-9]{20,}' \
  -- . ':!LICENSE' || true)
if [[ -n "$secret_files" ]]; then
  echo "Credential-shaped content was found in:"
  printf '%s\n' "$secret_files"
  failed=1
fi

pin_files=$(git grep -I -l -i -E \
  '(pin[_-]?[12]?|puk)[[:space:]]*[:=][[:space:]]*[^0-9[:space:]]?[0-9]{4,12}([^0-9]|$)' \
  -- . ':!LICENSE' || true)
if [[ -n "$pin_files" ]]; then
  echo "PIN- or PUK-shaped assignments were found in:"
  printf '%s\n' "$pin_files"
  failed=1
fi

pic_files=$(git grep -I -l -E \
  '[0-9]{6}[-+A-Y][0-9]{3}[0-9A-Y]' \
  -- . ':!LICENSE' || true)
if [[ -n "$pic_files" ]]; then
  echo "Finnish personal-identity-code-shaped content was found in:"
  printf '%s\n' "$pic_files"
  failed=1
fi

if [[ "$failed" -ne 0 ]]; then
  echo "Hygiene checks failed"
  exit 1
fi

echo "Hygiene checks passed"
