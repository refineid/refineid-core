#!/usr/bin/env python3
# Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.
"""Validate that remote workflow triggers do not duplicate the local floor.

Usage:
  python3 scripts/test-workflow-policy.py
"""

from __future__ import annotations

import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
WORKFLOW = ROOT / ".github" / "workflows" / "core-quality.yml"
FOLLOWING_LINE_OFFSET = 1
ROOT_INDENT = 0
MAPPING_CHILD_INDENT = len("  ")


def top_level_mapping_children(source: str, mapping: str) -> set[str]:
    """Read child keys from one uncomplicated top-level YAML mapping."""
    lines = source.splitlines()
    start = next(
        (position for position, line in enumerate(lines) if line == f"{mapping}:"),
        None,
    )
    if start is None:
        raise AssertionError(f"top-level YAML mapping is missing: {mapping}")

    keys = set()
    for line in lines[start + FOLLOWING_LINE_OFFSET :]:
        indent = len(line) - len(line.lstrip())
        if line and indent == ROOT_INDENT and not line.lstrip().startswith("#"):
            break
        if indent == MAPPING_CHILD_INDENT:
            key, separator, _ = line.strip().partition(":")
            if separator:
                keys.add(key)
    return keys


class WorkflowPolicyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.workflow = WORKFLOW.read_text(encoding="utf-8")

    def test_core_quality_is_manual_only(self) -> None:
        self.assertEqual(
            top_level_mapping_children(self.workflow, "on"), {"workflow_dispatch"}
        )

    def test_manual_workflow_keeps_linux_portability_coverage(self) -> None:
        self.assertIn("runs-on: ubuntu-latest", self.workflow)
        for command in (
            "cargo run --locked -p xtask -- check-magic-numbers",
            "cargo fmt --all -- --check",
            "cargo test --workspace --all-targets --locked",
            "cargo clippy --workspace --all-targets --locked -- -D warnings",
            "cargo doc --workspace --no-deps --locked",
            "cargo audit",
        ):
            with self.subTest(command=command):
                self.assertIn(command, self.workflow)

    def test_repository_hygiene_remains_in_local_source_gate(self) -> None:
        source_checks = (ROOT / "scripts" / "run-source-checks.sh").read_text(
            encoding="utf-8"
        )
        self.assertIn("scripts/verify-hygiene.sh", source_checks)
        self.assertIn("scripts/test-workflow-policy.py", source_checks)


if __name__ == "__main__":
    unittest.main()
