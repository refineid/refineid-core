#!/usr/bin/env python3
# Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.
"""Exercise local source-check receipt invalidation and failure behavior.

Usage:
  python3 scripts/test-check-receipt.py
"""

from __future__ import annotations

import importlib.util
import io
import os
import stat
import subprocess
import sys
import tempfile
import unittest
from argparse import Namespace
from contextlib import contextmanager, redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

SCRIPT = Path(__file__).with_name("check-receipt.py")
EXECUTABLE_MODE = stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR
SPEC = importlib.util.spec_from_file_location("check_receipt", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
check_receipt = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = check_receipt
SPEC.loader.exec_module(check_receipt)


@contextmanager
def working_directory(path: Path):
    original = Path.cwd()
    os.chdir(path)
    try:
        yield
    finally:
        os.chdir(original)


class CheckReceiptTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name) / "repo"
        self.root.mkdir()
        self.cache_home = Path(self.temporary.name) / "cache"
        self.counter = Path(self.temporary.name) / "calls"
        self.environment = {
            "XDG_CACHE_HOME": str(self.cache_home),
            "PATH": os.environ["PATH"],
            "HOME": os.environ["HOME"],
        }
        self._init_repo(self.root)
        self.command_file = self.root / "check.py"
        self.fail_marker = Path(self.temporary.name) / "fail-once"
        self.command_file.write_text(
            "#!/bin/sh\n"
            f"counter='{self.counter}'\n"
            f"fail_marker='{self.fail_marker}'\n"
            f"repo='{self.root}'\n"
            "calls=0\n"
            "if [ -f \"$counter\" ]; then IFS= read -r calls < \"$counter\"; fi\n"
            "printf '%s' \"$((calls + 1))\" > \"$counter\"\n"
            "if [ \"$calls\" -eq 0 ] && [ -f \"$fail_marker\" ]; then exit 7; fi\n",
            encoding="utf-8",
        )
        self.command_file.chmod(EXECUTABLE_MODE)
        self.input_file = self.root / "input.txt"
        self.input_file.write_text("first indexed input\n", encoding="ascii")
        self.fake_tool = Path(self.temporary.name) / "fake-tool"
        self.fake_tool.write_text("#!/bin/sh\nexit 0\n", encoding="ascii")
        self.fake_tool.chmod(EXECUTABLE_MODE)
        self._stage_all()
        self.arguments = Namespace(name="source-checks", tool=["sh", str(self.fake_tool)])
        self.diagnostic = ""
        self.notice = ""

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _init_repo(self, root: Path) -> None:
        subprocess.run(
            ["git", "init", "-q", str(root)], check=True, env=self.environment
        )

    def _stage_all(self) -> None:
        subprocess.run(
            ["git", "add", "--all"], cwd=self.root, check=True, env=self.environment
        )

    def _invoke(self, command: list[str]) -> int:
        """Run the checker with its diagnostics captured instead of leaked.

        The checker reports refusal and no-receipt reasons on stderr and
        receipt reuse on stdout. Exercised deliberately here, those would
        otherwise appear on the terminal as if a gate had failed.
        """
        diagnostics = io.StringIO()
        notice = io.StringIO()
        with (
            patch.dict(os.environ, self.environment, clear=True),
            working_directory(self.root),
            redirect_stderr(diagnostics),
            redirect_stdout(notice),
        ):
            status = check_receipt.run(self.arguments, command)
        self.diagnostic = diagnostics.getvalue()
        self.notice = notice.getvalue()
        return status

    def _run(self) -> int:
        return self._invoke([str(self.command_file)])

    def _calls(self) -> int:
        return int(self.counter.read_text(encoding="ascii")) if self.counter.exists() else 0

    def test_reuses_receipt_for_the_same_indexed_tree(self) -> None:
        self.assertEqual(self._run(), 0)
        self.assertNotIn("reusing local receipt", self.notice)
        self.assertEqual(self._run(), 0)
        self.assertIn("reusing local receipt", self.notice)
        self.assertEqual(self._calls(), 1)

    def test_changed_indexed_input_invalidates_receipt(self) -> None:
        self.assertEqual(self._run(), 0)
        self.input_file.write_text("second indexed input\n", encoding="ascii")
        self._stage_all()
        self.assertEqual(self._run(), 0)
        self.assertEqual(self._calls(), 2)

    def test_clean_filter_raw_input_change_invalidates_receipt(self) -> None:
        self.assertEqual(self._run(), 0)
        self.input_file.write_text("smudged worktree representation\n", encoding="ascii")
        original_run = subprocess.run

        def report_clean_diff(arguments, *args, **kwargs):
            if arguments[:4] == ["git", "diff", "--quiet", "--"]:
                return subprocess.CompletedProcess(arguments, 0)
            return original_run(arguments, *args, **kwargs)

        with patch.dict(os.environ, self.environment, clear=True), working_directory(self.root):
            with patch.object(check_receipt.subprocess, "run", side_effect=report_clean_diff):
                self.assertEqual(self._invoke([str(self.command_file)]), 0)
        self.assertEqual(self._calls(), 2)

    def test_changed_check_script_invalidates_receipt(self) -> None:
        self.assertEqual(self._run(), 0)
        with self.command_file.open("a", encoding="ascii") as script:
            script.write(": changed\n")
        self._stage_all()
        self.assertEqual(self._run(), 0)
        self.assertEqual(self._calls(), 2)

    def test_changed_tool_binary_invalidates_receipt(self) -> None:
        self.assertEqual(self._run(), 0)
        self.fake_tool.write_text("#!/bin/sh\ntrue\nexit 0\n", encoding="ascii")
        self.assertEqual(self._run(), 0)
        self.assertEqual(self._calls(), 2)

    def test_tool_change_during_check_prevents_receipt_creation(self) -> None:
        self.command_file.write_text(
            "#!/bin/sh\n"
            f"tool='{self.fake_tool}'\n"
            f"counter='{self.counter}'\n"
            "printf '%s' changed > \"$tool\"\n"
            "printf 'ran' > \"$counter\"\n",
            encoding="ascii",
        )
        self.command_file.chmod(EXECUTABLE_MODE)
        self._stage_all()
        self.assertEqual(self._run(), 1)
        self.assertEqual(
            list((self.cache_home / "refineid-core" / "quality-receipts").glob("*.json")),
            [],
        )

    def test_failed_check_never_creates_a_receipt(self) -> None:
        self.fail_marker.write_text("fail once", encoding="ascii")
        self.assertEqual(self._run(), 7)
        self.assertEqual(self._run(), 0)
        self.assertEqual(self._run(), 0)
        self.assertEqual(self._calls(), 2)

    def test_untracked_input_prevents_receipt_reuse(self) -> None:
        (self.root / "untracked.txt").write_text("untracked\n", encoding="ascii")
        self.assertEqual(self._run(), 0)
        self.assertEqual(self._run(), 0)
        self.assertEqual(self._calls(), 2)

    def test_partial_staging_is_rejected_before_running_checks(self) -> None:
        self.input_file.write_text("unstaged worktree edit\n", encoding="ascii")
        with patch.dict(os.environ, self.environment, clear=True), working_directory(self.root):
            with self.assertRaisesRegex(RuntimeError, "differ from the index"):
                self._invoke([str(self.command_file)])
        self.assertEqual(self._calls(), 0)

    def test_assume_unchanged_entry_is_rejected(self) -> None:
        subprocess.run(
            ["git", "update-index", "--assume-unchanged", "input.txt"],
            cwd=self.root,
            check=True,
            env=self.environment,
        )
        self.input_file.write_text("hidden worktree edit\n", encoding="ascii")
        with patch.dict(os.environ, self.environment, clear=True), working_directory(self.root):
            with self.assertRaisesRegex(RuntimeError, "assume-unchanged or skip-worktree"):
                self._invoke([str(self.command_file)])
        self.assertEqual(self._calls(), 0)

    def test_skip_worktree_entry_is_rejected(self) -> None:
        subprocess.run(
            ["git", "update-index", "--skip-worktree", "input.txt"],
            cwd=self.root,
            check=True,
            env=self.environment,
        )
        self.input_file.write_text("hidden worktree edit\n", encoding="ascii")
        with patch.dict(os.environ, self.environment, clear=True), working_directory(self.root):
            with self.assertRaisesRegex(RuntimeError, "assume-unchanged or skip-worktree"):
                self._invoke([str(self.command_file)])
        self.assertEqual(self._calls(), 0)

    def test_receipt_hit_rechecks_index_before_reusing(self) -> None:
        self.assertEqual(self._run(), 0)
        original_valid = check_receipt.valid_receipt

        def mutate_before_hit(path: Path, key: str) -> bool:
            self.input_file.write_text("changed during lookup\n", encoding="ascii")
            self._stage_all()
            return original_valid(path, key)

        with patch.dict(os.environ, self.environment, clear=True), working_directory(self.root):
            with patch.object(check_receipt, "valid_receipt", side_effect=mutate_before_hit):
                self.assertEqual(self._invoke([str(self.command_file)]), 1)
        self.assertIn("inputs changed while reading the receipt", self.diagnostic)
        self.assertNotIn("reusing local receipt", self.notice)
        self.assertEqual(self._calls(), 1)

    def test_receipt_hit_rechecks_tool_before_reusing(self) -> None:
        self.assertEqual(self._run(), 0)
        original_valid = check_receipt.valid_receipt

        def mutate_tool_before_hit(path: Path, key: str) -> bool:
            self.fake_tool.write_text("#!/bin/sh\ntrue\nexit 0\n", encoding="ascii")
            return original_valid(path, key)

        with patch.dict(os.environ, self.environment, clear=True), working_directory(self.root):
            with patch.object(check_receipt, "valid_receipt", side_effect=mutate_tool_before_hit):
                self.assertEqual(self._invoke([str(self.command_file)]), 1)
        self.assertEqual(self._calls(), 1)

    def test_corrupt_receipt_is_a_miss_and_is_replaced_after_success(self) -> None:
        self.assertEqual(self._run(), 0)
        receipt = next((self.cache_home / "refineid-core" / "quality-receipts").glob("*.json"))
        receipt.write_text("not a receipt\n", encoding="ascii")
        self.assertEqual(self._run(), 0)
        self.assertEqual(self._run(), 0)
        self.assertEqual(self._calls(), 2)

    def test_symlink_receipt_is_never_reused_or_overwritten(self) -> None:
        self.assertEqual(self._run(), 0)
        receipt = next((self.cache_home / "refineid-core" / "quality-receipts").glob("*.json"))
        receipt.unlink()
        target = Path(self.temporary.name) / "external"
        target.write_text("external state\n", encoding="ascii")
        receipt.symlink_to(target)
        self.assertEqual(self._run(), 0)
        self.assertEqual(self._run(), 0)
        self.assertEqual(self._calls(), 3)
        self.assertEqual(target.read_text(encoding="ascii"), "external state\n")

    def test_check_that_changes_the_index_is_not_recorded(self) -> None:
        self.command_file.write_text(
            "#!/bin/sh\n"
            f"counter='{self.counter}'\n"
            f"repo='{self.root}'\n"
            "printf '%s' changed > \"$repo/input.txt\"\n"
            "git -C \"$repo\" add input.txt\n"
            "printf 'ran' > \"$counter\"\n",
            encoding="ascii",
        )
        self.command_file.chmod(EXECUTABLE_MODE)
        self._stage_all()
        self.assertEqual(self._run(), 1)
        self.assertIn("indexed inputs changed during the check", self.diagnostic)
        self.assertTrue(self.counter.exists())

    def test_referenced_cargo_config_environment_invalidates_receipt(self) -> None:
        config_dir = self.root / ".cargo"
        config_dir.mkdir()
        config = config_dir / "config.toml"
        config.write_text('target-dir = "${RECEIPT_TEST_TARGET}"\n', encoding="ascii")
        self._stage_all()
        command = [str(self.command_file)]
        with patch.dict(os.environ, self.environment | {"RECEIPT_TEST_TARGET": "one"}, clear=True):
            first = check_receipt.fingerprint(self.root, self.arguments.name, command, self.arguments.tool)
        with patch.dict(os.environ, self.environment | {"RECEIPT_TEST_TARGET": "two"}, clear=True):
            second = check_receipt.fingerprint(self.root, self.arguments.name, command, self.arguments.tool)
        self.assertNotEqual(first, second)

    def test_git_hook_context_does_not_change_stable_environment_key(self) -> None:
        with patch.dict(os.environ, self.environment, clear=True):
            first = check_receipt.stable_environment_digest()
            with patch.dict(
                os.environ,
                {
                    "GIT_AUTHOR_DATE": "fixed metadata only",
                    "GIT_AUTHOR_EMAIL": "author@example.invalid",
                    "GIT_AUTHOR_NAME": "Author",
                    "GIT_INDEX_FILE": "/temporary/index",
                    "GIT_PREFIX": "src/",
                    "_": "/bin/sh",
                },
            ):
                second = check_receipt.stable_environment_digest()
        self.assertEqual(first, second)

    def test_fixture_git_commands_do_not_write_inherited_hook_repository(self) -> None:
        outer_repo = Path(self.temporary.name) / "outer-repo"
        outer_repo.mkdir()
        self._init_repo(outer_repo)
        outer_file = outer_repo / "sentinel.txt"
        outer_file.write_text("outer repository contents\n", encoding="ascii")
        subprocess.run(
            ["git", "add", "sentinel.txt"],
            cwd=outer_repo,
            check=True,
            env=self.environment,
        )
        config_path = outer_repo / ".git" / "config"
        index_path = outer_repo / ".git" / "index"
        original_config = config_path.read_bytes()
        original_index = index_path.read_bytes()
        nested_repo = Path(self.temporary.name) / "nested-repo"
        nested_repo.mkdir()
        with patch.dict(
            os.environ,
            {"GIT_DIR": str(outer_repo / ".git"), "GIT_INDEX_FILE": str(index_path)},
        ):
            self._init_repo(nested_repo)
            self._stage_all()
        self.assertEqual(config_path.read_bytes(), original_config)
        self.assertEqual(index_path.read_bytes(), original_index)


if __name__ == "__main__":
    unittest.main()
