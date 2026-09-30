#!/usr/bin/env python3
# Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.
"""Reuse successful local source checks for an identical indexed tree.

Usage:
  scripts/check-receipt.py NAME [--tool TOOL ...] -- COMMAND [ARG ...]

Receipts are local performance hints. CI runs the quality gates independently.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import re
import shutil
import stat
import subprocess
import sys
import tempfile
from pathlib import Path

RECEIPT_FORMAT = 1
PATH_SIZE_BYTES = 8
NULL_BYTE_VALUE = 0
NULL_BYTE = bytes((NULL_BYTE_VALUE,))
PRIVATE_DIRECTORY_MODE = stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR
PRIVATE_FILE_MODE = stat.S_IRUSR | stat.S_IWUSR
VERSION_ARGS = {
    "cargo": ["--version"],
    "cargo-fmt": ["--version"],
    "git": ["--version"],
    "rustc": ["--version", "--verbose"],
    "rustfmt": ["--version"],
}
VOLATILE_ENV = {
    "_",
    "GIT_AUTHOR_DATE",
    "GIT_AUTHOR_EMAIL",
    "GIT_AUTHOR_NAME",
    "GIT_COMMITTER_DATE",
    "GIT_COMMITTER_EMAIL",
    "GIT_COMMITTER_NAME",
    "GIT_EDITOR",
    "GIT_PAGER",
    "GIT_PREFIX",
    "OLDPWD",
    "PWD",
    "SHLVL",
}
STABLE_ENV = {
    "AR",
    "CARGO_BUILD_TARGET",
    "CARGO_ENCODED_RUSTFLAGS",
    "CARGO_HOME",
    "CARGO_INCREMENTAL",
    "CARGO_TARGET_DIR",
    "CC",
    "CFLAGS",
    "CPPFLAGS",
    "CXX",
    "CXXFLAGS",
    "GIT_EXEC_PATH",
    "HOME",
    "LDFLAGS",
    "PATH",
    "PKG_CONFIG",
    "PKG_CONFIG_LIBDIR",
    "PKG_CONFIG_PATH",
    "PKG_CONFIG_SYSROOT_DIR",
    "RUSTDOCFLAGS",
    "RUSTFLAGS",
    "RUSTUP_HOME",
    "RUSTUP_TOOLCHAIN",
    "SOURCE_DATE_EPOCH",
}


class CacheUnavailable(Exception):
    """The check can run, but its result cannot safely use a receipt."""


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def git(root: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", *args], cwd=root, check=True, text=True, capture_output=True
    )
    return result.stdout.strip()


def snapshot(root: Path) -> tuple[str, bool, str]:
    """Return the index tree, cache eligibility, and raw tracked-file digest."""
    try:
        tree = git(root, "write-tree")
    except subprocess.CalledProcessError as error:
        raise CacheUnavailable("the Git index cannot be snapshotted") from error

    clean_worktree = subprocess.run(
        ["git", "diff", "--quiet", "--"], cwd=root, check=False
    ).returncode == 0
    if not clean_worktree:
        raise RuntimeError(
            "tracked worktree files differ from the index; stage the intended "
            "files or restore the worktree before running quality checks"
        )

    flags = subprocess.run(
        ["git", "ls-files", "-v", "-z"], cwd=root, check=True, capture_output=True
    ).stdout.split(NULL_BYTE)
    if any(entry[:1] in {b"h", b"S", b"s"} for entry in flags if entry):
        raise RuntimeError(
            "the index has assume-unchanged or skip-worktree entries; clear those "
            "flags before running quality checks"
        )
    worktree_hash = tracked_worktree_digest(root)

    status = subprocess.run(
        ["git", "status", "--porcelain=v1", "-z", "--untracked-files=all"],
        cwd=root,
        check=True,
        capture_output=True,
    ).stdout
    has_untracked = any(record.startswith(b"?? ") for record in status.split(NULL_BYTE))
    ignored = subprocess.run(
        ["git", "ls-files", "--others", "--ignored", "--exclude-standard", "-z"],
        cwd=root,
        check=True,
        capture_output=True,
    ).stdout
    ignored_inputs = [
        Path(record.decode("utf-8", errors="surrogateescape"))
        for record in ignored.split(NULL_BYTE)
        if record
    ]
    has_non_build_ignored = any(
        not path.parts or path.parts[0] != "target" for path in ignored_inputs
    )
    return tree, not has_untracked and not has_non_build_ignored, worktree_hash


def tracked_worktree_digest(root: Path) -> str:
    """Hash the actual bytes for every stage-zero index entry."""
    entries = subprocess.run(
        ["git", "ls-files", "--stage", "-z"], cwd=root, check=True, capture_output=True
    ).stdout.split(NULL_BYTE)
    digest = hashlib.sha256()
    for entry in entries:
        if not entry:
            continue
        header, path_bytes = entry.split(b"\t", maxsplit=1)
        mode, _, stage = header.split()
        if stage != b"0" or mode == b"160000":
            raise CacheUnavailable("unmerged indexes and submodules do not use local receipts")
        path = root / os.fsdecode(path_bytes)
        try:
            metadata = path.lstat()
            if mode == b"120000" and stat.S_ISLNK(metadata.st_mode):
                contents = os.fsencode(os.readlink(path))
            elif mode in {b"100644", b"100755"} and stat.S_ISREG(metadata.st_mode):
                contents = path.read_bytes()
            else:
                raise CacheUnavailable("a tracked worktree path has an unexpected file type")
        except OSError as error:
            raise CacheUnavailable("a tracked worktree file cannot be read") from error
        digest.update(len(path_bytes).to_bytes(PATH_SIZE_BYTES, "big"))
        digest.update(path_bytes)
        digest.update(mode)
        digest.update(len(contents).to_bytes(PATH_SIZE_BYTES, "big"))
        digest.update(contents)
    return digest.hexdigest()


def file_digest(path: Path) -> str:
    try:
        return sha256(path.read_bytes())
    except OSError as error:
        raise CacheUnavailable(f"cannot fingerprint tool: {path.name}") from error


def tool_identity(name: str) -> dict[str, str]:
    executable = shutil.which(name)
    if executable is None:
        raise CacheUnavailable(f"required tool is unavailable: {name}")
    proxy = Path(executable).resolve(strict=True)
    if not proxy.is_file():
        raise CacheUnavailable(f"tool is not a regular file: {name}")
    selected = proxy
    if name in {"cargo", "rustc", "rustfmt"}:
        rustup = shutil.which("rustup")
        if rustup is not None:
            try:
                result = subprocess.run(
                    [rustup, "which", name], check=True, text=True, capture_output=True
                )
                selected = Path(result.stdout.strip()).resolve(strict=True)
            except (OSError, subprocess.CalledProcessError) as error:
                raise CacheUnavailable(f"cannot identify selected toolchain binary: {name}") from error
    if not selected.is_file():
        raise CacheUnavailable(f"selected tool is not a regular file: {name}")
    version_args = VERSION_ARGS.get(name)
    version = ""
    if name == str(Path(sys.executable).resolve()):
        version = sys.version
    if version_args is not None:
        try:
            result = subprocess.run(
                [executable, *version_args],
                check=True,
                text=True,
                capture_output=True,
            )
        except (OSError, subprocess.CalledProcessError) as error:
            raise CacheUnavailable(f"cannot identify tool version: {name}") from error
        version = result.stdout.strip() + result.stderr.strip()
    if name == "rustc":
        try:
            sysroot_result = subprocess.run(
                [executable, "--print", "sysroot"],
                check=True,
                text=True,
                capture_output=True,
            )
            version += chr(NULL_BYTE_VALUE) + "sysroot=" + sysroot_result.stdout.strip()
        except (OSError, subprocess.CalledProcessError) as error:
            raise CacheUnavailable("cannot identify selected Rust sysroot") from error
    return {
        "name": name,
        "proxy_path": str(proxy),
        "proxy_sha256": file_digest(proxy),
        "path": str(selected),
        "binary_sha256": file_digest(selected),
        "version_sha256": sha256(version.encode()),
    }


def cargo_config_digests(root: Path) -> list[tuple[str, str]]:
    paths: set[Path] = set()
    current = root
    while True:
        for name in ("config", "config.toml"):
            candidate = current / ".cargo" / name
            if candidate.is_file():
                paths.add(candidate)
        if current.parent == current:
            break
        current = current.parent

    cargo_home = Path(os.environ.get("CARGO_HOME", Path.home() / ".cargo"))
    for name in ("config", "config.toml"):
        candidate = cargo_home / name
        if candidate.is_file():
            paths.add(candidate)
    config_values = sorted((str(path.resolve()), file_digest(path)) for path in paths)
    referenced = set()
    for path in paths:
        try:
            source = path.read_text(encoding="utf-8")
        except (OSError, UnicodeError) as error:
            raise CacheUnavailable("cannot inspect Cargo configuration") from error
        referenced.update(re.findall(r"\$\{([A-Za-z_][A-Za-z0-9_]*)", source))
    config_values.extend(
        (f"env:{name}", sha256(os.environ.get(name, "").encode()))
        for name in sorted(referenced)
    )
    return sorted(config_values)


def fingerprint(
    root: Path, name: str, command: list[str], tools: list[str]
) -> str:
    command_path = Path(command[0])
    if not command_path.is_absolute():
        found = shutil.which(command[0])
        if found is None:
            raise CacheUnavailable(f"check command is unavailable: {command[0]}")
        command_path = Path(found)
    command_file = command_path.resolve(strict=True)
    if not command_file.is_file():
        raise CacheUnavailable("check command is not a regular file")

    identities = [tool_identity(tool) for tool in sorted(set(tools))]
    identities.append(tool_identity(str(Path(sys.executable).resolve())))
    identities.append(
        {
            "name": "check-command",
            "path": str(command_file),
            "binary_sha256": file_digest(command_file),
            "version_sha256": "",
        }
    )
    command_inputs = []
    for argument in command[1:]:
        candidate = Path(argument)
        if candidate.is_file():
            command_inputs.append((str(candidate.resolve()), file_digest(candidate)))

    material = {
        "format": RECEIPT_FORMAT,
        "check": name,
        "tree": git(root, "write-tree"),
        "worktree_sha256": tracked_worktree_digest(root),
        "platform": platform.system() + "/" + platform.machine(),
        "command": command,
        "command_inputs": sorted(command_inputs),
        "tools": identities,
        "cargo_config": cargo_config_digests(root),
        "environment_sha256": stable_environment_digest(),
    }
    return sha256(json.dumps(material, sort_keys=True, separators=(",", ":")).encode())


def stable_environment_digest() -> str:
    volatile_git = {
        "GIT_ALTERNATE_OBJECT_DIRECTORIES",
        "GIT_COMMON_DIR",
        "GIT_CEILING_DIRECTORIES",
        "GIT_DIR",
        "GIT_INDEX_FILE",
        "GIT_OBJECT_DIRECTORY",
        "GIT_WORK_TREE",
        "GIT_OPTIONAL_LOCKS",
    }
    unknown_overrides = [
        name
        for name in os.environ
        if name.startswith(("CARGO_", "RUST_", "GIT_"))
        and name not in STABLE_ENV
        and name not in VOLATILE_ENV
        and name not in volatile_git
    ]
    if unknown_overrides:
        names = ", ".join(sorted(unknown_overrides))
        raise CacheUnavailable(
            "unrecognized Cargo, Rust, or Git environment overrides are set: " + names
        )
    return sha256(
        NULL_BYTE.join(
            name.encode() + b"=" + value.encode()
            for name, value in sorted(os.environ.items())
            if name in STABLE_ENV
        )
    )


def no_symlink_components(path: Path) -> bool:
    current = Path(path.anchor)
    for component in path.parts[1:]:
        current = current / component
        try:
            if stat.S_ISLNK(current.lstat().st_mode):
                return False
        except FileNotFoundError:
            continue
    return True


def cache_directory(root: Path) -> Path:
    parent = Path(os.environ.get("XDG_CACHE_HOME", Path.home() / ".cache"))
    directory = parent.resolve(strict=False) / "refineid-core" / "quality-receipts"
    if not no_symlink_components(directory):
        raise CacheUnavailable("the local cache path contains a symbolic link")
    directory.mkdir(mode=PRIVATE_DIRECTORY_MODE, parents=True, exist_ok=True)
    if not directory.is_dir() or directory.is_symlink():
        raise CacheUnavailable("the local cache directory is not a regular directory")
    resolved = directory.resolve(strict=True)
    if os.path.commonpath((str(root.resolve()), str(resolved))) == str(root.resolve()):
        raise CacheUnavailable("the local cache directory is inside the repository")
    directory_status = resolved.stat()
    if directory_status.st_uid != os.getuid():
        raise CacheUnavailable("the local cache directory has a different owner")
    if stat.S_IMODE(directory_status.st_mode) != PRIVATE_DIRECTORY_MODE:
        raise CacheUnavailable("the local cache directory permissions are not private")
    return resolved


def valid_receipt(path: Path, key: str) -> bool:
    try:
        metadata = path.lstat()
        if path.is_symlink() or not stat.S_ISREG(metadata.st_mode):
            return False
        if metadata.st_uid != os.getuid() or stat.S_IMODE(metadata.st_mode) != PRIVATE_FILE_MODE:
            return False
        receipt = json.loads(path.read_text(encoding="ascii"))
        return receipt == {"format": RECEIPT_FORMAT, "key": key, "success": True}
    except (OSError, UnicodeError, json.JSONDecodeError):
        return False


def write_receipt(path: Path, key: str) -> None:
    if path.is_symlink():
        raise CacheUnavailable("the receipt path is a symbolic link")
    if path.exists():
        metadata = path.lstat()
        if not stat.S_ISREG(metadata.st_mode):
            raise CacheUnavailable("the receipt path is not a regular file")
        if metadata.st_uid != os.getuid() or stat.S_IMODE(metadata.st_mode) != PRIVATE_FILE_MODE:
            raise CacheUnavailable("the receipt file is not private to this user")
    payload = json.dumps(
        {"format": RECEIPT_FORMAT, "key": key, "success": True},
        sort_keys=True,
        separators=(",", ":"),
    ).encode("ascii")
    descriptor, temporary_name = tempfile.mkstemp(prefix=".receipt-", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        os.fchmod(descriptor, PRIVATE_FILE_MODE)
        with os.fdopen(descriptor, "wb") as receipt_file:
            receipt_file.write(payload)
            receipt_file.flush()
            os.fsync(receipt_file.fileno())
        os.replace(temporary, path)
        directory_descriptor = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory_descriptor)
        finally:
            os.close(directory_descriptor)
    finally:
        if temporary.exists():
            temporary.unlink()


def run(args: argparse.Namespace, command: list[str]) -> int:
    root = Path(git(Path.cwd(), "rev-parse", "--show-toplevel")).resolve()
    tree, cacheable, fingerprint_worktree = snapshot(root)
    receipt: Path | None = None
    key = ""
    if cacheable:
        try:
            directory = cache_directory(root)
            key = fingerprint(root, args.name, command, args.tool)
            receipt = directory / f"{key}.json"
        except CacheUnavailable as error:
            print(f"check receipt disabled: {error}", file=sys.stderr)
        if receipt is not None and valid_receipt(receipt, key):
            tree_after, cacheable_after, worktree_after = snapshot(root)
            try:
                key_after = fingerprint(root, args.name, command, args.tool)
            except CacheUnavailable as error:
                print(f"check receipt refused: {error}", file=sys.stderr)
                return 1
            if (
                tree_after != tree
                or worktree_after != fingerprint_worktree
                or not cacheable_after
                or key_after != key
            ):
                print("check receipt refused: inputs changed while reading the receipt", file=sys.stderr)
                return 1
            print("source checks passed for this indexed tree and tool set; reusing local receipt")
            return 0

    result = subprocess.run(command, cwd=root, check=False)
    if result.returncode != 0:
        return result.returncode

    try:
        tree_after, cacheable_after, worktree_after = snapshot(root)
    except (CacheUnavailable, RuntimeError) as error:
        print(f"check result not recorded: {error}", file=sys.stderr)
        return 1
    if tree_after != tree or worktree_after != fingerprint_worktree:
        print("check failed: indexed inputs changed during the check", file=sys.stderr)
        return 1
    if receipt is not None and cacheable_after:
        try:
            if fingerprint(root, args.name, command, args.tool) != key:
                print("check result not recorded: tools or check inputs changed", file=sys.stderr)
                return 1
            write_receipt(receipt, key)
        except CacheUnavailable as error:
            print(f"check result not recorded: {error}", file=sys.stderr)
    return 0


def main() -> int:
    if "--" not in sys.argv:
        print(__doc__.split("\n\n")[0], file=sys.stderr)
        return 2
    separator = sys.argv.index("--")
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("name")
    parser.add_argument("--tool", action="append", default=[])
    args = parser.parse_args(sys.argv[1:separator])
    command = sys.argv[separator + 1 :]
    if not command:
        parser.error("a check command is required after --")
    try:
        return run(args, command)
    except RuntimeError as error:
        print(f"check receipt refused: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
