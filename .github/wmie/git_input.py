"""Read immutable Git objects without checking out or running proposed code."""

from __future__ import annotations

import base64
import hashlib
import os
from pathlib import Path
import re
import subprocess

from core import GovernanceError, require, safe_path, sha, write_json


def git(directory, *args, token=""):
    environment = {**os.environ, "GIT_TERMINAL_PROMPT": "0", "GIT_CONFIG_NOSYSTEM": "1",
                   "GIT_CONFIG_GLOBAL": os.devnull}
    # Avoid credentials in arguments, files, process output, and cached remotes.
    if token:
        header = "Authorization: basic " + base64.b64encode(("x-access-token:" + token).encode()).decode()
        environment.update(GIT_CONFIG_COUNT="1", GIT_CONFIG_KEY_0="http.https://github.com/.extraheader", GIT_CONFIG_VALUE_0=header)
    result = subprocess.run(["git", "-C", str(directory), *args], env=environment, capture_output=True, timeout=300)
    if result.returncode:
        raise GovernanceError("git_input_failed", "Git could not read the requested immutable objects.")
    return result.stdout


def fetch(repository, base_sha, head_sha, destination, token=""):
    require(re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository), "invalid_repository")
    sha(base_sha)
    sha(head_sha)
    directory = Path(destination)
    directory.mkdir(parents=True, exist_ok=True)
    git(directory, "init", "--bare")
    git(directory, "remote", "add", "origin", "https://github.com/" + repository + ".git")
    git(directory, "fetch", "--filter=blob:none", "--no-tags", "origin", base_sha, head_sha, token=token)
    require(git(directory, "rev-parse", base_sha).decode().strip() == base_sha, "base_not_fetched")
    require(git(directory, "rev-parse", head_sha).decode().strip() == head_sha, "head_not_fetched")
    return directory


def tree_entry(directory, commit, path, token=""):
    result = git(directory, "ls-tree", "-z", commit, "--", safe_path(path), token=token)
    if not result:
        return None
    entries = [entry for entry in result.split(b"\0") if entry]
    require(len(entries) == 1, "ambiguous_git_entry")
    fields, actual_path = entries[0].split(b"\t", 1)
    mode, kind, oid = fields.decode().split()
    require(actual_path.decode() == path, "git_path_mismatch")
    if kind == 'tree':
        return None
    return {"mode": mode, "kind": kind, "oid": oid}


def discovery_tree(directory, commit, destination, token=""):
    """Materialize manifests and source names, not an executable checkout."""
    from ci import IGNORED, MANIFESTS

    destination = Path(destination)
    destination.mkdir(parents=True, exist_ok=True)
    require(not any(destination.iterdir()), "discovery_directory_not_empty")
    metadata = MANIFESTS | {".nvmrc", ".node-version", ".python-version", ".php-version", "rust-toolchain", "rust-toolchain.toml", "pytest.ini", "pnpm-workspace.yaml"}
    presence_only = {"pnpm-lock.yaml", "package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "bun.lock", "bun.lockb",
                     "uv.lock", "poetry.lock", "Cargo.lock", "binding.gyp"}
    source_suffixes = {".py", ".php", ".c", ".cpp", ".rs", ".go", ".java"}
    entries = git(directory, "ls-tree", "-r", "-z", sha(commit), token=token).split(b"\0")
    for item in entries:
        if not item:
            continue
        fields, encoded_path = item.split(b"\t", 1)
        path = encoded_path.decode()
        safe_path(path)
        parts = Path(path).parts
        if any(part in IGNORED for part in parts):
            continue
        mode, kind, oid = fields.decode().split()
        if mode == "120000":
            continue
        require(kind == "blob", "ci_submodule_requires_configuration", path)
        name = parts[-1]
        selected = name in metadata or name in presence_only or Path(path).suffix in source_suffixes
        if not selected:
            continue
        target = destination / path
        target.parent.mkdir(parents=True, exist_ok=True)
        needs_content = name in metadata or (name.startswith("test") and name.endswith(".py"))
        target.write_bytes(git(directory, "cat-file", "blob", oid, token=token) if needs_content else b"")
    return destination


def snapshot(directory, repository, pr_number, base_sha, head_sha, output_dir, token=""):
    sha(base_sha)
    sha(head_sha)
    merge_base = git(directory, "merge-base", base_sha, head_sha, token=token).decode().strip()
    sha(merge_base)
    changed = git(directory, "diff", "--no-renames", "--name-status", "-z", merge_base, head_sha, token=token).split(b"\0")
    changed = [part.decode() for part in changed if part]
    require(len(changed) % 2 == 0, "invalid_git_diff")
    output_dir = Path(output_dir)
    manifest = {"schema_version": 1, "repository": repository, "pr_number": pr_number,
                "base_sha": base_sha, "head_sha": head_sha, "merge_base_sha": merge_base, "files": []}
    statuses = {"A": "added", "M": "modified", "D": "deleted", "T": "type_changed"}
    for index in range(0, len(changed), 2):
        status, path = changed[index:index + 2]
        safe_path(path)
        require(status in statuses, "unsupported_git_change", status)
        file_record = {"path": path, "status": statuses[status], "base": None, "head": None}
        for side, commit in (("base", merge_base), ("head", head_sha)):
            entry = tree_entry(directory, commit, path, token)
            if entry is None:
                continue
            require(entry["kind"] == "blob", "submodule_review_requires_context", path)
            content = git(directory, "cat-file", "blob", entry["oid"], token=token)
            try:
                content.decode("utf-8")
                text = b"\0" not in content
            except UnicodeError:
                text = False
            file_record[side] = {"oid": entry["oid"], "mode": entry["mode"], "bytes": len(content),
                                 "sha256": hashlib.sha256(content).hexdigest(), "text": text,
                                 "lines": len(content.splitlines()) if text else 0}
            target = output_dir / side / path
            target.parent.mkdir(parents=True, exist_ok=True)
            require(not target.is_symlink(), "snapshot_symlink")
            # Git symlinks remain data files. They never become filesystem links.
            target.write_bytes(content)
        manifest["files"].append(file_record)
    require(manifest["files"], "empty_change")
    # A full diff and full changed blobs are available. No first-N-lines truncation.
    change_diff = git(directory, "diff", "--no-ext-diff", "--no-textconv", "--no-renames", merge_base, head_sha, token=token)
    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "change.diff").write_bytes(change_diff)
    for name in ("README.md", "SECURITY.md"):
        entry = tree_entry(directory, base_sha, name, token)
        if entry and entry["kind"] == "blob":
            target = output_dir / "context" / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(git(directory, "cat-file", "blob", entry["oid"], token=token))
    write_json(output_dir / "manifest.json", manifest)
    return manifest
