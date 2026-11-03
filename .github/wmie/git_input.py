"""Read immutable Git objects without checking out or running proposed code."""

from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess

from core import GovernanceError, require, safe_path, sha


def git(directory, *args, token="", input=None, no_lazy_fetch=False):
    environment = {**os.environ, "GIT_TERMINAL_PROMPT": "0", "GIT_CONFIG_NOSYSTEM": "1",
                   "GIT_CONFIG_GLOBAL": os.devnull}
    # Avoid credentials in arguments, files, process output, and cached remotes.
    if token:
        header = "Authorization: basic " + base64.b64encode(("x-access-token:" + token).encode()).decode()
        environment.update(GIT_CONFIG_COUNT="1", GIT_CONFIG_KEY_0="http.https://github.com/.extraheader", GIT_CONFIG_VALUE_0=header)
    if no_lazy_fetch:
        environment["GIT_NO_LAZY_FETCH"] = "1"
    result = subprocess.run(["git", "-C", str(directory), *args], env=environment,
                            input=input, capture_output=True, timeout=300)
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


def tree_index(directory, commit, token=""):
    """Read paths once; size only available local blobs, never lazy-fetch a tree."""
    entries = {}
    for item in git(directory, "ls-tree", "-r", "-z", sha(commit), token=token).split(b"\0"):
        if not item:
            continue
        fields, encoded_path = item.split(b"\t", 1)
        path = safe_path(encoded_path.decode())
        mode, kind, oid = fields.decode().split()
        entries[path] = {"mode": mode, "kind": kind, "oid": oid,
                         "bytes": None}
    sizes = blob_sizes(directory, [entry["oid"] for entry in entries.values() if entry["kind"] == "blob"], token)
    for entry in entries.values():
        entry["bytes"] = sizes.get(entry["oid"])
    return entries


def blob_sizes(directory, oids, token=""):
    """Inspect local blob sizes without turning missing objects into N fetches."""
    oids = list(dict.fromkeys(oids))
    if not oids:
        return {}
    for oid in oids:
        sha(oid)
    request = ("\n".join(oids) + "\n").encode()
    # Without this check a partial clone can silently fetch once per batch item.
    checks = git(directory, "cat-file", "--batch-check", input=request,
                 no_lazy_fetch=True, token=token).splitlines()
    require(len(checks) == len(oids), "invalid_git_batch")
    sizes = {}
    for oid, line in zip(oids, checks):
        fields = line.decode().split()
        require(fields[0] == oid, "git_object_mismatch")
        if fields[1:] == ["missing"]:
            sizes[oid] = None
        else:
            require(len(fields) == 3 and fields[1] == "blob", "invalid_git_blob")
            sizes[oid] = int(fields[2])
    return sizes


def read_blobs(directory, oids, token=""):
    """Read each unique blob once; hydrate missing promisor blobs in one fetch."""
    oids = list(dict.fromkeys(oids))
    if not oids:
        return {}
    missing = [oid for oid, size in blob_sizes(directory, oids, token).items() if size is None]
    if missing:
        git(directory, "fetch", "--no-tags", "--no-write-fetch-head", "--recurse-submodules=no",
            "--filter=blob:none", "--stdin", "origin", input=("\n".join(missing) + "\n").encode(), token=token)
    payload = git(directory, "cat-file", "--batch", input=("\n".join(oids) + "\n").encode(), token=token, no_lazy_fetch=True)
    result, offset = {}, 0
    for oid in oids:
        end = payload.find(b"\n", offset)
        require(end >= offset, "invalid_git_batch")
        fields = payload[offset:end].decode().split()
        require(len(fields) == 3 and fields[:2] == [oid, "blob"], "invalid_git_blob")
        size = int(fields[2])
        offset = end + 1
        require(size >= 0 and payload[offset + size:offset + size + 1] == b"\n", "invalid_git_batch")
        result[oid] = payload[offset:offset + size]
        offset += size + 1
    require(offset == len(payload), "invalid_git_batch")
    return result


def write_data(root, relative, content):
    """Write data only, refusing pre-existing symlinks in the output path."""
    root = Path(root)
    target = root
    require(not root.is_symlink(), "snapshot_symlink")
    for part in Path(safe_path(relative)).parts:
        target = target / part
        require(not target.is_symlink(), "snapshot_symlink")
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(content)


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
    selected = []
    for path, entry in tree_index(directory, commit, token).items():
        parts = Path(path).parts
        if any(part in IGNORED for part in parts):
            continue
        mode, kind, oid = entry["mode"], entry["kind"], entry["oid"]
        if mode == "120000":
            continue
        require(kind == "blob", "ci_submodule_requires_configuration", path)
        name = parts[-1]
        if not (name in metadata or name in presence_only or Path(path).suffix in source_suffixes):
            continue
        needs_content = name in metadata or (name.startswith("test") and name.endswith(".py"))
        selected.append((path, oid, needs_content))
    blobs = read_blobs(directory, [oid for _, oid, needed in selected if needed], token)
    for path, oid, needed in selected:
        write_data(destination, path, blobs[oid] if needed else b"")
    return destination


def snapshot(directory, repository, pr_number, base_sha, head_sha, output_dir, token="", *, prepare_context=False, tree_sizes=None):
    sha(base_sha)
    sha(head_sha)
    merge_base = git(directory, "merge-base", base_sha, head_sha, token=token).decode().strip()
    sha(merge_base)
    changed = git(directory, "diff", "--no-ext-diff", "--no-textconv", "--no-renames", "--name-status", "-z", merge_base, head_sha, token=token).split(b"\0")
    changed = [part.decode() for part in changed if part]
    require(len(changed) % 2 == 0, "invalid_git_diff")
    output_dir = Path(output_dir)
    manifest = {"schema_version": 1, "repository": repository, "pr_number": pr_number,
                "base_sha": base_sha, "head_sha": head_sha, "merge_base_sha": merge_base, "files": []}
    statuses = {"A": "added", "M": "modified", "D": "deleted", "T": "type_changed"}
    trees = {commit: tree_index(directory, commit, token) for commit in dict.fromkeys((merge_base, head_sha, base_sha))}
    requested = []
    for index in range(0, len(changed), 2):
        status, path = changed[index:index + 2]
        safe_path(path)
        require(status in statuses, "unsupported_git_change", status)
        for commit in (merge_base, head_sha):
            entry = trees[commit].get(path)
            if entry:
                require(entry["kind"] == "blob", "submodule_review_requires_context", path)
                requested.append(entry["oid"])
    for name in ("README.md", "SECURITY.md"):
        entry = trees[base_sha].get(name)
        if entry and entry["kind"] == "blob":
            requested.append(entry["oid"])
    blobs = read_blobs(directory, requested, token)
    for index in range(0, len(changed), 2):
        status, path = changed[index:index + 2]
        safe_path(path)
        require(status in statuses, "unsupported_git_change", status)
        file_record = {"path": path, "status": statuses[status], "base": None, "head": None}
        for side, commit in (("base", merge_base), ("head", head_sha)):
            entry = trees[commit].get(path)
            if entry is None:
                continue
            require(entry["kind"] == "blob", "submodule_review_requires_context", path)
            content = blobs[entry["oid"]]
            try:
                content.decode("utf-8")
                text = b"\0" not in content
            except UnicodeError:
                text = False
            file_record[side] = {"oid": entry["oid"], "mode": entry["mode"], "bytes": len(content),
                                 "sha256": hashlib.sha256(content).hexdigest(), "text": text,
                                 "lines": len(content.splitlines()) if text else 0}
            # Git symlinks remain data files. They never become filesystem links.
            write_data(output_dir, side + "/" + path, content)
        manifest["files"].append(file_record)
    require(manifest["files"], "empty_change")
    # A full diff and full changed blobs are available. No first-N-lines truncation.
    change_diff = git(directory, "diff", "--no-ext-diff", "--no-textconv", "--no-renames", merge_base, head_sha, token=token)
    write_data(output_dir, "change.diff", change_diff)
    for name in ("README.md", "SECURITY.md"):
        entry = trees[base_sha].get(name)
        if entry and entry["kind"] == "blob":
            write_data(output_dir, "context/" + name, blobs[entry["oid"]])
    if prepare_context:
        from review_context import prepare
        prepare(directory, manifest, trees, blobs, output_dir, token, tree_sizes=tree_sizes)
    write_data(output_dir, "manifest.json", (json.dumps(manifest, indent=2, ensure_ascii=False) + "\n").encode())
    return manifest
