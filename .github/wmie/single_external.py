"""Fetch pinned external action files as untrusted data before the single model call.

prepare_external runs once in the prepare job and writes source/external/.
read_external is pure: it only re-reads and re-hashes the local cache.
Fetched content is never executed and never enters the system prompt.

Required files (entry points, files they name, files named by changed lines) block
a complete review when they are missing. Optional files (the rest of what the workflow
names) only appear in the informational omitted list when they do not fit.
"""

import base64
import hashlib
import json
from pathlib import Path
import posixpath
import re

import yaml

from core import GovernanceError, read_json, require, safe_path, write_json

EXTERNAL_BYTES = 512 * 1024
MAX_REFS = 10
MAX_BLOB_FETCHES = 300
OWNER = r"[A-Za-z0-9][A-Za-z0-9-]{0,38}"
NAME = r"[A-Za-z0-9._-]{1,100}"
SHA = re.compile(r"[0-9a-f]{40}")
REPOSITORY = re.compile(OWNER + "/" + NAME, re.A)
WORKFLOW = re.compile(r"\.github/workflows/[^/]+\.ya?ml")
USES = re.compile(r"^\s*(?:-\s*)?uses:\s*['\"]?(" + OWNER + ")/(" + NAME + r")((?:/[A-Za-z0-9._/-]+)?)@([^\s#'\"]+)",
                  re.M | re.A)
SENSITIVE = re.compile(r"checkout|token|secret|credential|auth|permission", re.I)
MODES = {"100644", "100755"}
CANDIDATE_SUFFIXES = {".sh", ".cjs", ".js", ".mjs", ".ts", ".py", ".rb", ".ps1", ".md", ".json", ".yml", ".yaml", ".toml", ".txt"}
SEED_FIELDS = ("main", "pre", "post", "image")
OPTIONAL_SEED_FIELDS = ("entrypoint", "pre-entrypoint", "post-entrypoint")
TRUSTED_OWNERS = {"actions"}  # plain first-party wrappers; recorded as skipped, not as a coverage limitation
# ponytail: required = entry points + files they name + files named by changed lines; optional = the rest of what the
# workflow names. A name that matches several paths is optional. Raise the depth only if a trial shows a missing contract.


def _oid(data):
    return hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()


def _tier(path):
    suffix = posixpath.splitext(path)[1]
    if posixpath.basename(path) in ("action.yml", "action.yaml"):
        return 0
    return 1 if suffix == ".sh" else 3 if suffix in (".js", ".cjs", ".mjs", ".ts") else 2


def _candidate(path):
    return (posixpath.splitext(path)[1] in CANDIDATE_SUFFIXES or posixpath.basename(path) == "Dockerfile") \
        and "/node_modules/" not in "/" + path


def _tokens(text):
    return {token.strip(".-") for token in re.findall(r"[\w.-]+", text, re.A)}


def _text(data):
    try:
        content = data.decode("utf-8")
    except UnicodeDecodeError:
        return None
    return None if "\0" in content else content


def _fetch(api, slug, entry):
    blob = api.request("GET", f"/repos/{slug}/git/blobs/{entry['sha']}")
    require(isinstance(blob, dict) and blob.get("encoding") == "base64", "external_blob_invalid", entry["path"])
    try:
        data = base64.b64decode(blob.get("content", ""), validate=False)
    except ValueError as error:
        raise GovernanceError("external_blob_invalid", entry["path"]) from error
    require(len(data) == entry["size"] and _oid(data) == entry["sha"], "external_blob_mismatch", entry["path"])
    return data


def _api(call, *args):
    """Return None for an HTTP error from GitHub (missing or unreadable). Any other failure stays fatal."""
    try:
        return call(*args)
    except GovernanceError as error:
        if error.code != "github_api_error":
            raise
        return None


def prepare_external(api, root, max_bytes=EXTERNAL_BYTES):
    root = Path(root)
    target = root / "external"
    require(not target.exists(), "external_exists")
    manifest = json.loads((root / "manifest.json").read_text())
    texts = []
    for item in sorted(manifest["files"], key=lambda item: item["path"]):
        head = root / "head" / item["path"]
        if WORKFLOW.fullmatch(item["path"]) and head.is_file() and not head.is_symlink():
            texts.append(head.read_text(errors="replace"))
    workflow_text = "\n".join(texts)
    diff = root / "change.diff"
    lines = diff.read_text(errors="replace").splitlines() if diff.is_file() and not diff.is_symlink() else []
    changed_tokens = _tokens("\n".join(l[1:] for l in lines if l[:1] in ("+", "-") and l[:3] not in ("+++", "---")))
    workflow_tokens = _tokens(workflow_text)
    limitations, skipped, omitted, refs = set(), set(), set(), {}
    for owner, repo, subdirectory, ref in USES.findall(workflow_text):
        subdirectory = subdirectory.strip("/")
        label = f"{owner}/{repo}" + (f"/{subdirectory}" if subdirectory else "") + "@" + ref
        if owner.lower() in TRUSTED_OWNERS:
            skipped.add(label)
        elif not SHA.fullmatch(ref):
            limitations.add("external_unpinned:" + label)
        elif repo in (".", ".."):
            limitations.add("external_action_not_found:" + label)
        else:
            refs[(owner, repo, subdirectory, ref)] = label
    state, entries, blobs, trees, contexts = {"used": 0, "fetches": 0}, [], {}, {}, []

    def note(required, reason, slug, path):
        if required:
            limitations.add(f"{reason}:{slug}:{path}")
        else:
            omitted.add(f"{slug}:{path}")

    def take(ctx, paths, required):
        slug, files, got = ctx["slug"], ctx["files"], ctx["got"]
        # Required files go by tier. Optional files go in three groups: security-relevant names (the review criteria
        # cover permissions and secrets), then other files that the workflow names, then the rest.
        # Inside each group the smallest file goes first, which covers the most files for the same bytes.
        order = (lambda p: (_tier(p), p)) if required else (
            lambda p: (not SENSITIVE.search(posixpath.basename(p)), posixpath.basename(p) not in workflow_tokens,
                       files[p]["size"], p))
        for path in sorted(paths, key=order):
            if path in got:
                continue
            ctx["attempted"].add(path)
            safe_path(path)
            entry = files[path]
            if state["used"] + entry["size"] > max_bytes:
                note(required, "external_byte_limit", slug, path)
                continue
            if entry["sha"] not in blobs:
                if state["fetches"] >= MAX_BLOB_FETCHES:
                    note(required, "external_fetch_limit", slug, path)
                    continue
                state["fetches"] += 1
                data = _api(_fetch, api, slug, entry)
                if data is None:
                    note(required, "external_blob_unavailable", slug, path)
                    continue
                blobs[entry["sha"]] = data
            data = blobs[entry["sha"]]
            state["used"] += len(data)
            if _text(data) is None:
                note(required, "external_nontext", slug, path)
                continue
            got[path] = data
            entries.append({"repository": slug, "revision_sha": ctx["revision"], "source_path": path,
                            "oid": entry["sha"], "size": len(data)})

    def named(ctx, tokens, *, unique):
        found = set()
        for token in tokens:
            paths = ctx["names"].get(token, [])
            found.update(paths if len(paths) == 1 or not unique else [])
        return found - set(ctx["got"]) - ctx["attempted"]

    for position, key in enumerate(sorted(refs)):
        owner, repo, subdirectory, revision = key
        slug, label = f"{owner}/{repo}", refs[key]
        if position >= MAX_REFS:
            limitations.add("external_ref_limit:" + label)
            continue
        if (slug, revision) not in trees:
            tree = _api(api.request, "GET", f"/repos/{slug}/git/trees/{revision}?recursive=1")
            require(tree is None or (isinstance(tree, dict) and isinstance(tree.get("tree"), list)), "external_tree_invalid", slug)
            trees[(slug, revision)] = tree
        tree = trees[(slug, revision)]
        if tree is None:
            limitations.add("external_action_not_found:" + label)
            continue
        if tree.get("truncated"):
            limitations.add("external_tree_truncated:" + label)
            continue
        prefix = subdirectory + "/" if subdirectory else ""
        listed = [e for e in tree["tree"] if isinstance(e, dict) and isinstance(e.get("path"), str) and e["path"].startswith(prefix)]
        files = {e["path"]: e for e in listed if e.get("type") == "blob" and e.get("mode") in MODES
                 and type(e.get("size")) is int and SHA.fullmatch(str(e.get("sha")))}
        names, special = {}, {}
        for path in files:
            if _candidate(path):
                names.setdefault(posixpath.basename(path), []).append(path)
        for e in listed:  # symlinks and submodules cannot be fetched as file contents
            if e.get("type") in ("blob", "commit") and e.get("mode") not in MODES and _candidate(e["path"]):
                special.setdefault(posixpath.basename(e["path"]), []).append(e["path"])
        ctx = {"slug": slug, "revision": revision, "files": files, "names": names, "got": {}, "attempted": set()}
        action = next((prefix + n for n in ("action.yml", "action.yaml") if prefix + n in files), None)
        if action is None:
            limitations.add("external_action_not_found:" + label)
            continue
        take(ctx, [action], True)
        if action not in ctx["got"]:
            continue
        seeds = {action}
        try:
            runs = (yaml.safe_load(ctx["got"][action].decode()) or {}).get("runs") or {}
            require(isinstance(runs, dict), "external_action_invalid")
        except (yaml.YAMLError, AttributeError, GovernanceError):
            limitations.add("external_action_invalid:" + label)
            runs = {}
        for field in SEED_FIELDS + OPTIONAL_SEED_FIELDS:
            value = runs.get(field)
            if not isinstance(value, str) or value.startswith("docker://"):
                continue
            # The docs do not state the base of these paths; they resolve against the action directory.
            path = posixpath.normpath(posixpath.join(subdirectory, value))
            if path in files:
                seeds.add(path)
            elif field in SEED_FIELDS:
                limitations.add(f"external_entry_missing:{label}:{value}")
        take(ctx, seeds, True)
        scan = "\n".join(ctx["got"][p].decode() for p in sorted(ctx["got"]))
        required_tokens = changed_tokens | _tokens(scan)
        for token in sorted(required_tokens):
            for path in special.get(token, []):
                limitations.add(f"external_entry_unsupported:{slug}:{path}")
        take(ctx, named(ctx, required_tokens, unique=True), True)
        ctx["scan"] = scan + "\n" + "\n".join(ctx["got"][p].decode() for p in sorted(ctx["got"]) if p not in seeds)
        contexts.append(ctx)
    # Optional files only use the budget that every required pass left over.
    for ctx in contexts:
        take(ctx, named(ctx, _tokens(workflow_text + "\n" + ctx["scan"]), unique=False), False)
    if entries or limitations or omitted:
        for entry in entries:
            (target / "blobs").mkdir(parents=True, exist_ok=True)
            (target / "blobs" / entry["oid"]).write_bytes(blobs[entry["oid"]])
        write_json(target / "index.json", {"schema": 1, "entries": sorted(entries, key=lambda e: (e["repository"], e["source_path"])),
                                           "limitations": sorted(limitations), "omitted": sorted(omitted),
                                           "omitted_named_by_changed_lines": sorted(
                                               n for n in omitted if posixpath.basename(n.split(":", 1)[1]) in changed_tokens),
                                           "skipped": sorted(skipped)})


def read_omitted(root, field="omitted"):
    """Optional external files that did not fit the budget. Informational, never a coverage limitation.

    field "omitted_named_by_changed_lines" returns the subset whose name a changed line contains.
    """
    path = Path(root) / "external" / "index.json"
    if not path.is_file() or path.is_symlink():
        return []
    omitted = read_json(path).get(field, [])
    require(isinstance(omitted, list) and all(isinstance(item, str) for item in omitted), "external_index_invalid")
    return sorted(set(omitted))


def read_external(root):
    base = Path(root) / "external"
    if not base.exists() and not base.is_symlink():
        return {}, []
    require(base.is_dir() and not base.is_symlink(), "external_invalid")
    index = read_json(base / "index.json")
    require(isinstance(index, dict) and index.get("schema") == 1 and isinstance(index.get("entries"), list)
            and isinstance(index.get("limitations"), list), "external_index_invalid")
    evidence, seen = {}, set()
    for entry in index["entries"]:
        require(isinstance(entry, dict) and REPOSITORY.fullmatch(str(entry.get("repository")))
                and SHA.fullmatch(str(entry.get("revision_sha"))) and SHA.fullmatch(str(entry.get("oid")))
                and type(entry.get("size")) is int, "external_index_invalid")
        safe_path(entry.get("source_path"))
        blob = base / "blobs" / entry["oid"]
        require(blob.is_file() and not blob.is_symlink(), "external_blob_missing", entry["oid"])
        data = blob.read_bytes()
        require(_oid(data) == entry["oid"] and len(data) == entry["size"], "external_blob_mismatch", entry["oid"])
        content = _text(data)
        require(content is not None, "external_blob_mismatch", entry["oid"])
        seen.add(entry["oid"])
        evidence[f"{entry['repository']}@{entry['revision_sha']}:{entry['source_path']}"] = {**entry, "content": content}
    blobs = base / "blobs"
    require({p.name for p in blobs.iterdir()} <= seen if blobs.is_dir() else True, "external_blob_unexpected")
    require(all(isinstance(note, str) for note in index["limitations"]), "external_index_invalid")
    return evidence, sorted(set(index["limitations"]))
