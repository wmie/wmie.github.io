"""Run baseline content and secret checks without executing proposed code."""

from __future__ import annotations

import argparse
import fnmatch
import hashlib
import io
import json
import os
from pathlib import Path
import platform
import subprocess
import sys
import tarfile
import tempfile
import urllib.request

from core import GovernanceError, read_json, require, sha
from git_input import snapshot
from review import validate_manifest


def reject_json_constant(value):
    raise ValueError('Invalid JSON constant: ' + value)


def content(source, binding):
    with tempfile.TemporaryDirectory(prefix="wmie-content-") as directory:
        manifest = snapshot(source, binding["repository"], binding["pr_number"], binding["base_sha"], binding["head_sha"], directory)
        validate_manifest(manifest, binding["repository"], binding["pr_number"], binding["base_sha"], binding["head_sha"])
        ignored = binding["plan"].get("json_validation_exclude", [])
        checked, jsonc, excluded, symlinks = [], [], [], []
        for item in manifest["files"]:
            path = item["path"]
            if not path.lower().endswith(".json") or item["head"] is None:
                continue
            if item['head']['mode'] == '120000':
                symlinks.append(path)
                continue
            require(item['head']['mode'] in {'100644', '100755'}, 'unsupported_json_blob_mode', path)
            if any(fnmatch.fnmatchcase(path, pattern) for pattern in ignored):
                excluded.append(path)
                continue
            if Path(path).name.startswith(("tsconfig", "jsconfig")) or path.startswith(".vscode/"):
                jsonc.append(path)
                continue
            try:
                json.loads((Path(directory) / "head" / path).read_text(encoding="utf-8-sig"),
                           parse_constant=reject_json_constant)
            except (ValueError, UnicodeError) as error:
                raise GovernanceError("invalid_changed_json", path) from error
            checked.append(path)
        return {"state": "success", "files": len(manifest["files"]), "json_checked": checked,
                "jsonc_not_validated": jsonc, "json_excluded_by_profile": excluded, "json_symlinks_not_followed": symlinks}


def security(source, binding):
    versions = read_json(Path(__file__).with_name("tool-versions.json"))["gitleaks"]
    architecture = {"x86_64": "linux_x64", "aarch64": "linux_arm64"}.get(platform.machine())
    require(platform.system() == "Linux" and architecture, "unsupported_scanner_platform")
    name = f"gitleaks_{versions['version']}_{architecture}.tar.gz"
    url = f"https://github.com/gitleaks/gitleaks/releases/download/v{versions['version']}/{name}"
    with urllib.request.urlopen(url, timeout=60) as response:
        payload = response.read(64 * 1024 * 1024 + 1)
    require(len(payload) <= 64 * 1024 * 1024 and hashlib.sha256(payload).hexdigest() == versions[architecture], "scanner_digest_mismatch")
    with tempfile.TemporaryDirectory(prefix="wmie-security-") as temporary:
        root = Path(temporary)
        with tarfile.open(fileobj=io.BytesIO(payload), mode="r:gz") as archive:
            matches = [item for item in archive.getmembers() if item.name == "gitleaks"]
            require(len(matches) == 1 and matches[0].isfile(), "invalid_scanner_archive")
            binary = root / "gitleaks"
            binary.write_bytes(archive.extractfile(matches[0]).read())
            binary.chmod(0o700)
        # No PR-authored ignore file, config, or inline allow-comment can suppress a secret.
        config = root / "gitleaks.toml"
        config.write_text('[extend]\nuseDefault = true\n')
        report = root / "secrets.json"
        result = subprocess.run([str(binary), "git", str(Path(source).resolve()), "--config", str(config),
            "--gitleaks-ignore-path", str(root), "--ignore-gitleaks-allow", "--no-banner", "--redact=100", "--no-color",
            "--log-opts=" + sha(binding["base_sha"]) + ".." + sha(binding["head_sha"]), "--report-format=json", "--report-path", str(report)],
            cwd=root, capture_output=True, timeout=600)
        # Raw scanner output stays private. Even a future regression must not print secret values.
        require(result.returncode in {0, 1}, "secret_scanner_failed", "Read the scanner version and Git input metadata.")
        if result.returncode == 1:
            findings = json.loads(report.read_text()) if report.is_file() else []
            safe = [{key: item.get(key) for key in ("RuleID", "File", "StartLine")} for item in findings]
            raise GovernanceError("secrets_detected", json.dumps(safe))
        return {"state": "success", "scanner": "gitleaks", "version": versions["version"]}


def yarn():
    component = json.loads(os.environ["WMIE_COMPONENT"])
    versions = read_json(Path(__file__).with_name("tool-versions.json"))
    version = component.get("package_manager_version") or versions["yarn"]
    require(isinstance(version, str) and re_version(version), "invalid_yarn_version")
    for argv in (["npm", "install", "--global", "corepack@" + versions["corepack"]],
                 ["corepack", "enable"], ["corepack", "prepare", "yarn@" + version, "--activate"]):
        require(subprocess.run(argv).returncode == 0, "yarn_setup_failed")
    return {"state": "success", "package_manager": "yarn", "version": version}


def re_version(value):
    import re
    return re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+(?:[-+][A-Za-z0-9._-]+)?", value)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=("content", "security", "yarn"))
    parser.add_argument("--source", default="wmie-source")
    parser.add_argument("--binding", default="wmie-ci-binding.json")
    args = parser.parse_args()
    try:
        result = yarn() if args.command == "yarn" else globals()[args.command](args.source, read_json(args.binding))
        print(json.dumps(result, sort_keys=True))
        return 0
    except GovernanceError as error:
        print(json.dumps({"state": "blocked", "code": error.code, "detail": error.detail}), file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
