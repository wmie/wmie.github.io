"""Deterministic governance helpers. This module never calls an AI provider."""

from __future__ import annotations

import hashlib
import base64
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import urllib.error
import urllib.parse
import urllib.request
import zipfile


class GovernanceError(Exception):
    def __init__(self, code: str, detail: str = ""):
        self.code = code
        self.detail = detail
        super().__init__(f"{code}: {detail}" if detail else code)


def require(condition, code, detail=""):
    if not condition:
        raise GovernanceError(code, detail)


def sha(value):
    require(isinstance(value, str) and re.fullmatch(r"[0-9a-f]{40}", value), "invalid_commit")
    return value


def safe_path(value):
    require(isinstance(value, str) and value and "\x00" not in value, "invalid_path")
    path = PurePosixPath(value)
    require(not path.is_absolute() and ".." not in path.parts and str(path) == value,
            "invalid_path", value)
    require(not any(ord(c) < 32 for c in value) and "\\" not in value, "invalid_path", value)
    return value


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def read_json(path):
    try:
        return json.loads(Path(path).read_text())
    except (OSError, ValueError) as error:
        raise GovernanceError("invalid_json", str(path)) from error


def write_json(path, value):
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(value, indent=2, ensure_ascii=False) + "\n")


def output(name, value):
    require(re.fullmatch(r"[a-zA-Z_][a-zA-Z0-9_]*", name), "invalid_output_name")
    text = str(value) if not isinstance(value, (dict, list)) else json.dumps(value, separators=(",", ":"))
    require("\n" not in text and "\r" not in text, "invalid_output_value")
    if os.getenv("GITHUB_OUTPUT"):
        with open(os.environ["GITHUB_OUTPUT"], "a") as stream:
            stream.write(f"{name}={text}\n")


class GitHub:
    """Small REST adapter with no automatic retries or redirect of credentials."""

    def __init__(self, token=None, opener=None):
        self.token = token if token is not None else os.environ.get("GH_TOKEN", "")
        self.opener = opener or urllib.request.build_opener(NoRedirect())

    def request(self, method, endpoint, body=None, raw=False):
        require(endpoint.startswith("/") and not endpoint.startswith("//"), "invalid_api_path")
        url = "https://api.github.com" + endpoint
        data = None if body is None else json.dumps(body).encode()
        headers = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28",
                   "User-Agent": "wmie-governance", "Content-Type": "application/json"}
        if self.token:
            headers["Authorization"] = "Bearer " + self.token
        request = urllib.request.Request(url, data=data, method=method, headers=headers)
        try:
            with self.opener.open(request, timeout=60) as response:
                payload = response.read()
                return payload if raw else (json.loads(payload) if payload else None)
        except urllib.error.HTTPError as error:
            # Do not log provider bodies, repository data, or credentials.
            raise GovernanceError("github_api_error", f"{method} {endpoint.split('?')[0]} HTTP {error.code}") from error
        except (OSError, ValueError) as error:
            code = "github_write_outcome_unknown" if method != "GET" else "github_read_failed"
            raise GovernanceError(code, f"{method} {endpoint.split('?')[0]}") from error

    def pages(self, endpoint, field=None):
        result = []
        for page in range(1, 1001):
            separator = "&" if "?" in endpoint else "?"
            data = self.request("GET", f"{endpoint}{separator}per_page=100&page={page}")
            items = data[field] if field else data
            require(isinstance(items, list), "github_invalid_page")
            result.extend(items)
            if len(items) < 100:
                return result
        raise GovernanceError("github_pagination_incomplete", endpoint)

    def file(self, repository, path, ref):
        safe_path(path)
        data = self.request("GET", f"/repos/{repository}/contents/{urllib.parse.quote(path, safe='/')}?ref={urllib.parse.quote(ref, safe='')}")
        require(data.get("type") == "file" and data.get("encoding") == "base64", "github_file_incomplete", path)
        try:
            content = base64.b64decode(data["content"], validate=False)
        except (ValueError, KeyError) as error:
            raise GovernanceError("github_file_incomplete", path) from error
        require(len(content) == data.get("size"), "github_file_incomplete", path)
        return content

    def archive(self, endpoint, *, maximum_bytes=32 * 1024 * 1024):
        """Download an artifact without forwarding the API token to blob storage."""
        require(endpoint.startswith("/repos/") and endpoint.endswith("/zip"), "invalid_artifact_endpoint")
        headers = {"Accept": "application/vnd.github+json", "User-Agent": "wmie-governance"}
        if self.token:
            headers["Authorization"] = "Bearer " + self.token
        request = urllib.request.Request("https://api.github.com" + endpoint, headers=headers)
        try:
            try:
                response = self.opener.open(request, timeout=60)
            except urllib.error.HTTPError as error:
                require(error.code in {301, 302, 303, 307, 308}, "artifact_download_failed", str(error.code))
                location = error.headers.get("Location", "")
                parsed = urllib.parse.urlsplit(location)
                host = parsed.hostname or ""
                require(parsed.scheme == "https" and not parsed.username and not parsed.password
                        and parsed.port in {None, 443}
                        and (host.endswith(".blob.core.windows.net") or host.endswith(".actions.githubusercontent.com")),
                        "untrusted_artifact_redirect")
                # This new request carries no credentials, cookies, or API headers.
                response = self.opener.open(urllib.request.Request(location), timeout=60)
            with response:
                payload = response.read(maximum_bytes + 1)
            require(len(payload) <= maximum_bytes, "artifact_too_large")
            return payload
        except GovernanceError:
            raise
        except (OSError, ValueError) as error:
            raise GovernanceError("artifact_download_failed") from error


def archive_json(payload, member, *, maximum_bytes=8 * 1024 * 1024, json_lines=False):
    """Read one JSON member. Never extract executable or attacker-selected paths."""
    safe_path(member)
    try:
        with zipfile.ZipFile(io.BytesIO(payload)) as archive:
            entries = archive.infolist()
            names = [entry.filename for entry in entries]
            require(len(names) == len(set(names)), "duplicate_artifact_member")
            require(member in names, "missing_artifact_member", member)
            for entry in entries:
                safe_path(entry.filename.rstrip("/"))
                require(not entry.flag_bits & 1, "encrypted_artifact")
                require((entry.external_attr >> 16) & 0o170000 != 0o120000, "artifact_symlink")
            entry = archive.getinfo(member)
            require(entry.file_size <= maximum_bytes, "artifact_member_too_large")
            content = archive.read(entry)
            if json_lines:
                values = [json.loads(line) for line in content.splitlines() if line.strip()]
                require(all(isinstance(value, dict) for value in values), "invalid_artifact_json")
                return values
            value = json.loads(content)
            require(isinstance(value, dict), "invalid_artifact_json")
            return value
    except GovernanceError:
        raise
    except (OSError, ValueError, KeyError, zipfile.BadZipFile) as error:
        raise GovernanceError("invalid_artifact_archive") from error


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None
