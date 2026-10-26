"""Discover project-specific CI. No project code runs during discovery."""

from __future__ import annotations

import json
import fnmatch
from pathlib import Path
import re
import tomllib

from core import GovernanceError, digest, require, safe_path


IGNORED = {".git", ".github", "node_modules", "vendor", ".venv", "venv", "dist", "build", ".next",
           ".cache", "coverage", "target", "__pycache__", "generated"}
MANIFESTS = {"package.json", "pyproject.toml", "requirements.txt", "go.mod", "Cargo.toml", "composer.json", "CMakeLists.txt"}
NODE_CHECKS = {"lint", "check", "check:ci", "typecheck", "type-check", "check-types", "test", "test:ci", "test:unit",
               "test:int", "test:integration", "test:e2e", "build", "lint:ci", "format:check"}
PLACEHOLDER = re.compile(r"(?:no test specified|no tests? (?:yet|configured)|TODO.*tests?|^\s*(?:true|exit 0|echo\s+['\"]?(?:ok|TODO))\s*$)", re.I)


def _read(path):
    require(not path.is_symlink(), "manifest_symlink", str(path))
    try:
        return path.read_text()
    except (OSError, UnicodeError) as error:
        raise GovernanceError("manifest_unreadable", str(path)) from error


def _json(path):
    try:
        value = json.loads(_read(path))
        require(isinstance(value, dict), "invalid_project_manifest", str(path))
        return value
    except ValueError as error:
        raise GovernanceError("invalid_project_manifest", str(path)) from error


def _toml(path):
    try:
        return tomllib.loads(_read(path))
    except ValueError as error:
        raise GovernanceError("invalid_project_manifest", str(path)) from error


def _files(root):
    # Never traverse symlinks, downloaded dependencies, or generated directories.
    def walk(directory):
        for path in sorted(directory.iterdir()):
            if path.name in IGNORED or path.is_symlink():
                continue
            if path.is_dir():
                yield from walk(path)
            elif path.is_file():
                yield path
    yield from walk(root)


def _check(component_id, name, argv):
    return {"id": component_id + ":" + name, "name": name, "argv": argv, "applicable": True}


def _node_workspace(root, directory):
    for candidate in directory.parents:
        if candidate != root and root not in candidate.parents:
            break
        if not (candidate / "package.json").is_file():
            continue
        package = _json(candidate / "package.json")
        patterns = package.get("workspaces", [])
        if isinstance(patterns, dict):
            patterns = patterns.get("packages", [])
        if (candidate / "pnpm-workspace.yaml").is_file():
            from authoring import yaml_data
            patterns = yaml_data(candidate / "pnpm-workspace.yaml").get("packages", [])
        require(isinstance(patterns, list) and all(isinstance(p, str) for p in patterns), "invalid_workspaces")
        relative = directory.relative_to(candidate).as_posix()
        included = any(fnmatch.fnmatchcase(relative, p.rstrip("/")) for p in patterns if not p.startswith("!"))
        excluded = any(fnmatch.fnmatchcase(relative, p[1:].rstrip("/")) for p in patterns if p.startswith("!"))
        if included and not excluded:
            return candidate
    return directory


def _node(root, directory):
    package = _json(directory / "package.json")
    relative = directory.relative_to(root).as_posix()
    component_id = "node:" + relative
    workspace = _node_workspace(root, directory) if directory != root else directory
    workspace_package = _json(workspace / "package.json") if workspace != directory else package
    declared = package.get("packageManager", workspace_package.get("packageManager", ""))
    require(isinstance(declared, str), "invalid_package_manager", relative)
    manager = declared.split("@", 1)[0] if declared else None
    locks = [("pnpm-lock.yaml", "pnpm"), ("package-lock.json", "npm"), ("npm-shrinkwrap.json", "npm"),
             ("yarn.lock", "yarn"), ("bun.lock", "bun"), ("bun.lockb", "bun")]
    own_locks = {name for filename, name in locks if (directory / filename).is_file()}
    install_directory = directory if own_locks else workspace
    available = own_locks or {name for filename, name in locks if (workspace / filename).is_file()}
    require(len(available) <= 1 or manager in available, "ambiguous_package_manager", relative)
    manager = manager or (next(iter(available)) if available else "npm")
    require(manager in {"npm", "pnpm", "yarn", "bun"}, "unsupported_package_manager", manager)
    version = declared.split("@", 1)[1] if "@" in declared else None
    node_version = None
    for base in (directory, root):
        for name in (".nvmrc", ".node-version"):
            if (base / name).is_file():
                node_version = _read(base / name).strip()
                break
        if node_version:
            break
    node_version = node_version or package.get("engines", {}).get("node", "24")
    scripts = package.get("scripts", {})
    require(isinstance(scripts, dict) and all(isinstance(v, str) for v in scripts.values()), "invalid_scripts", relative)
    checks, absent = [], []
    for name, command in sorted(scripts.items()):
        if name not in NODE_CHECKS:
            continue
        if PLACEHOLDER.search(command):
            absent.append({"name": name, "reason": "The script is a placeholder."})
            continue
        # Prefer the explicit CI test command to an interactive test command.
        ci_variant = name + ":ci"
        if ci_variant in NODE_CHECKS and ci_variant in scripts and not PLACEHOLDER.search(scripts[ci_variant]):
            continue
        checks.append(_check(component_id, name, [manager, "run", name]))
    if not any(c["name"].startswith("test") for c in checks):
        absent.append({"name": "tests", "reason": "No real test command is declared."})
    install = {"npm": ["npm", "ci"] if available else ["npm", "install", "--package-lock=false"],
               "pnpm": ["pnpm", "install", "--frozen-lockfile"] if available else ["pnpm", "install", "--no-frozen-lockfile"],
               "yarn": ["yarn", "install", "--immutable"] if version and not version.startswith("1.") else ["yarn", "install", "--frozen-lockfile"],
               "bun": ["bun", "install", "--frozen-lockfile"] if available else ["bun", "install"]}[manager]
    return {"id": component_id, "path": relative, "ecosystem": "node", "manifest": "package.json",
            "runtime": str(node_version), "package_manager": manager, "package_manager_version": version,
            "install_path": install_directory.relative_to(root).as_posix(),
            "install": [install], "checks": checks, "not_configured": absent,
            "workspaces": package.get("workspaces", []), "native_addon": (directory / "binding.gyp").is_file()}


def _python(root, directory):
    relative = directory.relative_to(root).as_posix()
    component_id = "python:" + relative
    data = _toml(directory / "pyproject.toml") if (directory / "pyproject.toml").is_file() else {}
    project, tool = data.get("project", {}), data.get("tool", {})
    dependencies = project.get("dependencies", []) + [d for values in project.get("optional-dependencies", {}).values() for d in values]
    dependencies += [d for values in data.get("dependency-groups", {}).values() if isinstance(values, list) for d in values if isinstance(d, str)]
    requirements = _read(directory / "requirements.txt") if (directory / "requirements.txt").is_file() else ""
    deps = " ".join(str(d) for d in dependencies) + " " + requirements
    uses_uv = (directory / "uv.lock").is_file()
    install, prefix = [], []
    if uses_uv:
        install = [["uv", "sync", "--frozen", "--all-groups"]]
        prefix = ["uv", "run", "--frozen"]
    elif (directory / "poetry.lock").is_file() or "poetry" in tool:
        return {"id": component_id, "path": relative, "ecosystem": "python", "manifest": "pyproject.toml",
                "configuration_required": "Declare the Poetry version, install command, and CI commands in the local profile."}
    else:
        if requirements:
            install.append(["python3", "-m", "pip", "install", "-r", "requirements.txt"])
        if project and data.get("build-system"):
            extras = [name for name in ("test", "dev") if name in project.get("optional-dependencies", {})]
            install.append(["python3", "-m", "pip", "install", "." + ("[" + ",".join(extras) + "]" if extras else "")])
    checks = []
    if "pytest" in deps or "pytest" in tool or (directory / "pytest.ini").exists():
        checks.append(_check(component_id, "test", prefix + ["python3", "-m", "pytest"]))
    elif (directory / "tests").is_dir() and not (directory / "tests").is_symlink() and any(
            not p.is_symlink() and "unittest" in p.read_text(errors="replace") for p in (directory / "tests").glob("test*.py")):
        checks.append(_check(component_id, "test", prefix + ["python3", "-m", "unittest", "discover", "-s", "tests", "-v"]))
    if "ruff" in deps or "ruff" in tool:
        checks.append(_check(component_id, "lint", prefix + ["ruff", "check", "."]))
    if "mypy" in deps or "mypy" in tool:
        checks.append(_check(component_id, "typecheck", prefix + ["mypy", "."]))
    checks.append(_check(component_id, "syntax", ["python3", "-m", "compileall", "-q", "-x", r"(^|/)(\.venv|venv|node_modules)/", "."]))
    version_file = directory / ".python-version"
    runtime = _read(version_file).strip() if version_file.is_file() else project.get("requires-python", "3.12")
    return {"id": component_id, "path": relative, "ecosystem": "python", "manifest": "pyproject.toml" if data else "requirements.txt",
            "runtime": runtime, "package_manager": "uv" if uses_uv else "pip", "install": install, "checks": checks,
            "not_configured": [] if any(c["name"] == "test" for c in checks) else [{"name": "tests", "reason": "No test suite is declared."}]}


def _native(root, directory, ecosystem):
    relative = directory.relative_to(root).as_posix()
    component_id = ecosystem + ":" + relative
    install, checks, missing, extra = [], [], [], {}
    manifest = {"go": "go.mod", "rust": "Cargo.toml", "php": "composer.json", "cmake": "CMakeLists.txt"}[ecosystem]
    if ecosystem == "go":
        checks = [_check(component_id, name, ["go", name, "./..."]) for name in ("test", "vet", "build")]
    elif ecosystem == "rust":
        for base in (directory, root):
            if (base / "rust-toolchain.toml").is_file():
                extra["runtime"] = _toml(base / "rust-toolchain.toml").get("toolchain", {}).get("channel", "stable")
                break
            if (base / "rust-toolchain").is_file():
                extra["runtime"] = _read(base / "rust-toolchain").strip()
                break
        locked = ["--locked"] if (directory / "Cargo.lock").is_file() else []
        checks = [_check(component_id, name, ["cargo", name] + locked) for name in ("check", "test")]
    elif ecosystem == "php":
        package = _json(directory / manifest)
        php = package.get("require", {}).get("php", "")
        match = re.search(r"[0-9]+\.[0-9]+", php) if isinstance(php, str) else None
        extra["runtime"] = _read(directory / ".php-version").strip() if (directory / ".php-version").is_file() else (match[0] if match else "8.3")
        extra["php_extensions"] = [name[4:] for name in package.get("require", {}) if name.startswith("ext-")]
        install = [["composer", "install", "--no-interaction", "--prefer-dist"]]
        for name in ("lint", "check", "test", "analyse", "analyze"):
            if name in package.get("scripts", {}):
                checks.append(_check(component_id, name, ["composer", "run-script", name]))
        if not any(c["name"] == "test" for c in checks):
            missing.append({"name": "tests", "reason": "No Composer test command is declared."})
    else:
        checks = [_check(component_id, "configure", ["cmake", "-S", ".", "-B", ".wmie-build"]),
                  _check(component_id, "build", ["cmake", "--build", ".wmie-build"])]
        text = _read(directory / manifest)
        if re.search(r"\b(?:enable_testing|add_test)\s*\(|include\s*\(\s*CTest", text, re.I):
            checks.append(_check(component_id, "test", ["ctest", "--test-dir", ".wmie-build", "--output-on-failure", "--no-tests=error"]))
        else:
            missing.append({"name": "tests", "reason": "No CTest suite is declared."})
    return {"id": component_id, "path": relative, "ecosystem": ecosystem, "manifest": manifest,
            "install": install, "checks": checks, "not_configured": missing, **extra}


def discover(root):
    root = Path(root).resolve()
    paths = list(_files(root))
    by_directory = {}
    for path in paths:
        if path.name in MANIFESTS:
            by_directory.setdefault(path.parent, set()).add(path.name)
    components = []
    for directory, manifests in sorted(by_directory.items()):
        if "package.json" in manifests:
            components.append(_node(root, directory))
        if {"pyproject.toml", "requirements.txt"} & manifests:
            components.append(_python(root, directory))
        for manifest, ecosystem in [("go.mod", "go"), ("Cargo.toml", "rust"), ("composer.json", "php"), ("CMakeLists.txt", "cmake")]:
            if manifest in manifests:
                if ecosystem == "cmake" and directory != root and any((parent / "CMakeLists.txt").is_file()
                        for parent in directory.parents if parent == root or root in parent.parents):
                    # CMake subdirectories depend on their parent configuration.
                    if not re.search(r"(?mi)^\s*project\s*\(", _read(directory / manifest)):
                        continue
                components.append(_native(root, directory, ecosystem))
    # Source without a manifest needs explicit, local commands instead of a guessed toolchain.
    for suffix, ecosystem in [(".py", "python"), (".php", "php"), (".c", "c"), (".cpp", "cpp"), (".rs", "rust"), (".go", "go"), (".java", "java")]:
        covered = {c["path"] for c in components if c["ecosystem"] == ecosystem or
                   (ecosystem in {"c", "cpp"} and (c["ecosystem"] == "cmake" or c.get("native_addon")))}
        uncovered = [p for p in paths if p.suffix == suffix and not any(base == "." or p.relative_to(root).as_posix().startswith(base + "/") for base in covered)]
        if uncovered:
            components.append({"id": ecosystem + ":unconfigured", "path": ".", "ecosystem": ecosystem,
                               "configuration_required": "Declare the actual build and test commands for source without a manifest.",
                               "examples": [p.relative_to(root).as_posix() for p in uncovered[:5]]})
    return {"schema_version": 1, "components": components, "external_checks": [],
            "baseline_checks": ["content", "security"],
            "description": "Project checks come from real manifests and approved local overrides."}


def validate_profile(profile):
    require(profile.get("schema_version") == 1, "ci_profile_version")
    require(isinstance(profile.get("components"), list), "ci_profile_components")
    ids = set()
    for component in profile["components"]:
        require(isinstance(component, dict) and isinstance(component.get("id"), str), "invalid_ci_component")
        require(component["id"] not in ids, "duplicate_ci_component")
        ids.add(component["id"])
        path = component.get("path")
        require(path == "." or safe_path(path), "invalid_ci_component_path")
        require(not component.get("configuration_required"), "ci_configuration_required", component.get("configuration_required", ""))
        require(component.get("ecosystem") in {"node", "python", "go", "rust", "php", "cmake", "custom"}, "unsupported_ci_ecosystem")
        require(isinstance(component.get("checks", []), list) and isinstance(component.get("install", []), list), "invalid_ci_commands")
        for command in component.get("install", []):
            require(isinstance(command, list) and command and all(isinstance(x, str) for x in command), "invalid_install_command")
        for check in component.get("checks", []):
            require(check.get("applicable") is True, "invalid_local_check")
            require(check["id"] not in ids, "duplicate_ci_check")
            ids.add(check["id"])
            require(isinstance(check.get("argv"), list) and check["argv"] and all(isinstance(x, str) for x in check["argv"]), "invalid_ci_command")
    for check in profile.get("external_checks", []):
        filters = check.get('filters', {})
        require(isinstance(filters, dict) and set(filters) <= {'paths', 'paths-ignore', 'branches', 'branches-ignore'},
                'invalid_external_ci_filters')
        from ci_filters import glob_matches
        for patterns in filters.values():
            require(isinstance(patterns, list) and all(isinstance(p, str) and p for p in patterns), 'invalid_external_ci_filters')
            for pattern in patterns:
                glob_matches('', pattern.lstrip('!'))
        require(isinstance(check.get("id"), str) and bool(check["id"]), "invalid_external_check_id")
        require(check.get("id") not in ids, "duplicate_external_check")
        ids.add(check.get("id"))
        require(isinstance(check.get("name"), str) and check["name"], "invalid_external_check")
        require(safe_path(check.get("workflow")), "invalid_external_workflow")
        require(check["workflow"].startswith(".github/workflows/"), "invalid_external_workflow")
        require(isinstance(check.get("workflow_name"), str) and check["workflow_name"], "missing_external_workflow_name")
    external_ids = {check["id"] for check in profile.get("external_checks", [])}
    for component in profile["components"]:
        coverage = component.get("covered_by_external", [])
        require(isinstance(coverage, list) and all(isinstance(i, str) and i in external_ids for i in coverage),
                "invalid_external_component_coverage")
        require(not coverage or (not component.get("checks") and not component.get("install")),
                "duplicate_external_component_execution")
    require(isinstance(profile.get("json_validation_exclude", []), list) and
            all(isinstance(pattern, str) and pattern for pattern in profile.get("json_validation_exclude", [])), "invalid_json_exclusions")
    return profile


def plan(profile, observed):
    """The approved base profile stays authoritative when a PR changes project files."""
    validate_profile(profile)
    expected = []
    known = {c["id"]: c for c in profile["components"]}
    observed_by_id = {c["id"]: c for c in observed["components"]}
    components = []
    for original in profile["components"]:
        component = {**original, "checks": list(original.get("checks", []))}
        if original.get("covered_by_external"):
            components.append(component)
            continue
        current = observed_by_id.get(original["id"], {})
        known_checks = {c["id"] for c in component["checks"]}
        component["checks"].extend(c for c in current.get("checks", []) if c["id"] not in known_checks)
        if original["ecosystem"] == "node" and current.get("ecosystem") == "node":
            for key in ("runtime", "package_manager", "package_manager_version", "install", "install_path", "workspaces", "native_addon"):
                component[key] = current[key]
            component["checks"] = [{**c, "argv": [component["package_manager"], "run", c["name"]]}
                                   if c["name"] in NODE_CHECKS else c for c in component["checks"]]
        components.append(component)
        expected.extend(component["checks"])
    expected.extend({**item, "applicable": True} for item in profile.get("external_checks", []))
    additions = []
    for component in observed["components"]:
        if component["id"] not in known:
            require(not component.get("configuration_required"), "new_ci_configuration_required", component["id"])
            additions.append(component)
            expected.extend(component.get("checks", []))
    return {"schema_version": 1, "profile_sha256": digest(profile), "checks": expected,
            "components": components + additions,
            "baseline_checks": profile.get("baseline_checks", ["content", "security"]),
            "json_validation_exclude": profile.get("json_validation_exclude", [])}
