"""Parse repository configuration as data. No constructors can execute code."""

from __future__ import annotations

import copy
import json
from pathlib import Path
import re
import tempfile

from core import GovernanceError, require


def label_review_jobs(path):
    path = Path(path)
    before = yaml_data(path)
    names = {"agent": "Analyze code changes", "detection": "Check review output safety",
             "safe_outputs": "Publish review", "conclusion": "Review result"}
    text = path.read_text()
    expected = copy.deepcopy(before)
    for key, label in names.items():
        require(key in before["jobs"], "review_job_missing", key)
        pattern = r"(?ms)(^  " + re.escape(key) + r":\n(?:(?!^  [a-zA-Z_]).)*?^    name: )[^\n]+"
        text, count = re.subn(pattern, lambda match: match[1] + label, text)
        require(count == 1, "review_job_label_ambiguous", key)
        expected["jobs"][key]["name"] = label
    environment = expected["jobs"]["conclusion"].get("env", {})
    if "GH_AW_JOB_DISPLAY_NAMES" in environment:
        display_names = json.loads(environment["GH_AW_JOB_DISPLAY_NAMES"])
        display_names.update(names)
        environment["GH_AW_JOB_DISPLAY_NAMES"] = json.dumps(display_names, separators=(",", ":"))
        text, count = re.subn(r"(?m)(^      GH_AW_JOB_DISPLAY_NAMES: )[^\n]+",
                             lambda match: match[1] + json.dumps(environment["GH_AW_JOB_DISPLAY_NAMES"]), text)
        require(count == 1, "review_summary_labels_ambiguous")
    with tempfile.TemporaryDirectory() as temporary:
        candidate = Path(temporary) / "review.yml"
        candidate.write_text(text)
        require(yaml_data(candidate) == expected, "review_label_changed_behavior")
    path.write_text(text)


def yaml_data(path):
    try:
        import yaml
    except ImportError as error:
        raise GovernanceError("yaml_parser_missing", "Install the pinned governance requirements.") from error

    class Loader(yaml.SafeLoader):
        pass

    # GitHub uses YAML 1.2 booleans. In YAML 1.1, the key `on` becomes True.
    Loader.yaml_implicit_resolvers = copy.deepcopy(Loader.yaml_implicit_resolvers)
    for key, values in Loader.yaml_implicit_resolvers.items():
        Loader.yaml_implicit_resolvers[key] = [item for item in values if item[0] != "tag:yaml.org,2002:bool"]
    Loader.add_implicit_resolver("tag:yaml.org,2002:bool", re.compile(r"^(?:true|false|True|False|TRUE|FALSE)$"), list("tTfF"))
    path = Path(path)
    require(not path.is_symlink(), "yaml_symlink", str(path))
    require(path.stat().st_size <= 2 * 1024 * 1024, "yaml_too_large", str(path))
    try:
        data = yaml.load(path.read_text(), Loader=Loader)
        require(isinstance(data, dict), "yaml_object_required", str(path))
        return data
    except (OSError, UnicodeError, ValueError, yaml.YAMLError) as error:
        raise GovernanceError("invalid_yaml", str(path)) from error


if __name__ == "__main__":
    label_review_jobs(".github/workflows/wmie-review.lock.yml")
