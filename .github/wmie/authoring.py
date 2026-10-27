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


def wire_review_publication(path):
    path = Path(path)
    before = yaml_data(path)
    steps = before["jobs"]["safe_outputs"]["steps"]
    additions = [
        {"name": "Verify published review", "id": "wmie-verify-publication",
         "env": {"GH_TOKEN": "${{ steps.wmie-preflight-token.outputs.token }}"},
         "run": "python3 .github/wmie/control.py review-publication"},
        {"name": "Preserve published review evidence",
         "uses": "actions/upload-artifact@b7c566a772e6b6bfb58ed0dc250532a479d7789f",
         "with": {"name": "review-publication", "path": "/tmp/wmie-review-presentation/publication.json",
                  "if-no-files-found": "error"}}]
    positions = [i for i, step in enumerate(steps) if step.get("id") == "process_safe_outputs"]
    require(len(positions) == 1, "publication_step_ambiguous")
    index = positions[0] + 1
    if steps[index:index + 2] == additions:
        return
    require(not any(step.get("id") == "wmie-verify-publication" for step in steps), "publication_step_ambiguous")
    expected = copy.deepcopy(before)
    expected["jobs"]["safe_outputs"]["steps"][index:index] = additions
    insertion = '''      - name: Verify published review
        id: wmie-verify-publication
        env:
          GH_TOKEN: ${{ steps.wmie-preflight-token.outputs.token }}
        run: python3 .github/wmie/control.py review-publication
      - name: Preserve published review evidence
        uses: actions/upload-artifact@b7c566a772e6b6bfb58ed0dc250532a479d7789f
        with:
          name: review-publication
          path: /tmp/wmie-review-presentation/publication.json
          if-no-files-found: error
'''
    anchor = "      - name: Upload Safe Outputs Items\n"
    value = path.read_text()
    require(value.count(anchor) == 1, "publication_upload_ambiguous")
    value = value.replace(anchor, insertion + anchor)
    with tempfile.TemporaryDirectory() as temporary:
        candidate = Path(temporary) / "review.yml"
        candidate.write_text(value)
        require(yaml_data(candidate) == expected, "publication_changed_other_behavior")
    path.write_text(value)


if __name__ == "__main__":
    label_review_jobs(".github/workflows/wmie-review.lock.yml")
    wire_review_publication(".github/workflows/wmie-review.lock.yml")
