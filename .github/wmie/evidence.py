"""Read GitHub-owned execution facts rather than model-authored success claims."""

from __future__ import annotations

import hashlib
import re
from urllib.parse import quote

from core import archive_json, digest, require, sha
from review import validate_ci, validate_manifest, validate_native_output


CI_WORKFLOW = ".github/workflows/wmie-ci.yml"
REVIEW_WORKFLOW = ".github/workflows/wmie-review.lock.yml"


def canonical_run_title(title):
    for visible, internal in (("Pull request checks", "WMIE CI"), ("AI code review", "WMIE Review")):
        if isinstance(title, str) and title.startswith(visible + " pr="):
            return internal + title[len(visible):]
    return title


def canonical_job_name(name):
    aliases = {"Prepare checks": "WMIE plan", "JSON validation": "WMIE content",
               "Secret scan (Gitleaks)": "WMIE security", "Required checks": "WMIE CI",
               "Analyze code changes": "agent", "Check review output safety": "detection",
               "Publish review": "safe_outputs", "Review result": "conclusion"}
    if isinstance(name, str) and name.startswith("Project checks / "):
        return "WMIE / " + name.removeprefix("Project checks / ")
    return aliases.get(name, name)


def ci_title(pr_number, base_sha, head_sha):
    require(type(pr_number) is int and pr_number > 0, "invalid_pr_number")
    return f"WMIE CI pr={pr_number} base={sha(base_sha)} head={sha(head_sha)}"


def trusted_run(api, repository, run_id, workflow, *, events, default_branch=None):
    require(type(run_id) is int and run_id > 0, "invalid_run_id")
    run = api.request("GET", f"/repos/{repository}/actions/runs/{run_id}")
    require(run.get("id") == run_id, "run_id_mismatch")
    require(run.get("repository", {}).get("full_name") == repository, "run_repository_mismatch")
    require(run.get("head_repository", {}).get("full_name") == repository, "run_fork_not_trusted")
    require(run.get("path", "").split("@", 1)[0] == workflow, "run_workflow_mismatch")
    require(run.get("event") in events, "run_event_not_trusted")
    if default_branch is None:
        default_branch = api.request("GET", f"/repos/{repository}")["default_branch"]
    require(run.get("head_branch") == default_branch, "run_branch_not_trusted")
    source_sha = sha(run.get("head_sha"))
    # A dispatch from a feature branch cannot claim the default-branch workflow.
    comparison = api.request("GET", f"/repos/{repository}/compare/{source_sha}...{quote(default_branch, safe='')}")
    require(comparison.get("status") in {"identical", "ahead"}, "run_source_not_on_default_branch")
    require(type(run.get("run_attempt")) is int and run["run_attempt"] > 0, "invalid_run_attempt")
    return run


def run_jobs(api, repository, run):
    jobs = api.pages(f"/repos/{repository}/actions/runs/{run['id']}/attempts/{run['run_attempt']}/jobs", "jobs")
    result = {}
    for job in jobs:
        name = canonical_job_name(job.get("name"))
        require(isinstance(name, str) and name not in result, "ambiguous_job_name", str(name))
        result[name] = job
    return result


def artifact_record(api, repository, run, name, member, *, artifact_id=None, expected_digest=None, json_lines=False):
    artifacts = api.pages(f"/repos/{repository}/actions/runs/{run['id']}/artifacts", "artifacts")
    matches = [a for a in artifacts if a.get("name") == name]
    require(len(matches) == 1, "missing_or_ambiguous_artifact", name)
    artifact = matches[0]
    require(not artifact.get("expired"), "artifact_expired")
    require(artifact_id is None or artifact.get("id") == artifact_id, "artifact_id_mismatch")
    if artifact.get("workflow_run"):
        require(artifact["workflow_run"].get("id") == run["id"], "artifact_run_mismatch")
    recorded_digest = artifact.get("digest", "")
    require(isinstance(recorded_digest, str) and re.fullmatch(r"sha256:[a-f0-9]{64}", recorded_digest), "artifact_digest_missing")
    require(expected_digest is None or recorded_digest == expected_digest, "artifact_digest_mismatch")
    payload = api.archive(f"/repos/{repository}/actions/artifacts/{artifact['id']}/zip")
    require("sha256:" + hashlib.sha256(payload).hexdigest() == recorded_digest, "artifact_content_mismatch")
    return archive_json(payload, member, json_lines=json_lines)


def native_review_evidence(api, repository, run, manifest, review):
    envelope = artifact_record(api, repository, run, "agent-output-fallback", "agent_output.json")
    record = validate_native_output(envelope, manifest)
    items = artifact_record(api, repository, run, "safe-outputs-items", "safe-output-items.jsonl", json_lines=True)
    published = [item for item in items if item.get("type") == "submit_pull_request_review"]
    require(len(published) == 1, "native_publication_ambiguous")
    item = published[0]
    require(item.get("repo") == repository and item.get("number") == manifest["pr_number"], "native_publication_target_mismatch")
    require(item.get("id") == review["id"] and item.get("metadata", {}).get("review_id") == review["id"],
            "native_publication_review_mismatch")
    require(item.get("metadata", {}).get("review_event") == "APPROVE"
            and item["metadata"].get("review_state") == "APPROVED", "native_publication_not_approval")
    return record


def validate_ci_run(run, pr, plan, jobs):
    require(canonical_run_title(run.get("display_title")) == ci_title(pr["number"], pr["base"]["sha"], pr["head"]["sha"]),
            "ci_commit_binding_mismatch")
    base = pr["base"]
    if base.get("ref") and base.get("ref") == base.get("repo", {}).get("default_branch"):
        require(run.get("head_sha") == base["sha"], "ci_source_base_changed")
    require(run.get("status") == "completed" and run.get("conclusion") == "success", "ci_run_incomplete")
    expected = [{"id": name, "applicable": True} for name in ("WMIE plan", "WMIE content", "WMIE security", "WMIE CI")]
    expected.extend({"id": "WMIE / " + c["id"], "applicable": True} for c in plan["components"] if c.get("checks"))
    observations = [{"id": name, "conclusion": job.get("conclusion")} for name, job in jobs.items()]
    validate_ci(expected, observations)
    return True


def validate_input_record(record, run, pr, *, workflow_sha=None):
    require(record.get("schema_version") == 1, "input_version")
    validate_manifest(record.get("manifest", {}), run["repository"]["full_name"], pr["number"],
                      pr["base"]["sha"], pr["head"]["sha"])
    origin = record.get("provenance", {})
    require(origin.get("run_id") == run["id"] and origin.get("run_attempt") == run["run_attempt"],
            "input_run_mismatch")
    require(origin.get("workflow_sha") == (workflow_sha or run["head_sha"]), "input_workflow_sha_mismatch")
    require(origin.get("workflow_path") == REVIEW_WORKFLOW, "input_workflow_path_mismatch")
    require(record.get("manifest_sha256") == digest(record["manifest"]), "input_manifest_mismatch")
    require(record["manifest"].get("provenance") == origin, "manifest_provenance_mismatch")
    return record
