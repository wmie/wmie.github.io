"""Read GitHub-owned execution facts rather than model-authored success claims."""

from __future__ import annotations

import hashlib
import os
import re
from urllib.parse import quote

from core import archive_json, digest, require, sha
from review import BOT_ID, validate_ci, validate_manifest, validate_native_output
from presentation import ARTIFACT, review_reference, validate_publication


CI_WORKFLOW = ".github/workflows/wmie-ci.yml"
REVIEW_WORKFLOW = ".github/workflows/wmie-review.lock.yml"


def canonical_run_title(title):
    for visible, internal in (("Pull request checks", "WMIE CI"), ("AI code review", "WMIE Review")):
        if isinstance(title, str) and title.startswith(visible + " pr="):
            return internal + title[len(visible):]
    return title


def canonical_job_name(name):
    aliases = {"Prepare review": "WMIE review input", "Prepare checks": "WMIE plan", "JSON validation": "WMIE content",
               "Secret scan (Gitleaks)": "WMIE security", "Required checks": "WMIE CI",
               "Analyze code changes": "agent", "Check review output safety": "detection",
               "Publish review": "safe_outputs", "Review result": "conclusion"}
    if isinstance(name, str) and name.startswith("Project checks / "):
        return "WMIE / " + name.removeprefix("Project checks / ")
    return aliases.get(name, name)


def ci_title(pr_number, base_sha, head_sha):
    require(type(pr_number) is int and pr_number > 0, "invalid_pr_number")
    return f"WMIE CI pr={pr_number} base={sha(base_sha)} head={sha(head_sha)}"


BOOTSTRAP_BRANCH = 'chore/ubicloud-runners'
BOOTSTRAP_PRS = {BOOTSTRAP_BRANCH: 37, 'fix/ubicloud-replica-dispatch': 38}


def bootstrap_source(run):
    return (run.get('repository', {}).get('full_name') == 'wmie/.github'
            and run.get('head_branch') in BOOTSTRAP_PRS)


def source_matches_pr(run, pr):
    if bootstrap_source(run):
        return (pr.get('number') == BOOTSTRAP_PRS[run['head_branch']]
                and run.get('head_sha') == pr['head']['sha'])
    if run.get('head_sha') == pr['base']['sha']:
        return True
    replica = run.get('_wmie_replica')
    if replica and replica.get('pr_number') == pr.get('number') and replica.get('base_sha') == pr['base']['sha'] and replica.get('head_sha') == pr['head']['sha']:
        return True
    return False


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
    replica = None
    if (workflow == CI_WORKFLOW and run.get('head_branch', '').startswith('chore/wmie-agentic-update-')):
        from runner_migration import admit_replica_run
        replica = admit_replica_run(api, repository, run)
    require(run.get("head_branch") == default_branch or bootstrap_source(run) or replica, "run_branch_not_trusted")
    source_sha = sha(run.get("head_sha"))
    # A dispatch from a feature branch cannot claim the default-branch workflow.
    comparison = api.request("GET", f"/repos/{repository}/compare/{source_sha}...{quote(default_branch, safe='')}")
    on_default = comparison.get("status") in {"identical", "ahead"}
    if replica:
        run["_wmie_replica"] = replica
    if not on_default and not replica:
        pin = os.environ.get('WMIE_UBICLOUD_BOOTSTRAP_SHA')
        require(bootstrap_source(run), 'run_source_not_on_default_branch')
        if pin == source_sha:
            current = api.request('GET', f"/repos/{repository}/git/ref/heads/{run['head_branch']}")
            require(current['object']['sha'] == pin, 'bootstrap_branch_changed')
        else:
            # Historical proof survives a squash merge without enabling new runs.
            source_pr = api.request('GET', f"/repos/{repository}/pulls/{BOOTSTRAP_PRS[run['head_branch']]}")
            require(source_pr.get('merged') is True and source_pr['head']['sha'] == source_sha
                    and source_pr['base']['ref'] == default_branch
                    and source_pr.get('merged_by', {}).get('id') == BOT_ID,
                    'bootstrap_history_not_merged')
            merged = sha(source_pr.get('merge_commit_sha'))
            original = api.request('GET', f'/repos/{repository}/git/commits/{source_sha}')
            actual = api.request('GET', f'/repos/{repository}/git/commits/{merged}')
            require(original['tree']['sha'] == actual['tree']['sha'], 'bootstrap_merge_tree_changed')
            history = api.request('GET', f'/repos/{repository}/compare/{merged}...{quote(default_branch, safe="")}')
            require(history.get('status') in {'identical', 'ahead'}, 'bootstrap_merge_not_on_default')
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


def published_comments(api, repository, pr_number, review_id):
    entries = api.pages(f"/repos/{repository}/pulls/{pr_number}/reviews/{review_id}/comments")
    ids = [entry.get("id") for entry in entries]
    require(all(type(value) is int and value > 0 for value in ids) and len(set(ids)) == len(ids),
            "published_comment_identifiers_invalid")
    result = []
    for comment_id in ids:
        comment = api.request("GET", f"/repos/{repository}/pulls/comments/{comment_id}")
        require(comment.get("id") == comment_id and comment.get("pull_request_review_id") == review_id,
                "published_comment_binding_mismatch")
        result.append(comment)
    return result


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
    if manifest.get("provenance", {}).get("presentation_version") == 1:
        require(review_reference(review.get("body"), repository), "missing_review_reference")
        publication = artifact_record(api, repository, run, ARTIFACT, "publication.json")
        comments = published_comments(api, repository, manifest['pr_number'], review['id'])
        validate_publication(publication, record, review, comments)
    return record


def validate_ci_run(run, pr, plan, jobs):
    require(canonical_run_title(run.get("display_title")) == ci_title(pr["number"], pr["base"]["sha"], pr["head"]["sha"]),
            "ci_commit_binding_mismatch")
    base = pr["base"]
    if base.get("ref") and base.get("ref") == base.get("repo", {}).get("default_branch"):
        require(source_matches_pr(run, pr), "ci_source_base_changed")
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
    require(origin.get("presentation_version") in {None, 1}, "input_presentation_version")
    require(origin.get("run_id") == run["id"] and origin.get("run_attempt") == run["run_attempt"],
            "input_run_mismatch")
    require(origin.get("workflow_sha") == (workflow_sha or run["head_sha"]), "input_workflow_sha_mismatch")
    require(origin.get("workflow_path") == REVIEW_WORKFLOW, "input_workflow_path_mismatch")
    require(record.get("manifest_sha256") == digest(record["manifest"]), "input_manifest_mismatch")
    require(record["manifest"].get("provenance") == origin, "manifest_provenance_mismatch")
    return record
