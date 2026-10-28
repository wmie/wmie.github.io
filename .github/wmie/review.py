"""Validate native review proposals and actual GitHub approvals."""

from __future__ import annotations

import json
import re

from core import GovernanceError, digest, require, safe_path, sha
from presentation import review_reference


APP_ID = 3757770
BOT_ID = 285751170
EVENTS = {"approve": "APPROVE", "changes_requested": "REQUEST_CHANGES", "incomplete": "COMMENT"}


def review_data(body):
    require(isinstance(body, str) and len(body) <= 60000, "invalid_review_body")
    blocks = re.findall(r"```json\s*\n(.*?)\n```", body, re.S)
    require(len(blocks) == 1, "missing_review_record")
    try:
        record = json.loads(blocks[0])
    except ValueError as error:
        raise GovernanceError("invalid_review_record") from error
    require(isinstance(record, dict), "invalid_review_record")
    return record


def validate_manifest(manifest, repository, pr_number, base_sha, head_sha):
    require(isinstance(manifest, dict), "invalid_manifest")
    require(manifest.get("schema_version") == 1, "manifest_version")
    require(manifest.get("repository") == repository, "repository_mismatch")
    require(manifest.get("pr_number") == pr_number, "pr_mismatch")
    require(manifest.get("base_sha") == sha(base_sha), "base_changed")
    require(manifest.get("head_sha") == sha(head_sha), "head_changed")
    sha(manifest.get("merge_base_sha"))
    files = manifest.get("files")
    require(isinstance(files, list) and files, "empty_manifest")
    paths = []
    for item in files:
        require(isinstance(item, dict), "invalid_manifest_file")
        paths.append(safe_path(item.get("path")))
        require(item.get("status") in {"added", "modified", "deleted", "type_changed"}, "invalid_file_status")
        for side in ("base", "head"):
            blob = item.get(side)
            if blob is None:
                continue
            require(isinstance(blob, dict), "invalid_manifest_blob")
            sha(blob.get("oid"))
            require(blob.get("mode") in {"100644", "100755", "120000", "160000"}, "invalid_blob_mode")
            require(isinstance(blob.get("bytes"), int) and blob["bytes"] >= 0, "invalid_blob_size")
            require(re.fullmatch(r"[a-f0-9]{64}", blob.get("sha256", "")), "invalid_blob_digest")
    require(len(paths) == len(set(paths)), "duplicate_manifest_path")
    return set(paths)


def validate_record(record, manifest):
    require(isinstance(record, dict), "invalid_review_record")
    paths = validate_manifest(manifest, manifest["repository"], manifest["pr_number"],
                              manifest["base_sha"], manifest["head_sha"])
    require(record.get("schema_version") == 1, "review_version")
    for field in ("repository", "pr_number", "base_sha", "head_sha"):
        require(record.get(field) == manifest[field], "review_" + field + "_mismatch",
                json.dumps({"expected": manifest[field], "received": record.get(field)}))
    require(record.get("manifest_sha256") == digest(manifest), "review_manifest_mismatch",
            json.dumps({"expected": digest(manifest), "received": record.get("manifest_sha256")}))
    if "provenance" in manifest:
        origin = manifest["provenance"]
        require(record.get("review_run_id") == origin["run_id"], "review_run_id_mismatch")
        require(record.get("review_run_attempt") == origin["run_attempt"], "review_run_attempt_mismatch")
    verdict = record.get("verdict")
    require(verdict in EVENTS, "invalid_verdict")
    require(type(record.get("complete")) is bool, "invalid_completeness")
    require(record["complete"] == (verdict != "incomplete"), "contradictory_completeness")
    reviewed = record.get("reviewed_files")
    require(isinstance(reviewed, list) and all(isinstance(p, str) for p in reviewed), "invalid_reviewed_files")
    require(len(reviewed) == len(set(reviewed)) and set(reviewed) <= paths, "invalid_reviewed_files")
    if record["complete"]:
        missing = sorted(paths - set(reviewed))
        require(not missing, "review_coverage_incomplete", json.dumps(missing))
    findings = record.get("findings")
    require(isinstance(findings, list), "invalid_findings")
    for item in findings:
        require(isinstance(item, dict) and item.get("path") in paths, "invalid_finding_path")
        require(item.get("severity") in {"critical", "high", "medium"}, "invalid_finding_severity")
        require(type(item.get("line")) is int and item["line"] > 0, "invalid_finding_line")
        require(item.get("side") in {"base", "head"}, "invalid_finding_side")
        file_record = next(f for f in manifest["files"] if f["path"] == item["path"])
        blob = file_record.get(item["side"])
        require(blob is not None and item["line"] <= blob.get("lines", 0), "finding_line_out_of_range")
        for field in ("title", "evidence", "impact", "remediation"):
            require(isinstance(item.get(field), str) and item[field].strip(), "invalid_finding_" + field)
    require(verdict != "approve" or not findings, "approval_has_findings")
    require(verdict != "changes_requested" or bool(findings), "missing_blocking_findings")
    require(isinstance(record.get("summary"), str) and record["summary"].strip(), "missing_summary")
    return record


def validate_proposal(messages, manifest):
    require(isinstance(messages, list), "invalid_agent_messages")
    reviews = [m for m in messages if isinstance(m, dict) and m.get("type") == "submit_pull_request_review"]
    require(len(reviews) == 1, "expected_one_review")
    # No model-authored checks, pushes, issue changes, or extra reviews can accompany the result.
    permitted = {"submit_pull_request_review", "create_pull_request_review_comment", "noop"}
    require(all(isinstance(m, dict) and m.get("type") in permitted for m in messages), "unexpected_safe_output")
    review = reviews[0]
    require(review.get("repo", manifest["repository"]) == manifest["repository"], "proposal_repository_mismatch")
    require(str(review.get("pull_request_number")) == str(manifest["pr_number"]), "proposal_pr_mismatch")
    record = validate_record(review_data(review.get("body")), manifest)
    require(review.get("event") == EVENTS[record["verdict"]], "review_event_mismatch")
    # The trusted frontmatter pins commit-id. The native tool does not expose it to the model.
    if "commit_id" in review:
        require(review["commit_id"] == manifest["head_sha"], "proposal_commit_mismatch")
    comments = [m for m in messages if m.get("type") == "create_pull_request_review_comment"]
    require(record["verdict"] != "approve" or not comments, "approval_has_inline_findings")
    for comment in comments:
        require(comment.get("repo", manifest["repository"]) == manifest["repository"], "inline_repository_mismatch")
        require(str(comment.get("pull_request_number")) == str(manifest["pr_number"]), "inline_pr_mismatch")
        require(comment.get("path") in {f["path"] for f in manifest["files"]}, "inline_path_mismatch")
    return record


def validate_native_output(envelope, manifest):
    require(isinstance(envelope, dict), "invalid_native_output")
    require(not envelope.get("errors"), "native_output_errors")
    return validate_proposal(envelope.get("items"), manifest)


def validate_ci(expected, observations):
    """An absent or skipped required observation never becomes a successful result."""
    require(isinstance(expected, list) and isinstance(observations, list), "invalid_ci_evidence")
    by_id = {}
    for item in observations:
        require(isinstance(item, dict) and isinstance(item.get("id"), str), "invalid_ci_observation")
        require(item["id"] not in by_id, "duplicate_ci_observation", item["id"])
        by_id[item["id"]] = item
    failures = []
    for item in expected:
        if item.get("applicable") is False:
            require(isinstance(item.get("reason"), str) and item["reason"].strip(), "missing_ci_exclusion_reason")
            continue
        require(item.get("applicable") is True, "unknown_ci_applicability")
        actual = by_id.get(item["id"])
        if not actual or actual.get("conclusion") != "success":
            failures.append({"id": item["id"], "conclusion": (actual or {}).get("conclusion", "missing")})
    require(not failures, "ci_incomplete", json.dumps(failures))
    return True


def validate_published(review, record, manifest, live_pr, jobs, *, bot_id=BOT_ID):
    validate_manifest(manifest, manifest["repository"], live_pr["number"],
                      live_pr["base"]["sha"], live_pr["head"]["sha"])
    validate_record(record, manifest)
    require(live_pr.get("state") == "open" and not live_pr.get("draft"), "pr_not_ready")
    require(record["complete"] and record["verdict"] == "approve", "review_not_approval")
    require(all(jobs.get(name) == "success" for name in ("agent", "detection", "safe_outputs")), "review_jobs_incomplete")
    require(review.get("user", {}).get("id") == bot_id and review["user"].get("type") == "Bot", "wrong_reviewer")
    require(review.get("state") == "APPROVED", "approval_not_published")
    require(review.get("commit_id") == manifest["head_sha"], "published_commit_mismatch")
    reference = review_reference(review.get("body"), manifest["repository"])
    require(reference or manifest.get("provenance", {}).get("presentation_version") != 1, "missing_review_reference")
    if reference:
        require(all(reference[field] == record[field] for field in reference), "published_record_mismatch")
    else:
        require(review_data(review.get("body")) == record, "published_record_mismatch")
    return True
