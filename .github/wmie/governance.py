"""Dispatch isolated CI and publish App-owned checks from trusted GitHub facts."""

from __future__ import annotations

import json
import os
import re
import sys
import time
from urllib.parse import quote

from control import binding_for_run, ci_evidence, ci_title, live_pr, number, previous_analysis, recent_runs, repository_name, source_filter
from core import GitHub, GovernanceError, read_json, require
from diagnostics import native_error_diagnostic
from evidence import canonical_run_title, REVIEW_WORKFLOW, native_review_evidence, run_jobs, trusted_run, validate_input_record
from review import APP_ID, BOT_ID, review_data, validate_published
from presentation import check_summary, review_reference


def published_approval(api, repository, pr, ci, *, merged_source_commit=None):
    from release import release_approval
    certified = release_approval(api, None, repository, pr, ci)
    if certified:
        return certified
    reviews = api.pages(f"/repos/{repository}/pulls/{pr['number']}/reviews")
    candidates = [item for item in reviews if item.get("user", {}).get("id") == BOT_ID
                  and item.get("commit_id") == pr["head"]["sha"]]
    require(candidates, "wmie_review_missing", "Wait for the code review to finish.")
    latest = max(candidates, key=lambda item: item["id"])
    # A later incomplete, dismissed, or blocking review cannot reuse an older approval.
    review = api.request("GET", f"/repos/{repository}/pulls/{pr['number']}/reviews/{number(latest['id'])}")
    try:
        reference = review_reference(review.get("body"), repository)
        record = reference or review_data(review.get("body"))
    except GovernanceError as error:
        raise GovernanceError("wmie_review_missing", "The previous bot review does not contain a native WMIE record.") from error
    require(record.get("head_sha") == pr["head"]["sha"] and (reference or record.get("base_sha") == pr["base"]["sha"]), "published_review_stale")
    if reference:
        require(review.get("state") != "CHANGES_REQUESTED", "application_findings", f"Read code review {review['id']}.")
        require(review.get("state") != "COMMENTED", "analysis_incomplete", f"Read code review {review['id']}.")
    require(record.get("verdict") != "changes_requested", "application_findings", f"Read WMIE review {review['id']}.")
    require(record.get("verdict") != "incomplete", "analysis_incomplete", f"Read WMIE review {review['id']}.")
    run = trusted_run(api, repository, number(record.get("review_run_id")), REVIEW_WORKFLOW,
                      events={"workflow_run", "workflow_dispatch"})
    require(run.get("status") == "completed" and run.get("conclusion") == "success", "review_execution_incomplete")
    require(run["run_attempt"] == record.get("review_run_attempt"), "review_attempt_superseded")
    binding = validate_input_record(binding_for_run(api, repository, run), run, pr)
    require(binding.get("ci", {}).get("profile_sha256") == ci["profile_sha256"]
            and binding["ci"].get("plan_sha256") == ci["plan_sha256"], "published_ci_plan_mismatch")
    jobs = run_jobs(api, repository, run)
    original_record = native_review_evidence(api, repository, run, binding["manifest"], review)
    validate_published(review, original_record, binding["manifest"], pr,
                       {name: job.get("conclusion") for name, job in jobs.items()},
                       merged_source_commit=merged_source_commit)
    safe_steps = {step.get("name"): step.get("conclusion") for step in jobs["safe_outputs"].get("steps", [])}
    require([safe_steps[key] for key in ("Validate review before publishing", "WMIE preflight") if key in safe_steps] == ["success"] and safe_steps.get("Process Safe Outputs") == "success",
            "publication_preflight_unproven")
    return {"review_id": review["id"], "run_id": run["id"], "run_attempt": run["run_attempt"],
            "head_sha": pr["head"]["sha"], "base_sha": pr["base"]["sha"],
            **({"reviewed_base_sha": binding["manifest"]["merge_base_sha"]} if merged_source_commit else {})}


def set_check(api, repository, pr, name, *, success, details, read_api=None):
    read_api = read_api or api
    legacy = {"Required checks": "WMIE CI", "Code review approval": "WMIE approval"}.get(name)
    if legacy:
        branch = pr["base"].get("ref")
        require(isinstance(branch, str) and branch, "check_target_branch_missing")
        rules = read_api.pages(f"/repos/{repository}/rules/branches/{quote(branch, safe='')}")
        required = [check for rule in rules if rule.get("type") == "required_status_checks"
                    for check in rule.get("parameters", {}).get("required_status_checks", [])]
        if any(check.get("context") == legacy and check.get("integration_id") in {None, APP_ID} for check in required):
            set_check(api, repository, pr, legacy, success=success, details=details, read_api=read_api)
    external_id = f"wmie:{name}:{pr['base']['sha']}:{pr['head']['sha']}"
    checks = read_api.pages(f"/repos/{repository}/commits/{pr['head']['sha']}/check-runs?filter=latest", "check_runs")
    candidates = [item for item in checks if item.get("name") == name and item.get("app", {}).get("id") == APP_ID]
    existing = max(candidates, key=lambda item: item["id"], default=None)
    pending = not success and name in {"Code review approval", "WMIE approval"} and details.get("state") == "review_pending"
    body = {"name": name, "status": "in_progress" if pending else "completed", "external_id": external_id,
            "details_url": (f"https://github.com/{repository}/actions/runs/{details['run_id']}" if details.get("run_id")
                            else f"https://github.com/{repository}/pull/{pr['number']}/checks"),
            "output": {"title": "Review in progress" if pending else "Complete" if success else {
                           "ci_run_missing": "Required checks missing",
                           "wmie_review_missing": "Code review approval missing",
                           "application_findings": "Changes requested",
                           "analysis_incomplete": "Code review incomplete",
                           "reviewer_technical_error": "Code review process failed",
                       }.get(details.get("code"), "Required checks incomplete" if details.get("state") == "ci_incomplete" else "Code review incomplete"),
                       "summary": check_summary(repository, pr, name, success, details)}}
    if not pending:
        body["conclusion"] = "success" if success else "failure"
    # Start a new run rather than carry a completed conclusion into pending work.
    if pending and existing and existing.get("status") == "completed":
        existing = None
    if existing:
        result = api.request("PATCH", f"/repos/{repository}/check-runs/{existing['id']}", body)
    else:
        result = api.request("POST", f"/repos/{repository}/check-runs", {**body, "head_sha": pr["head"]["sha"]})
    require(result.get("app", {}).get("id") == APP_ID, "check_app_identity_mismatch")
    return result["id"]


def review_execution_state(api, repository, pr):
    title = f"WMIE Review pr={pr['number']} base={pr['base']['sha']} head={pr['head']['sha']}"
    unadmitted = None
    for candidate in recent_runs(api, repository, "wmie-review.lock.yml", **source_filter(pr)):
        if canonical_run_title(candidate.get("display_title")) != title:
            continue
        run = trusted_run(api, repository, candidate["id"], REVIEW_WORKFLOW, events={"workflow_dispatch"})
        details = {"run_id": run["id"], "run_attempt": run["run_attempt"], "run_url": f"https://github.com/{repository}/actions/runs/{run['id']}"}
        if run.get("status") != "completed":
            return {**details, "state": "review_pending", "code": "review_pending"}
        jobs = run_jobs(api, repository, run)
        if jobs.get("agent", {}).get("conclusion") == "skipped":
            unadmitted = {**details, "state": "review_not_admitted", "code": "wmie_review_missing",
                          "detail": "No model job started. Correct the input or App configuration before another CI event or manual review."}
            continue
        for phase in ("agent", "detection", "safe_outputs"):
            job = jobs.get(phase, {})
            if job.get("conclusion") != "success":
                return {**details, "state": "reviewer_technical_error", "code": "reviewer_technical_error", "phase": phase,
                        "conclusion": job.get("conclusion", "missing"),
                        "failed_steps": [s.get("name") for s in job.get("steps", []) if s.get("conclusion") == "failure"],
                        "cost": "unknown until native usage is reconciled", "automatic_retry": False,
                        **(native_error_diagnostic(api, repository, run) if phase == "agent" else {
                            "detail": f"Read the failed {phase} steps and reconcile native usage before another review."})}
        return {**details, "state": "reviewer_technical_error", "code": "approval_not_published",
                "detail": "The native execution finished without a readable WMIE review."}
    return unadmitted


def assess(api, write_api, repository, pr_number):
    pr = live_pr(api, repository, pr_number)
    try:
        ci = ci_evidence(api, repository, pr)
    except GovernanceError as error:
        details = {"state": "ci_incomplete", "code": error.code, "detail": error.detail}
        set_check(write_api, repository, pr, "Required checks", success=False, details=details, read_api=api)
        set_check(write_api, repository, pr, "Code review approval", success=False, details=details, read_api=api)
        return details
    set_check(write_api, repository, pr, "Required checks", success=True, details={"state": "complete", **ci}, read_api=api)
    try:
        from release import release_approval
        approval = release_approval(api, write_api, repository, pr, ci) or published_approval(api, repository, pr, ci)
        fresh = live_pr(api, repository, pr_number)
        require(fresh["base"]["sha"] == pr["base"]["sha"] and fresh["head"]["sha"] == pr["head"]["sha"], "approval_commits_changed")
        details = {"state": "approved", **approval, "ci_run_id": ci["run_id"]}
        set_check(write_api, repository, fresh, "Code review approval", success=True, details=details, read_api=api)
        return details
    except GovernanceError as error:
        details = {"state": "application_findings" if error.code == "application_findings" else "review_incomplete",
                   "code": error.code, "detail": error.detail}
        if error.code == "wmie_review_missing":
            details.update(review_execution_state(api, repository, pr) or {})
        set_check(write_api, repository, pr, "Code review approval", success=False, details=details, read_api=api)
        return details


def dispatch_ci(api, repository, pr):
    title = ci_title(pr["number"], pr["base"]["sha"], pr["head"]["sha"])
    existing = next((run for run in recent_runs(api, repository, "wmie-ci.yml", event="workflow_dispatch", **source_filter(pr))
                     if canonical_run_title(run.get("display_title")) == title), None)
    if existing:
        return {"state": "ci_already_dispatched", "run_id": existing["id"]}
    default_branch = api.request("GET", f"/repos/{repository}")["default_branch"]
    api.request("POST", f"/repos/{repository}/actions/workflows/wmie-ci.yml/dispatches", {
        "ref": default_branch, "inputs": {"pr_number": str(pr["number"]), "base_sha": pr["base"]["sha"], "head_sha": pr["head"]["sha"]}})
    return {"state": "ci_dispatched", "pr_number": pr["number"]}


def dispatch_review(api, repository, pr):
    ci = ci_evidence(api, repository, pr)
    title = f"WMIE Review pr={pr['number']} "
    active = next((run for run in recent_runs(api, repository, "wmie-review.lock.yml", **source_filter(pr))
                   if canonical_run_title(run.get("display_title", "")).startswith(title) and run.get("status") != "completed"), None)
    if active:
        return {"state": "review_already_active", "run_id": active["id"]}
    completed = next((run for run in recent_runs(api, repository, "wmie-review.lock.yml", **source_filter(pr))
                      if canonical_run_title(run.get("display_title", "")) == f"{title}base={pr['base']['sha']} head={pr['head']['sha']}"), None)
    if completed:
        return {"state": "review_already_attempted", "run_id": completed["id"]}
    previous = previous_analysis(api, repository, pr, 0)
    if previous:
        return {"state": "analysis_already_admitted", "run_id": previous}
    default_branch = api.request("GET", f"/repos/{repository}")["default_branch"]
    api.request("POST", f"/repos/{repository}/actions/workflows/wmie-review.lock.yml/dispatches", {
        "ref": default_branch, "inputs": {"pr_number": str(pr["number"]), "ci_run_id": str(ci["run_id"]), "repeat_review": "false",
                                          "base_sha": pr["base"]["sha"], "head_sha": pr["head"]["sha"]}})
    return {"state": "review_dispatched", "pr_number": pr["number"], "ci_run_id": ci["run_id"]}


def dispatch_merge(api, write_api, repository, pr, assessment):
    if os.environ.get("WMIE_AUTOMERGE_ENABLED") != "true":
        return {"state": "automatic_merge_disabled"}
    if assessment.get("state") != "approved":
        return {"state": "merge_not_approved"}
    require(assessment.get("head_sha") == pr["head"]["sha"]
            and assessment.get("base_sha") == pr["base"]["sha"], "merge_assessment_stale")
    default = api.request("GET", f"/repos/{repository}")["default_branch"]
    require(pr["base"]["ref"] == default, "merge_target_not_default")
    external_id = f"wmie:merge:{pr['number']}:{pr['base']['sha']}:{pr['head']['sha']}"
    attempts = api.pages(f"/repos/{repository}/commits/{pr['head']['sha']}/check-runs?filter=all", "check_runs")
    previous = next((item for item in attempts if item.get("external_id") == external_id
                     and item.get("app", {}).get("id") == APP_ID), None)
    if previous:
        return {"state": "merge_already_reserved", "check_id": previous["id"], "automatic_retry": False}
    # Reserve before dispatch. An uncertain write cannot cause automatic resubmission.
    claim = write_api.request("POST", f"/repos/{repository}/check-runs", {
        "name": "Request merge", "head_sha": pr["head"]["sha"], "external_id": external_id,
        "status": "completed", "conclusion": "neutral", "output": {
            "title": "Automatic merge attempt reserved",
            "summary": "Read the merge run for the result. If dispatch fails, reconcile the outcome before a manual retry."}})
    require(claim.get("app", {}).get("id") == APP_ID, "check_app_identity_mismatch")
    api.request("POST", f"/repos/{repository}/actions/workflows/wmie-merge.yml/dispatches", {
        "ref": default, "inputs": {"pr_number": str(pr["number"]), "expected_head": pr["head"]["sha"]}})
    return {"state": "merge_dispatched", "pr_number": pr["number"], "check_id": claim["id"]}


def affected_prs(api, repository, event_name, event):
    if event_name in {"pull_request_target", "workflow_dispatch"}:
        value = event.get("pull_request", {}).get("number") or event.get("inputs", {}).get("pr_number")
        return [number(value)]
    if event_name in {"push", "repository_dispatch"}:
        branch = event.get("repository", {}).get("default_branch")
        require(isinstance(branch, str) and branch, "missing_default_branch")
        if event_name == "push":
            require(event.get("ref") == "refs/heads/" + branch, "non_default_push")
        else:
            require(event.get("action") == "wmie-reconcile", "unsupported_reconciliation_event")
        return [item["number"] for item in api.pages(f"/repos/{repository}/pulls?state=open&base={quote(branch, safe='')}") if not item.get("draft")]
    require(event_name == "workflow_run", "unsupported_governance_event")
    run = api.request("GET", f"/repos/{repository}/actions/runs/{number(event['workflow_run']['id'])}")
    path = run.get("path", "").split("@", 1)[0]
    if path == ".github/workflows/wmie-review-events.yml" and run.get("event") == "push":
        branch = run.get("head_branch")
        require(isinstance(branch, str) and branch, "push_branch_missing")
        return [item["number"] for item in api.pages(f"/repos/{repository}/pulls?state=open&base={quote(branch, safe='')}")
                if not item.get("draft")]
    known = {".github/workflows/wmie-ci.yml", ".github/workflows/wmie-review.lock.yml"}
    match = re.search(r"\bpr=([1-9][0-9]*)\b", canonical_run_title(run.get("display_title", "")))
    if match and path in known:
        return [number(match[1])]
    if run.get("pull_requests"):
        return sorted({number(item["number"]) for item in run["pull_requests"]})
    return [item["number"] for item in api.pages(f"/repos/{repository}/commits/{run['head_sha']}/pulls") if item.get("state") == "open"]


def can_automatically_start_review(event_name, event, pr):
    source = event.get("_completion_run") or event.get("workflow_run", {})
    if source.get("path", "").split("@", 1)[0] != REVIEW_WORKFLOW:
        return True
    title = f"WMIE Review pr={pr['number']} base={pr['base']['sha']} head={pr['head']['sha']}"
    manual = f"WMIE Review pr={pr['number']} base=current head=current"
    # A failed preparation cannot recursively dispatch the same workflow forever.
    # Completion of an older pair can still release a review queued for a newer push.
    return canonical_run_title(source.get("display_title")) not in {title, manual}


def should_dispatch_ci(event_name, event):
    if event_name in {"push", "repository_dispatch"}:
        return True
    if event_name == "workflow_dispatch":
        return not event.get("inputs", {}).get("source_run_id")
    source = event.get("workflow_run", {})
    return (event_name == "workflow_run" and source.get("path", "").split("@", 1)[0] == ".github/workflows/wmie-review-events.yml"
            and source.get("event") in {"pull_request", "push"})


def await_source_completion(api, repository, event):
    value = event.get("inputs", {}).get("source_run_id")
    if not value:
        return
    run_id = number(value)
    pr_number = number(event["inputs"]["pr_number"])
    deadline = time.monotonic() + 120
    while True:
        candidate = api.request("GET", f"/repos/{repository}/actions/runs/{run_id}")
        path = candidate.get("path", "").split("@", 1)[0]
        require(path in {REVIEW_WORKFLOW, ".github/workflows/wmie-ci.yml"}, "untrusted_completion_source")
        run = trusted_run(api, repository, run_id, path, events={"workflow_dispatch"})
        require(re.search(rf"\bpr={pr_number}\b", canonical_run_title(run.get("display_title", ""))), "completion_pr_mismatch")
        if run.get("status") == "completed":
            return run
        require(time.monotonic() < deadline, "completion_pending", f"Run {run_id} did not finish within 120 seconds.")
        time.sleep(5)


def main():
    api = GitHub()
    write_api = GitHub(os.environ.get("WMIE_APP_TOKEN", ""))
    repository = repository_name(os.environ["GITHUB_REPOSITORY"])
    event = read_json(os.environ["GITHUB_EVENT_PATH"])
    event_name = os.environ["GITHUB_EVENT_NAME"]
    if event_name == "workflow_dispatch":
        event["_completion_run"] = await_source_completion(api, repository, event)
    results, failed = [], False
    for pr_number in affected_prs(api, repository, event_name, event):
        try:
            pr = live_pr(api, repository, pr_number)
            if should_dispatch_ci(event_name, event):
                results.append(dispatch_ci(api, repository, pr))
            result = assess(api, write_api, repository, pr_number)
            results.append(result)
            if result.get("state") == "approved":
                results.append(dispatch_merge(api, write_api, repository, pr, result))
            if result.get("code") in {"wmie_review_missing", "published_review_stale"} and can_automatically_start_review(event_name, event, pr):
                review = dispatch_review(api, repository, pr)
                results.append(review)
                if review.get("state") in {"review_dispatched", "review_already_active"}:
                    details = {**review, "state": "review_pending", "code": "review_pending",
                               "detail": "Wait for the code review to finish."}
                    set_check(write_api, repository, pr, "Code review approval", success=False, details=details, read_api=api)
        except GovernanceError as error:
            failed = True
            results.append({"pr_number": pr_number, "state": "blocked", "code": error.code, "detail": error.detail})
    print(json.dumps(results, sort_keys=True))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
