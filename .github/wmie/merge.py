"""Merge only after a current PR-specific approval and successful CI."""

import json
import os
import sys

from control import ci_evidence, live_pr, number, repository_name
from evidence import BOOTSTRAP_PRS
from core import GitHub, GovernanceError, require, sha, write_json
from governance import published_approval
from review import BOT_ID


def merge_approved(api, repository, pr_number, expected_head, default_branch="main"):
    expected_head = sha(expected_head)
    pr = live_pr(api, repository, number(pr_number))
    require(pr["base"]["ref"] == default_branch, "merge_target_not_default")
    require(pr["head"]["sha"] == expected_head, "merge_requested_head_changed")
    ci = ci_evidence(api, repository, pr)
    approval = published_approval(api, repository, pr, ci)
    fresh = live_pr(api, repository, pr_number)
    require(fresh["head"]["sha"] == expected_head and fresh["base"]["sha"] == pr["base"]["sha"]
            and fresh["base"]["ref"] == pr["base"]["ref"], "merge_commits_changed")
    require(fresh.get("mergeable") is True, "merge_conflict_or_unknown_mergeability")
    report = {"repository": repository, "pr_number": number(pr_number), "head_sha": expected_head,
              "base_sha": pr["base"]["sha"], "approval": approval, "state": "admitted", "automatic_retry": False}
    write_json("wmie-merge-result.json", report)
    try:
        result = api.request("PUT", f"/repos/{repository}/pulls/{pr_number}/merge",
                             {"sha": expected_head, "merge_method": "squash"})
    except GovernanceError as error:
        report.update(state="outcome_unknown" if error.code == "github_write_outcome_unknown" else "rejected",
                      code=error.code)
        write_json("wmie-merge-result.json", report)
        raise
    report.update(state="outcome_unknown", acknowledged_merge_sha=result.get("sha"))
    write_json("wmie-merge-result.json", report)
    actual = api.request("GET", f"/repos/{repository}/pulls/{pr_number}")
    require(result.get("merged") is True and actual.get("merged") is True
            and actual.get("head", {}).get("sha") == expected_head
            and (actual.get("merged_by") or {}).get("id") == BOT_ID
            and actual.get("merge_commit_sha") == result.get("sha"), "merge_readback_mismatch")
    report.update(state="merged", merge_sha=result["sha"], merged_by=actual["merged_by"]["login"])
    write_json("wmie-merge-result.json", report)
    return report


def main():
    require(os.environ.get("WMIE_AUTOMERGE_ENABLED") == "true", "automatic_merge_disabled")
    api = GitHub()
    repository = repository_name(os.environ["GITHUB_REPOSITORY"])
    default = api.request("GET", f"/repos/{repository}")["default_branch"]
    require(os.environ.get("GITHUB_EVENT_NAME") == "workflow_dispatch", "untrusted_merge_event")
    bootstrap_branch = next((branch for branch, pr in BOOTSTRAP_PRS.items()
                             if str(pr) == os.environ.get('WMIE_PR_NUMBER')), None)
    bootstrap = (repository == 'wmie/.github' and bootstrap_branch
                 and os.environ.get('GITHUB_REF') == 'refs/heads/' + bootstrap_branch
                 and os.environ.get('GITHUB_SHA') == os.environ.get('WMIE_UBICLOUD_BOOTSTRAP_SHA')
                 and bool(os.environ.get('WMIE_UBICLOUD_BOOTSTRAP_SHA')))
    require(os.environ.get("GITHUB_REF") == "refs/heads/" + default or bootstrap, "untrusted_merge_branch")
    source_branch = bootstrap_branch if bootstrap else default
    require(os.environ.get("GITHUB_WORKFLOW_REF") ==
            f"{repository}/.github/workflows/wmie-merge.yml@refs/heads/{source_branch}", "untrusted_merge_workflow")
    result = merge_approved(api, repository, number(os.environ["WMIE_PR_NUMBER"]), os.environ["WMIE_EXPECTED_HEAD"], default)
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    try:
        main()
    except GovernanceError as error:
        print(json.dumps({"state": "blocked", "code": error.code, "detail": error.detail}), file=sys.stderr)
        sys.exit(1)
