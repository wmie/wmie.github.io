"""Trusted CI preparation and native-review preflight. This code never publishes reviews."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
from urllib.parse import urlencode

from ci import discover, plan, validate_profile
from core import GitHub, GovernanceError, digest, output, read_json, require, safe_path, sha, write_json
from evidence import source_matches_pr, canonical_run_title, CI_WORKFLOW, REVIEW_WORKFLOW, artifact_record, ci_title, published_comments, run_jobs, trusted_run, validate_ci_run, validate_input_record
from git_input import discovery_tree, fetch, git, snapshot
from review import BOT_ID, validate_ci, validate_manifest, validate_native_output
from presentation import PLAN_PATH, RECORD_PATH, render, text_hash, without_framework_marker


def repository_name(value):
    require(isinstance(value, str) and re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", value), "invalid_repository")
    return value


def number(value):
    require(re.fullmatch(r"[1-9][0-9]{0,18}", str(value)), "invalid_identifier")
    require(int(value) <= 2 ** 63 - 1, "invalid_identifier")
    return int(value)


def live_pr(api, repository, pr_number):
    pr = api.request("GET", f"/repos/{repository}/pulls/{number(pr_number)}")
    require(pr.get("number") == number(pr_number) and pr.get("state") == "open" and not pr.get("draft"), "pr_not_ready")
    require(pr.get("base", {}).get("repo", {}).get("full_name") == repository, "pr_repository_mismatch")
    sha(pr["base"]["sha"])
    sha(pr["head"]["sha"])
    return pr


def profile_at(api, repository, commit):
    try:
        value = json.loads(api.file(repository, ".github/wmie/ci-profile.json", sha(commit)))
    except (ValueError, UnicodeError) as error:
        raise GovernanceError("invalid_ci_profile_json") from error
    return validate_profile(value)


def recent_runs(api, repository, workflow, **filters):
    suffix = "&" + urlencode(filters) if filters else ""
    for page in range(1, 11):
        data = api.request("GET", f"/repos/{repository}/actions/workflows/{workflow}/runs?per_page=100&page={page}{suffix}")
        items = data.get("workflow_runs")
        require(isinstance(items, list), "invalid_workflow_runs")
        yield from items
        if len(items) < 100:
            return
    raise GovernanceError("workflow_history_incomplete", "Narrow the history query before admitting another analysis.")


def latest_ci(api, repository, pr):
    title = ci_title(pr["number"], pr["base"]["sha"], pr["head"]["sha"])
    filters = {"event": "workflow_dispatch", **source_filter(pr)}
    if pr.get('head', {}).get('ref', '').startswith('chore/wmie-agentic-update-'):
        from runner_migration import replica_certificate
        if replica_certificate(api, repository, pr):
            filters = {'event':'workflow_dispatch', 'branch':pr['head']['ref'], 'head_sha':pr['head']['sha']}
    match = next((run for run in recent_runs(api, repository, "wmie-ci.yml", **filters)
                  if canonical_run_title(run.get("display_title")) == title), None)
    require(match is not None, "ci_run_missing", "Start Pull request checks for the current base and head.")
    return match["id"]


def source_filter(pr):
    base = pr["base"]
    default = base.get("repo", {}).get("default_branch")
    if pr.get('number') == 37 and base.get('repo', {}).get('full_name') == 'wmie/.github':
        return {'branch': 'chore/ubicloud-runners', 'head_sha': pr['head']['sha']}
    if pr.get('number') == 38 and base.get('repo', {}).get('full_name') == 'wmie/.github':
        # Both normal and pinned producers remain subject to trusted_run.
        return {}
    filters = {"branch": default} if default else {}
    if default and base.get("ref") == default:
        filters["head_sha"] = base["sha"]
    return filters


def current_plan(api, repository, pr, *, source=None):
    profile = profile_at(api, repository, pr["base"]["sha"])
    if source is not None:
        return profile, plan(profile, discover(source))
    with tempfile.TemporaryDirectory(prefix="wmie-plan-") as directory:
        root = Path(directory)
        objects = fetch(repository, pr["base"]["sha"], pr["head"]["sha"], root / "objects", api.token)
        inputs = discovery_tree(objects, pr["head"]["sha"], root / "manifests", api.token)
        return profile, plan(profile, discover(inputs))


def changed_paths(api, repository, pr):
    count = pr.get('changed_files')
    if isinstance(count, int) and count <= 3000:
        records = api.pages(f"/repos/{repository}/pulls/{pr['number']}/files")
        if len(records) == count:
            return {item[key] for item in records for key in ('filename', 'previous_filename') if item.get(key)}
    with tempfile.TemporaryDirectory(prefix='wmie-ci-paths-') as directory:
        objects = fetch(repository, pr['base']['sha'], pr['head']['sha'], Path(directory) / 'objects', api.token)
        base = git(objects, 'merge-base', pr['base']['sha'], pr['head']['sha'], token=api.token).decode().strip()
        return {p.decode() for p in git(objects, 'diff', '--no-renames', '--name-only', '-z', base,
                                       pr['head']['sha'], token=api.token).split(b'\0') if p}


def external_ci(api, repository, pr, checks):
    if not checks:
        return []
    observations = []
    from ci_filters import UNKNOWN, agent_authored, applicable, pr_condition
    paths = changed_paths(api, repository, pr) if any(c.get('filters') for c in checks) else set()
    expected_checks = []
    verified_workflows = set()
    trusted_workflows = {}
    source_runs = {}
    runs = api.pages(f"/repos/{repository}/commits/{pr['head']['sha']}/check-runs?filter=all", "check_runs")
    for expected in checks:
        if expected['workflow'] not in verified_workflows:
            original = api.file(repository, expected['workflow'], pr['base']['sha'])
            proposed = api.file(repository, expected['workflow'], pr['head']['sha'])
            from runner_migration import authorized_change
            require(original == proposed or authorized_change(repository, expected['workflow'], original, proposed),
                    'external_workflow_changed', expected['workflow'])
            verified_workflows.add(expected['workflow'])
            trusted_workflows[expected['workflow']] = original
        applies, reason = applicable(expected, pr['base'].get('ref', ''), paths)
        expected_checks.append({**expected, 'applicable': applies, **({'reason': reason} if reason else {})})
        if not applies:
            observations.append({'id': expected['id'], 'conclusion': 'not_applicable', 'reason': reason})
            continue
        name = expected["name"]
        if name.endswith(' ()'):
            from runner_migration import workflow
            parts = expected['id'].split(':')
            if (len(parts) == 4 and parts[0] == 'existing'
                    and parts[1] == Path(expected['workflow']).name and parts[3].isdecimal()):
                job = workflow(trusted_workflows[expected['workflow']]).get('jobs', {}).get(parts[2], {})
                matrix = job.get('strategy', {}).get('matrix', {})
                if (name == parts[2] + ' ()' and 'name' not in job and isinstance(matrix, dict) and len(matrix) == 1
                        and isinstance(next(iter(matrix.values())), list)
                        and '' in next(iter(matrix.values()))):
                    name = parts[2]
        candidates = []
        for check in runs:
            if check.get("name") != name or check.get("app", {}).get("id") != expected.get("app_id", 15368):
                continue
            match = re.fullmatch(r"https://github\.com/" + re.escape(repository) + r"/actions/runs/([0-9]+)/job/([0-9]+)", check.get("details_url", ""))
            if not match:
                continue
            run = api.request("GET", f"/repos/{repository}/actions/runs/{match[1]}")
            if run.get("path", "").split("@", 1)[0] != expected["workflow"] or run.get("head_sha") != pr["head"]["sha"]:
                continue
            if run.get('status') != 'completed' or run.get('conclusion') != 'success':
                continue
            job = api.request('GET', f"/repos/{repository}/actions/jobs/{match[2]}")
            check_url = f"https://api.github.com/repos/{repository}/check-runs/{check['id']}"
            if (job.get('run_id') != int(match[1]) or job.get('head_sha') != pr['head']['sha']
                    or job.get('check_run_url') != check_url or job.get('name') != name
                    or job.get('status') != 'completed' or job.get('conclusion') != check.get('conclusion')):
                continue
            candidates.append(check)
            source_runs[check["id"]] = run
        actual = max(candidates, key=lambda item: item["id"], default={})
        if (expected.get('condition') or expected.get('agent_condition')) and actual:
            if expected.get('agent_condition'):
                condition = expected['agent_condition']
                from runner_migration import maintenance_agent_exclusion
                authored = agent_authored(pr) and not maintenance_agent_exclusion(
                    pr, trusted_workflows[expected['workflow']], expected['name'])
                context = {'wmie_agent_authored': 'true' if authored else 'false'}
                result = pr_condition(condition, context)
            else:
                actor = source_runs[actual['id']].get('actor', {}).get('login')
                result = pr_condition(expected['condition'], {'github.actor': actor}) if actor else UNKNOWN
            require(result is not UNKNOWN, 'external_ci_condition_unknown', expected['id'])
            if result is False:
                require(actual.get('conclusion') == 'skipped', 'external_ci_condition_mismatch', expected['id'])
                reason = 'The trusted job condition excludes this PR context.'
                expected_checks[-1].update(applicable=False, reason=reason)
                observations.append({'id': expected['id'], 'conclusion': 'not_applicable', 'reason': reason,
                                     'check_id': actual['id']})
                continue
        observations.append({"id": expected["id"], "conclusion": actual.get("conclusion", "missing"), "check_id": actual.get("id")})
    validate_ci(expected_checks, observations)
    return observations


def ci_evidence(api, repository, pr, *, ci_run_id=None):
    run = trusted_run(api, repository, ci_run_id or latest_ci(api, repository, pr), CI_WORKFLOW, events={"workflow_dispatch"})
    profile, planned = current_plan(api, repository, pr)
    jobs = run_jobs(api, repository, run)
    validate_ci_run(run, pr, planned, jobs)
    external = external_ci(api, repository, pr, profile.get("external_checks", []))
    return {"run_id": run["id"], "run_attempt": run["run_attempt"], "profile_sha256": digest(profile),
            "plan_sha256": digest(planned), "external": external}


def binding_for_run(api, repository, run, *, artifact_id=None, expected_digest=None):
    name = f"wmie-binding-{run['id']}-{run['run_attempt']}"
    return artifact_record(api, repository, run, name, "binding.json", artifact_id=artifact_id, expected_digest=expected_digest)


def previous_analysis(api, repository, pr, current_run_id):
    title = f"WMIE Review pr={pr['number']} base={pr['base']['sha']} head={pr['head']['sha']}"
    manual_title = f"WMIE Review pr={pr['number']} base=current head=current"
    filters = source_filter(pr)
    for candidate in recent_runs(api, repository, "wmie-review.lock.yml", **filters):
        if candidate["id"] == current_run_id or canonical_run_title(candidate.get("display_title")) not in {title, manual_title}:
            continue
        run = trusted_run(api, repository, candidate["id"], REVIEW_WORKFLOW, events={"workflow_run", "workflow_dispatch"})
        artifacts = api.pages(f"/repos/{repository}/actions/runs/{run['id']}/artifacts", "artifacts")
        name = f"wmie-binding-{run['id']}-{run['run_attempt']}"
        if not any(item.get("name") == name and not item.get("expired") for item in artifacts):
            jobs = run_jobs(api, repository, run)
            if jobs.get("agent", {}).get("conclusion") == "skipped":
                continue
            # Lost or expired evidence never proves that an inference did not start.
            return run["id"]
        binding = binding_for_run(api, repository, run)
        manifest = binding.get("manifest", {})
        if manifest.get("pr_number") == pr["number"] and manifest.get("base_sha") == pr["base"]["sha"] and manifest.get("head_sha") == pr["head"]["sha"]:
            validate_input_record(binding, run, pr)
            return run["id"]
    return None


def review_prepare(api, repository, event):
    current_run_id = number(os.environ["GITHUB_RUN_ID"])
    run = trusted_run(api, repository, current_run_id, REVIEW_WORKFLOW, events={"workflow_run", "workflow_dispatch"})
    source_run_id = None
    if os.environ["GITHUB_EVENT_NAME"] == "workflow_run":
        source_run_id = event["workflow_run"]["id"]
        source_run = trusted_run(api, repository, source_run_id, CI_WORKFLOW, events={"workflow_dispatch"})
        match = re.fullmatch(r"WMIE CI pr=([1-9][0-9]*) base=([a-f0-9]{40}) head=([a-f0-9]{40})", canonical_run_title(source_run.get("display_title", "")))
        require(match is not None, "ci_title_invalid")
        pr_number = number(match[1])
    else:
        pr_number = number(event.get("inputs", {}).get("pr_number", ""))
        if event.get("inputs", {}).get("ci_run_id"):
            source_run_id = number(event["inputs"]["ci_run_id"])
    pr = live_pr(api, repository, pr_number)
    for side in ("base", "head"):
        expected = event.get("inputs", {}).get(side + "_sha")
        if expected:
            require(pr[side]["sha"] == sha(expected), side + "_changed")
    if pr["base"].get("ref") == pr["base"].get("repo", {}).get("default_branch"):
        require(source_matches_pr(run, pr), "review_source_base_changed",
                "Start a review from the current default branch before admitting inference.")
    evidence = ci_evidence(api, repository, pr, ci_run_id=source_run_id)
    repeat = os.environ["GITHUB_EVENT_NAME"] == "workflow_dispatch" and str(event.get("inputs", {}).get("repeat_review", "false")).lower() == "true"
    previous = previous_analysis(api, repository, pr, current_run_id)
    if previous and not repeat:
        output("ready", "false")
        return {"state": "analysis_already_admitted", "previous_run_id": previous,
                "action": "Read the previous result. Use an explicit manual review to authorize another analysis."}
    origin = {"run_id": run["id"], "run_attempt": run["run_attempt"], "workflow_sha": sha(os.environ["WMIE_WORKFLOW_SHA"]),
              "workflow_path": REVIEW_WORKFLOW, "presentation_version": 1}
    require(origin["workflow_sha"] == run["head_sha"], "workflow_source_mismatch")
    destination = Path("wmie-input")
    require(not destination.exists(), "review_input_directory_exists")
    with tempfile.TemporaryDirectory(prefix="wmie-review-") as temporary:
        objects = fetch(repository, pr["base"]["sha"], pr["head"]["sha"], Path(temporary) / "objects", api.token)
        manifest = snapshot(objects, repository, pr_number, pr["base"]["sha"], pr["head"]["sha"], destination / "source", api.token)
    manifest["provenance"] = origin
    validate_manifest(manifest, repository, pr_number, pr["base"]["sha"], pr["head"]["sha"])
    binding = {"schema_version": 1, "repository": repository, "pr_number": pr_number,
               "base_sha": pr["base"]["sha"], "head_sha": pr["head"]["sha"],
               "manifest": manifest, "manifest_sha256": digest(manifest), "provenance": origin, "ci": evidence}
    # Re-read after preparation, before the input artifacts and AI admission.
    fresh = live_pr(api, repository, pr_number)
    validate_manifest(manifest, repository, pr_number, fresh["base"]["sha"], fresh["head"]["sha"])
    write_json(destination / "binding.json", binding)
    write_json(destination / "source/binding.json", binding)
    write_json(destination / "source/manifest.json", manifest)
    output("ready", "true")
    output("pr_number", pr_number)
    output("head_sha", pr["head"]["sha"])
    return {"state": "ready", "pr_number": pr_number, "head_sha": pr["head"]["sha"], "files": len(manifest["files"])}


def review_preflight(api, repository):
    for name in ("PREPARE", "AGENT", "DETECTION"):
        require(os.getenv("WMIE_" + name + "_RESULT") == "success", "review_job_incomplete", name.lower())
    run = trusted_run(api, repository, number(os.environ["GITHUB_RUN_ID"]), REVIEW_WORKFLOW,
                      events={"workflow_run", "workflow_dispatch"})
    binding = binding_for_run(api, repository, run, artifact_id=number(os.environ["WMIE_INPUT_ARTIFACT_ID"]),
                              expected_digest="sha256:" + os.environ["WMIE_INPUT_DIGEST"])
    pr = live_pr(api, repository, binding["manifest"]["pr_number"])
    validate_input_record(binding, run, pr)
    jobs = run_jobs(api, repository, run)
    for name in ("agent", "detection", "WMIE review input"):
        require(jobs.get(name, {}).get("conclusion") == "success", "review_job_incomplete", name)
    envelope = read_json(os.environ["GH_AW_AGENT_OUTPUT"])
    record = validate_native_output(envelope, binding["manifest"])
    require(all(item.get("type") in {"submit_pull_request_review", "noop"} for item in envelope["items"]),
            "model_authored_inline_comments")
    evidence = ci_evidence(api, repository, pr)
    require(evidence["profile_sha256"] == binding["ci"]["profile_sha256"] and evidence["plan_sha256"] == binding["ci"]["plan_sha256"],
            "ci_plan_changed")
    fresh = live_pr(api, repository, pr["number"])
    validate_manifest(binding["manifest"], repository, pr["number"], fresh["base"]["sha"], fresh["head"]["sha"])
    files = api.pages(f"/repos/{repository}/pulls/{pr['number']}/files") if record["findings"] else []
    presentation = render(record, binding["manifest"], binding["ci"], files)
    write_json(PLAN_PATH, presentation)
    proposal = next(item for item in envelope["items"] if item.get("type") == "submit_pull_request_review")
    envelope["items"] = presentation["comments"] + [{**proposal, "body": presentation["body"]}]
    write_json(os.environ["GH_AW_AGENT_OUTPUT"], envelope)
    return {"state": "accepted", "verdict": record["verdict"], "pr_number": pr["number"], "head_sha": pr["head"]["sha"]}


def native_publication_text(values):
    module = Path(os.environ.get("RUNNER_TEMP", "")) / "gh-aw/actions/sanitize_content_core.cjs"
    require(module.is_file(), "native_publication_normalizer_missing")
    script = ("const fs = require('node:fs'); "
              "const { canonicalizePublicationText } = require(process.argv[1]); "
              "const values = JSON.parse(fs.readFileSync(0, 'utf8')); "
              "process.stdout.write(JSON.stringify(values.map(value => "
              "canonicalizePublicationText(value, {preserveImageAttributes: true}))));")
    result = subprocess.run(["node", "-e", script, str(module.resolve())], input=json.dumps(values),
                            capture_output=True, text=True, timeout=30)
    require(result.returncode == 0, "native_publication_normalization_failed")
    normalized = json.loads(result.stdout)
    require(isinstance(normalized, list) and len(normalized) == len(values)
            and all(isinstance(value, str) for value in normalized), "native_publication_normalization_failed")
    return normalized


def review_publication(api, repository, *, items_path="/tmp/gh-aw/safe-output-items.jsonl"):
    presentation = read_json(PLAN_PATH)
    record = presentation["record"]
    require(record["repository"] == repository and record["review_run_id"] == number(os.environ["GITHUB_RUN_ID"]),
            "publication_run_mismatch")
    require(record["review_run_attempt"] == number(os.environ["GITHUB_RUN_ATTEMPT"]), "publication_attempt_mismatch")
    pr_number = number(record["pr_number"])
    pr = live_pr(api, repository, pr_number)
    require(pr["head"]["sha"] == record["head_sha"] and pr["base"]["sha"] == record["base_sha"], "publication_commits_changed")
    items = [json.loads(line) for line in Path(items_path).read_text().splitlines() if line.strip()]
    reviews = [item for item in items if item.get("type") == "submit_pull_request_review"]
    require(len(reviews) == 1, "native_publication_ambiguous")
    item = reviews[0]
    require(item.get("repo") == repository and item.get("number") == pr_number, "native_publication_target_mismatch")
    review_id = number(item.get("id"))
    require(item.get("metadata", {}).get("review_id") == review_id, "native_publication_review_mismatch")
    review = api.request("GET", f"/repos/{repository}/pulls/{pr_number}/reviews/{review_id}")
    require(review.get("user", {}).get("id") == BOT_ID and review["user"].get("type") == "Bot", "wrong_reviewer")
    require(review.get("commit_id") == record["head_sha"], "published_commit_mismatch")
    state = {"approve": "APPROVED", "changes_requested": "CHANGES_REQUESTED", "incomplete": "COMMENTED"}[record["verdict"]]
    require(review.get("state") == state, "published_state_mismatch")
    require(item.get("metadata", {}).get("review_state") == state, "native_publication_state_mismatch")
    normalized = native_publication_text([presentation["body"]] + [c["body"] for c in presentation["comments"]])
    require(without_framework_marker(review.get("body", ""), repository) == normalized[0], "published_body_mismatch")
    comments = published_comments(api, repository, pr_number, review_id)
    expected = [{**comment, "body": body} for comment, body in zip(presentation["comments"], normalized[1:])]
    require(len(comments) == len(expected), "published_comments_mismatch")
    remaining = list(comments)
    for planned in expected:
        matches = [c for c in remaining if all(c.get(key) == planned[key] for key in ("path", "line", "side", "body"))]
        require(len(matches) == 1, "published_comments_mismatch")
        actual = matches[0]
        require(actual.get("user", {}).get("id") == BOT_ID and actual.get("commit_id") == record["head_sha"]
                and actual.get("pull_request_review_id") == review_id, "published_comment_binding_mismatch")
        remaining.remove(actual)
    publication = {"schema_version": 1, "repository": repository, "pr_number": pr_number,
                   "run_id": record["review_run_id"], "run_attempt": record["review_run_attempt"],
                   "head_sha": record["head_sha"], "review_id": review_id, "record_sha256": digest(record),
                   "body_sha256": text_hash(review["body"]),
                   "comments": [{**{key: c[key] for key in ("id", "path", "line", "side")},
                                 "body_sha256": text_hash(c["body"])} for c in comments]}
    write_json(RECORD_PATH, publication)
    return {"state": "publication_verified", "review_id": review_id, "inline_comments": len(comments)}


def ci_context(api, repository, event):
    inputs = event.get("inputs", {})
    pr = live_pr(api, repository, inputs.get("pr_number", ""))
    require(pr["base"]["sha"] == sha(inputs.get("base_sha")), "base_changed")
    require(pr["head"]["sha"] == sha(inputs.get("head_sha")), "head_changed")
    ancestry = api.request("GET", f"/repos/{repository}/compare/{pr['base']['sha']}...{pr['head']['sha']}")
    require(ancestry.get("status") in {"ahead", "identical"}, "branch_update_required",
            "Update the PR branch from its current base before starting CI and review.")
    run = trusted_run(api, repository, number(os.environ["GITHUB_RUN_ID"]), CI_WORKFLOW, events={"workflow_dispatch"})
    if "head_sha" in source_filter(pr):
        require(source_matches_pr(run, pr), "ci_source_base_changed")
    require(canonical_run_title(run.get("display_title")) == ci_title(pr["number"], pr["base"]["sha"], pr["head"]["sha"]), "ci_title_invalid")
    require(pr.get("merge_commit_sha"), "pr_merge_not_ready", "GitHub must compute the proposed merge before CI can start.")
    merge_sha = sha(pr["merge_commit_sha"])
    merge = api.request("GET", f"/repos/{repository}/commits/{merge_sha}")
    require({parent["sha"] for parent in merge.get("parents", [])} == {pr["base"]["sha"], pr["head"]["sha"]},
            "pr_merge_not_current", "Wait for GitHub to compute the current proposed merge.")
    result = {"pr_number": pr["number"], "base_sha": pr["base"]["sha"], "head_sha": pr["head"]["sha"], "merge_sha": merge_sha}
    for key, value in result.items():
        output(key, value)
    write_json("wmie-ci-context.json", result)
    return result


def ci_plan(api, repository, source):
    context = read_json("wmie-ci-context.json")
    pr = live_pr(api, repository, context["pr_number"])
    require(pr["base"]["sha"] == context["base_sha"] and pr["head"]["sha"] == context["head_sha"], "ci_commits_changed")
    _, planned = current_plan(api, repository, pr, source=source)
    matrix = [{"component": component} for component in planned["components"] if component.get("checks")]
    require(len(matrix) <= 200, "ci_matrix_requires_partition", "Partition the local profile without dropping checks.")
    result = {**context, "schema_version": 1, "repository": repository, "plan": planned}
    write_json("wmie-ci-binding.json", result)
    output("matrix", {"include": matrix})
    output("has_components", "true" if matrix else "false")
    return {"state": "planned", "components": len(matrix), "checks": len(planned["checks"]),
            "not_configured": [{"component": c["id"], **note} for c in planned["components"] for note in c.get("not_configured", [])]}


def execute_component(source, component):
    root = Path(source).resolve()

    def cwd(relative):
        require(relative == "." or safe_path(relative), "invalid_component_path")
        target = (root / relative).resolve()
        require(target == root or root in target.parents, "component_path_escape")
        require(target.is_dir(), "component_directory_missing", relative)
        return target

    for argv in component.get("install", []):
        result = subprocess.run(argv, cwd=cwd(component.get("install_path", component["path"])))
        require(result.returncode == 0, "dependency_install_failed", component["id"])
    for check in component.get("checks", []):
        result = subprocess.run(check["argv"], cwd=cwd(component["path"]))
        require(result.returncode == 0, "project_check_failed", check["id"])
    return {"state": "success", "component": component["id"]}


def ci_aggregate(api, repository, binding):
    pr = live_pr(api, repository, binding["pr_number"])
    require(pr["base"]["sha"] == binding["base_sha"] and pr["head"]["sha"] == binding["head_sha"], "ci_commits_changed")
    run = trusted_run(api, repository, number(os.environ["GITHUB_RUN_ID"]), CI_WORKFLOW, events={"workflow_dispatch"})
    require(canonical_run_title(run.get("display_title")) == ci_title(pr["number"], pr["base"]["sha"], pr["head"]["sha"]), "ci_title_invalid")
    jobs = run_jobs(api, repository, run)
    expected = [{"id": name, "applicable": True} for name in ("WMIE plan", "WMIE content", "WMIE security")]
    expected += [{"id": "WMIE / " + c["id"], "applicable": True} for c in binding["plan"]["components"] if c.get("checks")]
    validate_ci(expected, [{"id": name, "conclusion": job.get("conclusion")} for name, job in jobs.items()])
    profile = profile_at(api, repository, pr["base"]["sha"])
    require(digest(profile) == binding["plan"]["profile_sha256"], "ci_profile_changed")
    return {"state": "local_checks_complete", "pr_number": pr["number"], "expected_jobs": expected,
            "external_checks": "Required by ci_evidence before review admission, publication, and merge."}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=("review-prepare", "review-preflight", "review-publication", "ci-context", "ci-plan", "ci-component", "ci-aggregate"))
    parser.add_argument("--source", default="wmie-source")
    parser.add_argument("--binding", default="wmie-ci-binding.json")
    args = parser.parse_args()
    api = GitHub()
    repository = repository_name(os.environ["GITHUB_REPOSITORY"])
    try:
        event = read_json(os.environ["GITHUB_EVENT_PATH"])
        if args.command == "review-prepare":
            output("ready", "false")
            result = review_prepare(api, repository, event)
        elif args.command == "review-preflight":
            result = review_preflight(api, repository)
        elif args.command == "review-publication":
            result = review_publication(api, repository)
        elif args.command == "ci-context":
            result = ci_context(api, repository, event)
        elif args.command == "ci-plan":
            result = ci_plan(api, repository, args.source)
        elif args.command == "ci-component":
            result = execute_component(args.source, json.loads(os.environ["WMIE_COMPONENT"]))
        else:
            result = ci_aggregate(api, repository, read_json(args.binding))
        print(json.dumps(result, sort_keys=True))
        return 0
    except GovernanceError as error:
        print(json.dumps({"state": "blocked", "code": error.code, "detail": error.detail}, sort_keys=True), file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
