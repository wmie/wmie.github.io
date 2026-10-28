"""Render validated review records and bind the public text to native execution."""

from __future__ import annotations

import hashlib
import html
import re
from urllib.parse import quote

from core import digest, require


VERSION = 1
PLAN_PATH = "/tmp/wmie-review-presentation/plan.json"
RECORD_PATH = "/tmp/wmie-review-presentation/publication.json"
ARTIFACT = "review-publication"
MAX_INLINE = 10
STATES = {"approve": ("\u2705", "Approved"), "changes_requested": ("\u26d4", "Changes requested"),
          "incomplete": ("\u26a0\ufe0f", "Review incomplete")}


def text(value):
    parts = re.split(r"(`[^`\n]+`)", str(value))
    result = []
    for index, part in enumerate(parts):
        if index % 2:
            result.append(part)
        else:
            escaped = html.escape(part, quote=False).replace("@", "[at]")
            result.append(re.sub(r"([\\`*_{}\[\]()#+!|])", r"\\\1", escaped))
    return "".join(result).strip()


def text_hash(value):
    return hashlib.sha256(value.encode()).hexdigest()


def reference(record):
    repo = record["repository"]
    run, attempt = record["review_run_id"], record["review_run_attempt"]
    commit = record["head_sha"]
    return (f"AI code review · [Commit {commit[:7]}](https://github.com/{repo}/commit/{commit}) · "
            f"[Run {run}, attempt {attempt}](https://github.com/{repo}/actions/runs/{run}/attempts/{attempt})")


def review_reference(body, repository):
    if not isinstance(body, str):
        return None
    pattern = (r"(?m)^AI code review · \[Commit ([a-f0-9]{7})\]\(https://github\.com/" + re.escape(repository)
               + r"/commit/([a-f0-9]{40})\) · \[Run ([1-9][0-9]*), attempt ([1-9][0-9]*)\]"
               + r"\(https://github\.com/" + re.escape(repository)
               + r"/actions/runs/\3/attempts/\4\)$")
    matches = re.findall(pattern, body)
    if not matches:
        return None
    require(len(matches) == 1, "ambiguous_review_reference")
    short, commit, run, attempt = matches[0]
    require(short == commit[:7], "review_reference_commit_mismatch")
    return {"head_sha": commit, "review_run_id": int(run), "review_run_attempt": int(attempt)}


def source_link(record, finding):
    commit = record["head_sha"] if finding["side"] == "head" else record["base_sha"]
    path = quote(finding["path"], safe="/")
    return f"https://github.com/{record['repository']}/blob/{commit}/{path}#L{finding['line']}"


def finding_body(finding):
    return (f"### [{finding['severity'].title()}] {text(finding['title'])}\n\n"
            f"**Evidence:** {text(finding['evidence'])}\n\n"
            f"**Impact:** {text(finding['impact'])}\n\n"
            f"**Suggested fix:** {text(finding['remediation'])}")


def diff_lines(files):
    result = set()
    for file in files:
        old = new = None
        for line in (file.get("patch") or "").splitlines():
            match = re.match(r"@@ -(\d+)(?:,\d+)? \+(\d+)(?:,\d+)? @@", line)
            if match:
                old, new = map(int, match.groups())
            elif old is not None and line and line[0] in " +-":
                if line[0] != "+":
                    result.add((file["filename"], "base", old));old += 1
                if line[0] != "-":
                    result.add((file["filename"], "head", new));new += 1
    return result


def render(record, manifest, ci, files):
    allowed = diff_lines(files)
    findings = sorted(record["findings"], key=lambda f: (
        {"critical": 0, "high": 1, "medium": 2}[f["severity"]], f["path"], f["line"], f["title"]))
    comments, entries = [], []
    for index, finding in enumerate(findings, 1):
        inline = len(comments) < MAX_INLINE and (finding["path"], finding["side"], finding["line"]) in allowed
        location = f"{text(finding['path'])}:{finding['line']}"
        entries.append(f"{index}. **[{finding['severity'].title()}] {text(finding['title'])}** · [{location}]({source_link(record, finding)})")
        if inline:
            entries.append("   Details appear in the inline comment.")
            comments.append({"type": "create_pull_request_review_comment", "repo": record["repository"],
                             "pull_request_number": record["pr_number"], "path": finding["path"],
                             "line": finding["line"], "side": "RIGHT" if finding["side"] == "head" else "LEFT",
                             "body": finding_body(finding)})
        else:
            entries.append("\n" + finding_body(finding) + "\n")
    icon, title = STATES[record["verdict"]]
    body = (f"## {icon} {title}\n\n### Summary\n\n{text(record['summary'])}\n\n### Findings\n\n"
            + ("\n".join(entries) if entries else "No blocking issues found." if record["complete"] else "The analysis is incomplete. No approval was issued.")
            + f"\n\n### Review coverage\n\nReviewed {len(record['reviewed_files'])} of {len(manifest['files'])} changed files."
            + " Static code analysis. This review did not run application tests."
            + f"\n\nProject checks: [View CI results](https://github.com/{record['repository']}/actions/runs/{ci['run_id']}).")
    if record["verdict"] == "changes_requested":
        body += "\n\n### Next steps\n\nAddress the findings and request a new review on the updated commit."
    elif record["verdict"] == "incomplete":
        body += "\n\n### Next steps\n\nRead the execution details and resolve the missing context before requesting another review."
    body += "\n\n---\n\n" + reference(record)
    require(len(body) <= 59000 and all(len(c["body"]) <= 59000 for c in comments), "review_presentation_too_large")
    return {"schema_version": VERSION, "record": record, "body": body, "comments": comments}


def without_framework_marker(body, repository):
    marker = '\n\n[gh-aw-workflow-call-id]: # "' + quote(repository + "/wmie-review", safe="") + '"'
    return body.removesuffix(marker)


def validate_publication(publication, record, review, comments):
    require(publication.get("schema_version") == VERSION, "publication_version")
    require(publication.get("record_sha256") == digest(record), "published_record_mismatch")
    for field, expected in (("repository", record["repository"]), ("pr_number", record["pr_number"]),
                            ("head_sha", record["head_sha"]), ("run_id", record["review_run_id"]),
                            ("run_attempt", record["review_run_attempt"]), ("review_id", review["id"])):
        require(publication.get(field) == expected, "publication_binding_mismatch", field)
    require(publication.get("body_sha256") == text_hash(review["body"]), "published_body_changed")
    expected = publication.get("comments")
    require(isinstance(expected, list) and len(expected) == len(comments), "published_comments_changed")
    actual = {c["id"]: c for c in comments}
    require(len(actual) == len(comments), "published_comments_changed")
    require({c.get("id") for c in expected} == set(actual), "published_comments_changed")
    for entry in expected:
        c = actual.get(entry.get("id"), {})
        require(c.get("pull_request_review_id") == review["id"] and c.get("commit_id") == record["head_sha"],
                "published_comment_binding_mismatch")
        require(c.get("body") is not None and entry.get("body_sha256") == text_hash(c["body"]), "published_comments_changed")
        require(all(c.get(k) == entry.get(k) for k in ("path", "line", "side")), "published_comments_changed")


def check_summary(repository, pr, name, success, details):
    state, code = details.get("state"), details.get("code", "")
    if state == "review_pending":
        message = "Code review is in progress. Wait for the current execution to finish."
    elif success:
        message = "The required project checks passed." if name in {"Required checks", "WMIE CI"} else "The code review approved this commit and the required project checks passed."
    elif state == "application_findings" or code == "application_findings":
        message = "The code review requested changes. Address the findings in the latest review."
    elif state == "ci_incomplete":
        message = "Required project checks did not pass or are incomplete. Read the failed or missing checks."
    elif state == "reviewer_technical_error":
        message = "The code review process failed. Read the failed workflow steps before requesting another review."
    else:
        message = "Code review approval is unavailable or incomplete. Read the execution details before requesting another review."
    links = [f"[Pull request checks](https://github.com/{repository}/pull/{pr['number']}/checks)"]
    if details.get("review_id"):
        links.append(f"[Code review](https://github.com/{repository}/pull/{pr['number']}#pullrequestreview-{details['review_id']})")
    if details.get("run_id"):
        links.append(f"[Workflow details](https://github.com/{repository}/actions/runs/{details['run_id']})")
    return message + "\n\n" + " · ".join(links)
