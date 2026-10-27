"""Render local Actions workflows. Application code never receives App credentials."""

from __future__ import annotations

from pathlib import Path

from core import require, write_json


PINS = {
    "checkout": "actions/checkout@d23441a48e516b6c34aea4fa41551a30e30af803",
    "python": "actions/setup-python@ece7cb06caefa5fff74198d8649806c4678c61a1",
    "node": "actions/setup-node@249970729cb0ef3589644e2896645e5dc5ba9c38",
    "pnpm": "pnpm/action-setup@b906affcce14559ad1aafd4ab0e942779e9f58b1",
    "bun": "oven-sh/setup-bun@0c5077e51419868618aeaa5fe8019c62421857d6",
    "uv": "astral-sh/setup-uv@37802adc94f370d6bfd71619e3f0bf239e1f3b78",
    "go": "actions/setup-go@924ae3a1cded613372ab5595356fb5720e22ba16",
    "rust": "dtolnay/rust-toolchain@b725eda525362e7cf34af9a7243cac1e3f01a7ec",
    "php": "shivammathur/setup-php@eb7c497e18156a6bbabfef1d3a82760b9eda3962",
    "upload": "actions/upload-artifact@b7c566a772e6b6bfb58ed0dc250532a479d7789f",
    "download": "actions/download-artifact@37930b1c2abaa49bbe596cd826c3c89aef350131",
    "app": "actions/create-github-app-token@64ab729a6294000f5aa4a4bc0b73d1f32bc45510",
}


def trusted_setup():
    return [
        {"uses": PINS["checkout"], "with": {"ref": "${{ github.workflow_sha }}", "path": "wmie-control", "persist-credentials": False}},
        {"uses": PINS["python"], "with": {"python-version": "3.12"}},
        {"name": "Install the configuration parser", "run": "python3 -m pip install --only-binary=:all: --disable-pip-version-check -r wmie-control/.github/wmie/requirements.txt"},
    ]


def reconciliation_job(needs):
    return {"name": "Refresh pull request status", "needs": needs,
            "if": "always() && endsWith(github.workflow_ref, format('@refs/heads/{0}', github.event.repository.default_branch))",
            "runs-on": "ubuntu-latest", "timeout-minutes": 3, "permissions": {"actions": "write"},
            "steps": [{"name": "Request final governance assessment", "env": {
                "GH_TOKEN": "${{ github.token }}", "GH_REPO": "${{ github.repository }}",
                "WMIE_DEFAULT_BRANCH": "${{ github.event.repository.default_branch }}",
                "WMIE_PR_NUMBER": "${{ inputs.pr_number }}", "WMIE_SOURCE_RUN": "${{ github.run_id }}"},
                "run": 'gh workflow run wmie-governance.yml --ref "$WMIE_DEFAULT_BRANCH" -f pr_number="$WMIE_PR_NUMBER" -f source_run_id="$WMIE_SOURCE_RUN"'}]}


def ci_workflow():
    permissions = {"contents": "read", "pull-requests": "read", "actions": "read", "checks": "read"}
    context_env = {"GH_TOKEN": "${{ github.token }}"}
    planner = trusted_setup() + [
        {"name": "Bind the current PR and merge", "id": "context", "env": context_env,
         "run": "python3 wmie-control/.github/wmie/control.py ci-context"},
        {"name": "Read the proposed source", "uses": PINS["checkout"], "with": {
            "ref": "${{ steps.context.outputs.merge_sha }}", "path": "wmie-source", "persist-credentials": False}},
        {"name": "Derive applicable checks", "id": "plan", "env": context_env,
         "run": "python3 wmie-control/.github/wmie/control.py ci-plan --source wmie-source"},
        {"name": "Preserve the CI plan", "id": "binding", "uses": PINS["upload"], "with": {
            "name": "wmie-ci-binding-${{ github.run_id }}-${{ github.run_attempt }}", "path": "wmie-ci-binding.json",
            "if-no-files-found": "error", "retention-days": 30}},
    ]
    load_binding = {"name": "Load the trusted CI plan", "uses": PINS["download"], "with": {"artifact-ids": "${{ needs.plan.outputs.binding_id }}"}}
    checkout_source = {"name": "Read the proposed source", "uses": PINS["checkout"], "with": {
        "ref": "${{ needs.plan.outputs.merge_sha }}", "path": "wmie-source", "persist-credentials": False, "fetch-depth": 0}}
    component_steps = trusted_setup() + [
        {"uses": PINS["checkout"], "with": {"ref": "${{ needs.plan.outputs.merge_sha }}", "path": "wmie-source", "persist-credentials": False}},
        {"uses": PINS["node"], "if": "matrix.component.ecosystem == 'node'", "with": {"node-version": "${{ matrix.component.runtime }}"}},
        {"uses": PINS["pnpm"], "if": "matrix.component.package_manager == 'pnpm'", "with": {"version": "${{ matrix.component.package_manager_version || '10.33.0' }}", "run_install": False}},
        {"uses": PINS["bun"], "if": "matrix.component.package_manager == 'bun'", "with": {"bun-version": "${{ matrix.component.package_manager_version || '1.4.4' }}"}},
        {"name": "Prepare Yarn", "if": "matrix.component.package_manager == 'yarn'", "env": {"WMIE_COMPONENT": "${{ toJSON(matrix.component) }}"},
         "run": "python3 wmie-control/.github/wmie/baseline.py yarn"},
        {"uses": PINS["python"], "if": "matrix.component.ecosystem == 'python'", "with": {"python-version": "${{ matrix.component.runtime || '3.12' }}"}},
        {"uses": PINS["uv"], "if": "matrix.component.package_manager == 'uv'", "with": {"version": "0.13.5", "enable-cache": False}},
        {"uses": PINS["go"], "if": "matrix.component.ecosystem == 'go'", "with": {"go-version-file": "wmie-source/${{ matrix.component.path }}/go.mod", "cache": False}},
        {"uses": PINS["rust"], "if": "matrix.component.ecosystem == 'rust'", "with": {"toolchain": "${{ matrix.component.runtime || 'stable' }}"}},
        {"uses": PINS["php"], "if": "matrix.component.ecosystem == 'php'", "with": {
            "php-version": "${{ matrix.component.runtime || '8.3' }}", "extensions": "${{ join(matrix.component.php_extensions, ',') }}", "tools": "composer", "coverage": "none"}},
        {"name": "Execute project checks", "env": {"WMIE_COMPONENT": "${{ toJSON(matrix.component) }}", "CI": "true"},
         "run": "python3 wmie-control/.github/wmie/control.py ci-component --source wmie-source"},
    ]
    jobs = {
        "plan": {"name": "Prepare checks", "runs-on": "ubuntu-latest", "timeout-minutes": 10, "permissions": permissions,
                 "outputs": {"matrix": "${{ steps.plan.outputs.matrix }}", "has_components": "${{ steps.plan.outputs.has_components }}",
                             "merge_sha": "${{ steps.context.outputs.merge_sha }}", "binding_id": "${{ steps.binding.outputs.artifact-id }}"}, "steps": planner},
        "project": {"name": "Project checks / ${{ matrix.component.id }}", "needs": ["plan"], "if": "needs.plan.outputs.has_components == 'true'",
                    "runs-on": "ubuntu-latest", "timeout-minutes": 30, "permissions": {"contents": "read"},
                    "strategy": {"fail-fast": False, "matrix": "${{ fromJSON(needs.plan.outputs.matrix) }}"}, "steps": component_steps},
    }
    for kind in ("content", "security"):
        jobs[kind] = {"name": {"content": "JSON validation", "security": "Secret scan (Gitleaks)"}[kind], "needs": ["plan"], "runs-on": "ubuntu-latest", "timeout-minutes": 15,
                      "permissions": {"contents": "read"}, "steps": trusted_setup() + [checkout_source, load_binding,
                      {"name": "Inspect " + kind, "run": "python3 wmie-control/.github/wmie/baseline.py " + kind + " --source wmie-source --binding wmie-ci-binding.json"}]}
    jobs["aggregate"] = {"name": "Required checks", "needs": ["plan", "project", "content", "security"], "if": "always()",
                         "runs-on": "ubuntu-latest", "timeout-minutes": 20, "permissions": permissions,
                         "steps": trusted_setup() + [load_binding, {"name": "Require actual CI success", "env": context_env,
                         "run": "python3 wmie-control/.github/wmie/control.py ci-aggregate --binding wmie-ci-binding.json"}]}
    jobs["reconcile"] = reconciliation_job(["aggregate"])
    return {"name": "Pull request checks", "run-name": "Pull request checks pr=${{ inputs.pr_number }} base=${{ inputs.base_sha }} head=${{ inputs.head_sha }}",
            "on": {"workflow_dispatch": {"inputs": {key: {"required": True, "type": "string"} for key in ("pr_number", "base_sha", "head_sha")}}},
            "permissions": {}, "concurrency": {"group": "wmie-ci-pr-${{ inputs.pr_number }}", "cancel-in-progress": False, "queue": "max"}, "jobs": jobs}


def governance_workflow(default_branch, external_workflows=()):
    names = sorted(set(["Pull request checks", "AI code review", "Pull request events", "WMIE CI", "WMIE Review", "WMIE review events", *external_workflows]))
    steps = trusted_setup() + [
        {"name": "Authorize status updates", "id": "app", "uses": PINS["app"], "with": {
            "client-id": "${{ secrets.WMIE_REVIEW_CLIENT_ID }}", "private-key": "${{ secrets.WMIE_REVIEW_PRIVATE_KEY }}",
            "owner": "${{ github.repository_owner }}", "repositories": "${{ github.event.repository.name }}", "permission-checks": "write"}},
        {"name": "Assess the current PR", "env": {"GH_TOKEN": "${{ github.token }}", "WMIE_APP_TOKEN": "${{ steps.app.outputs.token }}",
            "WMIE_AUTOMERGE_ENABLED": "${{ vars.WMIE_AUTOMERGE_ENABLED || 'true' }}"},
         "run": "python3 wmie-control/.github/wmie/governance.py"},
    ]
    return {"name": "Coordinate pull request checks", "on": {
        "workflow_run": {"workflows": names, "types": ["completed"]},
        "push": {"branches": [default_branch]},
        "repository_dispatch": {"types": ["wmie-reconcile"]},
        "workflow_dispatch": {"inputs": {"pr_number": {"required": True, "type": "string"},
            "source_run_id": {"required": False, "type": "string", "default": ""}}}},
        "permissions": {}, "concurrency": {"group": "wmie-governance-${{ github.repository }}", "cancel-in-progress": False, "queue": "max"},
        "jobs": {"governance": {"if": "endsWith(github.workflow_ref, format('@refs/heads/{0}', github.event.repository.default_branch))",
            "runs-on": "ubuntu-latest", "timeout-minutes": 15, "environment": "wmie-review",
            "permissions": {"contents": "read", "actions": "write", "checks": "read", "pull-requests": "read"}, "steps": steps}}}


def review_events_workflow(default_branch="main"):
    return {"name": "Pull request events", "on": {
            "push": {"branches-ignore": [default_branch]},
            "pull_request": {"types": ["opened", "synchronize", "reopened", "ready_for_review", "edited"]},
            "pull_request_review": {"types": ["submitted", "edited", "dismissed"]}},
            "permissions": {}, "jobs": {"signal": {"runs-on": "ubuntu-latest", "permissions": {},
            "steps": [{"name": "Signal a review change", "run": "true"}]}}}


def merge_workflow():
    steps = trusted_setup() + [
        {"name": "Mint the constrained merger token", "id": "app", "uses": PINS["app"], "with": {
            "client-id": "${{ secrets.WMIE_REVIEW_CLIENT_ID }}",
            "private-key": "${{ secrets.WMIE_REVIEW_PRIVATE_KEY }}",
            "owner": "${{ github.repository_owner }}", "repositories": "${{ github.event.repository.name }}",
            "permission-contents": "write", "permission-pull-requests": "write",
            "permission-actions": "read", "permission-checks": "read"}},
        {"name": "Require the actual approval before merge", "env": {
            "GH_TOKEN": "${{ steps.app.outputs.token }}", "WMIE_PR_NUMBER": "${{ inputs.pr_number }}",
            "WMIE_EXPECTED_HEAD": "${{ inputs.expected_head }}",
            "WMIE_AUTOMERGE_ENABLED": "${{ vars.WMIE_AUTOMERGE_ENABLED || 'true' }}"},
         "run": "python3 wmie-control/.github/wmie/merge.py"},
        {"name": "Preserve the merge result", "if": "always()", "uses": PINS["upload"], "with": {
            "name": "wmie-merge-${{ github.run_id }}", "path": "wmie-merge-result.json",
            "if-no-files-found": "ignore", "retention-days": 30}},
    ]
    return {"name": "Merge approved pull request", "run-name": "Merge approved pull request pr=${{ inputs.pr_number }} head=${{ inputs.expected_head }}", "on": {"workflow_dispatch": {"inputs": {
                "pr_number": {"required": True, "type": "string"},
                "expected_head": {"required": True, "type": "string"}}}},
            "permissions": {}, "concurrency": {"group": "wmie-merge-${{ github.repository }}",
                "cancel-in-progress": False, "queue": "max"},
            "jobs": {"merge": {"if": "endsWith(github.workflow_ref, format('@refs/heads/{0}', github.event.repository.default_branch))",
                "environment": "wmie-review", "runs-on": "ubuntu-latest", "timeout-minutes": 15,
                "permissions": {"contents": "read"}, "steps": steps}}}


def render(directory, default_branch, profile):
    import yaml
    from ci import validate_profile
    validate_profile(profile)
    require(isinstance(default_branch, str) and default_branch, "missing_default_branch")
    root = Path(directory)
    workflows = root / ".github/workflows"
    workflows.mkdir(parents=True, exist_ok=True)
    values = {"wmie-ci.yml": ci_workflow(), "wmie-governance.yml": governance_workflow(default_branch, [c["workflow_name"] for c in profile.get("external_checks", [])]),
              "wmie-review-events.yml": review_events_workflow(default_branch), "wmie-merge.yml": merge_workflow()}
    class Dumper(yaml.SafeDumper):
        def ignore_aliases(self, value):
            return True
    for name, value in values.items():
        (workflows / name).write_text(yaml.dump(value, Dumper=Dumper, sort_keys=False, width=120))
    write_json(root / ".github/wmie/ci-profile.json", profile)
    return list(values)
