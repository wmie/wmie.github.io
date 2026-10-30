"""Distribute trusted reviewer files through local pull requests only."""

from __future__ import annotations

import copy
from concurrent.futures import ThreadPoolExecutor, as_completed
import hashlib
import itertools
import json
import os
from pathlib import Path
import re
import tempfile
from urllib.parse import quote

from authoring import yaml_data
from ci import discover, validate_profile
from ci_filters import UNKNOWN, glob_matches, pr_condition
from core import GitHub, GovernanceError, digest, read_json, require, safe_path, sha, write_json
from git_input import discovery_tree, git
from workflows import render

SOURCE_REPOSITORY = 'wmie/.github'
BRANCH = 'chore/wmie-agentic-update'
MARKER = '.github/wmie/installation.json'
# Operational exclusions require explicit owner instructions.
HOLDS = {}
LEGACY = re.compile(r'wmie/\.github/\.github/workflows/agent-(?:issue|pr-review)\.yml@')
COMMON = tuple('.github/wmie/' + p for p in (
    'agent-policy.md', 'authoring.py', 'baseline.py', 'ci.py', 'ci_filters.py', 'control.py', 'core.py', 'diagnostics.py', 'draft.py',
    'provider_ready.py', 'distribution.py', 'release.py', 'evidence.py', 'git_input.py', 'governance.py', 'merge.py', 'presentation.py', 'requirements.txt', 'review.py',
    'runner_migration.py', 'runner-migration.json', 'triage.openvex.json', 'tool-versions.json', 'workflows.py')) + (
    '.github/workflows/wmie-review.md', '.github/workflows/wmie-review.lock.yml', '.github/aw/actions-lock.json')


def repositories(api):
    return [r for r in api.pages('/installation/repositories', 'repositories')
            if r.get('owner', {}).get('login', '').lower() == 'wmie'
            and not r.get('archived') and not r.get('disabled')
            and r.get('full_name') not in {SOURCE_REPOSITORY, 'wmie/copilot-review-sandbox'}]


def tree_entries(api, repository, commit):
    entries = api.request('GET', f'/repos/{repository}/git/trees/{sha(commit)}?recursive=1')
    require(entries.get('truncated') is False, 'distribution_tree_incomplete', repository)
    return {entry['path']: entry for entry in entries['tree']}


def manifest_tree(api, repository, commit, directory):
    objects = Path(directory) / 'objects'
    objects.mkdir()
    git(objects, 'init', '--bare')
    git(objects, 'remote', 'add', 'origin', 'https://github.com/' + repository + '.git')
    git(objects, 'fetch', '--depth=1', '--filter=blob:none', '--no-tags', 'origin', sha(commit), token=api.token)
    return discovery_tree(objects, commit, Path(directory) / 'manifests', api.token)


def workflow_data(content, directory):
    p = Path(directory) / 'workflow.yml'
    p.write_bytes(content)
    return yaml_data(p)


def pr_workflow(data):
    events = data.get('on', {})
    if isinstance(events, str):
        return events == 'pull_request'
    if isinstance(events, list):
        return 'pull_request' in events
    if not isinstance(events, dict) or 'pull_request' not in events:
        return False
    types = (events.get('pull_request') or {}).get('types', [])
    return not types or bool(set(types) & {'opened', 'synchronize', 'reopened', 'ready_for_review', 'edited'})


def job_names(job_id, job):
    name = str(job.get('name', job_id))
    matrix = job.get('strategy', {}).get('matrix')
    if not matrix:
        require('${{' not in name, 'dynamic_ci_job_name', name)
        return [name]
    if isinstance(matrix, dict) and set(matrix) == {'include'}:
        names = []
        for row in matrix['include']:
            require(isinstance(row, dict), 'ci_matrix_configuration_required', job_id)
            expanded = name
            for key, value in row.items():
                expanded = re.sub(r'\$\{\{\s*matrix\.' + re.escape(key) + r'\s*\}\}', str(value), expanded)
            require('${{' not in expanded, 'dynamic_ci_job_name', name)
            names.append(expanded)
        return names
    require(isinstance(matrix, dict) and not matrix.get('include') and not matrix.get('exclude'),
            'ci_matrix_configuration_required', job_id)
    dimensions = {key: value for key, value in matrix.items() if isinstance(value, list)}
    require(len(dimensions) == len(matrix) and dimensions, 'ci_matrix_configuration_required', job_id)
    require(all(all(isinstance(v, (str, int, float)) for v in values) for values in dimensions.values()),
            'ci_matrix_configuration_required', job_id)
    output = []
    for values in itertools.product(*dimensions.values()):
        expanded = name
        for key, value in zip(dimensions, values):
            expanded = re.sub(r'\$\{\{\s*matrix\.' + re.escape(key) + r'\s*\}\}', str(value), expanded)
        require('${{' not in expanded, 'dynamic_ci_job_name', name)
        if expanded == name and '${{' not in name:
            suffix = ', '.join(map(str, values))
            if suffix:
                expanded += ' (' + suffix + ')'
        output.append(expanded)
    return output


def external_profile(api, repository, commit, entries, profile, directory):
    checks, coverage = [], {c['id']: [] for c in profile['components']}
    all_commands = []
    for path, entry in sorted(entries.items()):
        if not (path.startswith('.github/workflows/') and path.endswith(('.yml', '.yaml'))):
            continue
        if Path(path).name in {'wmie-ci.yml', 'wmie-governance.yml', 'wmie-merge.yml', 'wmie-review-events.yml',
                                'wmie-review.lock.yml', 'wmie-provision.yml', 'wmie-distribute.yml'}:
            continue
        content = api.file(repository, path, commit)
        if LEGACY.search(content.decode(errors='replace')):
            continue
        data = workflow_data(content, directory)
        if not pr_workflow(data):
            continue
        workflow_name = data.get('name', Path(path).name)
        require(isinstance(workflow_name, str) and workflow_name, 'invalid_ci_workflow_name', path)
        job_checks = []
        commands = []
        for job_id, job in data.get('jobs', {}).items():
            if job.get('name') == 'Comment guardrail status':
                continue
            names = [name for name in job_names(job_id, job) if name not in {'PR size check', 'Block new dependencies'}]
            if not names:
                continue
            condition = str(job.get('if', '')).strip()
            condition_result = pr_condition(condition)
            if condition_result is False:
                continue
            dynamic_condition = condition_result is UNKNOWN
            agent_condition = re.sub(r'needs\.[A-Za-z0-9_-]+\.outputs\.is_agent', 'wmie_agent_authored', condition)
            known_agent_condition = (agent_condition != condition
                and pr_condition(agent_condition, {'wmie_agent_authored': 'true'}) is True
                and pr_condition(agent_condition, {'wmie_agent_authored': 'false'}) is False)
            require(not dynamic_condition or 'github.actor' in condition or known_agent_condition,
                    'conditional_ci_configuration_required', path + ':' + job_id)
            require('uses' not in job, 'reusable_ci_configuration_required', path + ':' + job_id)
            for name in names:
                item = {'id': 'existing:' + Path(path).name + ':' + job_id + ':' + str(len(job_checks)),
                        'name': name, 'workflow': path, 'workflow_name': workflow_name}
                events = data.get('on', {})
                filters = (events.get('pull_request') or {}) if isinstance(events, dict) else {}
                filters = {key: value for key, value in filters.items() if key in {'paths', 'paths-ignore', 'branches', 'branches-ignore'}}
                for patterns in filters.values():
                    require(isinstance(patterns, list), 'ci_filter_configuration_required', path)
                    for pattern in patterns:
                        glob_matches('', pattern.lstrip('!'))
                if filters:
                    item['filters'] = filters
                if dynamic_condition:
                    if known_agent_condition:
                        item['agent_condition'] = agent_condition
                    else:
                        item['condition'] = condition
                checks.append(item)
                job_checks.append(item['id'])
            commands.extend(str(step.get('run', '')) for step in job.get('steps', []))
            commands.extend(str(row.get('command', '')) for row in job.get('strategy', {}).get('matrix', {}).get('include', []))
        all_commands.extend(commands)
        text = '\n'.join(commands)
        for component in profile['components']:
            ecosystem = component['ecosystem']
            markers = {'node': r'\b(?:pnpm|npm|yarn|bun)\b', 'python': r'\b(?:pytest|pip|uv|unittest|ruff)\b',
                       'php': r'\b(?:php|composer)\b', 'go': r'\bgo (?:test|build|vet)\b',
                       'rust': r'\bcargo\b', 'cmake': r'\b(?:cmake|ctest)\b'}
            if job_checks and re.search(markers.get(ecosystem, r'(?!)'), text):
                coverage[component['id']].extend(job_checks)
    for component in profile['components']:
        text = '\n'.join(all_commands)
        names = {check['name'] for check in component.get('checks', [])}
        families = [('build' in names, r'\bbuild\b'),
                    (any(name.startswith('test') for name in names), r'\b(?:test|pytest|vitest|unittest)\b'),
                    (bool(names & {'typecheck', 'type-check', 'check-types'}), r'\b(?:typecheck|type-check|check-types|tsc)\b'),
                    (bool(names & {'lint', 'check', 'check:ci', 'lint:ci'}), r'\b(?:lint|check|biome|eslint|ruff)\b')]
        adequate = all(not required or re.search(pattern, text) for required, pattern in families)
        if coverage[component['id']] and adequate:
            component.pop('configuration_required', None)
            component.update(checks=[], install=[], covered_by_external=sorted(set(coverage[component['id']])))
    profile['external_checks'] = checks
    return validate_profile(profile)


def profile_for(api, repository, commit, entries, directory):
    path = '.github/wmie/ci-profile.json'
    if path in entries:
        return validate_profile(json.loads(api.file(repository, path, commit)))
    observed = discover(manifest_tree(api, repository, commit, directory))
    return external_profile(api, repository, commit, entries, observed, directory)


def legacy_changes(api, repository, commit, entries, directory):
    """Remove legacy jobs, preserving unrelated workflow jobs and template sync."""
    import yaml
    result = {}
    for path in entries:
        if not (path.startswith('.github/workflows/') and path.endswith(('.yml', '.yaml'))):
            continue
        content = api.file(repository, path, commit)
        text = content.decode(errors='replace')
        if not LEGACY.search(text) and not any(name in text for name in ('PR size check', 'Block new dependencies')):
            continue
        data = workflow_data(content, directory)
        jobs = data.get('jobs', {})
        removed = {key for key, value in jobs.items() if LEGACY.search(str(value.get('uses', '')))
                   or value.get('name') in {'PR size check', 'Block new dependencies'}}
        removed.update(key for key, job in jobs.items() if job.get('name') == 'Comment guardrail status')
        changed_rows = False
        for key, job in jobs.items():
            matrix = job.get('strategy', {}).get('matrix', {})
            if not isinstance(matrix, dict) or set(matrix) != {'include'}:
                continue
            rows = matrix['include']
            kept_rows = [row for row in rows if row.get('name') not in {'PR size check', 'Block new dependencies'}]
            if kept_rows != rows:
                changed_rows = True
                if kept_rows:
                    matrix['include'] = kept_rows
                else:
                    removed.add(key)
        require(removed or changed_rows, 'legacy_call_unclassified', path)
        kept = {key: value for key, value in jobs.items() if key not in removed}
        require(not any(set(([v['needs']] if isinstance(v.get('needs'), str) else v.get('needs', []))) & removed
                        for v in kept.values()), 'legacy_job_dependency', path)
        if not kept:
            result[path] = None
        else:
            data['jobs'] = kept
            result[path] = yaml.safe_dump(data, sort_keys=False, width=120)
    return result



def instruction_changes(api, repository, commit, entries, source):
    if 'AGENTS.md' not in entries:
        return {}
    original = api.file(repository, 'AGENTS.md', commit).decode()
    text = original
    text = re.sub(r'(?m)^- Under \*\*1000 total lines\*\* \(additions \+ deletions\)\. Larger work must be split\.$',
                  '- Change size is a reviewability concern. Every PR requires a complete code review.', text)
    text = re.sub(r'(?m)^- Autonomous runs only: under \*\*1000 total lines\*\* \(additions \+ deletions\)\.\n  Larger work must be split\. \(No size cap on supervised work — but small\n  PRs still get reviewed faster\.\)',
                  '- Change size is a reviewability concern. Every PR requires a complete code review.', text)
    text = re.sub(r'(?ms)^2\. \*\*Never add or change dependencies[^\n]*\n.*?(?=\n\n)',
                  '2. Keep dependency changes relevant to the task and update the lockfile.\n   The reviewer assesses their security and compatibility with the application.', text)
    text = text.replace('Normal CI gates and human review\n  apply. The autonomous-agent rules below (agent branch naming, PR size\n  cap, dependency ban, strict coverage) do **not** apply.',
                        'Required project checks and code review approval apply. Agent branch naming applies only to unattended runs.')
    text = text.replace('10. Wait for CI green. Wait for human review.',
                        '10. Wait for required project checks and complete code review approval on the current commits.')
    text = text.replace('12. Once approved + merged, the branch auto-deletes.',
                        '12. Wait for the automatic merge after approval and successful required checks.')
    start, end = '<!-- WMIE managed review policy -->', '<!-- End WMIE managed review policy -->'
    policy = start + '\n' + (Path(source) / '.github/wmie/agent-policy.md').read_text().strip() + '\n' + end
    if start in text:
        require(text.count(start) == 1 and text.count(end) == 1, 'ambiguous_managed_agent_policy')
        text = re.sub(re.escape(start) + r'.*?' + re.escape(end), lambda match: policy, text, flags=re.S)
    elif '## WMIE review and merge' in text and 'GitHub Agentic Workflows runs the review locally in this repository.' in text:
        text = re.sub(r'(?ms)^## WMIE review and merge\n.*?(?=^## |\Z)', lambda match: policy + '\n', text)
    else:
        text = text.rstrip() + '\n\n' + policy + '\n'
    return {'AGENTS.md': text} if text != original else {}


def bundle(source, profile, branch, source_commit, repository=None):
    source = Path(source)
    files = {path: (source / path).read_text() for path in COMMON}
    migration_path = '.github/wmie/runner-migration.json'
    migration = json.loads(files[migration_path])
    records = migration['repositories']
    profile_line_width = records.get(repository, {}).get('profile_line_width', 100)
    migration['repositories'] = {repository: records[repository]} if repository in records else {}
    files[migration_path] = json.dumps(migration, indent=2, sort_keys=True) + '\n'
    with tempfile.TemporaryDirectory(prefix='wmie-render-') as temporary:
        for name in render(temporary, branch, profile, profile_line_width=profile_line_width):
            path = '.github/workflows/' + name
            files[path] = (Path(temporary) / path).read_text()
        files['.github/wmie/ci-profile.json'] = (Path(temporary) / '.github/wmie/ci-profile.json').read_text()
    release = {'schema_version': 1, 'source_repository': SOURCE_REPOSITORY,
               'source_commit': sha(source_commit), 'default_branch': branch,
               'files': {path: hashlib.sha256(text.encode()).hexdigest() for path, text in files.items()}}
    files[MARKER] = json.dumps(release, indent=2, sort_keys=True) + '\n'
    return files


def propose(api, meta, source, source_commit, *, dry_run=False, profile_override=None):
    repository = meta['full_name']
    if repository in HOLDS:
        return {'repository': repository, 'state': 'held', 'reason': HOLDS[repository]}
    if not meta.get('size'):
        return {'repository': repository, 'state': 'waiting_first_commit'}
    branch = meta['default_branch']
    commit = api.request('GET', f'/repos/{repository}/git/ref/heads/{quote(branch, safe="")}')['object']['sha']
    entries = tree_entries(api, repository, commit)
    with tempfile.TemporaryDirectory(prefix='wmie-distribution-') as directory:
        if profile_override is not None:
            require('.github/wmie/ci-profile.json' not in entries, 'profile_override_requires_first_install')
            profile = validate_profile(copy.deepcopy(profile_override))
        else:
            profile = profile_for(api, repository, commit, entries, directory)
        files = bundle(source, profile, branch, source_commit, repository=repository)
        files.update(legacy_changes(api, repository, commit, entries, directory))
        files.update(instruction_changes(api, repository, commit, entries, source))
        bootstrap_runners = os.environ.get('WMIE_RUNNER_BOOTSTRAP') == 'true'
        custom_runners = bootstrap_runners or os.environ.get('WMIE_RUNNER_CUSTOM') == 'true'
        if custom_runners:
            from runner_migration import approved_first_install, custom_changes
            installed = MARKER in entries and (bootstrap_runners or json.loads(api.file(repository, MARKER, commit)).get('source_commit') == source_commit)
            first_install = bootstrap_runners and approved_first_install(repository, commit, branch, entries)
            require(installed or first_install,
                    'migration_bundle_must_be_installed_first')
            files.update(custom_changes(api, repository, commit, entries=entries))
    if MARKER in entries:
        previous_marker = api.file(repository, MARKER, commit).decode()
        previous = json.loads(previous_marker)
        desired = json.loads(files[MARKER])
        if (previous.get('source_repository') == SOURCE_REPOSITORY
                and previous.get('default_branch') == branch and previous.get('files') == desired['files']):
            files[MARKER] = previous_marker
    update_branch = BRANCH + '-' + digest(json.loads(files[MARKER])['files'])[:12] + ('-runners' if custom_runners else '')
    changes = {}
    for path, value in files.items():
        safe_path(path)
        old = api.file(repository, path, commit).decode() if path in entries else None
        if old != value:
            changes[path] = value
    if not changes:
        return {'repository': repository, 'state': 'current', 'head_sha': commit}
    existing = api.pages(f'/repos/{repository}/pulls?state=open&head=wmie:{update_branch}')
    if existing:
        return {'repository': repository, 'state': 'update_pr_open', 'pr_number': existing[0]['number']}
    result = {'repository': repository, 'state': 'planned', 'base_sha': commit,
              'paths': sorted(changes), 'first_install': MARKER not in entries}
    if dry_run:
        return result
    # Reconcile a prior branch before any new write. Never overwrite a developer branch.
    refs = api.pages(f'/repos/{repository}/git/matching-refs/heads/{update_branch}')
    require(not any(r['ref'] == 'refs/heads/' + update_branch for r in refs), 'distribution_branch_requires_reconciliation', repository)
    current = api.request('GET', f'/repos/{repository}/git/ref/heads/{quote(branch, safe="")}')['object']['sha']
    require(current == commit, 'distribution_base_changed')
    base = api.request('GET', f'/repos/{repository}/git/commits/{commit}')
    tree = api.request('POST', f'/repos/{repository}/git/trees', {'base_tree': base['tree']['sha'], 'tree': [
        {'path': path, 'mode': '100644', 'type': 'blob', **({'sha': None} if value is None else {'content': value})}
        for path, value in changes.items()]})
    new = api.request('POST', f'/repos/{repository}/git/commits', {
        'message': 'ci: update repository automation', 'tree': tree['sha'], 'parents': [commit]})
    # Persist the expected write locally before creating the remote reference.
    write_json('wmie-distribution-writes/' + meta['name'] + '.json', {**result, 'head_sha': new['sha'], 'branch': update_branch})
    api.request('POST', f'/repos/{repository}/git/refs', {'ref': 'refs/heads/' + update_branch, 'sha': new['sha']})
    repair_paths = json.loads(files['.github/wmie/runner-migration.json'])['repositories'].get(repository, {}).get('project_repairs', {})
    project_note = ('This release includes exact project repairs from the reviewed central source. '
                    if custom_runners and any(path in changes for path in repair_paths)
                    else 'Application runtime behavior remains unchanged. ')
    pr = api.request('POST', f'/repos/{repository}/pulls', {
        'title': 'ci: update repository automation', 'head': update_branch, 'base': branch,
        'body': 'Update the repository automation and project check configuration.\n\n'
                'The bundle comes from ' + SOURCE_REPOSITORY + '@' + source_commit + '.\n'
                + project_note + 'Existing project checks remain required. '
                'This release includes the approved runner selection and test infrastructure changes.\n\n'
                '## Authorship\n\nAgent-authored: WMIE Sync. Authorized infrastructure update.\n\n'
                + ('First installation requires the authorized owner bootstrap path.\n' if result['first_install'] else '')
                + 'Subsequent PRs require complete code review approval and successful required checks.'})
    return {**result, 'state': 'update_pr_created', 'pr_number': pr['number'], 'head_sha': new['sha']}


def activation_rules():
    from review import APP_ID
    from rules import merger_ruleset
    return [
        {'name': 'Require checks and code review', 'target': 'branch', 'enforcement': 'active',
         'conditions': {'ref_name': {'include': ['~DEFAULT_BRANCH'], 'exclude': []}},
         'bypass_actors': [{'actor_type': 'OrganizationAdmin', 'bypass_mode': 'pull_request'}],
         'rules': [
             {'type': 'pull_request', 'parameters': {'required_approving_review_count': 1,
                 'dismiss_stale_reviews_on_push': True, 'require_code_owner_review': False,
                 'require_last_push_approval': True, 'required_review_thread_resolution': True,
                 'require_extra_approval_for_unattributed_changes': False,
                 'allowed_merge_methods': ['squash', 'rebase']}},
             {'type': 'required_status_checks', 'parameters': {
                 'strict_required_status_checks_policy': True, 'do_not_enforce_on_create': True,
                 'required_status_checks': [{'context': name, 'integration_id': APP_ID}
                     for name in ('Required checks', 'Code review approval')]}}]},
        merger_ruleset(['~DEFAULT_BRANCH'])]


def rules_match(actual, expected, *, check_bypass=True):
    if any(actual.get(key) != expected[key] for key in ('name', 'target', 'enforcement', 'conditions')):
        return False
    if check_bypass:
        actor = lambda value: (value['actor_type'], value.get('actor_id'), value['bypass_mode'])
        if sorted(map(actor, actual.get('bypass_actors', []))) != sorted(map(actor, expected['bypass_actors'])):
            return False
    observed = {rule['type']: rule for rule in actual.get('rules', [])}
    if set(observed) != {rule['type'] for rule in expected['rules']}:
        return False
    for rule in expected['rules']:
        parameters = observed[rule['type']].get('parameters', {})
        for key, value in rule.get('parameters', {}).items():
            default = False if key == 'update_allows_fetch_and_merge' else None
            if parameters.get(key, default) != value:
                return False
    return True


def verify_central_rules(api, meta):
    repository, branch = meta['full_name'], meta['default_branch']
    effective = api.pages(f'/repos/{repository}/rules/branches/{quote(branch, safe="")}')
    candidates = {rule['ruleset_id'] for rule in effective
                  if rule.get('ruleset_source_type') == 'Organization'
                  and rule.get('ruleset_source') == 'wmie'
                  and rule['type'] in {'pull_request', 'required_status_checks', 'update'}}
    inherited = [api.request('GET', f'/repos/{repository}/rulesets/{rule_id}')
                 for rule_id in sorted(candidates)]
    approval, merger = activation_rules()
    approval['name'] = 'main-branch-protection'
    approval['rules'] = [{'type': name} for name in ('deletion', 'non_fast_forward', 'required_linear_history')] + approval['rules']
    merger['name'] = 'Restrict default branch merges to owner and WMIE Agent'
    verified, bypass_verification = [], {}
    for expected in (approval, merger):
        matches = [rule for rule in inherited if rule['name'] == expected['name']]
        require(len(matches) == 1, 'central_rule_not_applicable', expected['name'])
        actual = matches[0]
        require(actual.get('source_type') == 'Organization' and actual.get('source') == 'wmie',
                'central_rule_untrusted_source', expected['name'])
        bypass_visible = 'bypass_actors' in actual
        if bypass_visible:
            require(isinstance(actual['bypass_actors'], list), 'central_rule_bypass_invalid', expected['name'])
        # The branch endpoint establishes repository applicability. Compare branch
        # targeting and protections separately from organization repository selectors.
        observed = {**actual, 'conditions': {'ref_name': actual.get('conditions', {}).get('ref_name')}}
        require(rules_match(observed, expected, check_bypass=bypass_visible),
                'central_rule_mismatch', expected['name'])
        verified.append(actual['id'])
        bypass_verification[str(actual['id'])] = 'live' if bypass_visible else 'not_visible'
    return {'branch': branch, 'ruleset_ids': verified, 'bypass_verification': bypass_verification}


def activate(api, meta):
    from credential_environment import ensure_environment, provision_secrets
    repository = meta['full_name']
    coverage = verify_central_rules(api, meta)
    environment = ensure_environment(api, repository, meta['default_branch'])
    provisioned = provision_secrets(api, repository, meta['default_branch'])
    changed = environment['created'] or bool(provisioned['installed'])
    if changed:
        api.request('POST', f'/repos/{repository}/dispatches', {'event_type': 'wmie-reconcile'})
    return {'repository': repository, 'state': 'active', 'reconciliation_dispatched': changed, 'environment_created': environment['created'],
            'credentials': provisioned, 'central_rules': coverage}


def main():
    require(os.environ.get('GITHUB_REPOSITORY') == SOURCE_REPOSITORY, 'untrusted_distribution_source')
    require(os.environ.get('GITHUB_REF') == 'refs/heads/main', 'untrusted_distribution_branch')
    require(os.environ.get('GITHUB_EVENT_NAME') in {'schedule', 'workflow_dispatch', 'push'}, 'untrusted_distribution_event')
    source = Path(os.environ.get('GITHUB_WORKSPACE', '.'))
    source_commit = sha(os.environ['GITHUB_SHA'])
    dry_run = os.environ.get('WMIE_DISTRIBUTION_APPLY') != 'true'
    verify_only = os.environ.get('WMIE_VERIFY_RULES_ONLY') == 'true'
    selected = os.environ.get('WMIE_TARGET_REPOSITORY', '').strip()
    require(not selected or re.fullmatch(r'[A-Za-z0-9_.-]+', selected), 'invalid_distribution_target')
    api = GitHub()
    results = []
    available = repositories(api)
    if verify_only:
        available.append(api.request('GET', f'/repos/{SOURCE_REPOSITORY}'))
    targets = [meta for meta in available if not selected or meta['name'] == selected]
    def update(meta):
        target_api = GitHub(api.token)
        try:
            if verify_only:
                result = {'repository': meta['full_name'], 'state': 'rules_verified',
                          'central_rules': verify_central_rules(target_api, meta)}
            else:
                result = propose(target_api, meta, source, source_commit, dry_run=dry_run)
                if result['state'] == 'current' and not dry_run:
                    result = activate(target_api, meta)
        except GovernanceError as error:
            result = {'repository': meta['full_name'], 'state': 'blocked', 'code': error.code, 'detail': error.detail}
        return result
    with ThreadPoolExecutor(max_workers=4) as executor:
        for future in as_completed([executor.submit(update, meta) for meta in targets]):
            result = future.result()
            results.append(result)
            write_json('wmie-distribution-result.json', {'source_commit': source_commit, 'dry_run': dry_run, 'repositories': results})
            print(json.dumps({key: value for key, value in result.items() if key != 'rules_before'}), flush=True)
    require(not selected or results, 'distribution_target_unavailable')
    return 1 if any(result['state'] == 'blocked' for result in results) else 0


if __name__ == '__main__':
    raise SystemExit(main())
