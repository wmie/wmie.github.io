"""Admit only the exact runner migration approved in the central release."""
import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import tempfile

from authoring import yaml_data
from core import GitHub, require, safe_path, sha
from workflows import RUNNER

VEX_ARGUMENT = '--vex .github/wmie/triage.openvex.json'
VEX_SHA256 = 'd8f6ecca253838b4c60b6b0d74938f625a53a0093ed489a06c3709422a6be4e9'
VEX_GUARD = 'echo "' + VEX_SHA256 + '  .github/wmie/triage.openvex.json" | sha256sum --check -'
CONTACT_RECIPIENT = 'synthetic@example.invalid'
MAINTENANCE_DETECTOR_SHA256 = '6e46ab8e335310bbfbb5b332f9f3c1645e7375aae1c4db9412afff3b46589585'
REVIEW_TEST_COMMAND = '    - run: node --test scripts/release/*.test.mjs\n'
REVIEW_DEPENDENCY_SETUP = ("    - uses: actions/setup-node@48b55a011bda9f5d6aeb4c2d9c7362e8dae4041e\n"
                         "      with:\n        node-version: '22'\n        cache: npm\n"
                         "        cache-dependency-path: package-lock.json\n    - run: npm ci\n")


def manifest():
    return json.loads(Path(__file__).with_name('runner-migration.json').read_text())


def blob(data):
    return hashlib.sha1(b'blob ' + str(len(data)).encode() + b'\0' + data).hexdigest()


def workflow(data):
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / 'workflow.yml'
        path.write_bytes(data)
        return yaml_data(path)


def maintenance_agent_exclusion(pr, data, job_name):
    if pr.get('user', {}).get('type') != 'Bot' or pr['user'].get('login') not in {
            'wmie-sync[bot]', 'dependabot[bot]'}:
        return False
    jobs = workflow(data).get('jobs', {})
    detector = jobs.get('detect-agent', {})
    steps = detector.get('steps', [])
    if (len(steps) != 1 or detector.get('outputs', {}).get('is_agent') != '${{ steps.check.outputs.is_agent }}'
            or hashlib.sha256(json.dumps(steps[0], sort_keys=True, separators=(',', ':')).encode()).hexdigest()
            != MAINTENANCE_DETECTOR_SHA256):
        return False
    targets = [job for key, job in jobs.items() if job.get('name', key) == job_name]
    return (len(targets) == 1 and targets[0].get('needs') in ('detect-agent', ['detect-agent'])
            and targets[0].get('if', '').strip() == "needs.detect-agent.outputs.is_agent == 'true'")


def migrate(data, *, vex=False, contact_recipient=False, review_dependencies=False):
    before = workflow(data)
    expected = copy.deepcopy(before)
    count = 0
    vex_commands = 0
    for job in expected.get('jobs', {}).values():
        if 'uses' in job:
            continue
        require(isinstance(job.get('runs-on'), str) and job['runs-on'] in {'ubuntu-latest', 'ubuntu-24.04', RUNNER},
                'migration_runner_not_supported')
        if job['runs-on'] != RUNNER:
            job['runs-on'] = RUNNER
            count += 1
        if vex:
            for step in job.get('steps', []):
                command = step.get('run', '')
                original = 'trivy fs \\\n'
                replacement = VEX_GUARD + '\ntrivy fs ' + VEX_ARGUMENT + ' \\\n'
                vex_commands += command.count(original) + command.count(replacement)
                if original in command:
                    step['run'] = command.replace(original, replacement)
    value, replaced = re.subn(rb'(?m)^(    runs-on: )(ubuntu-latest|ubuntu-24\.04)([ \t]*(?:#[^\n]*)?)$',
                              lambda m: m[1] + RUNNER.encode() + m[3], data)
    if review_dependencies:
        job = expected.get('jobs', {}).get('review', {})
        steps = job.get('steps', [])
        setup = [{'uses': 'actions/setup-node@48b55a011bda9f5d6aeb4c2d9c7362e8dae4041e',
                  'with': {'node-version': '22', 'cache': 'npm', 'cache-dependency-path': 'package-lock.json'}},
                 {'run': 'npm ci'}]
        require(job.get('name') == 'Review tooling tests'
                and steps and steps[-1] == {'run': 'node --test scripts/release/*.test.mjs'},
                'migration_review_test_setup_invalid')
        if len(steps) == 2:
            require(steps[0] == {'uses': 'actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd',
                                'with': {'persist-credentials': False}}, 'migration_review_test_setup_invalid')
            steps[1:1] = setup
            require(value.count(REVIEW_TEST_COMMAND.encode()) == 1, 'migration_review_test_setup_invalid')
            value = value.replace(REVIEW_TEST_COMMAND.encode(),
                                  (REVIEW_DEPENDENCY_SETUP + REVIEW_TEST_COMMAND).encode())
        else:
            require(len(steps) == 4 and steps[1:3] == setup, 'migration_review_test_setup_invalid')
    if contact_recipient:
        environment = expected.get('jobs', {}).get('test', {}).get('env', {})
        require(environment.get('PGDATABASE') == 'payload_test'
                and environment.get('CONTACT_TO') in {None, CONTACT_RECIPIENT}, 'migration_contact_environment_invalid')
        environment['CONTACT_TO'] = CONTACT_RECIPIENT
        if not re.search(rb'(?m)^      CONTACT_TO: ', value):
            value, inserted = re.subn(rb'(?m)^(      PGDATABASE: payload_test)$',
                lambda m: m[0] + b'\n      CONTACT_TO: ' + CONTACT_RECIPIENT.encode(), value)
            require(inserted == 1, 'migration_contact_environment_invalid')
    if vex:
        require(vex_commands == 1, 'migration_vex_command_not_supported')
        value = re.sub(rb'(?m)^([ \t]+)trivy fs \\\n',
            lambda m: m[1] + VEX_GUARD.encode() + b'\n' + m[1] + ('trivy fs ' + VEX_ARGUMENT + ' \\\n').encode(), value)
    require(replaced == count and workflow(value) == expected, 'migration_changed_other_behavior')
    return value


def authorized_change(repository, path, original, proposed):
    repair = project_repair_records(repository).get(path)
    if repair:
        return (blob(original) == repair['before_blob']
                and apply_project_repair(original, repair) == proposed)
    record = manifest()['repositories'].get(repository, {}).get('custom', {}).get(path)
    return bool(record and blob(original) == record['before_blob']
                and migrate(original, vex=record.get('vex', False),
                            contact_recipient=record.get('contact_recipient', False),
                            review_dependencies=record.get('review_dependencies', False)) == proposed)


def approved_baseline(repository, previous_commit, files):
    record = manifest()['repositories'].get(repository, {})
    return (record.get('source_commit') == previous_commit
            and record.get('installed_files') == files)


def approved_first_install(repository, base_commit, branch, entries):
    record = manifest()['repositories'].get(repository, {}).get('owner_approved_first_install', {})
    expected = record.get('base_sha')
    profile_blob = record.get('profile_blob')
    profile = entries.get('.github/wmie/ci-profile.json', {})
    return bool(isinstance(expected, str) and re.fullmatch(r'[0-9a-f]{40}', expected)
                and expected == base_commit and record.get('default_branch') == branch
                and isinstance(profile_blob, str) and re.fullmatch(r'[0-9a-f]{40}', profile_blob)
                and profile.get('type') == 'blob' and profile.get('mode') == '100644'
                and profile.get('sha') == profile_blob)


def test_repair_records(repository, inventory=None):
    records = (inventory if inventory is not None else manifest())['repositories'].get(repository, {}).get('test_repairs', {})
    require(isinstance(records, dict), 'migration_test_repairs_invalid')
    for path, record in records.items():
        safe_path(path)
        require(isinstance(record, dict), 'migration_test_repair_invalid')
        declaration_only = record.get('declaration_only') is True
        contact_environment = record.get('contact_environment') is True
        require(path == 'apps/web/playwright.config.ts'
                or (path.startswith('apps/web/tests/e2e/') and path.endswith('.ts'))
                or (declaration_only and path.startswith('apps/web/src/') and path.endswith('.tsx'))
                or (contact_environment and path == 'turbo.json'),
                'migration_test_path_forbidden')
        sha(record.get('before_blob'))
        sha(record.get('after_blob'))
        require(isinstance(record.get('edits'), list) and record['edits'], 'migration_test_edits_invalid')
        for edit in record['edits']:
            require(isinstance(edit, dict) and all(isinstance(edit.get(key), str) and edit[key]
                    for key in ('before', 'after')), 'migration_test_edit_invalid')
        if declaration_only or contact_environment:
            require(len(record['edits']) == 1 and isinstance(record.get('original'), str),
                    'migration_declaration_repair_invalid')
            edit = record['edits'][0]
            if declaration_only:
                require(not contact_environment, 'migration_declaration_repair_invalid')
                match = re.fullmatch(r'([ \t]*)const ([A-Za-z_$][A-Za-z0-9_$]*) = \(\) => \{', edit['before'])
                require(match and edit['after'] == match[1] + 'function ' + match[2] + '() {',
                        'migration_declaration_repair_invalid')
            original = record['original']
            require(original.count(edit['before']) == 1 and blob(original.encode()) == record['before_blob']
                    and blob(original.replace(edit['before'], edit['after']).encode()) == record['after_blob'],
                    'migration_declaration_repair_invalid')
            if contact_environment:
                expected = json.loads(original)
                environment = expected.get('globalPassThroughEnv')
                require(isinstance(environment, list) and 'CONTACT_TO' not in environment, 'migration_contact_environment_invalid')
                environment.insert(0, 'CONTACT_TO')
                require(json.loads(original.replace(edit['before'], edit['after'])) == expected,
                        'migration_contact_environment_invalid')
        require(isinstance(record.get('context', {}), dict), 'migration_test_context_invalid')
        for context_path, context in record.get('context', {}).items():
            safe_path(context_path)
            require(context_path.startswith('apps/web/tests/') and context_path.endswith('.ts')
                    and isinstance(context, dict) and isinstance(context.get('text'), str)
                    and blob(context['text'].encode()) == sha(context.get('blob')), 'migration_test_context_invalid')
    return records


def project_repair_records(repository, inventory=None):
    inventory = inventory if inventory is not None else manifest()
    repository_record = inventory['repositories'].get(repository, {})
    records = repository_record.get('project_repairs', {})
    require(isinstance(records, dict), 'migration_project_repairs_invalid')
    for path, record in records.items():
        safe_path(path)
        workflow_repair = (path.startswith('.github/workflows/') and path.endswith(('.yml', '.yaml'))
                           and not Path(path).name.startswith('wmie-')
                           and path in repository_record.get('custom', {}))
        require(not path.startswith('.') or workflow_repair,
                'migration_project_path_forbidden', path)
        require(Path(path).name not in {'AGENTS.md', 'CLAUDE.md', 'GEMINI.md'},
                'migration_project_path_forbidden', path)
        require(isinstance(record, dict), 'migration_project_repair_invalid')
        require('before_blob' in record, 'migration_project_before_blob_missing', path)
        sha(record.get('after_blob'))
        if record.get('before_blob') is None:
            require(isinstance(record.get('content'), str) and record['content']
                    and blob(record['content'].encode()) == record['after_blob']
                    and not path.startswith('.github/'), 'migration_project_new_file_invalid', path)
        else:
            sha(record['before_blob'])
            require(record['before_blob'] != record['after_blob']
                    and isinstance(record.get('edits'), list) and record['edits'],
                    'migration_project_edits_invalid', path)
            for edit in record['edits']:
                require(isinstance(edit, dict) and isinstance(edit.get('before'), str)
                        and edit['before'] and isinstance(edit.get('after'), str),
                        'migration_project_edit_invalid', path)
    return records


def apply_project_repair(original, record):
    require((blob(original) if original is not None else None) == record['before_blob'],
            'migration_project_file_changed')
    if original is None:
        proposed = record['content'].encode()
    else:
        proposed = original
        for edit in record['edits']:
            before, after = edit['before'].encode(), edit['after'].encode()
            require(proposed.count(before) == 1, 'migration_project_edit_ambiguous')
            proposed = proposed.replace(before, after)
    require(blob(proposed) == record['after_blob'], 'migration_project_repair_mismatch')
    return proposed


def custom_changes(api, repository, commit, entries=None):
    result = {}
    project_repairs = project_repair_records(repository)
    for path, record in manifest()['repositories'].get(repository, {}).get('custom', {}).items():
        if path in project_repairs:
            continue
        original = api.file(repository, path, commit)
        if blob(original) == record['before_blob']:
            proposed = migrate(original, vex=record.get('vex', False),
                               contact_recipient=record.get('contact_recipient', False),
                               review_dependencies=record.get('review_dependencies', False))
            if proposed != original:
                result[path] = proposed.decode()
        else:
            # Already migrated files must match the exact approved output blob.
            require(blob(original) == record['after_blob'], 'migration_custom_file_changed', path)
    for path, record in test_repair_records(repository).items():
        for context_path, context in record.get('context', {}).items():
            require(api.file(repository, context_path, commit) == context['text'].encode(),
                    'migration_test_context_changed', context_path)
        original = api.file(repository, path, commit)
        if blob(original) == record['after_blob']:
            continue
        require(blob(original) == record['before_blob'], 'migration_test_file_changed', path)
        proposed = original
        for edit in record['edits']:
            before, after = edit['before'].encode(), edit['after'].encode()
            require(proposed.count(before) == 1, 'migration_test_edit_ambiguous', path)
            proposed = proposed.replace(before, after)
        require(blob(proposed) == record['after_blob'], 'migration_test_repair_mismatch', path)
        result[path] = proposed.decode()
    if project_repairs:
        if entries is None:
            tree = api.request('GET', f'/repos/{repository}/git/trees/{commit}?recursive=1')
            require(tree.get('truncated') is False, 'migration_project_tree_incomplete')
            entries = {row['path']: row for row in tree['tree']}
        for path, record in project_repairs.items():
            entry = entries.get(path)
            require(entry is None or (entry.get('type') == 'blob' and entry.get('mode') == '100644'),
                    'migration_project_file_mode', path)
            original = api.file(repository, path, commit) if entry else None
            if original is not None and blob(original) == record['after_blob']:
                if path.startswith('.github/workflows/'):
                    validate_runners(workflow(original), path)
                continue
            proposed = apply_project_repair(original, record)
            if path.startswith('.github/workflows/'):
                validate_runners(workflow(proposed), path)
                require(set(workflow(original)['jobs']) <= set(workflow(proposed)['jobs']),
                        'migration_project_job_removed', path)
            result[path] = proposed.decode()
    return result


def validate_runners(value, label):
    for name, job in value.get('jobs', {}).items():
        if 'uses' not in job:
            require(job.get('runs-on') == RUNNER, 'runner_policy_failed', label + ':' + name)


def replica_certificate(api, repository, pr):
    from review import APP_ID
    if (repository not in manifest()['repositories']
            or not pr.get('head', {}).get('ref', '').startswith('chore/wmie-agentic-update-')):
        return None
    marker = json.loads(api.file(repository, '.github/wmie/installation.json', pr['head']['sha']))
    require(marker.get('source_repository') == 'wmie/.github', 'migration_source_invalid')
    from core import sha
    source = sha(marker.get('source_commit'))
    identity = f"wmie-replica:{pr['base']['sha']}:{pr['head']['sha']}:{source}"
    checks = api.pages(f"/repos/{repository}/commits/{pr['head']['sha']}/check-runs?filter=latest", 'check_runs')
    matches = [c for c in checks if c.get('name') == 'WMIE migration source'
               and c.get('app', {}).get('id') == APP_ID and c.get('external_id') == identity
               and c.get('status') == 'completed' and c.get('conclusion') == 'success']
    return {'source_commit': source, 'external_id': identity, 'check_id': matches[-1]['id']} if matches else None


def admit_replica_run(api, repository, run):
    from evidence import canonical_run_title
    from control import live_pr
    match = re.fullmatch(r'WMIE CI pr=([1-9][0-9]*) base=([0-9a-f]{40}) head=([0-9a-f]{40})',
                         canonical_run_title(run.get('display_title', '')))
    require(match, 'migration_ci_title_invalid')
    pr = live_pr(api, repository, int(match[1]))
    require(pr['base']['sha'] == match[2] and pr['head']['sha'] == match[3]
            and run['head_sha'] == match[3] and run['head_branch'] == pr['head']['ref'],
            'migration_ci_commits_changed')
    require(replica_certificate(api, repository, pr), 'migration_source_certificate_missing')
    return {'repository': repository, 'pr_number': pr['number'],
            'base_sha': pr['base']['sha'], 'head_sha': pr['head']['sha']}


def prepare_replica_ci(api, repository, pr):
    from release import release_approval
    from review import APP_ID
    certificate = release_approval(api, None, repository, pr, None, verify_only=True)
    require(certificate is not None, 'migration_release_not_certified')
    require(certificate['source_commit'] == os.environ.get('GITHUB_SHA'), 'migration_central_source_changed')
    identity = f"wmie-replica:{pr['base']['sha']}:{pr['head']['sha']}:{certificate['source_commit']}"
    body = {'name': 'WMIE migration source', 'head_sha': pr['head']['sha'], 'external_id': identity,
            'status': 'completed', 'conclusion': 'success',
            'details_url': f"https://github.com/wmie/.github/actions/runs/{os.environ['GITHUB_RUN_ID']}",
            'output': {'title': 'Replica source verified. CI remains required.',
                       'summary': json.dumps(certificate, sort_keys=True)}}
    check = api.request('POST', f'/repos/{repository}/check-runs', body)
    require(check.get('app', {}).get('id') == APP_ID, 'migration_certificate_identity_invalid')
    require(replica_certificate(api, repository, pr), 'migration_certificate_readback_failed')
    return {'state': 'verified_replica_ci_ready', **certificate, 'workflow_dispatch': {
        'repository': repository, 'workflow': 'wmie-ci.yml', 'ref': pr['head']['ref'],
        'inputs': {'pr_number': str(pr['number']), 'base_sha': pr['base']['sha'],
                   'head_sha': pr['head']['sha']}}}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('operation', choices=['prepare', 'finalize'])
    parser.add_argument('repository')
    parser.add_argument('pr', type=int)
    parser.add_argument('head')
    args = parser.parse_args()
    from control import ci_evidence, live_pr
    from distribution import HOLDS
    from governance import set_check
    from merge import merge_approved
    from release import release_approval
    require(os.environ.get('GITHUB_REPOSITORY') == 'wmie/.github'
            and os.environ.get('GITHUB_REF') == 'refs/heads/main'
            and os.environ.get('GITHUB_EVENT_NAME') == 'workflow_dispatch', 'untrusted_migration_context')
    require(args.repository in manifest()['repositories'] and args.repository not in HOLDS,
            'migration_target_not_approved')
    api = GitHub()
    pr = live_pr(api, args.repository, args.pr)
    require(pr['head']['sha'] == args.head, 'migration_head_changed')
    variables = api.pages(f'/repos/{args.repository}/actions/variables', 'variables')
    require(not any(v['name'] == 'WMIE_AUTOMERGE_ENABLED' and v['value'] == 'false' for v in variables),
            'automatic_merge_disabled')
    if args.operation == 'prepare':
        print(json.dumps(prepare_replica_ci(api, args.repository, pr)))
        return
    ci = ci_evidence(api, args.repository, pr)
    approval = release_approval(api, api, args.repository, pr, ci)
    require(approval is not None, 'migration_release_not_certified')
    fresh = live_pr(api, args.repository, args.pr)
    require(fresh['base']['sha'] == pr['base']['sha'] and fresh['head']['sha'] == args.head,
            'migration_commits_changed')
    set_check(api, args.repository, fresh, 'Required checks', success=True,
              details={'state': 'complete', **ci}, read_api=api)
    set_check(api, args.repository, fresh, 'Code review approval', success=True,
              details={'state': 'approved', **approval}, read_api=api)
    print(json.dumps(merge_approved(api, args.repository, args.pr, args.head, pr['base']['ref'])))


if __name__ == '__main__':
    main()
