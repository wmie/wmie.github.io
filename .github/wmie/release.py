"""Verify automation copies against independently reviewed central source."""
from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

from core import GitHub, GovernanceError, require, sha, safe_path


def release_approval(api, write_api, repository, pr, ci, *, verify_only=False):
    from distribution import SOURCE_REPOSITORY, MARKER, HOLDS, tree_entries
    from governance import published_approval
    from control import ci_evidence
    from review import BOT_ID
    if repository == SOURCE_REPOSITORY or repository in HOLDS or repository == 'wmie/copilot-review-sandbox':
        return None
    # Only the distributor's existing branch namespace and App author qualify.
    if (pr.get('user', {}).get('login') != 'wmie-sync[bot]'
            or pr.get('user', {}).get('type') != 'Bot'
            or not pr['head']['ref'].startswith('chore/wmie-agentic-update-')
            or pr['head'].get('repo', {}).get('full_name') != repository):
        return None
    changed = api.pages(f"/repos/{repository}/pulls/{pr['number']}/files")
    if not any(item['filename'] == MARKER for item in changed) and not pr['head']['ref'].endswith('-runners'):
        return None
    require(type(pr.get('changed_files')) is int and pr['changed_files'] == len(changed),
            'release_files_incomplete')
    require(all(item.get('status') != 'renamed' for item in changed), 'release_rename_forbidden')
    base, head = pr['base']['sha'], pr['head']['sha']
    marker = json.loads(api.file(repository, MARKER, head))
    require(marker.get('source_repository') == SOURCE_REPOSITORY, 'release_source_invalid')
    commit = sha(marker.get('source_commit'))
    token = os.environ.get('WMIE_RELEASE_READ_TOKEN')
    require(token, 'release_read_credential_missing')
    source_api = GitHub(token)
    meta = source_api.request('GET', f'/repos/{SOURCE_REPOSITORY}')
    branch = meta['default_branch']
    comparison = source_api.request('GET', f'/repos/{SOURCE_REPOSITORY}/compare/{commit}...{branch}')
    require(comparison.get('status') in {'ahead', 'identical'}, 'release_not_on_default_branch')
    candidates = source_api.pages(f'/repos/{SOURCE_REPOSITORY}/commits/{commit}/pulls')
    source_pr = next((p for p in candidates if p.get('merged_at') and p.get('merge_commit_sha') == commit
                      and p['base']['ref'] == branch), None)
    require(source_pr, 'release_source_pr_missing')
    source_pr = source_api.request('GET', f"/repos/{SOURCE_REPOSITORY}/pulls/{source_pr['number']}")
    source_ci = ci_evidence(source_api, SOURCE_REPOSITORY, source_pr)
    approval = published_approval(source_api, SOURCE_REPOSITORY, source_pr, source_ci,
                                  merged_source_commit=commit)
    entries = tree_entries(api, repository, base)
    if MARKER in entries:
        old_marker = json.loads(api.file(repository, MARKER, base))
        require(old_marker.get('source_repository') == SOURCE_REPOSITORY, 'release_previous_source_invalid')
        # Refuse to overwrite unrecorded local variants.
        for path, expected in old_marker['files'].items():
            require(hashlib.sha256(api.file(repository, path, base)).hexdigest() == expected,
                    'release_local_variant', path)
        previous_commit = sha(old_marker.get('source_commit'))
    else:
        from runner_migration import approved_first_install
        require(approved_first_install(repository, base, pr['base']['ref'], entries),
                'release_first_install_requires_owner')
        # The target base is owner-pinned. This base authenticates only the generator lineage.
        previous_commit = sha(approval['reviewed_base_sha'])
    profile = json.loads(api.file(repository, '.github/wmie/ci-profile.json', base))
    try:
        expected_files = reviewed_bundle(source_api, api, commit, repository, pr, profile, entries,
                                         reviewed_head=sha(source_pr['head']['sha']),
                                         reviewed_base=sha(approval['reviewed_base_sha']),
                                         previous_commit=previous_commit)
    except GovernanceError as error:
        if error.code in {'source_review_baseline_mismatch', 'release_source_not_forward'}:
            return None
        raise
    expected_changes = set()
    for path, text in expected_files.items():
        safe_path(path)
        if text is None:
            if path in entries:
                expected_changes.add(path)
        elif path not in entries or api.file(repository, path, base) != text.encode():
            expected_changes.add(path)
    require({item['filename'] for item in changed} == expected_changes, 'release_unexpected_paths')
    head_entries = tree_entries(api, repository, head)
    def file_entries(tree):
        return {path: (entry['type'], entry['mode'], entry['sha'])
                for path, entry in tree.items() if entry['type'] != 'tree'}
    base_files, head_files = file_entries(entries), file_entries(head_entries)
    actual_changes = {path for path in base_files.keys() | head_files.keys()
                      if base_files.get(path) != head_files.get(path)}
    require(actual_changes == expected_changes, 'release_tree_unexpected_paths')
    for path in expected_changes:
        text = expected_files[path]
        if text is None:
            require(path not in head_entries, 'release_deletion_mismatch', path)
        else:
            data = text.encode()
            blob = hashlib.sha1(b'blob ' + str(len(data)).encode() + b'\0' + data).hexdigest()
            actual = head_entries.get(path, {})
            require(actual.get('type') == 'blob' and actual.get('mode') == '100644'
                    and actual.get('sha') == blob, 'release_file_mismatch', path)
    if verify_only:
        return {'source_commit': commit, 'source_review_id': approval['review_id'],
                'base_sha': base, 'head_sha': head, 'repository': repository}
    repaired_paths = verified_project_repairs(repository, pr['head']['ref'], expected_files, head_entries)
    heading = 'Migration release and project repairs verified' if repaired_paths else 'Automation release verified'
    repair_note = ('\nProject repairs: ' + ', '.join(repaired_paths) + '\n') if repaired_paths else ''
    explanation = ('The automation files and exact project repairs match the reviewed central release. '
                   if repaired_paths else 'The automation files match the reviewed central release. ')
    body = (f"{heading}\n\n"
            f"Source: {SOURCE_REPOSITORY}@{commit}\n"
            f"Central review: https://github.com/{SOURCE_REPOSITORY}/pull/{source_pr['number']}#pullrequestreview-{approval['review_id']}\n"
            f"Target base: {base}\nTarget commit: {head}\n{repair_note}\n"
            f"{explanation}This is a deterministic copy verification, not a new AI analysis.")
    reviews = api.pages(f"/repos/{repository}/pulls/{pr['number']}/reviews")
    current = [review for review in reviews if review.get('user', {}).get('id') == BOT_ID
               and review.get('commit_id') == head]
    latest = max(current, key=lambda value: value['id'], default=None)
    if latest:
        require(latest.get('state') == 'APPROVED', 'release_review_conflict')
        if latest.get('body') != body:
            refreshed, count = re.subn(r'(?m)^Target base: [0-9a-f]{40}$',
                                       f'Target base: {base}', latest.get('body') or '')
            require(count == 1 and refreshed == body, 'release_review_conflict')
            latest = None
    if latest is None:
        require(write_api, 'release_approval_missing')
        fresh = api.request('GET', f"/repos/{repository}/pulls/{pr['number']}")
        require(fresh['base']['sha'] == base and fresh['head']['sha'] == head, 'release_commits_changed')
        latest = write_api.request('POST', f"/repos/{repository}/pulls/{pr['number']}/reviews",
                                   {'commit_id': head, 'event': 'APPROVE', 'body': body})
        require(latest.get('user', {}).get('id') == BOT_ID and latest.get('state') == 'APPROVED'
                and latest.get('commit_id') == head, 'release_review_identity_invalid')
        actual = api.request('GET', f"/repos/{repository}/pulls/{pr['number']}/reviews/{latest['id']}")
        require(actual.get('body') == body and actual.get('state') == 'APPROVED', 'release_publication_mismatch')
    return {'review_id': latest['id'], 'run_id': ci['run_id'], 'run_attempt': ci['run_attempt'],
            'head_sha': head, 'base_sha': base, 'source_commit': commit,
            'source_review_run_id': approval['run_id'], 'approval_kind': 'verified_automation_release'}


def verified_project_repairs(repository, branch, expected_files, head_entries):
    if not branch.endswith('-runners'):
        return []
    from runner_migration import project_repair_records
    records = project_repair_records(repository, json.loads(expected_files['.github/wmie/runner-migration.json']))
    for path, record in records.items():
        actual = head_entries.get(path, {})
        require(actual.get('type') == 'blob' and actual.get('mode') == '100644'
                and actual.get('sha') == record['after_blob'], 'release_project_repair_mismatch', path)
    return sorted(records)


# A fresh interpreter imports only the generator from the reviewed source tree.
# Target files are immutable data. No API credentials enter this process.
_GENERATE = r"""
import json, sys, tempfile
from pathlib import Path
root = Path(sys.argv[1])
sys.path.insert(0, str(root / '.github/wmie'))
from core import safe_path
from distribution import bundle, legacy_changes, instruction_changes
request = json.load(sys.stdin)
class Snapshot:
    def file(self, repository, path, ref):
        if repository != request['repository'] or ref != request['base']:
            raise ValueError('Unexpected snapshot request')
        return (Path(sys.argv[2]) / safe_path(path)).read_bytes()
with tempfile.TemporaryDirectory() as scratch:
    api = Snapshot()
    files = bundle(root, request['profile'], request['branch'], request['commit'], repository=request['repository'])
    files.update(legacy_changes(api, request['repository'], request['base'], request['entries'], scratch))
    files.update(instruction_changes(api, request['repository'], request['base'], request['entries'], root))
    if request.get('custom_runners'):
        from runner_migration import custom_changes
        files.update(custom_changes(api, request['repository'], request['base'], entries=request['entries']))
    print(json.dumps(files))
"""


def reviewed_bundle(source_api, target_api, commit, repository, pr, profile, entries, *,
                    reviewed_head, reviewed_base, previous_commit):
    from git_input import git
    commit = sha(commit)
    reviewed_head = sha(reviewed_head)
    reviewed_base = sha(reviewed_base)
    previous_commit = sha(previous_commit)
    progression = source_api.request('GET', f'/repos/wmie/.github/compare/{previous_commit}...{commit}')
    require(progression.get('status') in {'ahead', 'identical'}, 'release_source_not_forward')
    with tempfile.TemporaryDirectory(prefix='automation-release-') as directory:
        directory = Path(directory)
        objects, source, snapshot = (directory / name for name in ('objects', 'source', 'snapshot'))
        for path in (objects, source, snapshot):
            path.mkdir()
        git(objects, 'init', '--bare')
        git(objects, 'remote', 'add', 'origin', 'https://github.com/wmie/.github.git')
        git(objects, 'fetch', '--depth=1', '--no-tags', 'origin', commit, reviewed_head,
            reviewed_base, previous_commit, token=source_api.token)
        require(git(objects, 'rev-parse', commit).decode().strip() == commit, 'source_generator_commit_mismatch')
        require(git(objects, 'rev-parse', reviewed_head).decode().strip() == reviewed_head, 'source_generator_commit_mismatch')
        paths = ('.github/wmie', '.github/workflows', '.github/aw/actions-lock.json')
        tree = git(objects, 'ls-tree', '-r', '-z', commit, '--', *paths)
        reviewed_tree = git(objects, 'ls-tree', '-r', '-z', reviewed_head, '--', *paths)
        require(tree == reviewed_tree, 'source_generator_tree_unreviewed')
        previous_tree = git(objects, 'ls-tree', '-r', '-z', previous_commit, '--', *paths)
        review_base_tree = git(objects, 'ls-tree', '-r', '-z', reviewed_base, '--', *paths)
        if previous_tree != review_base_tree and previous_commit != commit:
            from runner_migration import approved_baseline
            old = json.loads(target_api.file(repository, '.github/wmie/installation.json', pr['base']['sha']))
            require(approved_baseline(repository, previous_commit, old.get('files')),
                    'source_review_baseline_mismatch')
        for row in tree.split(b'\0'):
            if not row:
                continue
            fields, path = row.split(b'\t', 1)
            mode, kind, oid = fields.decode().split()
            path = safe_path(path.decode())
            require(kind == 'blob' and mode in {'100644', '100755'}, 'source_generator_file_mode', path)
            target = source / path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(git(objects, 'cat-file', 'blob', oid))
        from runner_migration import test_repair_records, project_repair_records
        migration_path = source / '.github/wmie/runner-migration.json'
        custom_runners = pr.get('head', {}).get('ref', '').endswith('-runners')
        repairs = test_repair_records(repository, json.loads(migration_path.read_text())
                                      if migration_path.is_file() else {'repositories': {}}) if custom_runners else {}
        repair_paths = set(repairs) | {path for record in repairs.values() for path in record.get('context', {})}
        require(repair_paths <= entries.keys(), 'migration_test_file_missing')
        project_repairs = project_repair_records(repository, json.loads(migration_path.read_text())) if custom_runners else {}
        require({path for path, record in project_repairs.items() if record['before_blob'] is not None} <= entries.keys(),
                'migration_project_file_missing')
        repair_paths.update(project_repairs)
        for path, entry in entries.items():
            if path in repair_paths or path == 'AGENTS.md' or (path.startswith('.github/workflows/') and path.endswith(('.yml', '.yaml'))):
                require(entry.get('mode') in {'100644', '100755'}, 'release_snapshot_file_mode', path)
                target = snapshot / safe_path(path)
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(target_api.file(repository, path, pr['base']['sha']))
        request = {'repository': repository, 'base': pr['base']['sha'], 'commit': commit,
                   'branch': pr['base']['ref'], 'profile': profile, 'entries': entries,
                   'custom_runners': custom_runners}
        result = subprocess.run([sys.executable, '-I', '-B', '-c', _GENERATE, str(source), str(snapshot)],
                                input=json.dumps(request), text=True, capture_output=True,
                                cwd=directory, env={'PATH': os.defpath, 'LANG': 'C.UTF-8'}, timeout=60)
        require(result.returncode == 0, 'reviewed_generator_failed')
        files = json.loads(result.stdout)
        require(isinstance(files, dict) and files and all(isinstance(path, str)
                and (value is None or isinstance(value, str)) for path, value in files.items()),
                'reviewed_generator_output_invalid')
        return files
