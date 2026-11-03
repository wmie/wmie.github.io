"""Trusted single-call review stages and independent execution/publication evidence.

The execution protocol is intentionally distinct from gh-aw. Local validation never
manufactures a successful native agent, detection job or publication receipt.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
from pathlib import Path
import re
import urllib.request

import control
from core import GitHub, GovernanceError, NoRedirect, digest, output, read_json, require, sha, write_json
from evidence import canonical_run_title, published_comments, trusted_run
from presentation import render, text_hash, validate_publication
from review import BOT_ID, EVENTS, validate_manifest, validate_record

PROTOCOL = 'wmie-single-call-v1'
WORKFLOW = '.github/workflows/wmie-review-single.yml'
POLICY = '.github/wmie/single-call-policy.json'
from single_call import MODEL


def validate_binding(binding):
    require(isinstance(binding, dict) and binding.get('schema_version') == 1, 'single_binding_version')
    validate_manifest(binding.get('manifest'), binding.get('repository'), binding.get('pr_number'),
                      binding.get('base_sha'), binding.get('head_sha'))
    require(binding.get('manifest_sha256') == digest(binding['manifest']), 'single_binding_digest')
    origin = binding.get('provenance', {})
    require(origin.get('workflow_path') == WORKFLOW and origin.get('presentation_version') == 1,
            'single_workflow_mismatch')
    require(binding['manifest'].get('provenance') == origin, 'single_manifest_origin_mismatch')
    require(type(origin.get('run_id')) is int and origin['run_id'] > 0
            and type(origin.get('run_attempt')) is int and origin['run_attempt'] > 0, 'single_run_invalid')
    sha(origin.get('workflow_sha'))
    ci = binding.get('ci', {})
    require(type(ci.get('run_id')) is int and ci['run_id'] > 0
            and type(ci.get('run_attempt')) is int and ci['run_attempt'] > 0, 'single_ci_missing')
    for key in ('profile_sha256', 'plan_sha256'):
        require(isinstance(ci.get(key), str) and re.fullmatch('[a-f0-9]{64}', ci[key]), 'single_ci_missing')
    return binding


def validate_runtime(api, binding):
    """Only the exact default-branch workflow source may consume this binding."""
    validate_binding(binding)
    repository, origin = binding['repository'], binding['provenance']
    require(control.number(os.environ.get('GITHUB_RUN_ID', '')) == origin['run_id'], 'single_runtime_run_mismatch')
    require(control.number(os.environ.get('GITHUB_RUN_ATTEMPT', '')) == origin['run_attempt'], 'single_runtime_attempt_mismatch')
    require(os.environ.get('WMIE_WORKFLOW_SHA') == origin['workflow_sha'], 'single_runtime_source_mismatch')
    run = trusted_run(api, repository, origin['run_id'], WORKFLOW, events={'workflow_dispatch'})
    metadata = api.request('GET', f'/repos/{repository}')
    require(run.get('head_branch') == metadata.get('default_branch')
            and run.get('head_sha') == origin['workflow_sha']
            and run.get('run_attempt') == origin['run_attempt'], 'single_trusted_source_mismatch')
    return run


def fresh_inputs(api, binding):
    pr = control.live_pr(api, binding['repository'], binding['pr_number'])
    validate_manifest(binding['manifest'], binding['repository'], binding['pr_number'],
                      pr['base']['sha'], pr['head']['sha'])
    ci = control.ci_evidence(api, binding['repository'], pr)
    require(all(ci.get(k) == binding['ci'].get(k) for k in ('profile_sha256', 'plan_sha256')), 'single_ci_plan_changed')
    return pr, ci


def run_title(binding):
    return (f"WMIE Single Review pr={control.number(binding['pr_number'])} "
            f"base={sha(binding['base_sha'])} head={sha(binding['head_sha'])}")


def check_duplicate(api, repository, event, run):
    inputs = event.get('inputs', {})
    if str(inputs.get('repeat_review', 'false')).lower() == 'true':
        return
    require(run.get('run_attempt') == 1, 'single_repeat_authorization_required',
            'A prior attempt may already have incurred inference cost. Use an explicit repeated review.')
    title = run_title(inputs)
    for previous in control.recent_runs(api, repository, 'wmie-review-single.yml', branch=run['head_branch']):
        if previous.get('id') == run['id'] or canonical_run_title(previous.get('display_title', '')) != title:
            continue
        trusted_run(api, repository, previous['id'], WORKFLOW, events={'workflow_dispatch'})
        raise GovernanceError('single_repeat_authorization_required',
                              'An earlier execution for these commits may have started inference.')


def prepare(api, repository, event):
    """Reuse CI-first preparation, retaining all trusted-run and pinned Git checks."""
    run = trusted_run(api, repository, control.number(os.environ.get('GITHUB_RUN_ID', '')),
                      WORKFLOW, events={'workflow_dispatch'})
    metadata = api.request('GET', f'/repos/{repository}')
    require(run.get('head_branch') == metadata.get('default_branch'), 'single_default_branch_required')
    check_duplicate(api, repository, event, run)
    result = control.review_prepare(api, repository, event, workflow=WORKFLOW)
    if result['state'] != 'ready':
        return result
    binding = read_json('wmie-input/binding.json')
    validate_runtime(api, binding)
    from single_context import compile_context
    from single_external import prepare_external
    prepare_external(api, Path('wmie-input/source'))
    package = compile_context(Path('wmie-input/source'), binding)
    write_json('wmie-input/package.json', package)
    return {**result, 'context_complete': package.get('complete') is True,
            'limitations': package.get('limitations', [])}


def validate_result(result, package, binding, record):
    from single_call import build_request, validate_response
    require(isinstance(result, dict) and result.get('protocol') == PROTOCOL, 'single_execution_protocol')
    require(type(result.get('inference_requests')) is int and result['inference_requests'] == 1,
            'single_execution_request_count')
    require(result.get('model') == MODEL, 'single_execution_model')
    require(isinstance(result.get('request_id'), str) and result['request_id'].strip(), 'single_execution_request_id')
    elapsed = result.get('elapsed_seconds')
    require(type(elapsed) in (int, float) and math.isfinite(elapsed) and elapsed >= 0, 'single_execution_elapsed')
    usage = result.get('usage', {})
    require(isinstance(usage, dict) and all(type(usage.get(k)) is int and usage[k] >= 0
            for k in ('prompt_tokens', 'completion_tokens')), 'single_execution_usage')
    cost = usage.get('cost')
    require(type(cost) in (int, float) and math.isfinite(cost) and cost >= 0, 'single_execution_usage')
    expected_request = hashlib.sha256(json.dumps(build_request(package), ensure_ascii=False).encode()).hexdigest()
    require(result.get('request_sha256') == expected_request, 'single_execution_request_digest')
    require(isinstance(result.get('response_sha256'), str)
            and re.fullmatch('[a-f0-9]{64}', result['response_sha256']), 'single_execution_response_digest')
    expected_record = validate_response(result.get('response'), package, binding)
    require(expected_record == record, 'single_execution_response_mismatch')


def execution_record(binding, package, record, result):
    validate_binding(binding)
    validate_record(record, binding['manifest'])
    validate_result(result, package, binding, record)
    origin = binding['provenance']
    return {'schema_version': 1, 'protocol': PROTOCOL, 'repository': binding['repository'],
            'pr_number': binding['pr_number'], 'base_sha': binding['base_sha'], 'head_sha': binding['head_sha'],
            'run_id': origin['run_id'], 'run_attempt': origin['run_attempt'], 'workflow_sha': origin['workflow_sha'],
            'workflow_path': WORKFLOW, 'binding_sha256': digest(binding), 'package_sha256': digest(package),
            'record_sha256': digest(record), 'inference_requests': 1, 'inference': result,
            'safety': {'schema': True, 'evidence': True, 'locations': True, 'sensitive_output': True,
                       'coverage': record['complete']}}


def validate_execution(proof, binding, package, record):
    require(isinstance(proof, dict), 'single_execution_missing')
    require(proof == execution_record(binding, package, record, proof.get('inference')), 'single_execution_mismatch')
    return proof


def key_preflight(package, key, *, opener=None, model=MODEL):
    """Read the established dedicated-key policy; this GET is not inference.

    One byte per token plus framing is a deliberately conservative nominal
    estimate. Actual billed tokens/cost still come from the provider response.
    """
    from single_call import build_request, MAX_NOMINAL_USD
    payload = build_request(package, model)
    require(isinstance(key, str) and key.strip(), 'single_call_key_missing')
    price = payload['provider']['max_price']  # USD per million tokens, the ceiling of the chosen model
    nominal = round((len(json.dumps(payload, ensure_ascii=False).encode()) + 2048) * price['prompt'] / 1_000_000
                    + payload['max_tokens'] * price['completion'] / 1_000_000, 6)
    require(nominal <= MAX_NOMINAL_USD, 'single_nominal_budget_exceeded')
    request = urllib.request.Request('https://openrouter.ai/api/v1/key',
                                     headers={'Authorization': 'Bearer ' + key}, method='GET')
    try:
        with (opener or urllib.request.build_opener(NoRedirect())).open(request, timeout=20) as response:
            raw = response.read(64 * 1024 + 1)
        require(len(raw) <= 64 * 1024, 'single_key_policy_invalid')
        envelope = json.loads(raw)
    except (OSError, ValueError, TypeError) as error:
        raise GovernanceError('single_key_policy_unavailable') from error
    require(isinstance(envelope, dict) and isinstance(envelope.get('data'), dict), 'single_key_policy_invalid')
    data = envelope['data']
    remaining = data.get('limit_remaining')
    require(data.get('limit') == 50 and data.get('limit_reset') == 'monthly'
            and not data.get('disabled'), 'single_key_policy_invalid')
    require(type(remaining) in (int, float) and math.isfinite(remaining) and remaining >= nominal,
            'single_key_budget_insufficient')
    return {'provider': 'openrouter', 'monthly_limit_usd': 50, 'nominal_review_limit_usd': MAX_NOMINAL_USD,
            'nominal_max_usd': nominal, 'remaining_usd': remaining, 'state': 'ready'}


def review(api, source, directory, key, *, opener=None):
    from single_call import build_request, infer, validate_response
    from single_context import compile_context
    binding = read_json(Path(source).parent / 'binding.json')
    validate_runtime(api, binding)
    fresh_inputs(api, binding)
    package = compile_context(Path(source), binding)
    require(package == read_json(Path(source).parent / 'package.json'), 'single_prepared_context_changed')
    build_request(package)  # Admission before reading or sending the dedicated credential.
    budget = key_preflight(package, key, opener=opener)
    destination = Path(directory)
    require(not destination.exists(), 'single_output_exists')
    destination.mkdir(parents=True)
    # Persist admission before inference. No automatic retry if outcome becomes unknown.
    write_json(destination / 'admission.json', {'protocol': PROTOCOL, 'binding_sha256': digest(binding),
               'package_sha256': digest(package), 'budget': budget, 'state': 'request_admitted'})
    result = infer(package, key, opener=opener)
    write_json(destination / 'inference.json', result)
    record = validate_response(result['response'], package, binding)
    proof = execution_record(binding, package, record, result)
    for name, value in (('binding', binding), ('package', package), ('review', record), ('execution', proof)):
        write_json(destination / (name + '.json'), value)
    return {'state': 'review_validated', 'verdict': record['verdict'], 'complete': record['complete'],
            'elapsed_seconds': result['elapsed_seconds'], 'inference_requests': 1}


def publication_policy(api, binding):
    """An installed compatibility release must explicitly authorize this producer."""
    origin = binding['provenance']
    try:
        policy = json.loads(api.file(binding['repository'], POLICY, origin['workflow_sha']))
    except (GovernanceError, ValueError, TypeError, UnicodeError) as error:
        raise GovernanceError('single_publication_disabled', 'Trusted compatibility policy is absent or invalid.') from error
    require(isinstance(policy, dict) and policy.get('schema_version') == 1
            and policy.get('enabled') is True and policy.get('protocol') == PROTOCOL
            and policy.get('workflow_path') == WORKFLOW and policy.get('reviewer_bot_id') == BOT_ID
            and policy.get('governance_reader') == PROTOCOL, 'single_publication_disabled')
    return policy


def publication_record(binding, record, proof, review, comments):
    """Build a receipt only from the GitHub review and comment readback."""
    return {'schema_version': 1, 'protocol': PROTOCOL, 'repository': binding['repository'],
            'pr_number': binding['pr_number'], 'head_sha': binding['head_sha'],
            'run_id': record['review_run_id'], 'run_attempt': record['review_run_attempt'],
            'review_id': review['id'], 'record_sha256': digest(record), 'execution_sha256': digest(proof),
            'body_sha256': text_hash(review['body']),
            'comments': [{**{key: c[key] for key in ('id', 'path', 'line', 'side')},
                          'body_sha256': text_hash(c['body'])} for c in comments]}


def validate_single_publication(publication, binding, package, record, proof, review, comments, *, files=None):
    validate_execution(proof, binding, package, record)
    require(publication.get('protocol') == PROTOCOL and publication.get('execution_sha256') == digest(proof),
            'single_publication_execution_mismatch')
    require(review.get('user', {}).get('id') == BOT_ID and review['user'].get('type') == 'Bot', 'wrong_reviewer')
    require(review.get('commit_id') == record['head_sha'], 'published_commit_mismatch')
    require(review.get('state') == {'approve': 'APPROVED', 'changes_requested': 'CHANGES_REQUESTED',
                                  'incomplete': 'COMMENTED'}[record['verdict']], 'published_state_mismatch')
    require(all(c.get('user', {}).get('id') == BOT_ID and c['user'].get('type') == 'Bot' for c in comments),
            'wrong_reviewer')
    require(not record['findings'] or isinstance(files, list), 'single_publication_diff_required')
    plan = render(record, binding['manifest'], binding['ci'], files or [])
    require(review.get('body') == plan['body'], 'published_body_mismatch')
    require(sorted((c['path'], c['line'], c['side'], c['body']) for c in plan['comments']) ==
            sorted((c.get('path'), c.get('line'), c.get('side'), c.get('body')) for c in comments),
            'published_comments_mismatch')
    validate_publication(publication, record, review, comments)
    return publication


def publish(api, binding, package, record, proof):
    validate_execution(proof, binding, package, record)
    publication_policy(api, binding)
    validate_runtime(api, binding)
    pr, ci = fresh_inputs(api, binding)
    repository, number = binding['repository'], binding['pr_number']
    endpoint = f'/repos/{repository}/pulls/{number}/reviews'
    # Unknown write outcomes are reconciled by identity and content; never retried.
    previous = api.pages(endpoint)
    require(not any(r.get('user', {}).get('id') == BOT_ID and
                    f'Run {record["review_run_id"]}, attempt {record["review_run_attempt"]}' in r.get('body', '')
                    for r in previous), 'single_publication_already_attempted')
    files = api.pages(f'/repos/{repository}/pulls/{number}/files') if record['findings'] else []
    plan = render(record, binding['manifest'], binding['ci'], files)
    payload = {'commit_id': pr['head']['sha'], 'event': EVENTS[record['verdict']], 'body': plan['body'],
               'comments': [{key: c[key] for key in ('path', 'line', 'side', 'body')} for c in plan['comments']]}
    # Recheck head/base and required CI immediately before the only GitHub write.
    fresh_inputs(api, binding)
    try:
        posted = api.request('POST', endpoint, payload)
    except GovernanceError as error:
        if error.code != 'github_write_outcome_unknown':
            raise
        # A timeout may follow a successful write. Reconcile one exact actual
        # review; never issue another POST or manufacture a receipt.
        candidates = [r for r in api.pages(endpoint) if r.get('user', {}).get('id') == BOT_ID
                      and r['user'].get('type') == 'Bot' and r.get('commit_id') == record['head_sha']
                      and r.get('body') == plan['body']
                      and r.get('state') == {'approve': 'APPROVED', 'changes_requested': 'CHANGES_REQUESTED',
                                            'incomplete': 'COMMENTED'}[record['verdict']]]
        require(len(candidates) == 1, 'single_publication_outcome_unknown')
        posted = candidates[0]
    require(isinstance(posted, dict) and type(posted.get('id')) is int, 'single_publication_outcome_unknown')
    actual = api.request('GET', endpoint + '/' + str(posted['id']))
    comments = published_comments(api, repository, number, actual['id'])
    require(actual.get('body') == plan['body'], 'published_body_mismatch')
    expected = sorted((c['path'], c['line'], c['side'], c['body']) for c in plan['comments'])
    require(expected == sorted((c.get('path'), c.get('line'), c.get('side'), c.get('body')) for c in comments),
            'published_comments_mismatch')
    publication = publication_record(binding, record, proof, actual, comments)
    return validate_single_publication(publication, binding, package, record, proof, actual, comments, files=files)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('stage', choices=('prepare', 'review', 'publish'))
    parser.add_argument('--source', default='wmie-input/source')
    parser.add_argument('--directory', default='wmie-single-result')
    parser.add_argument('--dry-run', action='store_true')
    args = parser.parse_args()
    api = GitHub()
    if args.stage == 'prepare':
        result = prepare(api, control.repository_name(os.environ.get('GITHUB_REPOSITORY', '')),
                         read_json(os.environ['GITHUB_EVENT_PATH']))
    elif args.stage == 'review':
        result = review(api, args.source, args.directory, os.environ.get('WMIE_SINGLE_CALL_KEY', ''))
    else:
        root = Path(args.directory)
        binding, package, record, proof = [read_json(root / (name + '.json'))
                                           for name in ('binding', 'package', 'review', 'execution')]
        validate_execution(proof, binding, package, record)
        if args.dry_run:
            result = {'state': 'dry_run_validated', 'verdict': record['verdict'], 'published': False}
        else:
            result = publish(api, binding, package, record, proof)
            write_json(root / 'publication.json', result)
    output('result', result)
    print(json.dumps(result, ensure_ascii=False))


if __name__ == '__main__':
    try:
        main()
    except GovernanceError as error:
        raise SystemExit(error.code) from error
