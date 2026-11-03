"""One tool-free inference request and deterministic, fail-closed review validation."""

import hashlib
import json
import math
import re
import time
import urllib.error
import urllib.request

from core import GovernanceError, NoRedirect, digest, require
from review import validate_manifest, validate_record

MODEL = 'deepseek/deepseek-v4.1-flash'  # default: the only model that can pass publication
ALTERNATE_MODELS = ('anthropic/claude-sonnet-5.5',)  # comparison runs only. validate_result rejects any model but MODEL.
# Request settings per model. DeepSeek runs without reasoning: on a large prompt, reasoning used all 32,768 output
# tokens and returned no answer. The price ceilings sit above each model's price and stop a dearer route.
SETTINGS = {
    'deepseek/deepseek-v4.1-flash': {'effort': 'none', 'max_tokens': 32768, 'max_price': {'prompt': 0.5, 'completion': 2}},
    'anthropic/claude-sonnet-5.5': {'effort': 'low', 'max_tokens': 8192, 'max_price': {'prompt': 2, 'completion': 10}},
}
PROTOCOL = 'wmie-single-call-v1'
MAX_INPUT_BYTES = 2 * 1024 * 1024
MAX_NOMINAL_USD = 4.5


def obj(properties):
    return {'type':'object','properties':properties,'required':list(properties),'additionalProperties':False}


STRING = {'type':'string'}
STRINGS = {'type':'array','items':STRING}
SCHEMA = obj({
    'summary': STRING,
    'coverage': obj({'status':{'type':'string','enum':['complete','incomplete']},
                     'reviewed_files':STRINGS, 'missing_context':STRINGS}),
    'findings': {'type':'array','items':obj({
        'path':STRING, 'side':{'type':'string','enum':['base','head']}, 'line':{'type':'integer'},
        'changed_line_id':STRING, 'severity':{'type':'string','enum':['critical','high','medium']},
        'title':STRING, 'failure_scenario':STRING, 'preconditions':STRING,
        'evidence_ids':STRINGS, 'remediation':STRING,
        'status':{'type':'string','enum':['grounded','needs_investigation']}})}})


def parse_json(text):
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, 'single_call_duplicate_key')
            result[key] = value
        return result
    def constant(value):
        raise GovernanceError('single_call_nonfinite_json')
    try:
        return json.loads(text, object_pairs_hook=pairs, parse_constant=constant)
    except (ValueError, TypeError, RecursionError) as error:
        raise GovernanceError('single_call_invalid_json') from error


def build_request(package, model=MODEL):
    require(model in (MODEL, *ALTERNATE_MODELS) and model in SETTINGS, 'single_call_model_unsupported')
    settings = SETTINGS[model]
    require(package.get('complete') is True, 'single_call_context_incomplete')
    messages = package.get('messages')
    require(isinstance(messages,list) and len(messages)==2
            and [m.get('role') for m in messages]==['system','user']
            and all(isinstance(m.get('content'),str) for m in messages), 'single_call_messages_invalid')
    payload = {'model':model, 'messages':messages, 'reasoning':{'effort':settings['effort']},
               'response_format':{'type':'json_schema','json_schema':{'name':'wmie_review_v1','strict':True,'schema':SCHEMA}},
               'max_tokens':settings['max_tokens'], 'stream':False,
               'provider':{'require_parameters':True,'allow_fallbacks':False,
                           'max_price':dict(settings['max_price'])}, 'plugins':[]}
    require(len(json.dumps(payload,ensure_ascii=False).encode())<=MAX_INPUT_BYTES, 'single_call_input_too_large')
    return payload


def infer(package, key, opener=None, model=MODEL):
    payload = build_request(package, model)
    require(isinstance(key,str) and bool(key.strip()), 'single_call_key_missing')
    data = json.dumps(payload,ensure_ascii=False).encode()
    request = urllib.request.Request('https://openrouter.ai/api/v1/chat/completions',data=data,
                                    headers={'Authorization':'Bearer '+key,'Content-Type':'application/json'},method='POST')
    started = time.monotonic()
    try:
        with (opener or urllib.request.build_opener(NoRedirect())).open(request,timeout=600) as result:
            raw = result.read(1024*1024+1)
    except urllib.error.HTTPError as error:
        code = {402: 'single_call_payment_required', 429: 'single_call_rate_limited'}.get(error.code, 'single_call_provider_http_error')
        raise GovernanceError(code, f'HTTP {error.code}. One request attempted. No automatic retry.') from None
    except (OSError, urllib.error.URLError) as error:
        raise GovernanceError('single_call_transport_failed', 'One request attempted; outcome and cost require reconciliation.') from error
    require(len(raw)<=1024*1024, 'single_call_response_too_large')
    envelope = parse_json(raw)
    require(isinstance(envelope,dict) and not envelope.get('error'), 'single_call_provider_error')
    require(envelope.get('model')==model, 'single_call_model_mismatch')
    choices = envelope.get('choices')
    require(isinstance(choices,list) and len(choices)==1 and isinstance(choices[0],dict), 'single_call_choices_invalid')
    choice = choices[0]
    message = choice.get('message')
    require(choice.get('finish_reason')=='stop' and isinstance(message,dict)
            and not message.get('refusal') and not message.get('tool_calls') and not message.get('function_call'),
            'single_call_completion_incomplete')
    response = parse_json(message.get('content'))
    usage = envelope.get('usage')
    require(isinstance(usage,dict) and all(type(usage.get(k)) is int and usage[k]>=0
            for k in ('prompt_tokens','completion_tokens')), 'single_call_usage_missing')
    require(isinstance(envelope.get('id'),str) and envelope['id'], 'single_call_request_id_missing')
    cost = usage.get('cost')
    require(type(cost) in (int,float) and math.isfinite(cost) and cost>=0, 'single_call_cost_missing')
    return {'protocol':PROTOCOL,'response':response,'usage':usage,'request_id':envelope['id'],'model':model,
            'elapsed_seconds':round(time.monotonic()-started,3),'inference_requests':1,
            'request_sha256':hashlib.sha256(data).hexdigest(),'response_sha256':hashlib.sha256(raw).hexdigest(),
            'budget_alert':cost>2}


def validate_response(response, package, binding):
    from jsonschema import Draft202012Validator
    require(not list(Draft202012Validator(SCHEMA).iter_errors(response)), 'single_call_schema_invalid')
    manifest = binding['manifest']
    paths = validate_manifest(manifest,binding['repository'],binding['pr_number'],binding['base_sha'],binding['head_sha'])
    require(binding.get('manifest_sha256')==digest(manifest), 'single_call_binding_mismatch')
    # The package must name the manifest it was built for. A missing key is a failure, never a default.
    require(package.get('manifest_sha256')==digest(manifest), 'single_call_package_binding')
    for entry in package['evidence'].values():
        require(isinstance(entry,dict) and isinstance(entry.get('content'),str)
                and entry.get('sha256')==hashlib.sha256(entry['content'].encode()).hexdigest(),
                'single_call_evidence_digest')
    coverage = response['coverage']
    reviewed = coverage['reviewed_files']
    require(len(reviewed)==len(set(reviewed)) and set(reviewed)<=paths, 'single_call_coverage_invalid')
    require(response['summary'].strip(), 'single_call_summary_empty')
    # Repository text must never create actionable links or mentions via model output.
    texts = [response['summary']]+[v for f in response['findings'] for v in f.values() if isinstance(v,str)]
    require(not any(re.search(r'(?:sk-(?:or-v1-)?[A-Za-z0-9_-]{20,}|gh[pousr]_[A-Za-z0-9]{20,}|-----BEGIN .*PRIVATE KEY)',t)
                    for t in texts), 'single_call_sensitive_output')
    changed = {tuple(line) for line in package['changed_lines']}
    findings, seen, unresolved = [], set(), False
    for finding in response['findings']:
        path, side, line = finding['path'],finding['side'],finding['line']
        require(type(line) is int and (path,side,line) in changed, 'single_call_finding_location_invalid')
        require(finding['changed_line_id']==f'{side}:{path}:{line}', 'single_call_changed_line_mismatch')
        ids = finding['evidence_ids']
        require(ids and len(ids)==len(set(ids)), 'single_call_evidence_missing')
        evidence = []
        for identifier in ids:
            entry = package['evidence'].get(identifier)
            require(isinstance(entry,dict), 'single_call_evidence_unknown')
            evidence.append(entry)
        require(any(e['path']==path and e['side']==side and e['start_line']<=line<=e['end_line'] for e in evidence),
                'single_call_anchor_unsubstantiated')
        for field in ('title','failure_scenario','preconditions','remediation'):
            require(finding[field].strip() and len(finding[field])<=8000, 'single_call_finding_text_invalid')
        fingerprint = digest({k:finding[k] for k in ('path','side','line','title')})
        if fingerprint in seen:
            continue
        seen.add(fingerprint)
        unresolved |= finding['status']=='needs_investigation'
        findings.append({'path':path,'side':side,'line':line,'severity':finding['severity'],
                         'title':finding['title'],'evidence':finding['failure_scenario']+' Preconditions: '+finding['preconditions']
                         +' Evidence: '+', '.join(ids), 'impact':finding['failure_scenario'],'remediation':finding['remediation']})
    # The compiler computed an arithmetic counterexample on a changed line. The model must answer it with a finding
    # on that line. A silent approval of a known counterexample is never a complete review.
    answered = {(f['path'], f['side'], f['line']) for f in findings}
    observed = {(o['path'], o['side'], o['line']) for o in package.get('arithmetic_observations', [])}
    complete = (package.get('complete') is True and coverage['status']=='complete' and set(reviewed)==paths
                and not coverage['missing_context'] and not unresolved and observed <= answered)
    verdict = 'incomplete' if not complete else 'changes_requested' if findings else 'approve'
    record = {k:manifest[k] for k in ('repository','pr_number','base_sha','head_sha')}
    origin = manifest.get('provenance',{})
    record.update(schema_version=1,manifest_sha256=digest(manifest),complete=complete,verdict=verdict,
                  reviewed_files=reviewed,findings=findings,summary=response['summary'])
    if origin:
        record.update(review_run_id=origin['run_id'],review_run_attempt=origin['run_attempt'])
    return validate_record(record,manifest)
