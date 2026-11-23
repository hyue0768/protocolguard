"""Bridge the actual server-protection model review to bounded SDK executions.

Default: prepare an evidence/event mapping only. --execute runs existing saved
fixtures through the local HTTP/mock-ledger harness, with no model or real RPC.
"""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys

from deepseek_harness_user_spec import BASE, PIN, load_prepared, save, validate

RULE = 'SERVER_PROTECTION_AGAINST_CLIENT'
PG = BASE.parents[1]
HARNESS = PG / 'dynamic_verification/x402_guard/harness.cjs'
CASES = [
    ('normal_success', 'corpus/00001.json', 'F1', 'support_control'),
    ('invalid_signature', 'corpus/00003.json', 'F1', 'reject_control'),
    ('rejected_payment', 'corpus/00002.json', 'F1', 'reject_control'),
    ('reverted_settlement', 'corpus/00029.json', 'F1', 'settlement_failure_control'),
    ('missing_transfer_event', 'corpus/00028.json', 'F1', 'settlement_failure_control'),
    ('protected_error_body', 'corpus/00036.json', 'F2', 'conditional_goal_witness'),
    ('chunked_response', 'corpus/00040.json', 'F1', 'support_control'),
]
NODE = r'''
const fs=require('node:fs');
const {runCase}=require(process.argv[1]);
const input=JSON.parse(fs.readFileSync(0,'utf8'));
runCase(input).then(result=>process.stdout.write(JSON.stringify(result)))
 .catch(()=>{process.stderr.write('Harness execution failed');process.exitCode=1;});
'''


def check_identity(root, blobs, file, expected=None):
    path = root / file
    raw = path.read_bytes()
    if hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest() != blobs.get(file):
        raise ValueError('Source differs from pinned Git tree: ' + file)
    digest = hashlib.sha256(raw).hexdigest()
    if expected and digest != expected:
        raise ValueError('Source differs from reviewed input: ' + file)
    return digest


def evaluate(result, role):
    """Check the finite trace under the explicitly recorded fixture mapping.

    This single-request case maps one fixed resource/payer/provider/network to
    one session. No transaction equality on delivery can be checked because the
    wire event carries no tx; this is weaker than the exact user formula.
    """
    trace = result.get('trace', [])
    if result.get('frameworkError') or any(e.get('event') == 'FrameworkError' for e in trace):
        raise ValueError('Harness/framework error; not a protocol finding')
    events = []
    wire = ''
    for e in trace:
        if e.get('event') == 'PaymentSettled':
            if (e.get('amount') != '100' or e.get('network') != 'eip155:84532'
                or str(e.get('payTo', '')).lower() != '0x2222222222222222222222222222222222222222'
                or str(e.get('asset', '')).lower() != '0x1111111111111111111111111111111111111111'
                or not e.get('payer') or not e.get('tx')):
                raise ValueError('Unexpected settlement parameters in fixture')
            events.append(dict(kind='matching_mock_settlement', index=e['index'], tx=e.get('tx')))
        if e.get('event') == 'WireWrite':
            wire += e.get('bytes', '')
            if 'PROTECTED_RESOURCE' in wire and not any(x['kind'] == 'protected_bytes_emitted' for x in events):
                events.append(dict(kind='protected_bytes_emitted', index=e['index']))
    settled = [e for e in events if e['kind'] == 'matching_mock_settlement']
    deliveries = [e for e in events if e['kind'] == 'protected_bytes_emitted']
    violations = [d for d in deliveries if not any(s['index'] < d['index'] for s in settled)]
    actual = 'bounded_goal_violation_witness' if violations else ('bounded_goal_satisfied' if deliveries else 'no_delivery_observed')
    if role == 'support_control':
        control_passed = bool(deliveries and settled and not violations and 'PROTECTED_RESOURCE' in result.get('wire', ''))
    elif role in ['reject_control', 'settlement_failure_control']:
        control_passed = not deliveries and not settled
    else:
        control_passed = bool(violations)
    return dict(observation=actual, expected_control_behavior_observed=control_passed,
                projected_events=events, goal_violation_count=len(violations),
                protected_bytes_received='PROTECTED_RESOURCE' in result.get('wire', ''),
                confirmation_scope='Single bounded fixture with an explicit mock ledger; not deployed-chain or formal verification.',
                exact_tamarin_formula_checked=False)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--review', type=Path, default=BASE / 'codex-review-sol-low-004/review.json')
    p.add_argument('--prepared', type=Path, default=BASE / 'deepseek-user-spec-inputs')
    p.add_argument('--output', type=Path, required=True)
    p.add_argument('--execute', action='store_true', help='explicitly start local HTTP/mock-ledger execution')
    a = p.parse_args()
    out = a.output.resolve()
    if out.exists():
        p.error('Output exists; no overwrite or resume')
    record = json.loads(a.review.read_text())
    review = record['review']
    bundle, _ = load_prepared(a.prepared.resolve(), RULE)
    errors = validate(review, bundle)
    expected_hash = hashlib.sha256((a.prepared / 'inputs' / (RULE + '.json')).read_bytes()).hexdigest()
    if errors or record.get('input_sha256') != expected_hash:
        raise ValueError('Review evidence/schema or prepared-input identity check failed')
    if {f['id'] for f in review['findings']} != {'F1', 'F2', 'F3', 'F4'}:
        raise ValueError('This adapter maps the specific F1..F4 review; other results require a new mapping')
    # A finding id alone is not an identity: pin this mapping to the actual review.
    known_response = BASE / 'codex-review-sol-low-004/response.txt'
    reviewed_response = a.review.parent / 'response.txt'
    if not known_response.exists() or not reviewed_response.exists():
        raise ValueError('Original response required for mapping identity')
    if hashlib.sha256(reviewed_response.read_bytes()).hexdigest() != record['validation']['response_sha256']:
        raise ValueError('Response/review identity mismatch')
    if json.loads(reviewed_response.read_text()) != review or reviewed_response.read_bytes() != known_response.read_bytes():
        raise ValueError('Review is not the response this mapping was authored for')
    target = json.loads((BASE / 'target.json').read_text())
    tree = json.loads((BASE / 'tree.json').read_text())
    if target['commit'] != PIN or tree['sha'] != PIN or tree.get('truncated'):
        raise ValueError('Target identity mismatch')
    root = Path(target['upstream'])
    blobs = {r['path']: r['sha'] for r in tree['tree'] if r['type'] == 'blob'}
    source_hashes = {}
    for part in bundle['code'] + bundle['norms']:
        source_hashes[part['file']] = check_identity(root, blobs, part['file'], part['sha256'])
    # Establish the scheme cancellation and receipt-helper context specifically
    # called out as missing by this model response.
    extras = [
        'typescript/packages/mechanisms/evm/src/exact/server/scheme.ts',
        'typescript/packages/mechanisms/evm/src/shared/settleReceipt.ts',
        'typescript/packages/mechanisms/evm/src/exact/facilitator/eip3009-utils.ts',
    ]
    for file in extras:
        source_hashes[file] = check_identity(root, blobs, file)
    plan = []
    for name, relative, finding, role in CASES:
        path = BASE / 'fuzz' / relative
        value = json.loads(path.read_text())
        plan.append(dict(case_id=name, existing_fixture=str(path), fixture_sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
                         source_finding=finding, role=role, input=dict(transport='http', **value)))
    out.mkdir(parents=True)
    semantic = dict(rule_id=RULE, target=PIN, review_path=str(a.review.resolve()),
        method='coordinator source/evidence review plus explicit event mapping',
        source_and_quote_checks='passed', semantic_correctness_proven=False,
        semantic_validation_status='scoped source review completed; remaining assumptions explicit',
        finding_disposition={
            'F1': 'Ordinary response-buffering interpretation supported; bounded success and settlement-failure controls selected.',
            'F2': 'Conditional target-gap interpretation supported by error-response branch; existing fixture supplies protected content. It changes handler assumptions and does not establish an exploit against an unspecified honest application.',
            'F3': 'Trust assumptions remain: RPC/ledger correctness and custom hooks are not verified. Honest exact EVM scheme in this fixture has no custom cancellation-settlement policy.',
            'F4': 'Event mapping defined for one HTTP request/resource and mock settlement. Full sid/C/S/res/tx correspondence and formal proof remain unavailable.',
        },
        model_response_correction='The free-text scope_limits contains a mistyped commit. Use the verified input/target SHA, not the model transcription.',
        event_mapping={
            'setup': 'One isolated case, honest SDK server and honest mock facilitator; malicious/invalid request only where fixture specifies.',
            'Ev_ServerDelivered': 'First WireWrite completing the protected byte marker for this fixed endpoint; handler invocation and side effects excluded.',
            'Ev_PaymentSettled': 'Harness PaymentSettled after its independent mock contract predicates accept a transfer.',
            'tx_limitation': 'Delivery event has no transaction parameter. Tested ordering is weaker than the exact supplied Tamarin formula.',
        },
        assumptions=['No application-specific custom hooks.', 'Mock token/nonce/confirmation semantics stand in for deployed EVM/RPC.',
                     'The protected marker denotes the fixed resource only in this fixture.', 'Error body containing protected content is an explicit handler-contract assumption.'],
        formal_proof_status='not performed; no Tamarin model/proof artifacts supplied',
        source_sha256=source_hashes)
    save(out / 'semantic-validation.json', semantic)
    save(out / 'execution-plan.json', dict(target=PIN, rule_id=RULE, cases=plan,
        model_calls=0, external_rpc=False, real_transactions=False,
        status='executing' if a.execute else 'prepared_not_executed'))
    if not a.execute:
        print(json.dumps(dict(output=str(out), status='prepared_not_executed', cases=len(plan))))
        return
    (out / 'traces').mkdir()
    results = []
    for case in plan:
        completed = subprocess.run(['node', '-e', NODE, str(HARNESS)],
            input=json.dumps(case['input']), capture_output=True, text=True, timeout=30, check=False)
        if completed.returncode:
            raise ValueError('Harness case failed: ' + case['case_id'] + '; no retry')
        try:
            trace = json.loads(completed.stdout)
        except ValueError:
            raise ValueError('Harness returned non-JSON output; no retry') from None
        if trace.get('target') != PIN:
            raise ValueError('Executed target mismatch')
        # Verify every actually loaded source module, including imports omitted
        # from the earlier lexical slice, against the pinned tree.
        for file, metadata in trace['loadedModules'].items():
            check_identity(root, blobs, file, metadata['sha256'])
        save(out / 'traces' / (case['case_id'] + '.json'), trace)
        results.append(dict(case_id=case['case_id'], finding=case['source_finding'],
                            evaluation=evaluate(trace, case['role'])))
        save(out / 'partial-results.json', results)
    save(out / 'dynamic-validation.json', dict(rule_id=RULE, target=PIN,
        status='bounded_dynamic_validation_completed', cases=results,
        all_expected_controls_observed=all(r['evaluation']['expected_control_behavior_observed'] for r in results),
        semantic_correctness_proven=False, exact_tamarin_formula_proven=False,
        confirmed_real_world_vulnerability=False, model_calls=0, real_chain_transactions=0,
        limits=semantic['assumptions'] + ['Bounded executions neither prove universal security nor validate arbitrary deployments.']))
    print(json.dumps(dict(output=str(out), status='bounded_dynamic_validation_completed', cases=len(results))))


if __name__ == '__main__':
    try:
        main()
    except (ValueError, KeyError, OSError, subprocess.TimeoutExpired) as error:
        print('Stopped: ' + (str(error) if isinstance(error, ValueError) else type(error).__name__), file=sys.stderr)
        sys.exit(1)
