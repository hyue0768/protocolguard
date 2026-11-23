"""Prepare or manually execute bounded checks of exactly three user goals.

Uses existing saved fixtures, not model-generated inputs. --execute requires
new reviews grounded in the corrected three-goal spec. No paid model calls.
"""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys

from deepseek_harness_user_spec import BASE, PIN, PAYMENT_VALIDITY_IDS, load_prepared, save, validate

ACTIVE = BASE.parent / 'payment-validity'
PG = BASE.parents[1]
HARNESS = PG / 'dynamic_verification/x402_guard/harness.cjs'
PAYER = '0xd22b40f909a9980b41ebdbb0a318d8638ae8ae07'
ASSET = '0x1111111111111111111111111111111111111111'
PAYTO = '0x2222222222222222222222222222222222222222'
CASES = [
    ('normal_payment', '00001.json', PAYMENT_VALIDITY_IDS, 1),
    ('invalid_signature', '00003.json', ['PAYER_AUTHORIZATION'], 0),
    ('wrong_amount', '00005.json', ['PAYMENT_BINDING'], 0),
    ('wrong_recipient', '00006.json', ['PAYMENT_BINDING'], 0),
    ('mismatched_accepted_amount', '00009.json', ['PAYMENT_BINDING'], 0),
    ('sequential_replay', '00013.json', ['REPLAY_RESISTANCE'], 1),
    ('concurrent_replay', '00017.json', ['REPLAY_RESISTANCE'], 1),
    ('pending_settlement_retry', '00030.json', ['REPLAY_RESISTANCE'], 1),
]
NODE = r'''
const fs=require('node:fs');
const {runCase}=require(process.argv[1]);
runCase(JSON.parse(fs.readFileSync(0,'utf8')))
 .then(r=>process.stdout.write(JSON.stringify(r)))
 .catch(()=>{process.stderr.write('Harness failed');process.exitCode=1;});
'''


def evaluate(result, goals, expected_transfers):
    trace = result.get('trace', [])
    if result.get('frameworkError') or any(e.get('event') == 'FrameworkError' for e in trace):
        raise ValueError('Framework error is not a payment-validity result')
    transfers = result.get('ledgerTransfers')
    if not isinstance(transfers, list):
        raise ValueError('Missing independent mock-ledger transfer list')
    events = [e for e in trace if e.get('event') == 'PaymentSettled']
    if len(events) != len(transfers):
        raise ValueError('Mock ledger list/event count mismatch')
    required = ['payer', 'asset', 'payTo', 'network', 'nonce', 'amount', 'tx']
    for t in transfers:
        if not all(t.get(k) is not None for k in required):
            raise ValueError('Incomplete ledger transfer')
    keys = [(t['payer'].lower(), t['asset'].lower(), t['network'], t['nonce']) for t in transfers]
    assertions = {
        'PAYER_AUTHORIZATION': all(t['payer'].lower() == PAYER for t in transfers),
        'PAYMENT_BINDING': all(t['amount'] == '100' and t['asset'].lower() == ASSET
                               and t['payTo'].lower() == PAYTO and t['network'] == 'eip155:84532' for t in transfers),
        'REPLAY_RESISTANCE': len(keys) == len(set(keys)),
    }
    # Rejection alone does not demonstrate a positive valid-payment path.
    return dict(assertions={g: assertions[g] for g in goals},
                expected_transfer_count=expected_transfers, observed_transfer_count=len(transfers),
                positive_or_rejection_control_observed=len(transfers) == expected_transfers,
                facilitator_success_reports=sum(e.get('event') == 'FacilitatorResponse'
                    and e.get('operation') == 'settle' and e.get('result', {}).get('success') is True for e in trace),
                status='bounded_observation_only',
                assumptions=['Mock contract independently checks signature recovery, interval and nonce before transfer.',
                             'The fixed fixture account is the intended payer; delegate policy is not tested.',
                             'Fixed advertised monetary/network terms define binding for these fixtures.',
                             'Mock nonce atomicity/receipt semantics are assumed, not deployed-contract verification.'])


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--prepared', type=Path, default=ACTIVE / 'prepared')
    p.add_argument('--review-root', type=Path)
    p.add_argument('--output', type=Path, required=True)
    p.add_argument('--execute', action='store_true')
    a = p.parse_args()
    out = a.output.resolve()
    if out.exists():
        p.error('Output exists; no overwrite or resume')
    prepared = a.prepared.resolve()
    manifest = json.loads((prepared / 'manifest.json').read_text())
    if manifest.get('analysis_scope') != 'payment_validity_only' or [x['rule_id'] for x in manifest['rules']] != PAYMENT_VALIDITY_IDS:
        raise ValueError('Require the corrected three-goal prepared inputs')
    bundles = {g: load_prepared(prepared, g)[0] for g in PAYMENT_VALIDITY_IDS}
    review_hashes = {}
    if a.execute:
        if not a.review_root:
            p.error('--execute requires --review-root with a new review for each of the three goals')
        for goal, bundle in bundles.items():
            folder = a.review_root / goal
            raw = (folder / 'review.json').read_bytes()
            record = json.loads(raw)
            response = (folder / 'response.txt').read_bytes()
            expected = hashlib.sha256((prepared / 'inputs' / (goal + '.json')).read_bytes()).hexdigest()
            if (record.get('input_sha256') != expected or validate(record['review'], bundle)
                or not record.get('validation', {}).get('accepted_as_model_judgment')
                or hashlib.sha256(response).hexdigest() != record['validation']['response_sha256']
                or json.loads(response) != record['review']):
                raise ValueError('Review must match corrected inputs and source evidence: ' + goal)
            review_hashes[goal] = hashlib.sha256(raw).hexdigest()
    target = json.loads((BASE / 'target.json').read_text())
    tree = json.loads((BASE / 'tree.json').read_text())
    if target['commit'] != PIN or tree['sha'] != PIN or tree.get('truncated'):
        raise ValueError('Target identity mismatch')
    root = Path(target['upstream'])
    blobs = {x['path']: x['sha'] for x in tree['tree'] if x['type'] == 'blob'}

    def verify(file, digest):
        raw = (root / file).read_bytes()
        if hashlib.sha256(raw).hexdigest() != digest or hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest() != blobs.get(file):
            raise ValueError('Source identity mismatch: ' + file)

    for bundle in bundles.values():
        for part in bundle['code'] + bundle['norms']:
            verify(part['file'], part['sha256'])
    cases = []
    for id, filename, goals, expected in CASES:
        file = BASE / 'fuzz/corpus' / filename
        value = json.loads(file.read_text())
        cases.append(dict(case_id=id, goals=goals, expected_transfers=expected,
                          fixture=str(file), fixture_sha256=hashlib.sha256(file.read_bytes()).hexdigest(),
                          input=dict(transport='http', **value)))
    out.mkdir(parents=True)
    save(out / 'plan.json', dict(analysis_scope='payment_validity_only', spec_sha256=manifest['source_spec_sha256'],
         target=PIN, goals=PAYMENT_VALIDITY_IDS, cases=cases,
         status='executing' if a.execute else 'prepared_not_executed', review_sha256=review_hashes,
         excluded_from_assertions=['response delivery timing', 'eventual service delivery', 'standalone request idempotency', 'signed resource URL'],
         model_calls=0, external_rpc=False, real_transactions=False))
    if not a.execute:
        print(json.dumps(dict(output=str(out), status='prepared_not_executed', goals=3, cases=len(cases))))
        return
    (out / 'traces').mkdir()
    results = []
    for case in cases:
        run = subprocess.run(['node', '-e', NODE, str(HARNESS)], input=json.dumps(case['input']),
                             capture_output=True, text=True, timeout=30, check=False)
        if run.returncode:
            raise ValueError('Harness failed; no retry: ' + case['case_id'])
        result = json.loads(run.stdout)
        if result.get('target') != PIN:
            raise ValueError('Execution target mismatch')
        for file, metadata in result['loadedModules'].items():
            verify(file, metadata['sha256'])
        save(out / 'traces' / (case['case_id'] + '.json'), result)
        results.append(dict(case_id=case['case_id'], goals=case['goals'],
                            evaluation=evaluate(result, case['goals'], case['expected_transfers'])))
        save(out / 'partial-results.json', results)
    save(out / 'results.json', dict(analysis_scope='payment_validity_only', target=PIN,
         status='bounded_dynamic_validation_completed', cases=results,
         all_assertions_hold_in_observed_cases=all(all(r['evaluation']['assertions'].values()) for r in results),
         all_control_behaviors_observed=all(r['evaluation']['positive_or_rejection_control_observed'] for r in results),
         universal_semantic_correctness_proven=False, delegate_authorization_tested=False,
         deployed_chain_verified=False, model_calls=0, real_chain_transactions=0))
    print(json.dumps(dict(output=str(out), status='bounded_dynamic_validation_completed', cases=len(cases))))


if __name__ == '__main__':
    try:
        main()
    except (ValueError, KeyError, OSError, subprocess.TimeoutExpired) as error:
        print('Stopped: ' + (str(error) if isinstance(error, ValueError) else type(error).__name__), file=sys.stderr)
        sys.exit(1)
