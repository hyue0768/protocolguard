"""Source-equivalence gated historical EOA adapter; offline inventory by default.

Reuses the eight existing fixtures only. A historical snapshot must match all
41 modules in the recorded baseline; otherwise it is explicitly unsupported.
"""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

BASE=Path(__file__).resolve().parent
HARNESS=BASE.parent/'dynamic_verification/x402_guard/harness.cjs'
BASELINE=BASE/'payment-validity/runs/run-001/dynamic/traces'
PLAN=BASE/'payment-validity/dynamic-plan/plan.json'


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def profile():
    modules={};provenance=[]
    paths=sorted(BASELINE.glob('*.json'))
    if len(paths)!=8:
        raise ValueError('Expected eight existing baseline traces')
    for path in paths:
        trace=json.loads(path.read_text())
        if trace['target']!='1a084343e165d6f61b60b34f6146d6e4a4a7f3ca':
            raise ValueError('Baseline target changed')
        for name,meta in trace['loadedModules'].items():
            if Path(name).is_absolute() or '..' in Path(name).parts:
                raise ValueError('Invalid module path')
            if name in modules and modules[name]!=meta:
                raise ValueError('Inconsistent baseline module identities')
            modules[name]=meta
        provenance.append(dict(file=str(path),sha256=digest(path)))
    return dict(id='recorded-eoa-module-equivalence-v1',modules=modules,baseline=provenance,
                scope='eight existing EOA/exact fixtures, mocked contract/RPC; no delegate or deployed chain coverage')


def inspect(source, selected=None):
    selected=selected or profile()
    mismatches=[]
    for name,meta in selected['modules'].items():
        path=source/name
        if not path.is_file():mismatches.append(dict(file=name,reason='missing'))
        elif digest(path)!=meta['sha256']:mismatches.append(dict(file=name,reason='source_differs'))
    return dict(adapter=selected['id'],status='eligible_not_executed' if not mismatches else 'adapter_missing',
                expected_modules=len(selected['modules']),mismatches=mismatches,
                qualification='source equivalence only; runtime compatibility and behavior still require manual execution')


def execute(source,commit,output,allow_execute=False):
    if not allow_execute:raise ValueError('Payment-state execution requires --execute')
    selected=profile();capability=inspect(source,selected)
    if capability['status']!='eligible_not_executed':
        raise ValueError('Historical adapter missing: source modules differ; latest harness will not be substituted')
    if output.exists():raise ValueError('Output exists; no overwrite')
    planpath=PLAN
    if not planpath.is_file():
        # Existing installations name the one saved plan manifest explicitly.
        matches=sorted((BASE/'payment-validity/dynamic-plan').glob('*.json'))
        if len(matches)!=1:raise ValueError('Expected one saved payment fixture plan')
        planpath=matches[0]
    plan=json.loads(planpath.read_text())
    if len(plan['cases'])!=8:raise ValueError('Expected existing eight-case corpus')
    # Pin and validate all inputs before running any case.
    for case in plan['cases']:
        if digest(Path(case['fixture']))!=case['fixture_sha256']:
            raise ValueError('Existing fixture changed')
    sys.path.insert(0,str(BASE/'security'))
    from validate_payment_validity import evaluate
    output.mkdir(parents=True)
    manifest=output/'target.json'
    manifest.write_text(json.dumps(dict(upstream=str(source.resolve()),commit=commit,expectedModules=selected['modules'])))
    env=dict(PATH=os.environ.get('PATH','/usr/bin:/bin'),LC_ALL='C',PG_TARGET_MANIFEST=str(manifest.resolve()))
    # No shell and no inherited API keys/RPC credentials.
    program="const fs=require('node:fs');require(process.argv[1]).runCase(JSON.parse(fs.readFileSync(0,'utf8'))).then(r=>process.stdout.write(JSON.stringify(r))).catch(()=>{process.stderr.write('Harness failure');process.exitCode=1;});"
    results=[]
    for case in plan['cases']:
        run=subprocess.run(['node','-e',program,str(HARNESS)],input=json.dumps(case['input']),
                           capture_output=True,text=True,timeout=45,env=env)
        if run.returncode:raise ValueError('Historical EOA execution failed; no finding or automatic retry')
        trace=json.loads(run.stdout)
        if trace['target']!=commit:raise ValueError('Execution target identity mismatch')
        for name,meta in trace['loadedModules'].items():
            if selected['modules'].get(name)!=meta:raise ValueError('Runtime module identity mismatch')
        (output/(case['case_id']+'.trace.json')).write_text(json.dumps(trace,indent=2)+'\n')
        results.append(dict(case_id=case['case_id'],evaluation=evaluate(trace,case['goals'],case['expected_transfers'])))
    result=dict(status='bounded_historical_eoa_observations',commit=commit,adapter=capability,results=results,
                profile=selected,plan_sha256=digest(planpath),
                assumptions=['Baseline APIs/dependencies and fixed harness configuration are reused only for source-identical modules.',
                             'Other files and mechanisms in this release remain outside coverage.',
                             'Concurrent requests do not prove all nonce races or retry schedules.'],
                real_chain_transactions=0,whole_protocol_compliance='unknown',formal_proof=False)
    (output/'results.json').write_text(json.dumps(result,indent=2)+'\n')
    return result
