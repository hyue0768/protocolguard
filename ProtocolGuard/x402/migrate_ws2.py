"""Wait for a safe ws1 boundary, copy a stable audit, and dispatch on ws2.

User-authorized deployment only. No credential values enter this process.
"""
import argparse
import fcntl
import json
from pathlib import Path
import shlex
import shutil
import subprocess
import sys
import batch_scan as b
import parallel_scan as p

HOST='yly@10.7.14.24'
REMOTE_PROJECT=Path('/home/yly/research-code/x402_experiment/ProtocolGuard')
ENV_FILE=REMOTE_PROJECT/'.env.judge-wrapper-ws2'
PYTHON='/home/yly/codex-judge-protocolguard-ws2/.venv/bin/python'


def migrate(source,output,limit,workers):
    source=source.resolve();output=output.resolve();project=b.BASE.parent
    control=source.parent/'ws2-migration';control.mkdir(exist_ok=True)
    state=control/'state.json'
    b.write(state,dict(status='waiting_for_source_boundary',max_paid_calls=limit,workers=workers))
    # Block on the existing lock rather than polling or interrupting inference.
    with (source.parent/'run.lock').open('a') as lock:
        fcntl.flock(lock,fcntl.LOCK_EX)
        journal_path=source.parent/'journal.json';journal=b.load(journal_path)
        if journal['status']=='running':raise ValueError('Source lock released with uncertain running state; inspect manually')
        changed=False
        for key,task in journal['tasks'].items():
            if task['status']!='failed':continue
            log=b.load(Path(task['log']))
            expected='Stopped: WS2 handoff boundary: new version deferred before any model or target execution\n'
            if log.get('stderr')!=expected:raise ValueError('Source has a real failure requiring inspection: '+key)
            if not changed:shutil.copy2(journal_path,control/'journal.before-boundary-normalization.json')
            journal['tasks'][key]=dict(status='handoff_deferred_no_execution',previous_failure=task)
            changed=True
        if changed:
            journal['status']='paused_for_ws2_handoff';journal.pop('stop_reason',None);b.write(journal_path,journal)
    prepared=p.prepare(source,output,limit)
    with (source.parent/'run.lock').open('a') as lock:
        fcntl.flock(lock,fcntl.LOCK_EX)
        manifest=b.load(output/'manifest.json')
        if b.digest(source.parent/'journal.json')!=manifest['source_journal_sha256']:
            raise ValueError('Source changed before transfer; nothing dispatched')
        b.write(state,dict(status='copying_stable_snapshot',prepared=prepared))
        command=['rsync','-aH','--exclude=.env*','--exclude=.git/','--exclude=__pycache__/',
                 '--exclude=*.pyc','--exclude=api-key','--exclude=/x402/version-audits/ws2-handoff-boundary.json',
                 str(project)+'/',HOST+':'+str(REMOTE_PROJECT)+'/']
        subprocess.run(command,check=True)
        remote_manifest=REMOTE_PROJECT/output.relative_to(project)/'manifest.json'
        remote_script=REMOTE_PROJECT/'x402/parallel_scan.py'
        # The API service was configured separately by the curator. No key is
        # copied: each session sources its private ws2-only env at runtime.
        invocation=[PYTHON,str(remote_script),'run','--manifest',str(remote_manifest),
                    '--env-file',str(ENV_FILE),'--workers',str(workers),'--allow-paid','--execute']
        log=remote_manifest.parent/'controller.log'
        launch='nohup '+shlex.join(invocation)+' > '+shlex.quote(str(log))+' 2>&1 < /dev/null & echo $!'
        result=subprocess.run(['ssh','-o','BatchMode=yes','-o','ConnectTimeout=8',HOST,launch],check=True,text=True,capture_output=True)
        pid=result.stdout.strip()
        if not pid.isdigit():raise ValueError('Remote launch did not return a process ID; inspect before retrying')
        b.write(state,dict(status='remote_controller_dispatched',remote_pid=int(pid),remote_host=HOST,
                           remote_manifest=str(remote_manifest),remote_log=str(log),prepared=prepared,
                           inference_verified=False))
    return b.load(state)


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source-plan',type=Path,required=True);parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--max-paid-calls',type=int,required=True);parser.add_argument('--workers',type=int,default=16)
    args=parser.parse_args()
    try:print(json.dumps(migrate(args.source_plan,args.output,args.max_paid_calls,args.workers)))
    except (ValueError,OSError,subprocess.CalledProcessError) as error:
        control=args.source_plan.resolve().parent/'ws2-migration';control.mkdir(exist_ok=True)
        b.write(control/'failure.json',dict(status='migration_stopped_requires_inspection',error_type=type(error).__name__,message=str(error)))
        print('Stopped: '+str(error),file=sys.stderr);sys.exit(1)
