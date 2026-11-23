"""Prepare and run disjoint version processes with CPU affinity and one budget.

Preparation is offline. Running requires an idle source plan, explicit API env,
paid authorization, and target-execution authorization. No retry of failed work.
"""
import argparse
import concurrent.futures
import fcntl
import json
import os
from pathlib import Path
import shlex
import subprocess
import sys
import socket
import batch_scan as batch


def reserve(path,key,slots,limit):
    with path.with_suffix('.lock').open('a') as lock:
        fcntl.flock(lock,fcntl.LOCK_EX)
        state=batch.load(path)
        if state['limit']!=limit:raise ValueError('Worker cap differs from shared budget')
        if state['reserved_request_slots']+slots>limit:
            raise batch.StopScan('Shared request cap reached; no request sent')
        state['reserved_request_slots']+=slots
        state['reservations'].append(dict(task=key,slots=slots))
        batch.write(path,state)


def prepare(source_path,output,limit):
    source_path=source_path.resolve();output=output.resolve()
    if output.exists():raise ValueError('Parallel output exists; reuse its manifest without overwriting')
    with (source_path.parent/'run.lock').open('a') as lock:
        try:fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        except BlockingIOError:raise ValueError('Source scan still running; finalize parallel plans only after it pauses') from None
        plan=batch.load(source_path);journal_path=source_path.parent/'journal.json';journal=batch.load(journal_path)
        if journal['status']=='running':raise ValueError('Source journal still running; inspect before migrating')
        if journal['plan_sha256']!=batch.digest(source_path):raise ValueError('Source plan changed')
        if limit<journal['reserved_request_slots']:raise ValueError('Shared cap is below prior reservations')
        remaining=[];completed=[]
        for row in plan['versions']:
            prefix=row['version_id']+'/'
            tasks={k:v for k,v in journal['tasks'].items() if k.startswith(prefix)}
            blocked=[k for k,v in tasks.items() if v['status'] in ['started','failed']]
            if blocked:raise ValueError('Inspect failed/interrupted version before migration: '+row['version_id'])
            end=tasks.get(prefix+'payment')
            if end and end['status'] in ['completed','reused_completed_artifact','not_executed_adapter_missing']:
                completed.append(row['version_id']);continue
            remaining.append((row,tasks))
        pairs=[(r['commit'],r['spec_bundle_id']) for r,t in remaining]
        if len(pairs)!=len(set(pairs)):raise ValueError('Deduplicate code/spec pairs before parallel preparation')
        output.mkdir(parents=True)
        jobs=[]
        for number,(row,tasks) in enumerate(remaining,1):
            home=output/'workers'/f'{number:03}'
            worker=dict(plan,versions=[row],selection='one_disjoint_code_spec_pair',
                        counts=dict(versions=1,commits=1,code_spec_pairs=1,document_occurrences=len(row['documents'])))
            batch.write(home/'plan.json',worker)
            batch.write(home/'journal.json',dict(plan_sha256=batch.digest(home/'plan.json'),reserved_request_slots=0,
                tasks=tasks,status='awaiting_manual_continuation',historical_reservations_carried_in_shared_budget=True))
            jobs.append(dict(version_id=row['version_id'],plan=str(home/'plan.json'),status='pending'))
        batch.write(output/'budget.json',dict(schema=1,limit=limit,reserved_request_slots=journal['reserved_request_slots'],
            historical_reservations=journal['reserved_request_slots'],reservations=[]))
        manifest=dict(schema=1,source_plan=str(source_path),source_plan_sha256=batch.digest(source_path),
            source_journal_sha256=batch.digest(journal_path),completed_versions=completed,jobs=jobs,
            target_host='ws2',max_concurrency=50,shared_budget=str(output/'budget.json'),
            policy='no automatic retries; failed versions remain failed; other disjoint versions may continue')
        batch.write(output/'manifest.json',manifest)
        batch.write(output/'source-journal.before.json',journal)
        return dict(remaining=len(jobs),completed=len(completed),shared_limit=limit,
                    historical_reservations=journal['reserved_request_slots'],models_called=0)


def run(manifest_path,env_file,workers,cpus,allow_paid,execute):
    if not allow_paid or not execute:raise ValueError('Parallel launch requires --allow-paid --execute')
    if socket.gethostname()!='hkust-tint-team-ws2':raise ValueError('This deployment must run on the verified ws2 host')
    if not env_file.is_file() or env_file.stat().st_mode & 0o077:raise ValueError('Use an existing private 0600 env file on ws2')
    manifest=batch.load(manifest_path);home=manifest_path.parent
    allowed=os.sched_getaffinity(0)
    if not cpus:cpus=sorted(allowed)[:workers]
    if workers<1 or workers>50 or len(set(cpus))<workers or not set(cpus)<=allowed:
        raise ValueError('Choose 1..50 workers with distinct allowed CPU IDs')
    source=Path(manifest['source_plan'])
    with (home/'parallel.lock').open('a') as lock,(source.parent/'run.lock').open('a') as source_lock:
        for handle in [lock,source_lock]:
            try:fcntl.flock(handle,fcntl.LOCK_EX|fcntl.LOCK_NB)
            except BlockingIOError:raise ValueError('An existing runner still holds a plan lock') from None
        if batch.digest(source)!=manifest['source_plan_sha256'] or batch.digest(source.parent/'journal.json')!=manifest['source_journal_sha256']:
            raise ValueError('Source scan changed after preparation; do not launch stale plans')
        budget=batch.load(Path(manifest['shared_budget']))
        pending=[]
        for job in manifest['jobs']:
            if job['status']=='pending':pending.append(job)
            elif job['status'] in ['running','scheduled','failed','paused_budget']:raise ValueError('Inspect prior failed/interrupted or budget-paused parallel jobs; no automatic retry')
        def worker(cpu,queue):
            results=[]
            for job in queue:
                folder=Path(job['plan']).parent
                number=1
                while (folder/'sessions'/f'{number:03}').exists():number+=1
                session=folder/'sessions'/f'{number:03}';session.mkdir(parents=True)
                command=[sys.executable,str(batch.BASE/'batch_scan.py'),'run','--plan',job['plan'],
                         '--provider','judge-wrapper','--review-mode','single','--allow-paid','--execute',
                         '--max-paid-calls',str(budget['limit']),'--shared-budget',manifest['shared_budget']]
                script=session/'run-private-env.sh'
                # The script contains only a credential-file path, never its value.
                runtime=batch.BASE.parent/'runtime/bin'
                script.write_text('set -e\nexport PATH='+shlex.quote(str(runtime))+':"$PATH"\nset -a\nsource '+shlex.quote(str(env_file.resolve()))+'\nset +a\nexec '+
                                  shlex.join(['taskset','-c',str(cpu),*command])+'\n')
                script.chmod(0o700)
                with (session/'session.log').open('a') as log:
                    process=subprocess.Popen(['bash','--noprofile','--norc',str(script)],stdout=log,stderr=subprocess.STDOUT,start_new_session=True)
                    batch.write(session/'session.json',dict(pid=process.pid,session_id=process.pid,cpu=cpu,version_id=job['version_id']))
                    batch.write(folder/'current-session.json',dict(directory=str(session),pid=process.pid,cpu=cpu))
                    code=process.wait()
                state=batch.load(folder/'journal.json')
                status='completed' if code==0 else 'paused_budget' if state['status']=='paused_request_cap' else 'failed'
                result=dict(version_id=job['version_id'],cpu=cpu,returncode=code,status=status)
                batch.write(session/'session-result.json',result);results.append(result)
                if status=='paused_budget':break
            return results
        queues=[pending[i::workers] for i in range(workers)]
        # Publish running state before dispatch; a crash requires inspection.
        for job in pending:job['status']='scheduled'
        batch.write(manifest_path,manifest)
        results=[]
        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
            futures=[pool.submit(worker,cpus[i],queue) for i,queue in enumerate(queues)]
            for future in concurrent.futures.as_completed(futures):results.extend(future.result())
        byid={r['version_id']:r for r in results}
        for job in manifest['jobs']:
            if job['version_id'] in byid:job['status']=byid[job['version_id']]['status']
            elif job['status'] in ['running','scheduled']:job['status']='pending'
        batch.write(manifest_path,manifest);batch.write(home/'parallel-results.json',results)
        return dict(completed=sum(r['status']=='completed' for r in results),failed=sum(r['status']=='failed' for r in results))


def main():
    parser=argparse.ArgumentParser(description=__doc__);sub=parser.add_subparsers(dest='command',required=True)
    p=sub.add_parser('prepare');p.add_argument('--source-plan',type=Path,required=True);p.add_argument('--output',type=Path,required=True);p.add_argument('--max-paid-calls',type=int,required=True)
    p=sub.add_parser('run');p.add_argument('--manifest',type=Path,required=True);p.add_argument('--env-file',type=Path,required=True)
    p.add_argument('--workers',type=int,default=4);p.add_argument('--cpus',type=int,nargs='+');p.add_argument('--allow-paid',action='store_true');p.add_argument('--execute',action='store_true')
    args=parser.parse_args()
    result=prepare(args.source_plan,args.output,args.max_paid_calls) if args.command=='prepare' else run(args.manifest,args.env_file,args.workers,args.cpus,args.allow_paid,args.execute)
    print(json.dumps(result))


if __name__=='__main__':
    try:main()
    except (ValueError,OSError) as error:print('Stopped: '+str(error),file=sys.stderr);sys.exit(1)
