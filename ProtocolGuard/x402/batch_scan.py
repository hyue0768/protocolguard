"""Manually started serial per-version/per-rule scan. Planning never calls models.

Completed artifacts are referenced, failed attempts are never retried. A paid
failure stops the batch. Request-slot reservations persist across continuation;
they are a conservative request cap, not a dollar billing limit.
"""
import argparse
import fcntl
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys
import shutil
import os

import version_audit as audit
import payment_adapter
from relevance_view import advisory_plan

BASE=Path(__file__).resolve().parent
PAID={'extract':1,'locate':1,'prune':1,'review':4,'assert':1}
ORDER=['extract','locate','slice','prune','review','assert','dynamic','payment']


def load(path):return json.loads(path.read_text())


def write(path,value):
    path.parent.mkdir(parents=True,exist_ok=True)
    temporary=path.with_suffix(path.suffix+'.tmp')
    temporary.write_text(json.dumps(value,ensure_ascii=False,indent=2)+'\n')
    temporary.replace(path)


def digest(path):return hashlib.sha256(path.read_bytes()).hexdigest()


def make_plan(root,output,versions=(),all_versions=False,per_commit=False,stages=None):
    if output.exists():raise ValueError('Plan output exists; reuse its plan.json or choose a new directory')
    index=load(root/'index.json');rows=index['versions']
    if sum([bool(versions),all_versions,per_commit])!=1:
        raise ValueError('Select exact --version values, --all-versions or --per-commit')
    if versions:
        chosen=[]
        for name in versions:
            matches=[r for r in rows if name in [r['tag'],r['version_id']]]
            if len(matches)!=1:raise ValueError('Unknown or ambiguous version: '+name)
            if matches[0] not in chosen:chosen.append(matches[0])
    elif per_commit:
        seen=set();chosen=[]
        for row in rows:
            if row['commit'] not in seen:chosen.append(row);seen.add(row['commit'])
    else:chosen=rows
    stages=stages or ORDER
    if any(s not in ORDER for s in stages) or len(set(stages))!=len(stages):raise ValueError('Invalid/duplicate stage selection')
    stages=[s for s in ORDER if s in stages]
    documents=0;plan_rows=[]
    for row in chosen:
        folder=Path(row['folder']);bundle=load(folder/'01-spec/bundle.json')
        docs=sorted({d['path'] for d in bundle['documents'] if d['role']!='supporting_index_or_template'})
        documents+=len(docs)
        plan_rows.append(dict(version_id=row['version_id'],tag=row['tag'],commit=row['commit'],
                              spec_bundle_id=row['spec_bundle_id'],folder=str(folder.resolve()),documents=docs,
                              rule_discovery='all saved atomic rule files, including those created during extraction'))
    data=dict(schema=1,root=str(root.resolve()),index_sha256=digest(root/'index.json'),
              selection='all_tag_references' if all_versions else 'one_representative_tag_per_commit' if per_commit else 'explicit_versions',
              stages=stages,versions=plan_rows,
              counts=dict(versions=len(chosen),commits=len({r['commit'] for r in chosen}),document_occurrences=documents),
              cost_model=dict(extract_requests_per_document=1,atomic_rule_cap_per_document=64,
                              paid_request_slots_per_rule=sum(PAID.get(s,0) for s in stages if s!='extract'),
                              exact_total='unknown until semantic extraction and dependency eligibility are known'),
              policy=dict(serial=True,automatic_retries=False,overwrite=False,
                          completed_artifacts='reference without claiming independent new execution',
                          paid_failure='stop entire batch; never change prompt or resubmit to bypass refusal',
                          missing_adapter='not executed, never pass',
                          full_protocol_proof=False),
              excluded_automatic_stages=['native-test requires explicit language/project/cache/store selection',
                                         'native LLVM pipeline requires an explicit compilation bridge',
                                         'input generation is never enabled by this scanner'])
    write(output/'plan.json',data);return data


class StopScan(ValueError):pass


def deduplicate_plan(plan_path, output):
    """Offline migration: pin one existing folder per code/spec pair.

    Keep the most progressed representative; never merge independently
    generated rules or bypass a failed/started task by choosing another tag.
    All prior request reservations carry forward.
    """
    plan_path=plan_path.resolve();output=output.resolve()
    if output.exists():raise ValueError('Migration output exists; select a new directory')
    plan=load(plan_path);journal_path=plan_path.parent/'journal.json'
    journal=load(journal_path)
    if journal['plan_sha256']!=digest(plan_path):raise ValueError('Source plan identity changed')
    if journal['status']=='running':raise ValueError('Stop the running scan before migrating')
    groups={}
    for row in plan['versions']:groups.setdefault((row['commit'],row['spec_bundle_id']),[]).append(row)
    chosen=[];aliases=[]
    def entries(row):
        return [(k,v) for k,v in journal['tasks'].items() if k.startswith(row['version_id']+'/')]
    for pair,rows in groups.items():
        blocked=[r for r in rows if any(v['status'] in ['failed','started','transport_resume_prepared'] for k,v in entries(r))]
        if len(blocked)>1:raise ValueError('Multiple blocked representatives need inspection before migration')
        selected=blocked[0] if blocked else max(rows,key=lambda r:sum(v['status'] in ['completed','reused_completed_artifact'] for k,v in entries(r)))
        chosen.append(selected)
        aliases.append(dict(commit=pair[0],spec_bundle_id=pair[1],representative=selected['version_id'],
                            tag_references=[dict(version_id=r['version_id'],tag=r['tag']) for r in rows],
                            reuse='selected existing folder only; other rule sets are preserved, never merged'))
    result=dict(plan,selection='one_representative_per_code_spec_pair',versions=chosen,
                counts=dict(versions=len(chosen),commits=len({r['commit'] for r in chosen}),
                            code_spec_pairs=len(groups),tag_references=len(plan['versions']),
                            document_occurrences=sum(len(r['documents']) for r in chosen)),
                migration=dict(source_plan=str(plan_path),source_plan_sha256=digest(plan_path),
                               source_journal_sha256=digest(journal_path),source_reservations=journal['reserved_request_slots']))
    write(output/'plan.json',result)
    selected_ids={r['version_id'] for r in chosen}
    migrated=dict(journal,plan_sha256=digest(output/'plan.json'),
                  tasks={k:v for k,v in journal['tasks'].items() if k.split('/')[0] in selected_ids},
                  status='awaiting_manual_continuation')
    migrated.pop('stop_reason',None)
    write(output/'journal.json',migrated);write(output/'tag-aliases.json',aliases)
    shutil.copy2(plan_path,output/'source-plan.before.json')
    shutil.copy2(journal_path,output/'source-journal.before.json')
    return dict(output=str(output/'plan.json'),counts=result['counts'],
                retained_tasks=len(migrated['tasks']),reserved_request_slots=migrated['reserved_request_slots'],
                models_called=0,target_executions=0)


class Scan:
    def __init__(self,plan_path,allow_paid=False,key_file=None,max_paid_calls=0,execute=False,provider='responses',review_mode='triple',shared_budget=None):
        self.path=plan_path.resolve();self.plan=load(self.path);self.home=self.path.parent
        self.root=Path(self.plan['root']);self.allow_paid=allow_paid;self.key_file=key_file
        self.limit=max_paid_calls;self.execute=execute
        self.provider=provider
        self.review_mode=review_mode
        self.shared_budget=shared_budget
        if review_mode not in ['single','triple']:raise ValueError('Invalid review mode')
        if provider not in ['responses','judge-wrapper']:raise ValueError('Unknown model provider')
        if provider=='judge-wrapper':
            from judge_wrapper import configuration
            configuration()
        self.report_versions=[]
        if self.plan.get('schema')!=1 or self.plan['stages']!=[s for s in ORDER if s in self.plan['stages']]:raise ValueError('Invalid scan plan')
        if digest(self.root/'index.json')!=self.plan['index_sha256']:raise ValueError('Version index changed; no automatic replanning')
        indexed={r['version_id']:r for r in load(self.root/'index.json')['versions']}
        for row in self.plan['versions']:
            original=indexed.get(row['version_id'])
            if not original or any(row[k]!=original[k] for k in ['version_id','tag','commit','spec_bundle_id','folder']):
                raise ValueError('Plan version identity differs from pinned index')
        if max_paid_calls<0:raise ValueError('Negative request cap is invalid')
        has_key=bool(os.environ.get('PROTOCOLGUARD_JUDGE_API_KEY')) if provider=='judge-wrapper' else bool(key_file)
        if any(s in PAID for s in self.plan['stages']) and (not allow_paid or not has_key or max_paid_calls<1):
            raise ValueError('Paid stages require --allow-paid, provider credentials and a positive --max-paid-calls')
        if any(s in ['dynamic','payment'] for s in self.plan['stages']) and not execute:
            raise ValueError('Selected target stages require --execute before any paid work starts')
        self.journal_path=self.home/'journal.json'
        self.journal=load(self.journal_path) if self.journal_path.exists() else dict(
            plan_sha256=digest(self.path),reserved_request_slots=0,tasks={},status='not_started')
        if self.journal['plan_sha256']!=digest(self.path):raise ValueError('Scan plan changed after journal creation')
        if self.journal['reserved_request_slots']>self.limit and any(s in PAID for s in self.plan['stages']):
            raise ValueError('Paid cap is below prior reservations; reservations never reset on continuation')

    def save(self):write(self.journal_path,self.journal)

    def record(self,key,status,**extra):
        self.journal['tasks'][key]=dict(status=status,**extra);self.save()

    def task(self,row,stage,key,artifact,attempt,extra=()):
        previous=self.journal['tasks'].get(key)
        # Interrupted/failed requests are never retried, even if no output file
        # was created or some partial results happen to be present.
        if previous and previous['status'] in ['started','failed']:
            raise StopScan('Prior failed/interrupted task needs inspection; no retry: '+key)
        if artifact.is_file():
            value=load(artifact)
            if previous and previous.get('artifact_sha256') and previous['artifact_sha256']!=digest(artifact):
                raise StopScan('Completed artifact changed: '+key)
            if previous:return
            self.record(key,'reused_completed_artifact',artifact=str(artifact),artifact_sha256=digest(artifact),artifact_status=value.get('status'))
            return
        if previous and previous['status'] in ['completed','reused_completed_artifact']:
            raise StopScan('Completed artifact disappeared: '+key)
        resuming=bool(previous and previous['status']=='transport_resume_prepared' and stage=='review')
        location_resume=bool(previous and previous['status']=='location_resume_prepared' and stage=='locate')
        assertion_resume=bool(previous and previous['status']=='assertion_resume_prepared' and stage=='assert')
        if resuming:
            from review_resume import verify_marker
            verify_marker(attempt)
            extra=[*extra,'--resume-transport-review']
        elif location_resume:extra=[*extra,'--resume-location']
        elif assertion_resume:extra=[*extra,'--resume-assertions']
        elif attempt.exists():raise StopScan('Incomplete attempt exists; no overwrite or retry: '+key)
        reservation=PAID.get(stage,0)
        if stage=='locate' and self.provider=='judge-wrapper':
            data=audit.location_data(self.root,row,key.split('/')[-2])
            batches=audit.location_batches(data,self.provider);reservation=len(batches)
            if location_resume:
                cached=audit.location_checkpoints(attempt,data,batches,data['symbol_index'],data['rule'])
                reservation-=len(cached)
        if self.provider=='judge-wrapper' and stage in ['review','assert']:
            from chunked_review import request_budget
            folder=Path(row['folder']);rule_id=key.split('/')[-2]
            if stage=='review' and not resuming:reservation=request_budget(folder,rule_id,stage,self.review_mode)
            if stage=='assert':
                review=folder/'04-consistency'/rule_id/'synthesis.json'
                if review.is_file() and load(review).get('partitioned_review'):reservation=request_budget(folder,rule_id,stage)
                if assertion_resume:reservation-=len(list(attempt.glob('part-[0-9][0-9][0-9].json')))
        if stage=='prune':
            views=load(Path(row['folder'])/'03-slices'/(key.split('/')[-2]+'.slice')/'flow-views.json')['views']
            if not advisory_plan(views)['request_model']:reservation=0
        if self.journal['reserved_request_slots']+reservation>self.limit:
            self.journal['status']='paused_request_cap';self.save()
            raise StopScan('Request cap reached before '+key+'; increase the cap explicitly to continue unstarted tasks')
        if self.shared_budget and reservation:
            from parallel_scan import reserve
            try:reserve(self.shared_budget,key,reservation,self.limit)
            except ValueError as error:
                if not str(error).startswith('Shared request cap reached'):raise
                self.journal['status']='paused_request_cap';self.save()
                raise StopScan(str(error)) from None
        command=[sys.executable,str(BASE/'version_audit.py'),stage,'--root',str(self.root),'--version',row['version_id'],*extra]
        if reservation:
            command+=['--allow-paid','--max-calls',str(reservation)]
            if self.provider=='responses':command+=['--key-file',str(self.key_file)]
        if stage in PAID:command+=['--provider',self.provider]
        if stage=='review':command+=['--review-mode',self.review_mode]
        if stage in ['dynamic','payment']:command+=['--execute']
        public_command=command.copy()
        if '--key-file' in public_command:public_command[public_command.index('--key-file')+1]='<credential-file>'
        self.journal['reserved_request_slots']+=reservation
        self.record(key,'started',command=public_command,request_slots_reserved=reservation)
        print(json.dumps(dict(task=key,status='started',reserved_request_slots=self.journal['reserved_request_slots'])),flush=True)
        result=subprocess.run(command,text=True,capture_output=True,
                              timeout=max(1500,reservation*600+120) if self.provider=='judge-wrapper' else 1500)
        log=self.home/'logs'/(hashlib.sha256(key.encode()).hexdigest()+'.json')
        if log.exists():
            number=2
            while log.with_name(log.stem+f'.attempt-{number:03}.json').exists():number+=1
            log=log.with_name(log.stem+f'.attempt-{number:03}.json')
        write(log,dict(task=key,returncode=result.returncode,stdout=result.stdout,stderr=result.stderr))
        if result.returncode or not artifact.is_file():
            # Surface bounded provider metadata instead of hiding every cause
            # behind the same generic Stage failed message. Never print bodies.
            failure={}
            usages=list(attempt.rglob('*.usage.json')) if attempt.exists() else []
            if usages:
                value=load(max(usages,key=lambda p:p.stat().st_mtime_ns))
                statuses={'requesting','http_error','transport_or_response_failure','invalid_provider_json',
                          'incomplete_refused_or_invalid_response_no_retry','incomplete_response_no_retry',
                          'provider_refusal_no_retry','invalid_final_response_no_retry','response_received_unverified'}
                failure['provider_result']=value.get('status') if value.get('status') in statuses else 'unknown'
                for field in ['http_status','elapsed_seconds']:
                    if type(value.get(field)) in [int,float]:failure[field]=value[field]
                if value.get('incomplete_reason') in ['max_output_tokens','content_filter','unknown']:
                    failure['incomplete_reason']=value['incomplete_reason']
                for field in ['input_tokens','output_tokens']:
                    count=value.get('usage',{}).get(field)
                    if type(count) is int:failure[field]=count
            self.record(key,'failed',log=str(log),request_slots_reserved=reservation,failure=failure)
            detail='; '+json.dumps(failure,separators=(',',':')) if failure else ''
            raise StopScan('Stage failed; no retry or fallback: '+key+detail+'; log='+str(log))
        value=load(artifact)
        self.record(key,'completed',artifact=str(artifact),artifact_sha256=digest(artifact),request_slots_reserved=reservation,artifact_status=value.get('status'))

    def run_version(self,row):
        self.report_versions.append(row['version_id'])
        folder=Path(row['folder']);stages=self.plan['stages'];prefix=row['version_id']
        current=load(folder/'audit.json')
        if current['code_commit']!=row['commit']:raise StopScan('Version source identity changed')
        bundle=load(folder/'01-spec/bundle.json')
        documents=sorted({d['path'] for d in bundle['documents'] if d['role']!='supporting_index_or_template'})
        if bundle['id']!=row['spec_bundle_id'] or documents!=row['documents']:raise StopScan('Version specification identity changed')
        audit.norms(folder)
        source=self.root/'shared/code'/row['commit']
        for item in load(source/'files.json'):
            raw=(source/'source'/item['file']).read_bytes()
            if (hashlib.sha256(raw).hexdigest()!=item['sha256'] or
                hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()!=item['git_blob']):
                raise StopScan('Source identity changed before artifact reuse')
        if not documents:self.record(prefix+'/spec','not_executed_no_normative_documents')
        if 'extract' in stages:
            for document in documents:
                candidate=hashlib.sha256((row['spec_bundle_id']+':'+document).encode()).hexdigest()[:16]
                attempt=folder/'02-rules'/candidate
                self.task(row,'extract',prefix+'/extract/'+candidate,attempt/'result.json',attempt,['--document',document])
                result=load(attempt/'result.json')
                for index in range(1,len(result['rules'])+1):
                    if not (folder/'02-rules'/(candidate+'-'+str(index).zfill(2)+'.json')).is_file():
                        raise StopScan('Extraction result has missing rule files; no automatic replay')
        rules=sorted((folder/'02-rules').glob('*.json'))
        if not rules:self.record(prefix+'/rules','no_atomic_rules_available',security_conclusion='unknown')
        for path in rules:
            rule=path.stem
            if not re.fullmatch(r'[a-f0-9]{16}-[0-9]{2}',rule):raise StopScan('Unexpected atomic rule filename')
            data=load(path);key=prefix+'/'+rule
            if data['target']!=row['commit']:raise StopScan('Atomic rule targets a different source commit')
            locate=folder/'03-slices'/(rule+'.location');sliced=folder/'03-slices'/(rule+'.slice')
            for stage in stages:
                if stage in ['extract','payment']:continue
                extra=['--rule',rule]
                if stage=='locate':artifact=locate/'result.json';attempt=locate
                elif stage=='slice':
                    if not (locate/'result.json').is_file():raise StopScan('Run locate before slice')
                    if not load(locate/'result.json').get('handlers'):
                        self.record(key+'/downstream','not_executed_no_handler',security_conclusion='unknown');break
                    fields=data['rule'].get('req_fields',[])+data['rule'].get('res_fields',[])
                    # Use model-supplied paths verbatim, never invent a receiver.
                    for field in sorted({f for f in fields if isinstance(f,str) and re.fullmatch(r'[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*',f)}):
                        extra+=['--criterion-field',field]
                    artifact=sliced/'slice.json';attempt=sliced
                elif stage=='prune':
                    flow=sliced/'flow-views.json'
                    if not flow.is_file() or not any(v['view']['status']=='bounded_dependency_view_not_sound_slice' for v in load(flow)['views']):
                        self.record(key+'/prune','not_executed_no_bounded_dependency_view',security_conclusion='unknown');continue
                    attempt=folder/'03-slices'/(rule+'.relevance');artifact=attempt/'result.json'
                elif stage=='review':attempt=folder/'04-consistency'/rule;artifact=attempt/'synthesis.json'
                elif stage=='assert':attempt=folder/'05-assertions'/rule;artifact=attempt/'plan.json'
                elif stage=='dynamic':attempt=folder/'06-dynamic'/rule;artifact=attempt/'results.json'
                self.task(row,stage,key+'/'+stage,artifact,attempt,extra)
        if 'payment' in stages:
            capability=payment_adapter.inspect(self.root/'shared/code'/row['commit']/'source')
            if capability['status']!='eligible_not_executed':
                self.record(prefix+'/payment','not_executed_adapter_missing',capability=capability)
            else:
                attempt=folder/'06-dynamic/payment-state'
                self.task(row,'payment',prefix+'/payment',attempt/'results.json',attempt)

    def run(self):
        self.journal['status']='running';self.save()
        try:
            for row in self.plan['versions']:self.run_version(row)
            self.journal['status']='serial_traversal_finished_not_security_proof';self.journal.pop('stop_reason',None);self.save()
        except (ValueError,OSError,KeyError,subprocess.TimeoutExpired,KeyboardInterrupt) as error:
            if self.journal['status']!='paused_request_cap':self.journal['status']='stopped_requires_inspection'
            self.journal['stop_reason']=str(error) or type(error).__name__;self.save()
            raise
        finally:
            # Evidence reports are offline: refresh traversed versions even on
            # budget pause/failure. Reporting must never retry model requests.
            reportable=[row['version_id'] for row in self.plan['versions'] if row['version_id'] in self.report_versions and (Path(row['folder'])/'analysis.md').exists()]
            if reportable:
                try:
                    from report_audits import run as refresh_reports
                    refresh_reports(self.root,reportable)
                except (ValueError,OSError,KeyError) as error:
                    self.journal['report_error']=type(error).__name__+': '+str(error);self.save()
            counts={};artifact_statuses={}
            for task in self.journal['tasks'].values():
                counts[task['status']]=counts.get(task['status'],0)+1
                if task.get('artifact_status'):artifact_statuses[task['artifact_status']]=artifact_statuses.get(task['artifact_status'],0)+1
            write(self.home/'summary.json',dict(status=self.journal['status'],task_status_counts=counts,
                artifact_status_counts=artifact_statuses,
                report_error=self.journal.get('report_error'),
                reserved_request_slots=self.journal['reserved_request_slots'],max_paid_calls=self.limit,
                note='Reservations are not actual billed calls. Traversal and artifact reuse do not prove security or exhaustive coverage.',
                whole_protocol_compliance='unknown',automatic_retries=0))


def main():
    parser=argparse.ArgumentParser(description=__doc__);sub=parser.add_subparsers(dest='command',required=True)
    p=sub.add_parser('plan');p.add_argument('--root',type=Path,default=audit.ROOT);p.add_argument('--output',type=Path,required=True)
    choice=p.add_mutually_exclusive_group(required=True);choice.add_argument('--version',action='append',default=[]);choice.add_argument('--all-versions',action='store_true');choice.add_argument('--per-commit',action='store_true')
    p.add_argument('--stages',nargs='+',choices=ORDER,default=ORDER)
    p=sub.add_parser('deduplicate',help='Offline migration to one existing representative per code/spec pair')
    p.add_argument('--plan',type=Path,required=True);p.add_argument('--output',type=Path,required=True)
    p=sub.add_parser('recover-transport-review',help='Prepare an explicit failed review for manual continuation; no API calls')
    p.add_argument('--plan',type=Path,required=True);p.add_argument('--task',required=True)
    p=sub.add_parser('run');p.add_argument('--plan',type=Path,required=True);p.add_argument('--allow-paid',action='store_true');p.add_argument('--key-file',type=Path);p.add_argument('--max-paid-calls',type=int,default=0);p.add_argument('--execute',action='store_true')
    p.add_argument('--provider',choices=['responses','judge-wrapper'],default='responses')
    p.add_argument('--review-mode',choices=['single','triple'],default='triple')
    p.add_argument('--shared-budget',type=Path,help='Prepared shared request cap; historical reservations included once')
    args=parser.parse_args()
    if args.command=='plan':
        result=make_plan(args.root.resolve(),args.output.resolve(),args.version,args.all_versions,args.per_commit,args.stages)
        print(json.dumps(dict(output=str(args.output/'plan.json'),counts=result['counts'],models_called=0,target_executions=0)));return
    with (args.plan.resolve().parent/'run.lock').open('a') as lock:
        try:fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        except BlockingIOError:raise StopScan('Another scan already holds this plan lock') from None
        if args.command=='deduplicate':
            print(json.dumps(deduplicate_plan(args.plan,args.output)));return
        if args.command=='recover-transport-review':
            from review_resume import prepare
            print(json.dumps(prepare(args.plan,args.task)));return
        scan=Scan(args.plan,args.allow_paid,args.key_file,args.max_paid_calls,args.execute,args.provider,args.review_mode,args.shared_budget);scan.run()
    print(json.dumps(dict(output=str(scan.home/'summary.json'),status=scan.journal['status'])))


if __name__=='__main__':
    try:main()
    except (ValueError,OSError,KeyError,subprocess.TimeoutExpired,KeyboardInterrupt) as error:
        print('Stopped: '+(str(error) or type(error).__name__),file=sys.stderr);sys.exit(1)
