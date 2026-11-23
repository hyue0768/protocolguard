"""Synthetic planner/executor tests. No model, credential or target execution."""
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import batch_scan as batch


class BatchTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name);self.folder=self.root/'version';self.plan=self.root/'scan/plan.json'
        for name in ['01-spec','02-rules','03-slices','04-consistency','05-assertions','06-dynamic']:
            (self.folder/name).mkdir(parents=True)
        self.row=dict(version_id='v',tag='tag',commit='fixture',spec_bundle_id='spec',folder=str(self.folder))
        batch.write(self.root/'index.json',dict(versions=[self.row]))
        batch.write(self.folder/'audit.json',dict(code_commit='fixture'))
        raw=b'Client MUST check the fixture.\n';(self.root/'spec.md').write_bytes(raw)
        document=dict(path='specs/spec.md',role='core',local_file='spec.md',
                      git_blob=hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest())
        batch.write(self.folder/'01-spec/bundle.json',dict(id='spec',documents=[document]))
        (self.root/'shared/code/fixture/source').mkdir(parents=True)
        batch.write(self.root/'shared/code/fixture/files.json',[])
        self.calls=[]

    def prepare(self,stages):batch.make_plan(self.root,self.plan.parent,all_versions=True,stages=stages)

    def fake_run(self,command,**kwargs):
        stage=command[2];self.calls.append(stage)
        if stage=='extract':
            candidate=hashlib.sha256(b'spec:specs/spec.md').hexdigest()[:16]
            batch.write(self.folder/'02-rules'/candidate/'result.json',dict(rules=[{},{}]))
            for i in [1,2]:batch.write(self.folder/'02-rules'/(candidate+'-'+str(i).zfill(2)+'.json'),dict(target='fixture',rule=dict(req_fields=[],res_fields=[])))
        else:
            rule=command[command.index('--rule')+1]
            paths=dict(locate=('03-slices/'+rule+'.location/result.json',dict(handlers=['f'],context=[])),
                       slice=('03-slices/'+rule+'.slice/slice.json',dict(mock=True)),
                       review=('04-consistency/'+rule+'/synthesis.json',dict(mock=True)),
                       assert_=('05-assertions/'+rule+'/plan.json',dict(mock=True)),
                       dynamic=('06-dynamic/'+rule+'/results.json',dict(status='not_executed_adapter_missing')))
            path,data=paths['assert_' if stage=='assert' else stage];batch.write(self.folder/path,data)
        return subprocess.CompletedProcess(command,0,'{}','')

    def test_plan_has_no_execution_or_credential_access(self):
        with patch.object(batch.subprocess,'run') as run:
            self.prepare(batch.ORDER)
        run.assert_not_called();plan=batch.load(self.plan)
        self.assertEqual(plan['counts']['versions'],1)
        self.assertEqual(plan['versions'][0]['documents'],['specs/spec.md'])
        self.assertFalse(plan['policy']['automatic_retries'])
        with self.assertRaises(ValueError):self.prepare(batch.ORDER)

    def test_gates_precede_any_work(self):
        self.prepare(batch.ORDER)
        with self.assertRaises(ValueError):batch.Scan(self.plan)
        with self.assertRaisesRegex(ValueError,'--execute'):
            batch.Scan(self.plan,True,Path('/never-read'),10)
        self.assertFalse((self.plan.parent/'journal.json').exists())

    def test_new_rules_are_discovered_and_budget_continuation_does_not_retry(self):
        self.prepare(['extract','locate','slice','review','assert','dynamic'])
        with patch.object(batch.audit,'MAP',self.root),patch.object(batch.subprocess,'run',side_effect=self.fake_run):
            scan=batch.Scan(self.plan,True,Path('/never-read'),2,True)
            with self.assertRaisesRegex(batch.StopScan,'Request cap'):scan.run()
            self.assertEqual(self.calls,['extract','locate','slice'])
            self.assertEqual(batch.load(self.plan.parent/'summary.json')['reserved_request_slots'],2)
            continued=batch.Scan(self.plan,True,Path('/never-read'),13,True);continued.run()
        self.assertEqual(self.calls.count('extract'),1)
        for name in ['locate','slice','review','assert','dynamic']:self.assertEqual(self.calls.count(name),2)
        self.assertEqual(continued.journal['reserved_request_slots'],13)
        summary=batch.load(self.plan.parent/'summary.json')
        self.assertEqual(summary['whole_protocol_compliance'],'unknown')
        self.assertEqual(summary['status'],'serial_traversal_finished_not_security_proof')

    def test_paid_failure_stops_and_cannot_be_retried(self):
        self.prepare(['extract'])
        failure=subprocess.CompletedProcess([],1,'','Provider failure')
        with patch.object(batch.audit,'MAP',self.root),patch.object(batch.subprocess,'run',return_value=failure) as run:
            scan=batch.Scan(self.plan,True,Path('/never-read'),2)
            with self.assertRaises(batch.StopScan):scan.run()
            continued=batch.Scan(self.plan,True,Path('/never-read'),2)
            with self.assertRaisesRegex(batch.StopScan,'no retry'):continued.run()
        self.assertEqual(run.call_count,1)

    def test_plan_tampering_is_rejected(self):
        self.prepare(['slice']);data=batch.load(self.plan);data['versions'][0]['commit']='different'
        batch.write(self.plan,data)
        with self.assertRaisesRegex(ValueError,'identity'):batch.Scan(self.plan)

    def test_prepared_transport_review_passes_explicit_resume_flag(self):
        self.prepare(['review']);rule='0000000000000000-01'
        batch.write(self.folder/'02-rules'/(rule+'.json'),dict(target='fixture',rule=dict(req_fields=[],res_fields=[])))
        attempt=self.folder/'04-consistency'/rule;attempt.mkdir()
        batch.write(attempt/'transport-resume.json',dict(attempt_directory='transport-attempt-001',preserved_sha256={}))
        scan=batch.Scan(self.plan,True,Path('/never-read'),8)
        scan.journal['reserved_request_slots']=4
        scan.journal['tasks']['v/'+rule+'/review']=dict(status='transport_resume_prepared')
        scan.save()
        def execute(command,**kwargs):
            self.assertIn('--resume-transport-review',command)
            return self.fake_run(command,**kwargs)
        with patch.object(batch.audit,'MAP',self.root),patch.object(batch.subprocess,'run',side_effect=execute):scan.run()
        self.assertEqual(self.calls,['review'])
        self.assertEqual(scan.journal['reserved_request_slots'],8)

    def test_unnecessary_prune_reserves_no_paid_slot(self):
        self.prepare(['prune']);rule='0000000000000000-01'
        views=[dict(symbol_id='f',view=dict(status='bounded_dependency_view_not_sound_slice',
               selected_nodes=[0],graph=dict(nodes=[dict(id=0,calls=[],terminal=False)])))]
        batch.write(self.folder/'03-slices'/(rule+'.slice')/'flow-views.json',dict(views=views))
        attempt=self.folder/'03-slices'/(rule+'.relevance');artifact=attempt/'result.json'
        scan=batch.Scan(self.plan,True,Path('/never-read'),1)
        def execute(command,**kwargs):
            self.assertNotIn('--key-file',command)
            self.assertNotIn('--allow-paid',command)
            batch.write(artifact,dict(status='not_executed_optional_relevance_full_context_retained'))
            return subprocess.CompletedProcess(command,0,'{}','')
        with patch.object(batch.subprocess,'run',side_effect=execute):
            scan.task(self.row,'prune','v/'+rule+'/prune',artifact,attempt,['--rule',rule])
        self.assertEqual(scan.journal['reserved_request_slots'],0)

    def test_wrapper_child_inherits_environment_without_key_arguments(self):
        self.prepare(['extract'])
        with patch.dict(batch.os.environ,dict(PROTOCOLGUARD_JUDGE_API_KEY='synthetic-fixture-token',
                        PROTOCOLGUARD_JUDGE_BASE_URL='http://127.0.0.1:18768/v1')):
            scan=batch.Scan(self.plan,True,None,1,False,'judge-wrapper')
            def execute(command,**kwargs):
                self.assertEqual(command[command.index('--provider')+1],'judge-wrapper')
                self.assertNotIn('--key-file',command)
                self.assertNotIn('synthetic-fixture-token',' '.join(command))
                self.assertGreaterEqual(kwargs['timeout'],720)
                return self.fake_run(command,**kwargs)
            with patch.object(batch.audit,'MAP',self.root),patch.object(batch.subprocess,'run',side_effect=execute):scan.run()
        self.assertEqual(self.calls,['extract'])

    def test_wrapper_location_reserves_all_partitions_before_starting(self):
        self.prepare(['locate']);rule='0000000000000000-01'
        with patch.dict(batch.os.environ,dict(PROTOCOLGUARD_JUDGE_API_KEY='synthetic-fixture-token',PROTOCOLGUARD_JUDGE_BASE_URL='http://127.0.0.1:18768/v1')):
            scan=batch.Scan(self.plan,True,None,1,False,'judge-wrapper')
            attempt=self.folder/'03-slices'/(rule+'.location');artifact=attempt/'result.json'
            with patch.object(batch.audit,'location_data',return_value={}),patch.object(batch.audit,'location_batches',return_value=[{},{}]),patch.object(batch.subprocess,'run') as execute:
                with self.assertRaisesRegex(batch.StopScan,'Request cap reached'):
                    scan.task(self.row,'locate','v/'+rule+'/locate',artifact,attempt,['--rule',rule])
                execute.assert_not_called()
                self.assertEqual(scan.journal['reserved_request_slots'],0)

    def test_per_commit_selection_is_explicit(self):
        rows=[self.row,dict(self.row,version_id='v2',tag='tag2')]
        batch.write(self.root/'index.json',dict(versions=rows))
        plan=batch.make_plan(self.root,self.plan.parent,per_commit=True,stages=['slice'])
        self.assertEqual(plan['counts']['versions'],1)
        self.assertEqual(plan['selection'],'one_representative_tag_per_commit')

    def test_deduplicate_preserves_progress_budget_and_original_journal(self):
        self.prepare(['slice'])
        plan=batch.load(self.plan);second=dict(plan['versions'][0],version_id='v2',tag='tag2')
        third=dict(second,version_id='v3',tag='tag3',spec_bundle_id='different-spec')
        plan['versions'] += [second,third];batch.write(self.plan,plan)
        tasks={'v/a':dict(status='completed'),'v2/a':dict(status='completed'),'v2/b':dict(status='completed')}
        batch.write(self.plan.parent/'journal.json',dict(plan_sha256=batch.digest(self.plan),tasks=tasks,
                    reserved_request_slots=300,status='paused_request_cap'))
        before=batch.digest(self.plan.parent/'journal.json');output=self.root/'deduplicated'
        result=batch.deduplicate_plan(self.plan,output)
        self.assertEqual(result['counts']['versions'],2)
        self.assertEqual(result['counts']['commits'],1)
        self.assertEqual(result['reserved_request_slots'],300)
        self.assertEqual(batch.load(output/'plan.json')['versions'][0]['version_id'],'v2')
        self.assertEqual(batch.digest(self.plan.parent/'journal.json'),before)
        self.assertEqual(batch.load(output/'journal.json')['tasks'],{k:v for k,v in tasks.items() if k.startswith('v2/')})

    def test_deduplicate_cannot_bypass_blocked_or_running_tasks(self):
        self.prepare(['slice']);plan=batch.load(self.plan)
        plan['versions'].append(dict(plan['versions'][0],version_id='v2',tag='tag2'));batch.write(self.plan,plan)
        journal=dict(plan_sha256=batch.digest(self.plan),reserved_request_slots=4,status='stopped_requires_inspection',
                     tasks={'v/a':dict(status='failed'),'v2/a':dict(status='completed'),'v2/b':dict(status='completed')})
        batch.write(self.plan.parent/'journal.json',journal)
        output=self.root/'deduplicated';batch.deduplicate_plan(self.plan,output)
        self.assertEqual(batch.load(output/'plan.json')['versions'][0]['version_id'],'v')
        journal['status']='running';batch.write(self.plan.parent/'journal.json',journal)
        with self.assertRaisesRegex(ValueError,'Stop the running'):batch.deduplicate_plan(self.plan,self.root/'rejected')


if __name__=='__main__':unittest.main()
