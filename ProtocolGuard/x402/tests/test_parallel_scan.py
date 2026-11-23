"""Synthetic parallel plan and atomic-budget tests; no workers or API calls."""
import concurrent.futures
import fcntl
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
import types
import json
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import parallel_scan as p
import batch_scan as b


class ParallelTests(unittest.TestCase):
    def test_atomic_budget_includes_history_exactly_once(self):
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/'budget.json';b.write(path,dict(limit=10,reserved_request_slots=2,reservations=[]))
            def attempt(i):
                try:p.reserve(path,str(i),1,10);return True
                except b.StopScan:return False
            with concurrent.futures.ThreadPoolExecutor(max_workers=16) as pool:results=list(pool.map(attempt,range(40)))
            self.assertEqual(sum(results),8)
            self.assertEqual(b.load(path)['reserved_request_slots'],10)
            self.assertEqual(len(b.load(path)['reservations']),8)
            with self.assertRaises(ValueError):p.reserve(path,'different-cap',1,11)

    def fixture(self,root):
        source=root/'source/plan.json';rows=[]
        for i in range(2):rows.append(dict(version_id=f'v{i}',tag=f't{i}',commit=f'c{i}',spec_bundle_id='s',documents=['spec'],folder=str(root/f'v{i}')))
        b.write(source,dict(schema=1,versions=rows,stages=b.ORDER,root=str(root),index_sha256='fixture'))
        b.write(source.with_name('journal.json'),dict(plan_sha256=b.digest(source),status='paused_request_cap',reserved_request_slots=7,
            tasks={'v0/payment':dict(status='not_executed_adapter_missing'),'v1/a/locate':dict(status='completed')}))
        return source

    def test_prepare_disjoint_remaining_plans_preserves_old_journal(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);source=self.fixture(root);original=b.digest(source.with_name('journal.json'))
            result=p.prepare(source,root/'parallel',10)
            self.assertEqual(result['remaining'],1);self.assertEqual(result['completed'],1)
            self.assertEqual(b.load(root/'parallel/budget.json')['reserved_request_slots'],7)
            self.assertEqual(b.load(root/'parallel/workers/001/journal.json')['reserved_request_slots'],0)
            self.assertEqual(b.digest(source.with_name('journal.json')),original)

    def test_active_source_lock_blocks_migration(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);source=self.fixture(root)
            with source.with_name('run.lock').open('a') as lock:
                fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
                with self.assertRaisesRegex(ValueError,'still running'):p.prepare(source,root/'parallel',10)
            self.assertFalse((root/'parallel').exists())

    def test_failed_version_cannot_be_hidden_by_parallel_migration(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);source=self.fixture(root);j=b.load(source.with_name('journal.json'))
            j['tasks']['v1/a/review']=dict(status='failed');b.write(source.with_name('journal.json'),j)
            with self.assertRaisesRegex(ValueError,'Inspect failed'):p.prepare(source,root/'parallel',10)

    def test_disjoint_sessions_use_distinct_cpus_without_exposing_env(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);source=self.fixture(root);plan=b.load(source)
            plan['versions'].append(dict(plan['versions'][1],version_id='v2',tag='t2',commit='c2'))
            b.write(source,plan);j=b.load(source.with_name('journal.json'));j['plan_sha256']=b.digest(source);b.write(source.with_name('journal.json'),j)
            out=root/'parallel';p.prepare(source,out,10)
            env=root/'.env-private';env.write_text('# synthetic fixture only\n');env.chmod(0o600)
            observed=[]
            def spawn(command,**kwargs):
                self.assertTrue(kwargs['start_new_session'])
                script=Path(command[-1]);observed.append(script.read_text())
                return types.SimpleNamespace(pid=1000+len(observed),wait=lambda:0)
            with patch.object(p.socket,'gethostname',return_value='hkust-tint-team-ws2'),patch.object(p.os,'sched_getaffinity',return_value={0,1}),patch.object(p.subprocess,'Popen',side_effect=spawn):
                result=p.run(out/'manifest.json',env,2,[0,1],True,True)
            self.assertEqual(result['completed'],2)
            self.assertTrue(any('taskset -c 0' in s for s in observed))
            self.assertTrue(any('taskset -c 1' in s for s in observed))
            self.assertTrue(all('--shared-budget' in s and '--review-mode single' in s for s in observed))
