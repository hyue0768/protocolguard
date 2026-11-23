"""Partition planning and checkpoint execution use synthetic local model stubs."""
import json
import sys
import tempfile
import types
from pathlib import Path
import unittest
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import chunked_review as c
import version_audit as a
import judge_wrapper as w
from context_encoding import pack_context


class ChunkTests(unittest.TestCase):
    def fixture(self):
        code=[dict(symbol_id=str(i),file=f'{i}.ts',lines=[dict(line=j,text='a'*1000) for j in range(1,71)]) for i in range(3)]
        return dict(rule=dict(rule_id='fixture',rule=dict(evidence=[])),norms=[dict(file='spec',lines=[dict(line=1,text='MUST verify')])],
                    slice=dict(code=code,unresolved={str(i):[] for i in range(3)},resolutions={str(i):[] for i in range(3)},
                               field_evidence=[dict(file=f'{i}.ts',line=1,column=1,expression='a',classification='lexical') for i in range(3)],call_graph={}),relevance_view=None)

    def test_lossless_source_and_norms_with_bounded_partial_context(self):
        data=self.fixture();parts=c.partition(data,c.prompt())
        self.assertGreater(len(parts),1)
        def lines(code):return {(d['symbol_id'],d['file'],l['line'],l['text']) for d in code for l in d['lines']}
        self.assertEqual(lines(data['slice']['code']),lines([d for p in parts for d in p['slice']['code']]))
        for p in parts:
            self.assertEqual(p['norms'],data['norms'])
            self.assertLessEqual(c.size(c.prompt(),p),c.TARGET)
            self.assertFalse(p['partition_scope']['cross_partition_dispatch_proven'])

    def test_preflight_budget_failure_sends_nothing(self):
        with tempfile.TemporaryDirectory() as tmp,patch.object(c,'inputs',return_value=self.fixture()),patch.object(a,'Model') as model:
            with self.assertRaisesRegex(ValueError,'before any request'):c.run_review(types.SimpleNamespace(rule='fixture',max_calls=0),Path(tmp))
            model.assert_not_called()

    def test_single_mode_requests_one_judgment_per_partition(self):
        data=self.fixture();parts=c.partition(data,c.prompt());called=[]
        class Model:
            def __init__(self,args,out):self.calls=0
            def call(self,label,instruction,value):
                self.calls+=1;called.append(label)
                return dict(rule_id='fixture',status='model_judgment_unverified',findings=[],limitations=['unknown'])
        with tempfile.TemporaryDirectory() as tmp,patch.object(c,'inputs',return_value=data),patch.object(a,'Model',Model):
            result,count=c.run_review(types.SimpleNamespace(rule='fixture',max_calls=len(parts),review_mode='single'),Path(tmp))
            self.assertEqual(count,len(parts))
            self.assertEqual(result['review_mode'],'single')
            self.assertTrue(all(label.endswith('judge1') for label in called))

    def test_completed_chunks_reuse_only_matching_requests_and_responses(self):
        data=self.fixture();requested=[]
        class Model:
            def __init__(self,args,out):self.calls=0;self.out=out
            def call(self,label,instruction,value):
                self.calls+=1;requested.append(label)
                doc=value['slice']['code'][0];line=doc['lines'][0]
                result=dict(rule_id='fixture',status='model_judgment_unverified',findings=[dict(id='F1',kind='implementation_support',
                    evidence=[dict(file=doc['file'],line=line['line'],quote=line['text'][:8])])],limitations=['partial'])
                user='Return a valid json object only.\n\n'+json.dumps(pack_context(value),ensure_ascii=False,separators=(',',':'))
                a.save(self.out/(label+'.request.json'),w.payload(dict(model='fixture',reasoning='medium'),instruction,user))
                a.save(self.out/(label+'.response.txt'),result)
                return result
        with tempfile.TemporaryDirectory() as tmp,patch.object(c,'inputs',return_value=data),patch.object(a,'Model',Model):
            folder=Path(tmp);args=types.SimpleNamespace(rule='fixture',max_calls=512)
            first,calls=c.run_review(args,folder)
            self.assertEqual(calls,4*first['partition_count'])
            second,calls=c.run_review(args,folder)
            self.assertEqual(calls,0);self.assertEqual(first,second)
            path=folder/'04-consistency/fixture/chunk-001-judge1.response.txt'
            a.save(path,dict(tampered=True))
            count=len(requested)
            with self.assertRaisesRegex(ValueError,'response changed'):c.run_review(args,folder)
            self.assertEqual(len(requested),count)


if __name__=='__main__':unittest.main()
