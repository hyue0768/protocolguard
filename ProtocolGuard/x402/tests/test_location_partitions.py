"""Lossless partition and pre-send budget checks; no service or real key."""
import json
import os
from pathlib import Path
import sys
import tempfile
import types
import unittest
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import location_partitions as partitions
import judge_wrapper as wrapper
import version_audit as audit


class PartitionTests(unittest.TestCase):
    def fixture(self):
        return dict(rule=dict(rule=dict(evidence=[])),target='fixture',symbol_index=[dict(id=str(i),file=f'{i}.ts') for i in range(3)],
                    source_context=[dict(file=f'{i}.ts',lines=[dict(line=n,text='\\"中文'+('a'*1000)) for n in range(1,100)]) for i in range(3)])

    def test_every_source_line_survives_and_each_request_fits(self):
        data=self.fixture();batches=partitions.partition(data,'instruction')
        self.assertGreater(len(batches),1)
        expected=[(d['file'],l['line'],l['text']) for d in data['source_context'] for l in d['lines']]
        actual=[(d['file'],l['line'],l['text']) for b in batches for d in b['source_context'] for l in d['lines']]
        self.assertEqual(actual,expected)
        for b in batches:
            user='Return a valid json object only.\n\n'+json.dumps(b,ensure_ascii=False,separators=(',',':'))
            request=wrapper.payload(dict(model='fixture',reasoning='medium'),'instruction',user)
            self.assertLessEqual(wrapper.prompt_characters(request),partitions.LIMIT)
            self.assertEqual({s['file'] for s in b['symbol_index']},{d['file'] for d in b['source_context']})

    def test_indivisible_source_line_fails_before_generation(self):
        data=self.fixture();data['source_context']=[dict(file='0.ts',lines=[dict(line=1,text='a'*110000)])]
        with self.assertRaisesRegex(ValueError,'One source line'):partitions.partition(data,'instruction')

    def test_model_budget_check_precedes_network_and_output_creation(self):
        with tempfile.TemporaryDirectory() as tmp,patch.dict(os.environ,dict(PROTOCOLGUARD_JUDGE_API_KEY='synthetic-fixture-token',PROTOCOLGUARD_JUDGE_BASE_URL='http://127.0.0.1:18768/v1')):
            out=Path(tmp)/'not-created'
            args=types.SimpleNamespace(provider='judge-wrapper',allow_paid=True,key_file=None,max_calls=1)
            with patch.object(audit.urllib.request,'build_opener') as network:
                model=audit.Model(args,out)
                with self.assertRaisesRegex(ValueError,'no request sent'):model.call('fixture','instruction',dict(text='a'*110000))
                network.assert_not_called();self.assertFalse(out.exists());self.assertEqual(model.calls,0)

    def test_location_checkpoint_reuse_requires_matching_inputs_and_responses(self):
        data=self.fixture();batches=audit.location_batches(data,'judge-wrapper')
        with tempfile.TemporaryDirectory() as tmp:
            out=Path(tmp);result=dict(handlers=[],context=[],limitations='partial context')
            audit.save(out/'part-001.json',result);audit.save(out/'location-part-001.response.txt',result)
            user='Return a valid json object only.\n\n'+json.dumps(batches[0],ensure_ascii=False,separators=(',',':'))
            audit.save(out/'location-part-001.request.json',dict(messages=[dict(role='system',content=audit.LOCATION_PROMPT),dict(role='user',content=user)]))
            import hashlib
            identity=hashlib.sha256(json.dumps(data,sort_keys=True).encode()).hexdigest()
            audit.save(out/'partition-plan.json',dict(input_sha256=identity))
            audit.save(out/'location-resume.json',dict(input_sha256=identity,preserved_sha256={p.name:audit.sha(p) for p in out.iterdir()}))
            self.assertEqual(audit.location_checkpoints(out,data,batches,data['symbol_index'],data['rule']),{1:result})
            audit.save(out/'part-001.json',dict(handlers=['invented'],context=[]))
            with self.assertRaisesRegex(ValueError,'checkpoint changed'):
                audit.location_checkpoints(out,data,batches,data['symbol_index'],data['rule'])


if __name__=='__main__':unittest.main()
