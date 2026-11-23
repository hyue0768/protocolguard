"""Version workflow checks with synthetic data; no model or target execution."""
import importlib.util
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import types
import io
import unittest
from unittest.mock import patch

BASE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BASE))
import version_audit as audit


class VersionAuditTests(unittest.TestCase):
    def test_ws2_boundary_stops_before_norms_or_models(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);audit.save(root/'ws2-handoff-boundary.json',dict(allowed_commit='current'))
            args=types.SimpleNamespace(version='next',stage='extract')
            with patch.object(audit,'version',return_value=(dict(commit='next'),root)),patch.object(audit,'norms') as norms,patch.object(audit,'Model') as model:
                with self.assertRaisesRegex(ValueError,'before any model or target execution'):audit.stage(args,root)
                norms.assert_not_called();model.assert_not_called()
    def test_provider_incomplete_and_refusal_metadata_remain_distinct(self):
        sys.path.insert(0,str(BASE/'security'))
        import codex_api_user_spec as api
        answers=[
            (dict(status='incomplete',incomplete_details=dict(reason='max_output_tokens'),
                  output=[],usage=dict(input_tokens=100,output_tokens=12000)), 'incomplete_response_no_retry'),
            (dict(status='completed',output=[dict(type='message',role='assistant',content=[dict(type='refusal',refusal='synthetic fixture')])]), 'provider_refusal_no_retry'),
        ]
        for answer,expected in answers:
            with tempfile.TemporaryDirectory() as tmp:
                out=Path(tmp);args=types.SimpleNamespace(allow_paid=True,key_file=out/'never-read',max_calls=1)
                opener=types.SimpleNamespace(open=lambda *a,**k:io.StringIO(json.dumps(answer)))
                with patch.object(api,'read_key',return_value='synthetic-fixture-token'),patch.object(audit.urllib.request,'build_opener',return_value=opener):
                    model=audit.Model(args,out)
                    with self.assertRaises(ValueError):model.call('fixture','JSON fixture',{})
                usage=audit.read(out/'fixture.usage.json')
                self.assertEqual(usage['status'],expected)
                self.assertEqual(model.calls,1)
                self.assertFalse((out/'fixture.response.txt').exists())
                self.assertIn('elapsed_seconds',usage)
                if expected=='incomplete_response_no_retry':self.assertEqual(usage['incomplete_reason'],'max_output_tokens')

    def test_slice_stage_preserves_full_code_and_writes_dependency_view(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);folder=root/'version';snapshot=root/'shared/code/fixture'
            (snapshot/'source').mkdir(parents=True)
            for name in ['01-spec','02-rules','03-slices']:(folder/name).mkdir(parents=True)
            text='def verify(req):\n    amount = req.amount\n    unused = 9\n    return amount\n'
            raw=text.encode();(snapshot/'source/f.py').write_bytes(raw)
            audit.save(snapshot/'files.json',[dict(file='f.py',sha256=hashlib.sha256(raw).hexdigest(),
                       git_blob=hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest())])
            audit.save(root/'index.json',dict(versions=[dict(version_id='fixture',tag='fixture',commit='fixture',folder=str(folder))]))
            audit.save(folder/'01-spec/bundle.json',dict(documents=[]))
            rule='0000000000000000-01'
            audit.save(folder/('02-rules/'+rule+'.json'),dict(rule=dict(obligation='Check amount')))
            audit.save(folder/'03-slices/symbols.json',[dict(id='f',file='f.py',name='verify',calls=[],line=1,end=4,parser_status='parsed')])
            audit.save(folder/('03-slices/'+rule+'.location/result.json'),dict(handlers=['f'],context=[]))
            args=types.SimpleNamespace(version='fixture',stage='slice',rule=rule,max_symbols=20,
                                       criterion_field=['req.amount'],criterion_line=[])
            audit.stage(args,root)
            result=audit.read(folder/('03-slices/'+rule+'.slice/slice.json'))
            self.assertEqual(len(result['code'][0]['lines']),4)
            self.assertFalse(result['dispatch_complete'])
            self.assertEqual(result['dependency_views']['statuses'],dict(bounded_dependency_view_not_sound_slice=1))
            self.assertTrue((folder/('03-slices/'+rule+'.slice/contexts.db')).is_file())
            # If every AST node must remain, optional model labels serve no
            # purpose. Standalone prune must finish locally without a key.
            flowpath=folder/('03-slices/'+rule+'.slice/flow-views.json')
            flow=audit.read(flowpath)
            for view in flow['views']:
                view['view']['selected_nodes']=[n['id'] for n in view['view'].get('graph',{}).get('nodes',[])]
            audit.save(flowpath,flow);args.stage='prune'
            with patch.object(audit,'Model',side_effect=AssertionError('No model allowed')):
                audit.stage(args,root)
            retained=audit.read(folder/('03-slices/'+rule+'.relevance/result.json'))
            self.assertEqual(retained['models_called'],0)
            self.assertTrue(retained['full_context_preserved'])
            args.stage='slice'
            with self.assertRaises(ValueError):audit.stage(args,root)

    def test_candidates_preserve_source_and_skip_code(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);(root/'one.md').write_text('# Context\nClient MUST check x.\n```text\nMUST ignore this code example.\n```\n')
            bundle=dict(documents=[dict(role='core',path='specs/core.md',git_blob='fixture',local_file='one.md')])
            with patch.object(audit,'MAP',root):rows=audit.candidate_rows(bundle)
            self.assertEqual(len(rows),1)
            self.assertEqual(rows[0]['line'],2)
            self.assertEqual(rows[0]['heading'],['Context'])

    def test_evidence_validation_rejects_wrong_line_and_type(self):
        docs=[dict(file='file.ts',lines=[dict(line=1,text='return false;')])]
        good=dict(evidence=[dict(file='file.ts',line=1,quote='false')])
        self.assertFalse(audit.grounding(good,docs))
        self.assertTrue(audit.grounding(dict(evidence=[dict(file='file.ts',line=2,quote='false')]),docs))
        self.assertTrue(audit.grounding(dict(evidence=[dict(file=[],line=1,quote='false')]),docs))

    def test_review_quote_punctuation_remains_strict_and_error_identifies_line(self):
        docs=[dict(file='schema.ts',lines=[dict(line=46,text='  authorization: Schema,')])]
        value=dict(rule_id='fixture',status='model_judgment_unverified',findings=[dict(kind='implementation_support',
                   evidence=[dict(file='schema.ts',line=46,quote='  authorization: Schema;')])])
        with self.assertRaisesRegex(ValueError,'schema.ts:46'):audit.validate_review(value,'fixture',docs)
        value['findings'][0]['evidence'][0]['quote']='  authorization: Schema,'
        audit.validate_review(value,'fixture',docs)

    def test_model_stage_requires_manual_paid_gate(self):
        with self.assertRaises(ValueError):
            audit.Model(types.SimpleNamespace(allow_paid=False,key_file=None),Path('/not-created'))

    def test_all_version_identities_and_stage_directories(self):
        root=BASE/'version-audits';index=audit.read(root/'index.json')
        mapping=audit.read(BASE/'release-spec-map/mapping.json')['rows']
        self.assertEqual(len(index['versions']),750)
        self.assertEqual({(r['tag'],r['commit']) for r in index['versions']},{(r['tag'],r['code_commit']) for r in mapping})
        for row in index['versions']:
            folder=Path(row['folder']);meta=audit.read(folder/'audit.json')
            self.assertEqual(meta['code_commit'],row['commit'])
            self.assertEqual(audit.read(folder/'01-spec/bundle.json')['id'],row['spec_bundle_id'])
            for stage in audit.STAGES:self.assertTrue((folder/stage).is_dir())
            self.assertTrue((folder/'source').is_dir())


if __name__=='__main__':
    unittest.main()
