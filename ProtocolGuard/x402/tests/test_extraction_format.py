import copy
from pathlib import Path
import sys
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from extraction_format import normalize
from judge_wrapper import extraction_format
import version_audit as a


class ExtractionTests(unittest.TestCase):
    def fixture(self):
        atom=dict(obligation='verify',actor='server',message_type=None,applicability=None,normative_strength='MUST',req_fields=[],res_fields=[],
                  preconditions='when configured',exceptions=None,evidence=[dict(file='spec',line=1,quote='Server MUST verify')])
        return dict(candidate_id='c',classification='normative',rules=[atom]),dict(file='spec',lines=[dict(line=1,text='Server MUST verify')])

    def test_scalar_and_null_are_preserved_without_inventing_absence(self):
        value,doc=self.fixture();before=copy.deepcopy(value);result=normalize(value,doc)
        self.assertEqual(value,before)
        self.assertEqual(result['rules'][0]['preconditions'],['when configured'])
        self.assertEqual(result['rules'][0]['exceptions'],[])
        self.assertIn('exceptions',result['rules'][0]['unspecified_list_fields'])
        self.assertEqual(result['local_list_normalizations'][1]['original_value'],None)
        a.validate_extraction(result,'c',[doc],64)

    def test_full_bad_quote_not_rewritten_but_new_line_reference_is_materialized(self):
        value,doc=self.fixture();value['rules'][0]['evidence']=[dict(file='spec',line=1,quote='different claim')]
        with self.assertRaises(ValueError):a.validate_extraction(normalize(value,doc),'c',[doc],64)
        value['rules'][0]['evidence']=[dict(line=1)];result=normalize(value,doc)
        a.validate_extraction(result,'c',[doc],64)
        self.assertFalse(result['local_source_anchor_materialization']['semantic_entailment_verified'])

    def test_strict_schema_rejects_scalar_lists_and_nonexistent_line_ids(self):
        import jsonschema
        value,doc=self.fixture();fmt=extraction_format(dict(candidate=dict(id='c'),document=doc));schema=fmt['json_schema']['schema']
        jsonschema.Draft202012Validator.check_schema(schema)
        value.update(limitations=[],unprocessed_sections=[])
        atom=value['rules'][0];atom.update(preconditions=[],exceptions=[],unspecified_list_fields=['exceptions'],evidence=[dict(line=1)])
        jsonschema.validate(value,schema)
        atom['preconditions']='scalar'
        with self.assertRaises(jsonschema.ValidationError):jsonschema.validate(value,schema)
        atom['preconditions']=[];atom['evidence']=[dict(line=2)]
        with self.assertRaises(jsonschema.ValidationError):jsonschema.validate(value,schema)
        def strict(node):
            if isinstance(node,dict):
                if node.get('type')=='object':self.assertIs(node.get('additionalProperties'),False);self.assertEqual(set(node['required']),set(node['properties']))
                for x in node.values():strict(x)
            elif isinstance(node,list):
                for x in node:strict(x)
        strict(schema)
