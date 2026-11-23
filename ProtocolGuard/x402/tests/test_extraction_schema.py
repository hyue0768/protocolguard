"""Extraction schema and grounding regression; no API or target execution."""
import copy
from pathlib import Path
import sys
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from version_audit import validate_extraction


class ExtractionTests(unittest.TestCase):
    def setUp(self):
        self.docs=[dict(file='spec.md',lines=[dict(line=1,text='Server must know the amount.')])]
        self.result=dict(candidate_id='fixture',classification='normative',rules=[dict(
            obligation='Know amount',actor='server',normative_strength='must',message_type=None,
            req_fields=[],res_fields=[],preconditions=[],exceptions=[],
            evidence=[dict(file='spec.md',line=1,quote='must know the amount')])])

    def test_explicit_unspecified_type_and_named_type_are_accepted(self):
        validate_extraction(self.result,'fixture',self.docs,64)
        self.result['rules'][0]['message_type']='payment'
        validate_extraction(self.result,'fixture',self.docs,64)

    def test_missing_empty_or_invalid_type_is_rejected(self):
        for value in ['',[],12]:
            result=copy.deepcopy(self.result);result['rules'][0]['message_type']=value
            with self.assertRaises(ValueError):validate_extraction(result,'fixture',self.docs,64)
        del self.result['rules'][0]['message_type']
        with self.assertRaises(ValueError):validate_extraction(self.result,'fixture',self.docs,64)

    def test_nullable_type_does_not_relax_evidence_or_rule_requirements(self):
        self.result['rules'][0]['evidence'][0]['quote']='invented quote'
        with self.assertRaises(ValueError):validate_extraction(self.result,'fixture',self.docs,64)
        self.result['rules'][0]['evidence']=[]
        with self.assertRaises(ValueError):validate_extraction(self.result,'fixture',self.docs,64)


if __name__=='__main__':unittest.main()
