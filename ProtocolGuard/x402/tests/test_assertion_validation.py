import sys
from pathlib import Path
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from assertion_validation import validate


class AssertionTests(unittest.TestCase):
    def fixture(self):
        return dict(rule_id='r',adapter_status='adapter_missing',assertions=[dict(id='a',case_id='helper',predicate='observe_only',
                    evidence=[dict(file='f',line=1,quote='return x')])])

    def test_missing_adapter_observations_are_preserved_but_never_executable(self):
        source=self.fixture();result=validate(source,'r',[dict(file='f',lines=[dict(line=1,text='return x')])],[dict(id='helper')])
        self.assertEqual(result['assertions'],[])
        self.assertEqual(result['adapter_status'],'adapter_missing')
        self.assertEqual(result['non_executable_observations'],source['assertions'])
        self.assertEqual(len(source['assertions']),1)

    def test_missing_adapter_executable_assertion_still_rejected(self):
        value=self.fixture();value['assertions'][0]['predicate']='rejected'
        with self.assertRaisesRegex(ValueError,'Missing adapter'):
            validate(value,'r',[dict(file='f',lines=[dict(line=1,text='return x')])],[dict(id='helper')])

    def test_bad_evidence_never_becomes_a_retained_observation(self):
        with self.assertRaises(ValueError):validate(self.fixture(),'r',[dict(file='f',lines=[dict(line=1,text='other')])],[dict(id='helper')])

    def test_explicit_empty_support_status_object_is_missing_only(self):
        value=self.fixture();value['adapter_status']=dict(supported_component_cases=[],adapter_missing=['helper'])
        result=validate(value,'r',[dict(file='f',lines=[dict(line=1,text='return x')])],[dict(id='helper')])
        self.assertEqual(result['adapter_status'],'adapter_missing');self.assertEqual(result['assertions'],[])
        self.assertEqual(result['original_adapter_status'],value['adapter_status'])
        value['adapter_status']['supported_component_cases']=['helper']
        with self.assertRaises(ValueError):validate(value,'r',[dict(file='f',lines=[dict(line=1,text='return x')])],[dict(id='helper')])
