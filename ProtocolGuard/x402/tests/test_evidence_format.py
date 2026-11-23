"""Narrow source quote formatting repair must never repair substantive evidence."""
import copy
from pathlib import Path
import sys
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from evidence_format import normalize
from version_audit import grounding


class FormatTests(unittest.TestCase):
    def setUp(self):
        self.docs=[dict(file='f.ts',lines=[dict(line=4,text='    isValid: true,')])]

    def test_terminal_punctuation_repair_is_audited_and_original_kept(self):
        value=dict(evidence=[dict(file='f.ts',line=4,quote='    isValid: true;')])
        before=copy.deepcopy(value);result=normalize(value,self.docs)
        self.assertEqual(value,before)
        self.assertFalse(grounding(result,self.docs))
        self.assertEqual(result['local_evidence_corrections'][0]['original_quote'],'    isValid: true;')
        self.assertEqual(normalize(result,self.docs),result)

    def test_identifier_value_line_and_internal_whitespace_never_repaired(self):
        for line,quote in [(4,'isValid: false;'),(4,'valid: true;'),(5,'isValid: true;'),(4,'isValid:true;')]:
            value=dict(evidence=[dict(file='f.ts',line=line,quote=quote)])
            self.assertEqual(normalize(value,self.docs),value)
            self.assertTrue(grounding(value,self.docs))

    def test_exact_evidence_is_untouched(self):
        value=dict(evidence=[dict(file='f.ts',line=4,quote='isValid: true,')])
        self.assertEqual(normalize(value,self.docs),value)

    def test_only_leading_tab_escapes_are_decoded_against_exact_source(self):
        docs=[dict(file='f.go',lines=[dict(line=1,text='\tAmount float64')])]
        value=dict(evidence=[dict(file='f.go',line=1,quote='\\tAmount float64')])
        result=normalize(value,docs)
        self.assertFalse(grounding(result,docs))
        self.assertEqual(result['local_evidence_corrections'][0]['kind'],'leading_tab_escape_quote_format_only')
        value['evidence'][0]['quote']='\\tOther float64'
        self.assertEqual(normalize(value,docs),value)
        value['evidence'][0]['quote']='value = "\\t"'
        self.assertEqual(normalize(value,docs),value)


if __name__=='__main__':unittest.main()
