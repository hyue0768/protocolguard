"""Encoding changes representation only, never code, spec, fields or order."""
import copy
from pathlib import Path
import sys
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from context_encoding import pack_context,unpack_context


class EncodingTests(unittest.TestCase):
    def test_roundtrip_preserves_interleaved_fields_and_all_evidence(self):
        value=dict(slice=dict(code=[dict(file='a',lines=[dict(line=2,text='return false;'),dict(line=5,text='中文')])],
                   field_evidence=[dict(file=f,classification='lexical',line=i,column=2,expression='x.y') for i,f in enumerate(['a','b','a'])]),
                   norms=[dict(file='spec',lines=[dict(line=1,text='MUST check')])])
        original=copy.deepcopy(value);packed=pack_context(value)
        self.assertEqual(value,original)
        self.assertEqual(unpack_context(packed),value)
        self.assertNotEqual(packed,value)

    def test_empty_and_nonuniform_metadata_is_preserved(self):
        for value in [dict(rule='fixture'),dict(slice={}),dict(slice=dict(field_evidence=[])),
                      dict(slice=dict(field_evidence=[dict(file='a'),dict(file='b',extra=True)]))]:
            self.assertEqual(unpack_context(pack_context(value)),value)


if __name__=='__main__':unittest.main()
