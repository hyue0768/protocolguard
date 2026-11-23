import importlib.util
import json
import sqlite3
import tempfile
import unittest
from pathlib import Path
BASE=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('pipeline',BASE/'pipeline.py');pipe=importlib.util.module_from_spec(spec);spec.loader.exec_module(pipe)
spec=importlib.util.spec_from_file_location('slicer',BASE.parent/'program_slicing/src/source_slicer.py');slicer=importlib.util.module_from_spec(spec);spec.loader.exec_module(slicer)

class PipelineTest(unittest.TestCase):
    def test_candidate_provenance_and_code_fence_exclusion(self):
        with tempfile.TemporaryDirectory() as tmp:
            p=Path(tmp)/'spec.md';p.write_text('# A\nThe server MUST reject invalid payment.\n```json\n"must": 1\n```\n')
            rows=pipe.extract(p,'spec.md');self.assertEqual(len(rows),1);self.assertEqual(rows[0]['line'],2)
            self.assertEqual(rows[0]['heading'],['A']);self.assertEqual(rows,pipe.extract(p,'spec.md'))
    def test_source_closure_db_contract_and_pending_decision(self):
        with tempfile.TemporaryDirectory() as tmp:
            p=Path(tmp);(p/'sdk.py').write_text('def helper(x):\n    return x+1\ndef handle(x):\n    if x:\n        return helper(x)\n    return 0\n')
            rows=slicer.slice_python(p,[{'id':'one','rule':'test'},{'id':'two','rule':'pending'}],{'one':{'handlers':['sdk.py::handle']}},p/'slices.db')
            self.assertEqual(rows[1]['status'],'pending_handler_decision')
            self.assertEqual(len(rows[0]['functions']),2)
            with sqlite3.connect(p/'slices.db') as db:
                text,response=db.execute('SELECT code_snippet,llm_response FROM rule_code_snippet').fetchone()
                self.assertIn('if x:',text);self.assertIn('def helper',text);self.assertIsNone(response)
            with self.assertRaises(ValueError):
                slicer.slice_python(p,[{'id':'one','rule':'test'}],{'one':{'handlers':['unknown']}},p/'slices.db')

if __name__=='__main__':unittest.main()
