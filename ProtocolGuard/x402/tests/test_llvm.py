import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

PG=Path(__file__).resolve().parents[2]

class LLVMTest(unittest.TestCase):
    def test_indirect_function_pointer_argument_propagation(self):
        with tempfile.TemporaryDirectory(dir=PG/'x402') as tmp:
            p=Path(tmp);source=p/'indirect.c'
            source.write_text('int child(int field) { return field+7; }\nint (*dispatch)(int)=child;\nint handle(int field) { return dispatch(field); }\n')
            subprocess.run(['clang-18','-g','-O0','-Xclang','-disable-O0-optnone','-fno-discard-value-names','-emit-llvm','-c',str(source),'-o',str(p/'toy.bc')],check=True)
            criteria=p/'criteria.json';criteria.write_text(json.dumps(dict(handler='handle',variable='field')))
            env=dict(PATH=os.environ.get('PATH','/usr/bin:/bin'),PG_CRITERIA=str(criteria),PG_OUTPUT=str(p/'slice.json'))
            subprocess.run(['opt-18','-load-pass-plugin',str(PG/'program_slicing/build/src/libMatchPass.so'),'-passes=function(mem2reg),match-pass',str(p/'toy.bc'),'-disable-output'],env=env,check=True)
            data=json.loads((p/'slice.json').read_text())
            self.assertIn('child',{i['function'] for i in data['instructions']})
            self.assertTrue(any(c['caller']=='handle' and c['callee']=='child' for c in data['calls']))
            self.assertTrue(any(c['callee']=='<indirect-unresolved>' for c in data['calls']))
            self.assertIn('LLVM AA',data['alias_analysis'])

    def test_forward_propagation_and_assertions(self):
        with tempfile.TemporaryDirectory(dir=PG/'x402') as tmp:
            p=Path(tmp)
            source=p/'toy.c'
            source.write_text('extern void abort(void);\nint child(int field) { return field+1; }\nint handle(int field) { int y=child(field); if(y>10) abort(); return y; }\n')
            subprocess.run(['clang-18','-g','-O0','-Xclang','-disable-O0-optnone','-fno-discard-value-names','-emit-llvm','-c',str(source),'-o',str(p/'toy.bc')],check=True)
            criteria=p/'criteria.json';criteria.write_text(json.dumps({'handler':'handle','variable':'field'}))
            env=os.environ.copy(); env.update(PG_CRITERIA=str(criteria),PG_OUTPUT=str(p/'slice.json'))
            subprocess.run(['opt-18','-load-pass-plugin',str(PG/'program_slicing/build/src/libMatchPass.so'),'-passes=function(mem2reg),match-pass',str(p/'toy.bc'),'-disable-output'],env=env,check=True)
            data=json.loads((p/'slice.json').read_text())
            self.assertEqual({i['function'] for i in data['instructions']},{'child','handle'})
            self.assertFalse(data['fallback_full_subgraph'])
            criteria.write_text(json.dumps({'handler':'handle'}))
            subprocess.run(['opt-18','-load-pass-plugin',str(PG/'program_slicing/build/src/libMatchPass.so'),'-passes=match-pass',str(p/'toy.bc'),'-disable-output'],env=env,check=True)
            self.assertTrue(json.loads((p/'slice.json').read_text())['fallback_full_subgraph'])
            env['PG_OUTPUT']=str(p/'assert.json')
            subprocess.run(['opt-18','-load-pass-plugin',str(PG/'program_slicing/build/src/libAssertPass.so'),'-passes=assert-call-analysis',str(p/'toy.bc'),'-disable-output'],env=env,check=True)
            self.assertEqual(len(json.loads((p/'assert.json').read_text())['assertions']),1)
            subprocess.run(['python3',str(PG/'program_slicing/src/ast_export.py'),str(source)],check=True,stdout=subprocess.DEVNULL)
            ast=json.loads((p/'.cf_toy.json').read_text());self.assertEqual(len(ast['functions']),2)
            self.assertEqual(ast['functions'][1]['control_flow'][0]['type'],'IF')

if __name__=='__main__':unittest.main()
