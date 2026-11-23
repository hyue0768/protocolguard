"""Compile and execute synthetic C only, never ProtocolGuard target SDKs."""
import importlib.util
import json
from pathlib import Path
import shutil
import tempfile
import unittest

HERE=Path(__file__).resolve().parents[2]/'dynamic_verification/DFUZZ'
spec=importlib.util.spec_from_file_location('pg_directed',HERE/'directed.py')
directed=importlib.util.module_from_spec(spec);spec.loader.exec_module(directed)


@unittest.skipUnless(shutil.which('clang-18') and shutil.which('opt-18') and (HERE/'build18/libDirected18.so').is_file(),'LLVM18 plugin/toolchain absent')
class DirectedTests(unittest.TestCase):
    def test_indirect_target_gets_conservative_distance_candidate(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary);source=root/'toy.c'
            source.write_text('int target(int x){return x;}\nint (*dispatch)(int)=target;\nint main(void){return dispatch(0);}\n')
            criteria=root/'criteria.json';criteria.write_text('{"function":"target"}')
            directed.prepare(source,criteria,root/'prepared')
            graph=json.loads((root/'prepared/graph.json').read_text())
            self.assertTrue(graph['unresolved_indirect_calls'])
            self.assertTrue(any(n['function']=='main' and n['distance']>0 for n in graph['blocks']))
            self.assertFalse(graph['reachability_proven'])

    def test_distance_instrumentation_and_existing_corpus_replay(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary);source=root/'toy.c'
            source.write_text('#include <stdio.h>\nint target(int x){ if(x==65) return 1; return 0; }\nint main(void){ int c=getchar(); return target(c)==1?0:2; }\n')
            criteria=root/'criteria.json';criteria.write_text(json.dumps(dict(function='target',line=2)))
            directed.prepare(source,criteria,root/'prepared')
            graph=json.loads((root/'prepared/graph.json').read_text())
            self.assertTrue(any(n['target'] for n in graph['blocks']))
            self.assertTrue(any(n['function']=='main' and n['distance']>0 for n in graph['blocks']))
            corpus=root/'corpus';corpus.mkdir();(corpus/'one').write_bytes(b'A');(corpus/'two').write_bytes(b'B')
            result=directed.replay(root/'prepared',corpus,root/'run',True)
            self.assertEqual(len(result['results']),2)
            self.assertEqual(result['results'][0]['returncode'],0)
            self.assertEqual(result['results'][1]['returncode'],2)
            self.assertTrue(all(n['target_reached'] for n in result['results']))
            with self.assertRaises(ValueError):directed.fuzz(root/'prepared',corpus,root/'fuzz-denied',True,False)
            if shutil.which('bwrap'):
                fuzzed=directed.fuzz(root/'prepared',corpus,root/'fuzz',True,True,max_cases=4)
                self.assertEqual(len(fuzzed['results']),4)
                self.assertGreater(fuzzed['generated_inputs'],0)
                self.assertFalse(fuzzed['original_dfuzz_reproduction'])
            with self.assertRaises(ValueError):directed.replay(root/'prepared',corpus,root/'run2',False)
            with self.assertRaises(ValueError):directed.prepare(source,criteria,root/'prepared')

    def test_tampered_binary_is_rejected_before_execution(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary);source=root/'toy.c';source.write_text('int main(void){return 0;}\n')
            criteria=root/'criteria.json';criteria.write_text('{"function":"main"}')
            directed.prepare(source,criteria,root/'prepared')
            with (root/'prepared/target').open('ab') as stream:stream.write(b'changed')
            corpus=root/'corpus';corpus.mkdir();(corpus/'one').write_bytes(b'')
            with self.assertRaisesRegex(ValueError,'identity mismatch'):
                directed.replay(root/'prepared',corpus,root/'run',True)


if __name__=='__main__':unittest.main()
