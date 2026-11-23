import importlib.util
import json
import sqlite3
import subprocess
import tempfile
import unittest
from pathlib import Path
PG=Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location('driver',PG/'program_slicing/src/llvm_driver.py');driver=importlib.util.module_from_spec(spec);spec.loader.exec_module(driver)

class DriverTest(unittest.TestCase):
    def test_config_to_llvm_to_completed_source_to_database(self):
        with tempfile.TemporaryDirectory(dir=PG/'x402') as tmp:
            p=Path(tmp).resolve();source=p/'toy.c'
            source.write_text('int handle(int value) {\n  if (value > 5) return value + 1;\n  return 0;\n}\n')
            subprocess.run(['clang-18','-g','-O0','-fno-discard-value-names','-emit-llvm','-c',str(source),'-o',str(p/'toy.bc')],check=True)
            (p/'rules.json').write_text(json.dumps([{'id':'one','rule':'A test rule'}]))
            (p/'decisions.json').write_text(json.dumps({'one':{'handler':'handle'}}))
            (p/'config.toml').write_text('[project]\nrule_path = '+json.dumps(str(p/'rules.json'))+'\noriginal_llvm_ir_path = '+json.dumps(str(p/'toy.bc'))+'\n')
            driver.run(p/'config.toml',p/'decisions.json',p/'output')
            with sqlite3.connect(p/'output/slices.db') as db:
                text,response=db.execute('SELECT code_snippet,llm_response FROM rule_code_snippet').fetchone()
                self.assertIn('if (value > 5)',text);self.assertIn('return 0;',text);self.assertIsNone(response)

if __name__=='__main__':unittest.main()
