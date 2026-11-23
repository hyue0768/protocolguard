"""Native adapter planning and synthetic network sandbox only; no SDK tests."""
from pathlib import Path
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import native_adapters as native


class NativeAdapterTests(unittest.TestCase):
    def test_all_four_adapters_preserve_unknown_protocol_status(self):
        for language in ['go','rust','solidity','java']:
            plan=native.plan(language,'project')
            self.assertEqual(plan['rules_covered'],[])
            self.assertFalse(plan['semantic_correctness_proven'])

    def test_path_and_manual_gates(self):
        for path in ['../escape','/absolute']:
            with self.assertRaises(ValueError):native.plan('go',path)
        with self.assertRaisesRegex(ValueError,'--execute'):
            native.execute(Path('/not-read'),'0'*40,'go','go',Path('/not-created'))

    def test_missing_toolchain_is_not_success(self):
        with patch.object(native.shutil,'which',return_value=None):
            with self.assertRaisesRegex(ValueError,'missing'):
                native.execute(Path('/not-read'),'0'*40,'go','go',Path('/not-created'),True)

    @unittest.skipUnless(shutil.which('bwrap'),'bwrap absent')
    def test_synthetic_sandbox_clears_environment_and_has_no_external_route(self):
        with tempfile.TemporaryDirectory() as temporary:
            output=Path(temporary);work=output/'work/project';work.mkdir(parents=True)
            program="import os,json;print(json.dumps(dict(credential_present='PG_SYNTHETIC_SECRET' in os.environ,route=open('/proc/net/route').read().splitlines()[1:])))"
            command=native.sandbox_command(output/'work',output,None,'project',['/usr/bin/python3','-c',program])
            result=subprocess.run(command,text=True,capture_output=True,env=dict(PATH='/usr/bin:/bin',PG_SYNTHETIC_SECRET='synthetic-only'),timeout=10)
            self.assertEqual(result.returncode,0,result.stderr)
            data=json.loads(result.stdout)
            self.assertFalse(data['credential_present']);self.assertEqual(data['route'],[])


if __name__=='__main__':unittest.main()
