"""Offline checks: response provenance, goal isolation, and paid-run gating."""
import copy
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

BASE = Path(__file__).resolve().parents[1]
SCRIPT = BASE / 'security/deepseek_harness_user_spec.py'
loader = importlib.util.spec_from_file_location('user_spec_harness', SCRIPT)
adapter = importlib.util.module_from_spec(loader)
loader.loader.exec_module(adapter)


class HarnessInputTests(unittest.TestCase):
    def setUp(self):
        self.bundle = dict(rule_id='PAYER_AUTHORIZATION',
                           code=[dict(file='sample.ts', lines=[dict(line=7, text='return verifySignature();')])],
                           norms=[])
        self.response = dict(rule_id='PAYER_AUTHORIZATION', status='model_judgment_unverified',
            scope_limits=['Static evidence only.'], findings=[dict(id='F1',
                goals=['PAYER_AUTHORIZATION'], kind='implementation_support',
                conclusion='Local signature check is present.', assumptions=['Verifier correct.'],
                remaining_gaps=['Runtime dependencies not checked.'],
                next_validation_scope='Check verifier behavior separately.',
                evidence=[dict(file='sample.ts', line=7, quote='verifySignature()')])])

    def test_exact_quote_accepted_but_tamper_rejected(self):
        self.assertEqual(adapter.validate(self.response, self.bundle), [])
        self.response['findings'][0]['evidence'][0]['quote'] = 'bypassSignature()'
        self.assertTrue(adapter.validate(self.response, self.bundle))

    def test_wrong_line_and_goal_rejected(self):
        wrong = copy.deepcopy(self.response)
        wrong['findings'][0]['evidence'][0]['line'] = 8
        self.assertTrue(adapter.validate(wrong, self.bundle))
        wrong = copy.deepcopy(self.response)
        wrong['findings'][0]['goals'] = ['REPLAY_RESISTANCE']
        self.assertTrue(adapter.validate(wrong, self.bundle))

    def test_malformed_and_proof_status_rejected(self):
        for value in [[], None, {'findings': 'not an array'}]:
            self.assertTrue(adapter.validate(value, self.bundle))
        self.response['status'] = 'proven_secure'
        self.assertTrue(adapter.validate(self.response, self.bundle))

    def test_all_prepared_goal_identities_and_pins(self):
        prepared = BASE / 'security/deepseek-user-spec-inputs'
        manifest = json.loads((prepared / 'manifest.json').read_text())
        self.assertEqual(len(manifest['rules']), 7)
        for entry in manifest['rules']:
            bundle, task = adapter.load_prepared(prepared, entry['rule_id'])
            self.assertEqual(bundle['target'], adapter.PIN)
            self.assertTrue(task.exists())
            self.assertTrue(bundle['code'])
            self.assertTrue(bundle['norms'])

    def test_paid_execution_refused_before_output_or_harness(self):
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / 'no-run'
            result = subprocess.run([sys.executable, str(SCRIPT), 'run',
                '--rule', 'PAYER_AUTHORIZATION', '--output', str(output),
                '--dsh', '/nonexistent-do-not-launch'], capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('requires --allow-paid', result.stderr)
            self.assertFalse(output.exists())

    def test_existing_output_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            result = subprocess.run([sys.executable, str(SCRIPT), 'prepare', '--output', tmp],
                                    capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('Output already exists', result.stderr)


if __name__ == '__main__':
    unittest.main()
