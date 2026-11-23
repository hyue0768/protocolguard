"""API adapter checks with in-memory fixtures; no real credentials or network."""
import importlib.util
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

SECURITY = Path(__file__).resolve().parents[1] / 'security'
sys.path.insert(0, str(SECURITY))
spec = importlib.util.spec_from_file_location('user_spec_api', SECURITY / 'deepseek_api_user_spec.py')
api = importlib.util.module_from_spec(spec)
spec.loader.exec_module(api)


class APIAdapterTests(unittest.TestCase):
    def argv(self, out, *extra):
        return [str(SECURITY / 'deepseek_api_user_spec.py'), '--rule', 'PAYER_AUTHORIZATION',
                '--output', str(out), '--budget-usd', '1', *extra]

    def test_paid_gate_before_key_or_network(self):
        with tempfile.TemporaryDirectory() as tmp, patch.object(api.urllib.request, 'urlopen') as network:
            out = Path(tmp) / 'result'
            with patch.object(sys, 'argv', self.argv(out)), patch('sys.stderr', io.StringIO()):
                with self.assertRaises(SystemExit):
                    api.main()
            network.assert_not_called()
            self.assertFalse(out.exists())

    def test_budget_gate_before_key_or_network(self):
        with tempfile.TemporaryDirectory() as tmp, patch.object(api.urllib.request, 'urlopen') as network:
            out = Path(tmp) / 'result'
            args = self.argv(out, '--allow-paid', '--key-stdin')
            args[args.index('--budget-usd') + 1] = '0.000001'
            with patch.object(sys, 'argv', args), patch('sys.stderr', io.StringIO()):
                with self.assertRaises(SystemExit):
                    api.main()
            network.assert_not_called()
            self.assertFalse(out.exists())

    def fake_answer(self, finish):
        bundle = api.load_prepared(SECURITY / 'deepseek-user-spec-inputs', 'PAYER_AUTHORIZATION')[0]
        source = bundle['code'][0]
        line = next(x for x in source['lines'] if x['text'].strip())
        result = dict(rule_id='PAYER_AUTHORIZATION', status='model_judgment_unverified',
            scope_limits=['Offline test fixture only.'], findings=[dict(id='fixture',
                goals=['PAYER_AUTHORIZATION'], kind='unknown', conclusion='Fixture, not a real audit.',
                assumptions=[], remaining_gaps=['Not reviewed.'], next_validation_scope='None in this test.',
                evidence=[dict(file=source['file'], line=line['line'], quote=line['text'])])])
        return io.StringIO(json.dumps(dict(choices=[dict(finish_reason=finish,
            message=dict(content=json.dumps(result), reasoning_content='not-to-be-saved'))],
            usage=dict(prompt_tokens=100, completion_tokens=100, total_tokens=200))))

    def run_fixture(self, finish):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / 'result'
            with patch.object(sys, 'argv', self.argv(out, '--allow-paid', '--key-stdin')), \
                 patch.object(sys, 'stdin', io.StringIO('offline-test-placeholder\n')), \
                 patch.object(sys, 'stdout', io.StringIO()), \
                 patch.object(api.urllib.request, 'urlopen', return_value=self.fake_answer(finish)) as network:
                if finish == 'stop':
                    api.main()
                    self.assertIn('direct DeepSeek', json.loads((out / 'review.json').read_text())['provenance'])
                else:
                    with self.assertRaises(ValueError):
                        api.main()
                    self.assertFalse((out / 'review.json').exists())
                self.assertEqual(network.call_count, 1)
            for file in out.iterdir():
                self.assertNotIn('offline-test-placeholder', file.read_text())
                self.assertNotIn('not-to-be-saved', file.read_text())

    def test_successful_fixture_grounding_and_secret_exclusion(self):
        self.run_fixture('stop')

    def test_truncation_stops_without_retry(self):
        self.run_fixture('length')


if __name__ == '__main__':
    unittest.main()
