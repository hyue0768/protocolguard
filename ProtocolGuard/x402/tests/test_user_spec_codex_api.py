"""Responses adapter checks with synthetic fixtures; never use actual credentials."""
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
spec = importlib.util.spec_from_file_location('user_spec_codex_api', SECURITY / 'codex_api_user_spec.py')
api = importlib.util.module_from_spec(spec)
spec.loader.exec_module(api)


class ResponsesAdapterTests(unittest.TestCase):
    def args(self, output, *extra):
        return [str(SECURITY / 'codex_api_user_spec.py'), '--rule', 'PAYER_AUTHORIZATION',
                '--model', 'offline-fixture-model', '--output', str(output), *extra]

    def test_no_execution_without_paid_gate(self):
        with tempfile.TemporaryDirectory() as tmp, patch.object(api, 'read_key') as key, \
             patch.object(api.urllib.request, 'build_opener') as network, \
             patch.object(sys, 'argv', self.args(Path(tmp) / 'result')), patch.object(sys, 'stderr', io.StringIO()):
            with self.assertRaises(SystemExit):
                api.main()
            key.assert_not_called()
            network.assert_not_called()

    def test_prepare_never_reads_key_or_network(self):
        with tempfile.TemporaryDirectory() as tmp, patch.object(api, 'read_key') as key, \
             patch.object(api.urllib.request, 'build_opener') as network, patch.object(sys, 'stdout', io.StringIO()):
            out = Path(tmp) / 'prepared'
            with patch.object(sys, 'argv', self.args(out, '--prepare-only', '--key-file', '/does-not-exist')):
                api.main()
            key.assert_not_called()
            network.assert_not_called()
            payload = json.loads((out / 'request.json').read_text())
            self.assertFalse(payload['store'])
            self.assertFalse(payload['stream'])
            self.assertEqual(payload['tools'], [])

    def test_endpoint_rejects_embedded_secrets_and_insecure_urls(self):
        self.assertEqual(api.endpoint_for('https://example.invalid/v1'), 'https://example.invalid/v1/responses')
        self.assertEqual(api.endpoint_for('https://example.invalid/v1/responses'), 'https://example.invalid/v1/responses')
        for value in ['http://example.invalid/v1', 'https://user:password@example.invalid/v1',
                      'https://example.invalid/v1?key=fixture', 'https://example.invalid/v1#fragment']:
            with self.assertRaises(ValueError):
                api.endpoint_for(value)

    def test_text_ignores_reasoning_and_nonmessage_output(self):
        response = dict(status='completed', output=[dict(type='reasoning', text='do-not-save'),
            dict(type='message', role='assistant', content=[dict(type='output_text', text='{"ok":true}')])])
        self.assertEqual(api.final_text(response), '{"ok":true}')

    def test_incomplete_and_refusal_stop(self):
        with self.assertRaises(ValueError):
            api.final_text(dict(status='incomplete', output=[]))
        with self.assertRaises(ValueError):
            api.final_text(dict(status='completed', output=[dict(type='message', role='assistant',
                content=[dict(type='refusal', refusal='fixture')])]))

    def test_single_mock_response_validates_and_excludes_key(self):
        bundle = api.load_prepared(SECURITY / 'deepseek-user-spec-inputs', 'PAYER_AUTHORIZATION')[0]
        source = bundle['code'][0]
        line = next(x for x in source['lines'] if x['text'].strip())
        judgment = dict(rule_id='PAYER_AUTHORIZATION', status='model_judgment_unverified',
            scope_limits=['Synthetic fixture only.'], findings=[dict(id='fixture', goals=['PAYER_AUTHORIZATION'],
                kind='unknown', conclusion='Fixture, not an audit result.', assumptions=[], remaining_gaps=[],
                next_validation_scope='No execution.', evidence=[dict(file=source['file'], line=line['line'], quote=line['text'])])])
        response = dict(status='completed', usage=dict(input_tokens=100, output_tokens=100, total_tokens=200),
            output=[dict(type='reasoning', text='do-not-save'), dict(type='message', role='assistant',
                content=[dict(type='output_text', text=json.dumps(judgment))])])
        with tempfile.TemporaryDirectory() as tmp, patch.object(api, 'read_key', return_value='offline-placeholder'), \
             patch.object(api.urllib.request, 'build_opener') as opener, patch.object(sys, 'stdout', io.StringIO()):
            out = Path(tmp) / 'result'
            opener.return_value.open.return_value = io.StringIO(json.dumps(response))
            with patch.object(sys, 'argv', self.args(out, '--allow-paid', '--key-file', '/fixture')):
                api.main()
            self.assertEqual(opener.return_value.open.call_count, 1)
            self.assertTrue((out / 'review.json').exists())
            for path in out.iterdir():
                self.assertNotIn('offline-placeholder', path.read_text())
                self.assertNotIn('do-not-save', path.read_text())


if __name__ == '__main__':
    unittest.main()
