"""JSON-mode compatibility tests; no credential file or network access."""
import json
from pathlib import Path
import sys
import tempfile
import types
import unittest
from unittest.mock import patch
BASE=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(BASE));sys.path.insert(0,str(BASE/'security'))
import codex_api_user_spec as api
import version_audit as audit


class JsonModeTests(unittest.TestCase):
    def test_keyword_does_not_depend_on_source_content(self):
        original=dict(rule='payer authorization',source='支付校验')
        text=api.json_mode_input(original)
        prefix,body=text.split('\n\n',1)
        self.assertIn('json',prefix)
        self.assertEqual(json.loads(body),original)

    def test_single_rule_parameters_stay_unchanged(self):
        payload=api.request_body(dict(review_instructions='Review code.'),'gpt-6.1-sol',12000,'low')
        self.assertIn('json',payload['input'])
        self.assertEqual(payload['text'],dict(format=dict(type='json_object')))
        self.assertEqual(payload['reasoning'],dict(effort='low'))
        self.assertEqual(payload['model'],'gpt-6.1-sol')
        self.assertEqual(payload['instructions'],'Review code.')

    def test_versioned_model_prepares_json_input_before_credential_read(self):
        with tempfile.TemporaryDirectory() as temporary:
            out=Path(temporary)/'attempt'
            args=types.SimpleNamespace(allow_paid=True,key_file=Path('/never-read'),max_calls=1)
            with patch.object(api,'read_key',side_effect=ValueError('synthetic credential gate')) as key,patch.object(audit.urllib.request,'build_opener') as network:
                with self.assertRaisesRegex(ValueError,'synthetic credential gate'):
                    audit.Model(args,out).call('test','Return JSON only.',dict(rule='Check payer'))
            key.assert_called_once();network.assert_not_called()
            request=json.loads((out/'test.request.json').read_text())
            self.assertIn('json',request['input'])
            self.assertEqual(json.loads(request['input'].split('\n\n',1)[1]),dict(rule='Check payer'))


if __name__=='__main__':unittest.main()
