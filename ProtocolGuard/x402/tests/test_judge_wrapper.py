"""Only mock transports and synthetic credentials; no real service calls."""
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import types
import unittest
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import judge_wrapper as wrapper
import version_audit as audit

ENV=dict(PROTOCOLGUARD_JUDGE_API_KEY='synthetic-fixture-token',
         PROTOCOLGUARD_JUDGE_BASE_URL='http://127.0.0.1:18768/v1',
         PROTOCOLGUARD_JUDGE_MODEL='gpt-5.6-sol',PROTOCOLGUARD_JUDGE_REASONING_EFFORT='medium')


class WrapperTests(unittest.TestCase):
    def test_assertion_status_output_schema_is_an_enum_string(self):
        schema=wrapper.assertion_format()['json_schema']['schema']
        import jsonschema
        jsonschema.Draft202012Validator.check_schema(schema)
        jsonschema.validate(dict(rule_id='r',adapter_status='adapter_missing',assertions=[],uncovered_requirements=[]),schema)
        with self.assertRaises(jsonschema.ValidationError):
            jsonschema.validate(dict(rule_id='r',adapter_status={},assertions=[],uncovered_requirements=[]),schema)
        def strict_object(node):
            if isinstance(node,dict):
                if node.get('type')=='object':
                    self.assertIs(node.get('additionalProperties'),False)
                    self.assertEqual(set(node.get('required',[])),set(node['properties']))
                if node.get('type')=='array':self.assertIn('items',node)
                for child in node.values():strict_object(child)
            elif isinstance(node,list):
                for child in node:strict_object(child)
        strict_object(schema)
    def test_payload_uses_text_chat_not_responses(self):
        with patch.dict(os.environ,ENV):config=wrapper.configuration()
        payload=wrapper.payload(config,'instruction','json fixture')
        self.assertEqual(config['endpoint'],'http://127.0.0.1:18768/v1/chat/completions')
        self.assertEqual(payload['model'],'gpt-5.6-sol')
        self.assertEqual(payload['reasoning_effort'],'medium')
        self.assertEqual(payload['messages'][0]['role'],'system')
        self.assertNotIn('input',payload);self.assertNotIn('instructions',payload)

    def test_other_instance_or_embedded_credentials_rejected(self):
        for value in ['http://127.0.0.1:18766/v1','http://secret@127.0.0.1:18768/v1','http://127.0.0.1:18768/v1?key=fixture']:
            with patch.dict(os.environ,dict(ENV,PROTOCOLGUARD_JUDGE_BASE_URL=value)):
                with self.assertRaises(ValueError):wrapper.configuration()

    def test_incomplete_refusal_and_tools_fail_closed(self):
        answer=dict(choices=[dict(finish_reason='length',message=dict(role='assistant',content='partial'))])
        normalized=wrapper.normalized_response(answer)
        self.assertEqual(normalized['status'],'incomplete')
        self.assertEqual(normalized['incomplete_details']['reason'],'max_output_tokens')
        answer['choices'][0].update(finish_reason='stop',message=dict(role='assistant',content=None,refusal='fixture'))
        self.assertEqual(wrapper.normalized_response(answer)['output'][0]['content'][0]['type'],'refusal')
        answer['choices'][0]['message']=dict(role='assistant',content='{}',tool_calls=[{}])
        with self.assertRaises(ValueError):wrapper.normalized_response(answer)

    def test_model_mock_transport_does_not_read_key_files_or_retry(self):
        answer=dict(choices=[dict(finish_reason='stop',message=dict(role='assistant',content='{"fixture":true}'))],
                    usage=dict(prompt_tokens=11,completion_tokens=5,total_tokens=16))
        observed=[]
        def open_request(request,timeout):
            observed.append((request.full_url,timeout,request.get_header('Authorization')))
            return io.StringIO(json.dumps(answer))
        with tempfile.TemporaryDirectory() as tmp,patch.dict(os.environ,ENV):
            args=types.SimpleNamespace(allow_paid=True,key_file=None,max_calls=1,provider='judge-wrapper')
            opener=types.SimpleNamespace(open=open_request)
            with patch.object(audit.urllib.request,'build_opener',return_value=opener):
                model=audit.Model(args,Path(tmp));result=model.call('test','instruction',dict(fixture=True))
                with self.assertRaisesRegex(ValueError,'cap reached'):model.call('second','instruction',{})
            self.assertTrue(result['fixture']);self.assertEqual(len(observed),1)
            self.assertEqual(observed[0],('http://127.0.0.1:18768/v1/chat/completions',600,'Bearer synthetic-fixture-token'))
            for path in Path(tmp).iterdir():self.assertNotIn(ENV['PROTOCOLGUARD_JUDGE_API_KEY'],path.read_text())
            self.assertEqual(audit.read(Path(tmp)/'test.usage.json')['usage']['input_tokens'],11)

    def test_missing_environment_key_fails_before_network(self):
        with patch.dict(os.environ,{},clear=True),patch.object(audit.urllib.request,'build_opener') as network:
            with self.assertRaises(ValueError):audit.Model(types.SimpleNamespace(allow_paid=True,key_file=None,provider='judge-wrapper'),Path('/not-created'))
            network.assert_not_called()


if __name__=='__main__':unittest.main()
