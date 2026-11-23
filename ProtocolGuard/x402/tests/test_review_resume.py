"""Transport recovery tests use only synthetic saved responses; never call APIs."""
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import review_resume as recovery


class RecoveryTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name);self.plan=self.root/'plan.json'
        self.rule='0000000000000000-01';self.task=f'v/{self.rule}/review'
        self.out=self.root/'v/04-consistency'/self.rule;self.out.mkdir(parents=True)
        recovery.write(self.plan,dict(versions=[dict(version_id='v',folder=str(self.root/'v'))]))
        recovery.write(self.root/'journal.json',dict(plan_sha256=recovery.digest(self.plan),reserved_request_slots=4,
                        tasks={self.task:dict(status='failed',log='original-log')},status='stopped'))
        self.request=dict(input='fixture',instructions='fixture')
        recovery.write(self.out/'judge1.request.json',self.request)
        self.usage=dict(status='transport_or_response_failure',request_sha256=hashlib.sha256(
            json.dumps(self.request,ensure_ascii=False,separators=(',',':')).encode()).hexdigest())
        recovery.write(self.out/'judge1.usage.json',self.usage)

    def test_prepare_preserves_originals_and_reservations(self):
        old=recovery.digest(self.out/'judge1.usage.json')
        result=recovery.prepare(self.plan,self.task)
        self.assertEqual(result['models_called'],0)
        self.assertEqual(recovery.read(self.root/'journal.json')['reserved_request_slots'],4)
        self.assertEqual(recovery.digest(self.out/'judge1.usage.json'),old)
        self.assertEqual(recovery.verify_marker(self.out)['attempt_directory'],'transport-attempt-001')
        self.assertTrue((Path(result['backup'])/'journal.before.json').is_file())
        with self.assertRaises(ValueError):recovery.prepare(self.plan,self.task)

    def test_refusal_http_and_invalid_json_are_not_retried(self):
        for status in ['http_error','invalid_provider_json','incomplete_refused_or_invalid_response_no_retry']:
            recovery.write(self.out/'judge1.usage.json',dict(self.usage,status=status))
            with self.assertRaisesRegex(ValueError,'Only a transport'):recovery.prepare(self.plan,self.task)
        self.assertFalse((self.out/'transport-resume.json').exists())

    def test_existing_response_must_be_inspected_offline(self):
        (self.out/'judge1.response.txt').write_text('{}')
        with self.assertRaisesRegex(ValueError,'response exists'):recovery.prepare(self.plan,self.task)

    def test_tampered_request_is_rejected(self):
        recovery.write(self.out/'judge1.request.json',dict(input='changed'))
        with self.assertRaisesRegex(ValueError,'identity mismatch'):recovery.prepare(self.plan,self.task)

    def test_checkpoint_reuse_requires_identical_input_prompt_and_response(self):
        data=dict(rule='fixture');instruction='prompt'
        security=str(Path(__file__).resolve().parents[1]/'security')
        sys.path.insert(0,security)
        from codex_api_user_spec import json_mode_input
        value=dict(findings=[])
        recovery.write(self.out/'judge1.json',value)
        recovery.write(self.out/'judge1.response.txt',value)
        recovery.write(self.out/'judge1.request.json',dict(input=json_mode_input(data),instructions=instruction))
        self.assertEqual(recovery.cached_judgments(self.out,data,instruction,lambda v:None),dict(judge1=value))
        with self.assertRaisesRegex(ValueError,'differs'):recovery.cached_judgments(self.out,dict(rule='changed'),instruction,lambda v:None)
        recovery.write(self.out/'judge1.response.txt',dict(findings=['changed']))
        with self.assertRaisesRegex(ValueError,'matching raw'):recovery.cached_judgments(self.out,data,instruction,lambda v:None)

    def test_marker_detects_checkpoint_tampering(self):
        recovery.prepare(self.plan,self.task)
        (self.out/'judge1.request.json').write_text('{}')
        with self.assertRaisesRegex(ValueError,'checkpoint changed'):recovery.verify_marker(self.out)


if __name__=='__main__':unittest.main()
