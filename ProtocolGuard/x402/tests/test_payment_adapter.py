"""Adapter identity and execution gates only; no SDK or model execution."""
import json
from pathlib import Path
import sys
import tempfile
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import payment_adapter as adapter


class PaymentAdapterTests(unittest.TestCase):
    def test_missing_and_changed_modules_fail_closed(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary);(root/'file.ts').write_text('original')
            profile=dict(id='fixture',modules={'file.ts':dict(sha256=adapter.digest(root/'file.ts'))})
            self.assertEqual(adapter.inspect(root,profile)['status'],'eligible_not_executed')
            (root/'file.ts').write_text('changed')
            self.assertEqual(adapter.inspect(root,profile)['status'],'adapter_missing')
            (root/'file.ts').unlink()
            self.assertEqual(adapter.inspect(root,profile)['mismatches'][0]['reason'],'missing')

    def test_manual_gate_precedes_any_target_load(self):
        with self.assertRaisesRegex(ValueError,'--execute'):
            adapter.execute(Path('/not-read'), 'fixture',Path('/not-written'))

    def test_existing_baseline_profile_is_consistent(self):
        profile=adapter.profile()
        self.assertEqual(len(profile['modules']),41)
        self.assertEqual(len(profile['baseline']),8)


if __name__=='__main__':unittest.main()
