"""Reorganization keeps old paths working and execution explicitly gated."""
import json
from pathlib import Path
import subprocess
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
ENTRY = ROOT / 'payment-validity/run.py'


class EntryTests(unittest.TestCase):
    def call(self, stage, *args):
        return subprocess.run([sys.executable, str(ENTRY), stage, '--run-id', 'offline-entry-check', *args],
                              capture_output=True, text=True)

    def test_status_is_read_only(self):
        result = self.call('status')
        self.assertEqual(result.returncode, 0)
        self.assertEqual(json.loads(result.stdout)['dynamic'], 'not_run')
        self.assertFalse((ROOT / 'payment-validity/runs/offline-entry-check').exists())

    def test_review_and_dynamic_require_explicit_gates(self):
        self.assertNotEqual(self.call('review').returncode, 0)
        self.assertNotEqual(self.call('dynamic').returncode, 0)
        self.assertFalse((ROOT / 'payment-validity/runs/offline-entry-check').exists())

    def test_old_path_resolves_to_new_folder(self):
        self.assertEqual((ROOT / 'security/payment-validity').resolve(), ROOT / 'payment-validity')


if __name__ == '__main__':
    unittest.main()
