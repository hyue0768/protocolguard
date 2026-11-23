import importlib.util
import json
from pathlib import Path
import sqlite3
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class GeneralWorkflowTests(unittest.TestCase):
    def test_python_context_keeps_local_callee_and_reports_external_calls(self):
        slicer = load("source_slicer", ROOT / "program_slicing/src/source_slicer.py")
        sample = ROOT / "example/python-context"
        with tempfile.TemporaryDirectory() as temp:
            database = Path(temp) / "slices.db"
            report = slicer.slice_python(sample, json.loads((sample / "rules.json").read_text()), json.loads((sample / "decisions.json").read_text()), database)
            self.assertEqual(report[0]["functions"], ["handler.py::handle_message", "handler.py::parse_length"])
            self.assertIn("int", report[0]["unresolved_calls"]["handler.py::parse_length"])
            with sqlite3.connect(database) as connection:
                source, verdict = connection.execute("SELECT code_snippet, llm_response FROM rule_code_snippet").fetchone()
            self.assertIn("def handle_message", source)
            self.assertIn("def parse_length", source)
            self.assertIsNone(verdict)

    def test_unknown_handler_fails_instead_of_silently_claiming_coverage(self):
        slicer = load("source_slicer", ROOT / "program_slicing/src/source_slicer.py")
        with tempfile.TemporaryDirectory() as temp:
            with self.assertRaisesRegex(ValueError, "Unknown source selectors"):
                slicer.slice_python(ROOT / "example/python-context", [{"id": "r", "rule": "example"}], {"r": {"handlers": ["missing.py::absent"]}}, Path(temp) / "slices.db")

    def test_extraction_stage_paths_are_independent_of_invoking_directory(self):
        entry = load("extraction_entry", ROOT / "rule_extraction/main.py")
        with tempfile.TemporaryDirectory() as temp:
            html = Path(temp) / "spec.html"
            html.write_text("<p>Example specification.</p>")
            argv = ["main.py", "--apikey", "offline-placeholder", "--protocol", "example", "--version", "1", "--html-file", str(html)]
            with patch.object(sys, "argv", argv), patch.object(entry, "run_command") as runner, patch("builtins.print"):
                entry.main()
            self.assertEqual(runner.call_count, 3)
            for call in runner.call_args_list:
                self.assertTrue(Path(call.kwargs["cwd"]).is_absolute())
            self.assertEqual(Path(runner.call_args_list[-1].kwargs["cwd"]).name, "ruleProcess")


if __name__ == "__main__":
    unittest.main()
