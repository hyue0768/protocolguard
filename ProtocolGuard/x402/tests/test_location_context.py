"""Original-source location context; synthetic text, no model execution."""
from pathlib import Path
import sys
import tempfile
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from version_audit import location_context,validate_location


class LocationContextTests(unittest.TestCase):
    def test_mixed_spec_source_evidence_is_valid_but_spec_alone_is_not(self):
        symbols=[dict(id='f',file='code.ts',line=3,end=6)]
        source=[dict(file='code.ts',lines=[dict(line=4,text='const amount = config.price;')])]
        spec=dict(file='spec.md',line=1,quote='Server must know the amount.')
        rule=dict(rule=dict(evidence=[spec]))
        result=dict(handlers=['f'],context=[],evidence=[spec,dict(file='code.ts',line=4,quote='config.price')])
        validate_location(result,symbols,source,rule)
        result['evidence']=[spec]
        with self.assertRaisesRegex(ValueError,'Each handler'):validate_location(result,symbols,source,rule)

    def test_each_handler_needs_its_own_source_evidence(self):
        symbols=[dict(id='a',file='code.ts',line=1,end=3),dict(id='b',file='code.ts',line=5,end=8)]
        source=[dict(file='code.ts',lines=[dict(line=2,text='check(amount);')])]
        result=dict(handlers=['a','b'],context=[],evidence=[dict(file='code.ts',line=2,quote='check(amount)')])
        with self.assertRaisesRegex(ValueError,'Each handler'):validate_location(result,symbols,source,dict(rule=dict(evidence=[])))

    def test_unprovided_spec_quotes_still_fail(self):
        symbols=[dict(id='a',file='code.ts',line=1,end=3)]
        source=[dict(file='code.ts',lines=[dict(line=2,text='check(amount);')])]
        result=dict(handlers=['a'],context=[],evidence=[dict(file='code.ts',line=2,quote='check(amount)'),dict(file='spec.md',line=9,quote='invented')])
        with self.assertRaises(ValueError):validate_location(result,symbols,source,dict(rule=dict(evidence=[])))

    def test_function_bodies_are_included_and_overlapping_ranges_merged(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);(root/'source').mkdir();(root/'source/x.py').write_text('def f():\n    return 4\n')
            symbols=[dict(file='x.py',line=1,end=2,parser_status='parsed'),dict(file='x.py',line=2,end=2,parser_status='parsed')]
            result=location_context(symbols,root)
            self.assertEqual(result,[dict(file='x.py',lines=[dict(line=1,text='def f():'),dict(line=2,text='    return 4')])])

    def test_unknown_parser_retains_full_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);(root/'source').mkdir();(root/'source/x.rs').write_text('first\nsecond\n')
            result=location_context([dict(file='x.rs',line=2,end=2,parser_status='lexical_only_no_parser')],root)
            self.assertEqual(len(result[0]['lines']),2)

    def test_empty_scope_and_bad_ranges_stop_before_model(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);(root/'source').mkdir();(root/'source/x.py').write_text('line\n')
            with self.assertRaises(ValueError):location_context([],root)
            with self.assertRaises(ValueError):location_context([dict(file='x.py',line=1,end=9,parser_status='parsed')],root)


if __name__=='__main__':unittest.main()
