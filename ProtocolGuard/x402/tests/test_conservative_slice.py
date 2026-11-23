"""Synthetic index fixtures only; never loads target SDK code."""
import sys
import unittest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from conservative_slice import closure, field_evidence


def symbol(sid, name, calls=()):
    return dict(id=sid, name=name, calls=list(calls))


class ClosureTests(unittest.TestCase):
    def test_ambiguous_methods_are_all_retained_including_transitive_calls(self):
        symbols = [symbol('root', 'handler', ['wallet.verify']),
                   symbol('a', 'A.verify', ['settle']), symbol('b', 'B.verify'),
                   symbol('c', 'settle', ['handler']), symbol('unused', 'unrelated')]
        result = closure(symbols, ['root'])
        self.assertEqual(result['symbol_ids'], ['a', 'b', 'c', 'root'])
        self.assertEqual(result['call_graph']['root'], ['a', 'b'])
        self.assertFalse(result['dispatch_complete'])

    def test_unique_short_name_is_not_claimed_resolved(self):
        result = closure([symbol('a', 'handler', ['external.verify', 'unknown']),
                          symbol('b', 'verify')], ['a'])
        self.assertEqual(len(result['unresolved']['a']), 2)
        self.assertEqual(result['unresolved']['a'][1]['candidates'], [])

    def test_no_silent_truncation_or_unknown_roots(self):
        with self.assertRaises(ValueError):
            closure([symbol('a', 'a', ['b']), symbol('b', 'b')], ['a'], 1)
        with self.assertRaises(ValueError):
            closure([], ['missing'])

    def test_field_navigation_preserves_source_location_and_optional_chain(self):
        result = field_evidence([dict(file='x.ts', lines=[dict(line=9, text='  req?.payment.amount;')])])
        self.assertEqual(result[0]['expression'], 'req?.payment.amount')
        self.assertEqual((result[0]['line'], result[0]['column']), (9, 3))
        self.assertEqual(result[0]['classification'], 'lexical_member_path_not_def_use')


if __name__ == '__main__':
    unittest.main()
