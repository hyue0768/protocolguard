"""Synthetic source AST tests: never imports the analyzed source."""
from pathlib import Path
import sys
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from flow_analysis import analyze_document, may_paths, overlap


class FlowTests(unittest.TestCase):
    def test_python_alias_field_dependency_and_control(self):
        source='''def verify(req):
    payment = req.payment
    amount = payment.amount
    unrelated = 9
    if amount > 0:
        accepted = amount
    return accepted
'''
        result=analyze_document('verify.py',source,1,7,['req.payment.amount'])
        self.assertEqual(result['status'],'bounded_dependency_view_not_sound_slice')
        selected=[result['graph']['nodes'][i]['line'] for i in result['selected_nodes']]
        self.assertIn(3,selected);self.assertIn(5,selected);self.assertIn(6,selected)
        self.assertNotIn(4,selected)

    def test_ts_alias_field_dependency(self):
        source='''function verify(req: any) {
 const payment = req.payment;
 const amount = payment.amount;
 const irrelevant = 9;
 if (amount > 0) { return amount; }
 return 0;
}'''
        result=analyze_document('verify.ts',source,1,7,['req.payment.amount'])
        self.assertEqual(result['status'],'bounded_dependency_view_not_sound_slice')
        selected=[result['graph']['nodes'][i]['line'] for i in result['selected_nodes']]
        self.assertIn(3,selected);self.assertNotIn(4,selected)

    def test_unknown_criteria_fail_closed_and_calls_retained(self):
        source='def f(req):\n    log(req)\n    x = 1\n    return req.amount\n'
        self.assertEqual(analyze_document('f.py',source,1,4,['missing.field'])['status'],'full_context_required')
        result=analyze_document('f.py',source,1,4,['req.amount'])
        self.assertIn(0,result['selected_nodes'])

    def test_unsupported_and_syntax_errors_are_not_passes(self):
        self.assertEqual(analyze_document('f.go','garbage',1,1)['status'],'full_context_required')
        self.assertEqual(analyze_document('f.py','def (',1,1)['status'],'full_context_required')

    def test_alias_bound_wildcards_and_field_separation(self):
        self.assertTrue(overlap('req.*','req.amount'))
        self.assertFalse(overlap('req.asset','req.amount'))
        self.assertIn('req.payment.amount',may_paths('p.amount',[['p','req.payment']]))
        with self.assertRaises(ValueError):may_paths('a.x',[['a','a.more']],5)


if __name__=='__main__':unittest.main()
