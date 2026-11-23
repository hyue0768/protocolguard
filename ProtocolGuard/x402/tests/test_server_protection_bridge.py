"""Synthetic event-oracle checks only: do not execute dynamic SDK fixtures."""
import importlib.util
from pathlib import Path
import sys
import unittest

SECURITY = Path(__file__).resolve().parents[1] / 'security'
sys.path.insert(0, str(SECURITY))
spec = importlib.util.spec_from_file_location('server_bridge', SECURITY / 'validate_server_protection.py')
bridge = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bridge)


class EventMappingTests(unittest.TestCase):
    def settlement(self, index):
        return dict(event='PaymentSettled', index=index, tx='fixture-tx', payer='fixture-payer',
                    amount='100', network='eip155:84532',
                    payTo='0x2222222222222222222222222222222222222222',
                    asset='0x1111111111111111111111111111111111111111')

    def test_order_and_split_bytes(self):
        result = dict(trace=[self.settlement(0), dict(event='WireWrite', index=1, bytes='PROTECTED_'),
                             dict(event='WireWrite', index=2, bytes='RESOURCE')], wire='PROTECTED_RESOURCE')
        answer = bridge.evaluate(result, 'support_control')
        self.assertTrue(answer['expected_control_behavior_observed'])
        self.assertFalse(answer['exact_tamarin_formula_checked'])

    def test_later_settlement_does_not_satisfy_earlier_delivery(self):
        result = dict(trace=[dict(event='WireWrite', index=0, bytes='PROTECTED_RESOURCE'), self.settlement(1)])
        self.assertEqual(bridge.evaluate(result, 'conditional_goal_witness')['goal_violation_count'], 1)

    def test_facilitator_report_not_ledger_settlement(self):
        result = dict(trace=[dict(event='FacilitatorResponse', index=0, result={'success': True}),
                            dict(event='WireWrite', index=1, bytes='PROTECTED_RESOURCE')])
        self.assertEqual(bridge.evaluate(result, 'conditional_goal_witness')['goal_violation_count'], 1)

    def test_no_delivery_is_not_a_positive_security_proof(self):
        answer = bridge.evaluate(dict(trace=[]), 'reject_control')
        self.assertEqual(answer['observation'], 'no_delivery_observed')
        self.assertTrue(answer['expected_control_behavior_observed'])

    def test_framework_error_not_protocol_finding(self):
        with self.assertRaises(ValueError):
            bridge.evaluate(dict(trace=[dict(event='FrameworkError')]), 'support_control')


if __name__ == '__main__':
    unittest.main()
