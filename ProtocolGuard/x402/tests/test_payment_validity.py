"""Scope isolation and independent transfer-oracle tests; no target execution."""
import importlib.util
import json
from pathlib import Path
import sys
import unittest

SECURITY = Path(__file__).resolve().parents[1] / 'security'
sys.path.insert(0, str(SECURITY))
import deepseek_harness_user_spec as inputs
import codex_api_user_spec as api
import validate_payment_validity as dynamic


class PaymentValidityTests(unittest.TestCase):
    def transfer(self, **updates):
        t = dict(payer=dynamic.PAYER, asset=dynamic.ASSET, payTo=dynamic.PAYTO,
                 network='eip155:84532', amount='100', nonce='fixture-nonce', tx='fixture-tx')
        t.update(updates)
        return t

    def result(self, transfers):
        return dict(ledgerTransfers=transfers, trace=[dict(event='PaymentSettled', **x) for x in transfers])

    def test_exact_three_original_statements(self):
        spec = json.loads((SECURITY / 'payment-validity/spec.json').read_text())
        self.assertEqual([x['id'] for x in spec['payment_validity_goals']], inputs.PAYMENT_VALIDITY_IDS)
        self.assertEqual([x['predicate'] for x in spec['payment_validity_goals']], [
            'the payment should be authorized by the intended payer or delegate.',
            'the payment should match the terms advertised by the service provider.',
            'the same payment should not be settleable more than once.'])
        self.assertNotIn('formal_properties', spec)
        self.assertNotIn('threat_model', spec)

    def test_corrected_inputs_exclude_old_goal_ids_and_results(self):
        prepared = SECURITY / 'payment-validity/prepared'
        for goal in inputs.PAYMENT_VALIDITY_IDS:
            bundle, _ = inputs.load_prepared(prepared, goal)
            encoded = json.dumps(bundle)
            self.assertNotIn('SERVER_PROTECTION_AGAINST_CLIENT', encoded)
            self.assertNotIn('CLIENT_PROTECTION_AGAINST_SERVER', encoded)
            self.assertNotIn('SERVER_PROTECTION_AGAINST_FACILITATOR', encoded)
            self.assertNotIn('REQUEST_IDEMPOTENCY_CONTEXT', encoded)
            self.assertNotIn('reported_result', encoded)
            self.assertEqual(api.request_body(bundle, 'gpt-6.1-sol', 12000, 'low')['instructions'], inputs.PAYMENT_VALIDITY_SYSTEM)
        with self.assertRaises(ValueError):
            inputs.load_prepared(prepared, 'SERVER_PROTECTION_AGAINST_CLIENT')

    def test_duplicate_transfer_is_replay_failure(self):
        t = self.transfer()
        r = dynamic.evaluate(self.result([t, self.transfer(tx='second-tx')]), ['REPLAY_RESISTANCE'], 1)
        self.assertFalse(r['assertions']['REPLAY_RESISTANCE'])

    def test_success_reports_do_not_count_as_duplicate_transfers(self):
        r = self.result([self.transfer()])
        r['trace'] += [dict(event='FacilitatorResponse', operation='settle', result={'success': True})] * 2
        e = dynamic.evaluate(r, ['REPLAY_RESISTANCE'], 1)
        self.assertTrue(e['assertions']['REPLAY_RESISTANCE'])
        self.assertEqual(e['facilitator_success_reports'], 2)

    def test_wrong_payer_and_terms_fail_separately(self):
        e = dynamic.evaluate(self.result([self.transfer(payer='other-payer', amount='1')]), inputs.PAYMENT_VALIDITY_IDS, 1)
        self.assertFalse(e['assertions']['PAYER_AUTHORIZATION'])
        self.assertFalse(e['assertions']['PAYMENT_BINDING'])

    def test_no_transfer_does_not_satisfy_positive_control(self):
        e = dynamic.evaluate(self.result([]), inputs.PAYMENT_VALIDITY_IDS, 1)
        self.assertFalse(e['positive_or_rejection_control_observed'])


if __name__ == '__main__':
    unittest.main()
