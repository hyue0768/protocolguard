import sys
from pathlib import Path
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from relevance_view import validate_relevance,retained_context_fallback,advisory_plan,retained_without_request


class RelevanceTests(unittest.TestCase):
    def test_all_protected_nodes_need_no_model_request(self):
        self.views[0]['view']['selected_nodes']=[0,1]
        plan=advisory_plan(self.views)
        self.assertFalse(plan['request_model'])
        self.assertEqual(plan['reason'],'no_unprotected_advisory_candidates')
        result=retained_without_request(plan)
        self.assertEqual(result['models_called'],0)
        self.assertTrue(result['full_context_preserved'])
        self.assertFalse(result['semantic_correctness_proven'])

    def test_large_optional_label_output_retains_source_locally(self):
        self.views[0]['view']['graph']['nodes']=[dict(id=i,calls=[],terminal=False) for i in range(137)]
        plan=advisory_plan(self.views)
        self.assertEqual(plan['reason'],'advisory_output_budget_exceeded')
        self.assertEqual(plan['candidate_nodes'],136)

    def test_small_optional_candidate_can_still_be_reviewed(self):
        self.assertTrue(advisory_plan(self.views)['request_model'])
        with self.assertRaises(ValueError):retained_without_request(advisory_plan(self.views))

    def test_opaque_calls_and_terminal_nodes_are_never_candidates(self):
        node=self.views[0]['view']['graph']['nodes'][1]
        for key,value in [('calls',['opaque']),('terminal',True)]:
            node.update(calls=[],terminal=False);node[key]=value
            self.assertFalse(advisory_plan(self.views)['request_model'])
    def test_null_node_is_a_retained_known_empty_context(self):
        self.views.append(dict(symbol_id='opaque',view=dict(status='full_context_required',reason='no parser')))
        item=dict(symbol_id='opaque',node_id=None,relevance='unknown',reason='no AST nodes',evidence=[{}])
        result=validate_relevance(dict(labels=self.labels+[item]),self.views)
        self.assertEqual(len(result['labels']),2)
        self.assertEqual(result['context_labels'],[item])
        self.assertTrue(result['full_context_preserved'])

    def test_null_cannot_replace_a_real_node_or_exclude_opaque_source(self):
        invalid=dict(symbol_id='f',node_id=None,relevance='unknown',reason='invalid replacement',evidence=[{}])
        with self.assertRaises(ValueError):validate_relevance(dict(labels=self.labels+[invalid]),self.views)
        self.views.append(dict(symbol_id='opaque',view=dict(status='full_context_required')))
        invalid.update(symbol_id='opaque',relevance='irrelevant_candidate')
        with self.assertRaises(ValueError):validate_relevance(dict(labels=self.labels+[invalid]),self.views)

    def test_separate_context_labels_and_unlabelled_context_are_supported(self):
        self.views.append(dict(symbol_id='opaque',view=dict(status='full_context_required')))
        item=dict(symbol_id='opaque',node_id=None,relevance='unknown',reason='opaque',evidence=[{}])
        result=validate_relevance(dict(labels=self.labels,context_labels=[item]),self.views)
        self.assertEqual(result['context_labels'],[item])
        result=validate_relevance(dict(labels=self.labels),self.views)
        self.assertEqual(result['unlabelled_context_symbols'],['opaque'])

    def test_duplicates_and_non_objects_still_fail(self):
        self.views.append(dict(symbol_id='opaque',view=dict(status='full_context_required')))
        item=dict(symbol_id='opaque',node_id=None,relevance='unknown',reason='opaque',evidence=[{}])
        with self.assertRaises(ValueError):validate_relevance(dict(labels=self.labels+[item,item]),self.views)
        with self.assertRaises(ValueError):validate_relevance(dict(labels=self.labels+[None]),self.views)

    def test_fallback_is_unknown_and_retains_no_unvalidated_labels(self):
        result=retained_context_fallback('bad schema')
        self.assertEqual(result['status'],'unusable_relevance_full_context_retained')
        self.assertEqual(result['labels'],[])
        self.assertFalse(result['semantic_correctness_proven'])
        self.assertTrue(result['full_context_preserved'])

    def setUp(self):
        self.views=[dict(symbol_id='f',view=dict(status='bounded_dependency_view_not_sound_slice',
            selected_nodes=[0],graph=dict(nodes=[dict(id=0,calls=[],terminal=False),dict(id=1,calls=[],terminal=False)])))]
        self.labels=[dict(symbol_id='f',node_id=0,relevance='relevant',reason='dependency',evidence=[{}]),
                     dict(symbol_id='f',node_id=1,relevance='irrelevant_candidate',reason='unused local',evidence=[{}])]

    def test_labels_are_advisory_and_full_source_is_preserved(self):
        result=validate_relevance(dict(labels=self.labels),self.views)
        self.assertTrue(result['full_context_preserved'])
        self.assertFalse(result['semantic_correctness_proven'])

    def test_selected_nodes_cannot_be_excluded(self):
        self.labels[0]['relevance']='irrelevant_candidate'
        with self.assertRaises(ValueError):validate_relevance(dict(labels=self.labels),self.views)

    def test_unknown_and_omitted_nodes_fail(self):
        with self.assertRaises(ValueError):validate_relevance(dict(labels=self.labels[:1]),self.views)
        self.labels[1]['node_id']=999
        with self.assertRaises(ValueError):validate_relevance(dict(labels=self.labels),self.views)

    def test_unknown_analysis_and_calls_cannot_be_pruned(self):
        self.views[0]['view']['graph']['nodes'][1]['calls']=['opaque']
        with self.assertRaises(ValueError):validate_relevance(dict(labels=self.labels),self.views)


if __name__=='__main__':unittest.main()
