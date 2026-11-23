"""Synthetic report provenance/retention checks; no model or SDK execution."""
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import report_audits as reports


class ReportTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup);self.root=Path(self.temp.name)
        self.rows=[]
        for index,commit in enumerate(['one','two']):
            folder=self.root/'versions'/commit
            for stage in ['01-spec','02-rules','03-slices','04-consistency','05-assertions','06-dynamic']:(folder/stage).mkdir(parents=True)
            source=self.root/'shared/code'/commit/'source';source.mkdir(parents=True);(folder/'source').symlink_to(source)
            code='def check(amount):\n    return True\n' if index==0 else 'def check(amount):\n    return amount > 0\ndef nonce(value):\n    return value\n'
            (source/'guard.py').write_text(code)
            reports.put(source.parent/'files.json',[dict(file='guard.py',git_blob=hashlib.sha1(code.encode()).hexdigest())])
            symbols=[dict(id='check',name='check',kind='FunctionDef',file='guard.py',line=1,end=2,parser_status='parsed')]
            if index:symbols.append(dict(id='nonce',name='nonce',kind='FunctionDef',file='guard.py',line=3,end=4,parser_status='parsed'))
            reports.put(source.parent/'symbols.json',symbols)
            row=dict(version_id=commit,tag='pkg@'+commit,commit=commit,spec_bundle_id=commit,folder=str(folder));self.rows.append(row)
            reports.put(folder/'audit.json',dict(mapping=dict(family='pkg',baseline_tag='EMPTY-TREE' if not index else 'pkg@one',baseline_commit='empty' if not index else 'one')))
            reports.put(folder/'01-spec/bundle.json',dict(documents=[]))
            (folder/'analysis.md').write_text('# Initial\n\nManual note. [[1]](#ref-1)\n\n## References\n\n<a id="ref-1"></a>[1] Original. [evidence](audit.json)\n')
            (folder/'refs.bib').write_text('% Preserve this bibliography note.\n')
        reports.put(self.root/'index.json',dict(versions=self.rows))
        folder=Path(self.rows[1]['folder']);rule='0000000000000000-01'
        reports.put(folder/'02-rules'/(rule+'.json'),dict(rule=dict(obligation='Check amount',actor='server',message_type=None,normative_strength='must',evidence=[])))
        reports.put(folder/'03-slices'/(rule+'.location/result.json'),dict(handlers=[],context=['check'],rationale='Only an index was supplied.'))

    def test_changed_symbols_are_observations_not_security_fixes(self):
        reports.run(self.root)
        delta=reports.read(Path(self.rows[1]['folder'])/'evolution.json')
        self.assertEqual([s['name'] for s in delta['added_symbols']],['nonce'])
        self.assertEqual([s['name'] for s in delta['modified_symbols']],['check'])
        self.assertEqual(delta['semantic_security_change'],'unverified')
        summary=reports.read(Path(self.rows[1]['folder'])/'analysis-evidence.json')
        self.assertEqual(summary['observed']['located_handlers'],0)
        self.assertEqual(summary['rules'][0]['review_status'],'not_run')

    def test_manual_text_backup_and_managed_refresh_are_preserved(self):
        original=(Path(self.rows[1]['folder'])/'analysis.md').read_text();reports.run(self.root)
        folder=Path(self.rows[1]['folder']);first=(folder/'analysis.md').read_text()
        self.assertEqual((folder/'analysis.before-live-report.md').read_text(),original)
        self.assertIn('Manual note.',first);self.assertIn('handler 为空',first)
        reports.run(self.root);self.assertEqual((folder/'analysis.md').read_text(),first)
        self.assertIn('% Preserve this bibliography note.',(folder/'refs.bib').read_text())

    def test_unknown_baseline_does_not_become_first_snapshot(self):
        folder=Path(self.rows[1]['folder']);meta=reports.read(folder/'audit.json');meta['mapping'].update(baseline_commit='unavailable',baseline_tag='other')
        reports.put(folder/'audit.json',meta);reports.run(self.root)
        delta=reports.read(folder/'evolution.json');self.assertEqual(delta['status'],'baseline_unavailable')
        self.assertNotIn('added_files',delta)

    def test_tables_are_contiguous_and_subset_refresh_keeps_other_versions(self):
        reports.run(self.root);reports.run(self.root,['two'])
        body=(self.root/'EVOLUTION.md').read_text()
        self.assertIn('pkg@one',body);self.assertIn('pkg@two',body)
        self.assertNotIn('|\n\n|',body)
        aggregate=reports.read(self.root/'analysis-summary.json')
        self.assertEqual(aggregate['observed']['reviews'],0)
        self.assertEqual(aggregate['whole_protocol_compliance'],'unknown')
        self.assertIn('尚无有效的 spec–源码一致性审查结果',(self.root/'analysis.md').read_text())


if __name__=='__main__':unittest.main()
