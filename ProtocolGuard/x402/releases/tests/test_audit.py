import importlib.util,json,sys,unittest
from pathlib import Path
BASE=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(BASE))
import audit,reproduce
class AuditTest(unittest.TestCase):
    def test_live_tag_coverage_and_baselines(self):
        data=json.loads((BASE/'results.json').read_text());live=json.loads((BASE/'live-tags.json').read_text())['tags']
        self.assertEqual({x['tag'] for x in data['tags']},{x['name'] for x in live})
        self.assertEqual(len(data['tags']),len(live))
        for r in data['tags']:
            self.assertTrue((BASE/r['event_report']).exists())
            interval=json.loads((BASE/r['interval_file']).read_text())
            if isinstance(interval,dict):self.assertEqual(interval['head'],r['sha']);self.assertEqual(interval['baseline'],r['baseline_sha'])
    def test_structural_guards_and_test_scope(self):
        self.assertFalse(audit.code('e2e/test.ts'));self.assertFalse(audit.code('go/example_test.go'))
        self.assertTrue(audit.code('go/server.go'))
        node=audit.Node()
        try:
            r=node.call({'mode':'static','path':'x.ts','source':'export function check(x:number){if(x<1) throw new Error("no");return x;}'} )
            self.assertEqual(r['symbols'][0]['guards'],['x<1'])
        finally:node.close()
    def test_preserved_v2_unicode_witness_and_buffer_control(self):
        rows=reproduce.replay('94d7f2c0d2769b2edda9e4c2474691d8ef2530f2','required_header_unicode_roundtrip')
        browser=[c for r in rows if r.get('runtime')=='web_base64_globals' for c in r.get('results',[])]
        buffer=[c for r in rows if r.get('runtime')=='buffer_only' for c in r.get('results',[])]
        self.assertTrue(any(c['behavior']=='threw' for c in browser))
        self.assertTrue(any(c.get('value') is True for c in buffer))
    def test_no_fabricated_model_verdict(self):
        import sqlite3
        for db in (BASE/'events').glob('*/contexts.db'):
            with sqlite3.connect(db) as conn:self.assertEqual(conn.execute('SELECT count(*) FROM rule_code_snippet WHERE llm_response IS NOT NULL').fetchone()[0],0)
if __name__=='__main__':unittest.main()
