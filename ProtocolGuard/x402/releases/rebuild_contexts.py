"""Keep code/spec associations within the declared implementation scope, rebuild NULL-only DBs."""
import json,sqlite3
import audit
repo=audit.Repo()
try:
    for file in (audit.BASE/'events').glob('*/contexts.json'):
        sha=file.parent.name;repo.tree(sha)
        rows=[r for r in json.loads(file.read_text()) if audit.code(r['symbol']['path'])]
        rules={r['id']:r for r in json.loads(file.with_name('candidates.json').read_text())}
        with sqlite3.connect(file.with_name('contexts.db')) as db:
            if db.execute('SELECT count(*) FROM rule_code_snippet WHERE llm_response IS NOT NULL').fetchone()[0]:raise ValueError('Refusing to overwrite semantic results')
            db.execute('DELETE FROM rule_code_snippet')
            for row in rows:
                symbol=row['symbol'];text='\n'.join(repo.blob(symbol['blob']).splitlines()[symbol['line']-1:symbol['end']])
                code=f"{symbol['path']}:{symbol['line']}-{symbol['end']}\n{text}"
                for rid in row['candidate_ids']:
                    r=rules[rid];label=r['source']+':'+str(r['line'])+' '+r['rule']
                    db.execute('INSERT INTO rule_code_snippet VALUES(?,?,?,NULL) ON CONFLICT(rule_desc) DO UPDATE SET code_snippet=code_snippet || char(10) || excluded.code_snippet',
                               (label,code,json.dumps(symbol['calls'])))
        file.write_text(json.dumps(rows,indent=2));sfile=file.with_name('summary.json');s=json.loads(sfile.read_text());s['contexts']=len(rows);sfile.write_text(json.dumps(s,indent=2))
finally:repo.close()
