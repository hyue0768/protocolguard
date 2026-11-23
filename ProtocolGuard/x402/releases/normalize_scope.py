import json,collections
import audit
p=audit.BASE
corrections=[]
for path in (p/'events').glob('*/static.json'):
    original=json.loads(path.read_text());rows=[r for r in original if audit.code(r['path'])]
    excluded=[r for r in original if not audit.code(r['path'])]
    if excluded:corrections.append({'sha':path.parent.name,'excluded_test_files':excluded})
    path.write_text(json.dumps(rows,indent=2))
    summary=path.with_name('summary.json');s=json.loads(summary.read_text());s.update(implementation_files=len(rows),static_status_counts=dict(collections.Counter(x['status'] for x in rows)),syntax_errors=sum(bool(x['parse_errors']) for x in rows));summary.write_text(json.dumps(s,indent=2))
for path in (p/'intervals').glob('*.json'):
    original=json.loads(path.read_text());items=original['changes'] if isinstance(original,dict) else original
    rows=[r for r in items if audit.code(r['path']) or audit.manifest(r['path']) or r['path'].startswith('specs/')]
    if isinstance(original,dict):original['changes']=rows
    else:original=rows
    path.write_text(json.dumps(original,indent=2))
(p/'scope-corrections.json').write_text(json.dumps(corrections,indent=2))
