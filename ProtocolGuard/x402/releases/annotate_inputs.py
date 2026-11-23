"""Only compare version behavior when the selected case has identical semantic input."""
import gzip,hashlib,json
from pathlib import Path
BASE=Path(__file__).resolve().parent

def fingerprint(value):return hashlib.sha256(json.dumps(value,sort_keys=True,ensure_ascii=False,separators=(',',':')).encode()).hexdigest()
for path in (BASE/'events').glob('*/dynamic.json'):
    inputs=json.loads(gzip.decompress(path.with_name('dynamic-inputs.json.gz').read_bytes()))
    original=next((x['request'] for x in inputs if x['request'].get('seed')),{'seed':None,'corpus':[]})
    seed=original['seed'];values={c['name']:c['value'] for c in original['corpus']}
    if seed:
        values['coeval_spec_example']=seed;values['required_header_roundtrip']=seed
        unicode=json.loads(json.dumps(seed));unicode['resource']['description']='支付 x402 € 🚀';values['required_header_unicode_roundtrip']=unicode
    rows=json.loads(path.read_text())
    for row in rows:
        for c in row.get('results',[]):
            name=c['name'];value=values.get(name)
            if name.startswith('base64_'):value={'fixed_fixture_name':name,'fixture_revision':2,'backend':row['backend']}
            elif name.startswith(('money_','atomic_','parse_money_')):value={'fixed_fixture_name':name,'fixture_revision':2}
            if value is not None or name=='json_null':c['input_sha256']=fingerprint(value)
    path.write_text(json.dumps(rows,indent=2))
