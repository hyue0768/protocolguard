"""Supplemental check of source-map content from integrity-verified published core 2.1.0."""
import gzip,hashlib,json,subprocess
from pathlib import Path
BASE=Path(__file__).resolve().parent
sources=json.loads((BASE/'package-evidence/core-2.1.0-embedded-sources.json').read_text())
chosen={}
for suffix in ['src/utils/index.ts','src/http/index.ts']:
    choices={text for path,text in sources.items() if path.endswith(suffix)}
    if len(choices)!=1:raise ValueError('Ambiguous embedded sources for '+suffix)
    chosen[suffix]=choices.pop()
old=json.loads(gzip.decompress((BASE/'events/94d7f2c0d2769b2edda9e4c2474691d8ef2530f2/dynamic-inputs.json.gz').read_bytes()))
fixture=next(x['request'] for x in old if x['backend']=='typescript' and 'core/' in ' '.join(x['paths']))
results=[]
for runtime in ['web_base64_globals','buffer_only']:
    request={**fixture,'source':'\n'.join(chosen.values()),'runtime':runtime}
    p=subprocess.run(['node',str(BASE/'ts_probe.cjs')],input=json.dumps(request)+'\n',text=True,capture_output=True,check=True,timeout=15)
    result=json.loads(p.stdout);result.update(runtime=runtime,provenance='SRI-verified npm 2.1.0 source map; not the Git tag target',fixture_source='protocol v2 example from core 2.0.0 repository snapshot')
    results.append(result)
(BASE/'package-evidence/core-2.1.0-dynamic.json').write_text(json.dumps(results,indent=2))
print(json.dumps([{'runtime':r['runtime'],'unicode':[x for x in r.get('results',[]) if x['name']=='required_header_unicode_roundtrip']} for r in results],indent=2))
