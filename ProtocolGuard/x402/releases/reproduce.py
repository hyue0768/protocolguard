"""Replay preserved source slices, without Git, network, model calls or payments."""
import argparse,gzip,json,subprocess
from pathlib import Path
BASE=Path(__file__).resolve().parent

def replay(sha,case=None):
    inputs=json.loads(gzip.decompress((BASE/'events'/sha/'dynamic-inputs.json.gz').read_bytes()))
    output=[]
    for item in inputs:
        if item['backend']=='typescript':
            for runtime in ['web_base64_globals','buffer_only']:
                request={**item['request'],'runtime':runtime}
                p=subprocess.run(['node',str(BASE/'ts_probe.cjs')],input=json.dumps(request)+'\n',text=True,capture_output=True,timeout=15,check=True)
                r=json.loads(p.stdout);r.update(runtime=runtime,paths=item['paths'],backend='typescript')
                if case:r['results']=[x for x in r.get('results',[]) if x['name']==case]
                output.append(r)
        else:
            p=subprocess.run([str(BASE.parent/'.venv/bin/python'),str(BASE/'python_probe.py')],input=json.dumps(item['request']),text=True,capture_output=True,timeout=15,check=True)
            r=json.loads(p.stdout);r['backend']='python'
            if case:r['results']=[x for x in r.get('results',[]) if x['name']==case]
            output.append(r)
    return output
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--sha',default='94d7f2c0d2769b2edda9e4c2474691d8ef2530f2');p.add_argument('--case',default='required_header_unicode_roundtrip')
    a=p.parse_args();print(json.dumps(replay(a.sha,a.case),indent=2,ensure_ascii=False))
