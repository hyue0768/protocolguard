"""Resolve previously unavailable immutable code blobs without changing history."""
import hashlib
import json
from pathlib import Path
import sys
import urllib.request

HERE=Path(__file__).resolve().parent;JUDGE=HERE.parent;BASE=JUDGE.parent
sys.path.insert(0,str(BASE));from map_release_specs import Sources


def main():
    data=json.loads((JUDGE/'inputs.json').read_text());available={f['git_blob']:(c['commit'],f) for c in data['commits'] for f in c['indexed_files']+c['additional_local_code']}
    missing={}
    for c in data['commits']:
        for f in c['unavailable_code']:missing.setdefault(f['git_blob'],[]).append(dict(commit=c['commit'],file=f['file']))
    out=HERE/'resolved';out.mkdir();sources=Sources();records=[]
    try:
        for oid,occurrences in missing.items():
            reference=available.get(oid);raw=None;origin=None
            if reference:
                commit,item=reference
                if item.get('local_file'):
                    raw=Path(item['local_file']).read_bytes();origin='existing_pinned_local_source'
                else:
                    raw=sources.blob(commit,item['file'],oid);origin='same_blob_in_another_saved_snapshot'
            else:
                first=occurrences[0]
                url='https://raw.githubusercontent.com/x402-foundation/x402/'+first['commit']+'/'+first['file']
                request=urllib.request.Request(url,headers={'User-Agent':'ProtocolGuard-static-source-review'})
                try:
                    with urllib.request.urlopen(request,timeout=30) as response:raw=response.read(2000001)
                    origin=url
                except Exception as error:
                    records.append(dict(git_blob=oid,status='unavailable',error_type=type(error).__name__,occurrences=occurrences));continue
            if len(raw)>2000000 or hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()!=oid:raise ValueError('Code identity mismatch; refuse substitute')
            path=out/(oid+Path(occurrences[0]['file']).suffix);path.write_bytes(raw)
            records.append(dict(git_blob=oid,status='resolved',origin=origin,local_file=str(path),sha256=hashlib.sha256(raw).hexdigest(),occurrences=occurrences))
    finally:sources.close()
    (HERE/'source-resolution.json').write_text(json.dumps(records,ensure_ascii=False,indent=2)+'\n')
    print(json.dumps(dict(blobs=len(records),resolved=sum(x['status']=='resolved' for x in records),occurrences=sum(len(x['occurrences']) for x in records if x['status']=='resolved'))))


if __name__=='__main__':main()
