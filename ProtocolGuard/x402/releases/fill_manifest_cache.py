"""Fetch only missing public manifest blobs, validate Git identity, keep scoped cache."""
import concurrent.futures,gzip,hashlib,json,urllib.request
import audit
repo=audit.Repo();requests={}
try:
    for path in (audit.BASE/'intervals').glob('*.json'):
        interval=json.loads(path.read_text());repo.tree(interval['baseline']);repo.tree(interval['head'])
        for c in interval['changes']:
            if c.get('kind')!='manifest' or c.get('metadata_status')!='unavailable':continue
            for key,sha in [('before_blob',interval['baseline']),('after_blob',interval['head'])]:
                blob=c.get(key)
                if not blob:continue
                try:repo.blob(blob)
                except Exception:requests[blob]=(sha,c['path'])
finally:repo.close()
cache=audit.BASE/'blob-cache';cache.mkdir(exist_ok=True)
def fetch(item):
    blob,(sha,path)=item;url='https://raw.githubusercontent.com/x402-foundation/x402/'+sha+'/'+path
    try:
        data=urllib.request.urlopen(url,timeout=30).read()
        if hashlib.sha1(b'blob '+str(len(data)).encode()+b'\0'+data).hexdigest()!=blob:raise ValueError('Git identity mismatch')
        (cache/(blob+'.gz')).write_bytes(gzip.compress(data,mtime=0))
        return {'blob':blob,'url':url,'status':'fetched_identity_verified'}
    except Exception as e:return {'blob':blob,'url':url,'status':'unavailable','error':str(e)}
results=list(concurrent.futures.ThreadPoolExecutor(6).map(fetch,requests.items()))
(audit.BASE/'manifest-fetch.json').write_text(json.dumps(results,indent=2));print(json.dumps(results,indent=2))
