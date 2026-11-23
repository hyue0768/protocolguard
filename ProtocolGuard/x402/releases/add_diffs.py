"""Retain real source diffs, so implementation behavior can be reviewed without inference."""
import difflib,gzip,json
import audit
repo=audit.Repo()
try:
    for path in sorted((audit.BASE/'intervals').glob('*.json')):
        obj=json.loads(path.read_text());diffs=[]
        repo.tree(obj['baseline']);repo.tree(obj['head'])
        for change in obj['changes']:
            if not audit.code(change['path']):continue
            before=repo.blob(change['before_blob']).splitlines() if change['before_blob'] else []
            after=repo.blob(change['after_blob']).splitlines() if change['after_blob'] else []
            diffs.extend(difflib.unified_diff(before,after,fromfile=obj['baseline']+'/'+change['path'],tofile=obj['head']+'/'+change['path'],lineterm=''))
        path.with_suffix('.implementation.diff.gz').write_bytes(gzip.compress(('\n'.join(diffs)+'\n').encode(),mtime=0))
finally:repo.close()
