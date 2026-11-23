"""Separate repository snapshot checks from evidence about a named published package."""
import json,re
import audit
p=audit.BASE
repo=audit.Repo();cache={};records=[]
try:
    for row in json.loads((p/'inventory.json').read_text()):
        sha=row['sha']
        if sha not in cache:
            packages=[]
            for path,obj in repo.tree(sha).items():
                if path.endswith('package.json') and path.startswith('typescript/packages/'):
                    try:
                        meta=json.loads(repo.blob(obj))
                        packages.append({'path':path,'name':meta.get('name'),'version':meta.get('version')})
                    except Exception:pass
            cache[sha]=packages
        tag=row['tag'];expected=tag[4:].rsplit('@v',1)[0] if tag.startswith('npm-') and '@v' in tag else None
        matches=[x for x in cache[sha] if x['name']==expected] if expected else []
        records.append({'tag':tag,'sha':sha,'expected_npm_name':expected,'matching_source_metadata':matches,
                        'status':'matched_name' if matches else 'not_applicable_non_npm_tag' if not expected else 'no_matching_npm_metadata_in_snapshot',
                        'scope':'tag target source only; registry tarballs not executed or byte-compared'})
    (p/'package-scope.json').write_text(json.dumps(records,indent=2))
finally:repo.close()
