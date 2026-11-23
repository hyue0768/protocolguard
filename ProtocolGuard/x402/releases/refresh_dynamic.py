"""Refresh changed bounded probes, retaining static results and original inputs."""
import json
import audit

def main():
    repo=audit.Repo();node=audit.Node()
    try:
        for i,path in enumerate(sorted((audit.BASE/'events').glob('*/summary.json')),1):
            summary=json.loads(path.read_text());sha=summary['sha'];dest=path.parent
            rows=audit.dynamic(repo,node,repo.tree(sha),sha,dest/'dynamic.json')
            extra=[]
            for row in rows:
                if row.get('backend')!='typescript_vm_source_slice':continue
                paths=row['paths'];text='\n'.join(repo.blob(repo.tree(sha)[p]) for p in paths)
                seed,src=audit.seed_for(repo,repo.tree(sha))
                result=node.call(dict(mode='dynamic',path='slice.ts',source=text,seed=seed,corpus=audit.corpus(seed),runtime='buffer_only'))
                result.update(backend='typescript_vm_source_slice',runtime='buffer_only',paths=paths,blob_ids=row['blob_ids'],seed_source=src)
                for c in result.get('results',[]):
                    if 'roundtrip' in c['name'] or c['name']=='base64_decode_utf8':c['assertion']='pass' if c.get('value') is True else 'failed'
                    elif c['name'].startswith(('json_','version_99','missing_resource','network_non_caip2')):c['assertion']='rejected' if c['behavior'] in ('rejected','threw') else 'accepted_candidate_gap'
                    else:c['assertion']='behavior_observation_only'
                extra.append(result)
                row['runtime']='web_base64_globals'
            rows+=extra
            for row in rows:
                for c in row.get('results',[]):
                    if c['name']=='base64_decode_utf8':c['assertion']='pass' if c.get('value') is True else 'failed'
            (dest/'dynamic.json').write_text(json.dumps(rows,indent=2))
            summary.update(dynamic_cases=sum(len(x.get('results',[])) for x in rows),
                candidate_gap_observations=sum(c.get('assertion')=='accepted_candidate_gap' for r in rows for c in r.get('results',[])),
                roundtrip_failures=sum(c.get('assertion')=='failed' for r in rows for c in r.get('results',[])),
                dynamic_harness_errors=[r['harness_error'] for r in rows if 'harness_error' in r])
            path.write_text(json.dumps(summary,indent=2))
            print(i,sha[:9],summary['dynamic_cases'],flush=True)
    finally:repo.close();node.close()

if __name__=='__main__':main()
