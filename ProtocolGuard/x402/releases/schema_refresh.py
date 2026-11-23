import json,subprocess
import audit

def main():
    repo=audit.Repo()
    worker=subprocess.Popen(['node',str(audit.BASE/'ts_schema.cjs')],stdin=subprocess.PIPE,stdout=subprocess.PIPE,text=True,bufsize=1)
    try:
        for path in sorted((audit.BASE/'events').glob('*/summary.json')):
            summary=json.loads(path.read_text());tree=repo.tree(summary['sha']);key='typescript/packages/core/src/schemas/index.ts'
            if key not in tree:continue
            seed,source=audit.seed_for(repo,tree)
            if not seed:continue
            metadata=json.loads(repo.blob(tree['typescript/packages/core/package.json']));dep=metadata.get('dependencies',{}).get('zod','')
            req=dict(source=repo.blob(tree[key]),dependency=dep,seed=seed,corpus=audit.corpus(seed))
            worker.stdin.write(json.dumps(req)+'\n');worker.stdin.flush();r=json.loads(worker.stdout.readline())
            r.update(backend='typescript_zod_schema',paths=[key],blob_ids={key:tree[key]},seed_source=source)
            for case in r.get('results',[]):
                if case['name']=='coeval_spec_example':case['assertion']='pass' if case['behavior']=='accepted' else 'failed'
                elif case['name'].startswith(('json_','version_99','missing_resource','network_non_caip2')):case['assertion']='rejected' if case['behavior']=='rejected' else 'accepted_candidate_gap'
                else:case['assertion']='behavior_observation_only'
            resultfile=path.parent/'dynamic.json';rows=[x for x in json.loads(resultfile.read_text()) if x['backend']!='typescript_zod_schema'];rows.append(r);resultfile.write_text(json.dumps(rows,indent=2))
            (path.parent/'schema-input.json').write_text(json.dumps(req,indent=2))
            summary.update(dynamic_cases=sum(len(x.get('results',[])) for x in rows),
                candidate_gap_observations=sum(c.get('assertion')=='accepted_candidate_gap' for row in rows for c in row.get('results',[])),
                roundtrip_failures=sum(c.get('assertion')=='failed' for row in rows for c in row.get('results',[])),
                dynamic_harness_errors=[row['harness_error'] for row in rows if 'harness_error' in row])
            path.write_text(json.dumps(summary,indent=2));print(summary['sha'][:9],r.get('harness_error','ok'),flush=True)
    finally:repo.close();worker.stdin.close();worker.wait()

if __name__=='__main__':main()
