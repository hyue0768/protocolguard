"""Read-only historical inputs; write an explicit per-tag, per-interval audit.
No model calls. Static structure and bounded component execution are not semantic proofs.
"""
import argparse, ast, collections, datetime, functools, gzip, hashlib, importlib.util
import json, os, re, sqlite3, subprocess, sys
from pathlib import Path
BASE=Path(__file__).resolve().parent
PG=BASE.parents[1]
ROOT=PG.parent
GIT=BASE/'upstream.git'
SNAPSHOTS={'07c4cafccdb41012fafc2c84252cc5ac1954c810':ROOT/'x402_upstream_20261113_07c4caf_snapshot',
           '2178d4b77aff61395c375bbdf30757876393b85d':ROOT/'x402_upstream_20261113_2178d4b_snapshot'}
EMPTY='4b825dc642cb6eb9a060e54bf8d69288fbee4904'
ENV={**os.environ,'GIT_NO_LAZY_FETCH':'1','GIT_OPTIONAL_LOCKS':'0'}

def git(*args):
    return subprocess.check_output(['git','-C',str(GIT),*args],env=ENV,stderr=subprocess.PIPE)

def family(tag):
    return tag.rsplit('@v',1)[0] if '@v' in tag else ('go' if tag.startswith('go/v') else 'repository')

def code(path):
    parts=Path(path).parts
    return Path(path).suffix in ('.py','.ts','.tsx','.go','.sol','.rs') and not any(x in parts for x in ('test','tests','e2e','examples','demo','demos','site','docs','node_modules','vendor')) and Path(path).name not in ('test.ts','test.py','test.go') and not re.search(r'([._]test|[._]spec)\.',path)

def manifest(path):
    return Path(path).name in ('package.json','go.mod','pyproject.toml','Cargo.toml','requirements.txt','requirements-dev.txt') and not any(x in Path(path).parts for x in ('examples','site','e2e','tests','test','node_modules','vendor'))

class Repo:
    def __init__(self):
        self.proc=subprocess.Popen(['git','-C',str(GIT),'cat-file','--batch'],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,env=ENV)
        self.snapshot_blobs={}
    @functools.lru_cache(maxsize=200)
    def tree(self,sha):
        if sha==EMPTY:return {}
        if sha in SNAPSHOTS:
            treefile=BASE.parent/('upstream-tree.json' if sha.startswith('07c4') else 'upstream-tree-latest.json')
            tree=json.loads(treefile.read_text());result={}
            for x in tree['tree']:
                if x['type']=='blob':
                    result[x['path']]=x['sha'];self.snapshot_blobs[x['sha']]=SNAPSHOTS[sha]/x['path']
            return result
        raw=git('ls-tree','-r','-z',sha);out={}
        for row in raw.split(b'\0'):
            if not row:continue
            meta,path=row.split(b'\t',1);mode,kind,obj=meta.split()
            if kind==b'blob':out[path.decode()]=obj.decode()
        return out
    @functools.lru_cache(maxsize=1024)
    def blob(self,obj):
        cached=BASE/'blob-cache'/(obj+'.gz')
        if cached.exists():
            data=gzip.decompress(cached.read_bytes())
        elif obj in self.snapshot_blobs:
            data=self.snapshot_blobs[obj].read_bytes()
        else:
            self.proc.stdin.write((obj+'\n').encode());self.proc.stdin.flush();head=self.proc.stdout.readline().split()
            if len(head)<3:raise ValueError('missing Git blob '+obj)
            n=int(head[2]);data=self.proc.stdout.read(n);self.proc.stdout.read(1)
        if hashlib.sha1(b'blob '+str(len(data)).encode()+b'\0'+data).hexdigest()!=obj:raise ValueError('blob identity mismatch '+obj)
        return data.decode('utf-8')
    def close(self):
        self.proc.stdin.close();self.proc.wait();self.proc.stdout.close()

class Node:
    def __init__(self):self.p=subprocess.Popen(['node',str(BASE/'ts_probe.cjs')],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,bufsize=1)
    def call(self,data):
        self.p.stdin.write(json.dumps(data)+'\n');self.p.stdin.flush();line=self.p.stdout.readline()
        if not line:raise RuntimeError('TS worker exited')
        return json.loads(line)
    def close(self):self.p.stdin.close();self.p.wait();self.p.stdout.close();self.p.stderr.close()

class Analyzer:
    def __init__(self,repo,node):
        self.repo,self.node=repo,node;self.cache=BASE/'static-cache';self.cache.mkdir(exist_ok=True)
        import tree_sitter,tree_sitter_go
        self.go=tree_sitter.Parser(tree_sitter.Language(tree_sitter_go.language()))
    @functools.lru_cache(maxsize=256)
    def parse(self,path,obj):
        cache=self.cache/(obj+Path(path).suffix+'.json.gz')
        if cache.exists():
            cached=json.loads(gzip.decompress(cache.read_bytes()))
            if cached.get('parser_revision')==2:return cached
        try:
            text=self.repo.blob(obj);lines=text.splitlines();suffix=Path(path).suffix
            errors=[];symbols=[];status='parsed'
            if suffix in ('.ts','.tsx'):
                result=self.node.call(dict(mode='static',path=path,source=text));errors=result.get('parse_errors',[]);symbols=result.get('symbols',[])
                if 'harness_error' in result:raise ValueError(result['harness_error'])
            elif suffix=='.py':
                tree=ast.parse(text,filename=path)
                def walk(node,scope=''):
                    for n in ast.iter_child_nodes(node):
                        if isinstance(n,(ast.FunctionDef,ast.AsyncFunctionDef,ast.ClassDef)):
                            calls=[ast.unparse(c.func) for c in ast.walk(n) if isinstance(c,ast.Call)]
                            symbols.append(dict(name=scope+n.name,kind=type(n).__name__,line=n.lineno,end=n.end_lineno,calls=sorted(set(calls)),guards=sorted({ast.unparse(c.test) for c in ast.walk(n) if isinstance(c,(ast.If,ast.Assert,ast.IfExp))})))
                            walk(n,scope+n.name+'.')
                        else:walk(n,scope)
                walk(tree)
            elif suffix=='.go':
                source=text.encode();tree=self.go.parse(source)
                def walk(n):
                    if n.type in ('function_declaration','method_declaration','type_declaration'):
                        name=n.child_by_field_name('name')
                        symbols.append(dict(name=source[name.start_byte:name.end_byte].decode() if name else source[n.start_byte:n.end_byte].decode().splitlines()[0],kind=n.type,line=n.start_point.row+1,end=n.end_point.row+1,calls=[]))
                    if n.type=='ERROR' or n.is_missing:errors.append({'line':n.start_point.row+1,'message':'tree-sitter '+n.type})
                    for c in n.children:walk(c)
                walk(tree.root_node)
            else:
                status='lexical_only_no_parser'
                for i,line in enumerate(lines,1):
                    m=re.search(r'\b(function|contract|struct|fn|impl)\s+(\w+)',line)
                    if m:symbols.append(dict(name=m[2],kind=m[1],line=i,end=i,calls=[]))
            for symbol in symbols:
                fragment='\n'.join(lines[symbol['line']-1:symbol['end']])
                symbol['sha256']=hashlib.sha256(fragment.encode()).hexdigest()
            result={'parser_revision':2,'status':status,'parse_errors':errors,'symbols':symbols}
        except Exception as e:result={'parser_revision':2,'status':'unavailable','error':type(e).__name__+': '+str(e),'symbols':[],'parse_errors':[]}
        cache.write_bytes(gzip.compress(json.dumps(result).encode(),mtime=0));return result


def build_inventory(repo):
    historical={x['tag']:x for x in json.loads((ROOT/'x402_release_history/history.json').read_text()) if x['tag']!='UNRELEASED-HEAD'}
    live=json.loads((BASE/'live-tags.json').read_text())['tags'];rows=[]
    for t in live:
        tag,sha=t['name'],t['commit']['sha'];prior=historical.get(tag)
        if prior and prior['sha']!=sha:raise ValueError('Retag detected; manual decision required '+tag)
        if prior:date=prior['commit_date'];baseline=prior['baseline_sha'];base_tag=prior['baseline']
        else:
            date='2026-11-12T22:04:42+00:00' if sha.startswith('07c4') else git('show','-s','--format=%cI',sha).decode().strip()
            choices=[x for x in historical.values() if x['family']==family(tag)]
            prev=max(choices,key=lambda x:datetime.datetime.fromisoformat(x['commit_date'])) if choices else None
            baseline=prev['sha'] if prev else EMPTY;base_tag=prev['tag'] if prev else 'EMPTY-TREE'
        rows.append(dict(tag=tag,sha=sha,family=family(tag),commit_date=date,baseline_sha=baseline,baseline_tag=base_tag,
                         publication_time=(prior or {}).get('registry_published_at'),publication_note='historical registry metadata; latest tags not refreshed individually'))
    rows.sort(key=lambda x:(datetime.datetime.fromisoformat(x['commit_date']),x['tag']))
    (BASE/'inventory.json').write_text(json.dumps(rows,indent=2))
    return rows


def candidates(repo,tree):
    out=[];errors=[]
    spec=importlib.util.spec_from_file_location('pipeline',BASE.parent/'pipeline.py');mod=importlib.util.module_from_spec(spec);spec.loader.exec_module(mod)
    for path,obj in sorted(tree.items()):
        if not path.startswith('specs/') or not path.endswith('.md') or 'template' in path or path.endswith(('README.md','CONTRIBUTING.md')):continue
        try:
            # Use the same segmentation/provenance semantics as the x402 adapter.
            heading=[];fenced=False
            for line,text in enumerate(repo.blob(obj).splitlines(),1):
                if text.lstrip().startswith('```'):fenced=not fenced;continue
                if fenced:continue
                m=re.match(r'^(#{1,6})\s+(.+)',text)
                if m:heading=heading[:len(m[1])-1]+[m[2]];continue
                if re.search(r'\b(MUST(?: NOT)?|SHOULD(?: NOT)?|REQUIRED|must|should|required|shall)\b',text):
                    out.append(dict(id=hashlib.sha256(f'{path}:{line}:{text}'.encode()).hexdigest()[:16],source=path,blob=obj,line=line,heading=heading[:],rule=text.strip(),status='candidate_unreviewed'))
        except Exception as e:errors.append({'path':path,'error':str(e)})
    return out,errors


def seed_for(repo,tree):
    for path in ['specs/x402-specification-v2.md','specs/x402-specification.md','specs/x402-specification-v1.md']:
        if path not in tree:continue
        for block in re.findall(r'```json\s*\n(.*?)```',repo.blob(tree[path]),re.S):
            try:obj=json.loads(block)
            except json.JSONDecodeError:continue
            if isinstance(obj,dict) and obj.get('x402Version')==2 and 'accepts' in obj and 'resource' in obj:return obj,path
    return None,None


def corpus(seed):
    values=[{'name':'json_array','value':[]},{'name':'json_null','value':None},{'name':'json_string','value':'payment'},{'name':'json_number','value':42}]
    if seed:
        for label,fn in [('version_99',lambda x:x.update(x402Version=99)),('missing_resource',lambda x:x.pop('resource',None)),('network_non_caip2',lambda x:x['accepts'][0].update(network='base-mainnet')),
                         ('amount_negative',lambda x:x['accepts'][0].update(amount='-1')),('amount_scientific',lambda x:x['accepts'][0].update(amount='1e3')),
                         ('amount_fractional',lambda x:x['accepts'][0].update(amount='1.5'))]:
            obj=json.loads(json.dumps(seed));fn(obj);values.append({'name':label,'value':obj})
    return values


def dynamic(repo,node,tree,sha,out):
    seed,source=seed_for(repo,tree);cases=corpus(seed)
    ts_paths=[p for p in tree if p.endswith('/src/shared/base64.ts') or p=='typescript/packages/core/src/utils/index.ts' or p=='typescript/packages/core/src/http/index.ts']
    # core util functions and HTTP functions share a context; legacy helpers isolated.
    groups={'core':[p for p in ts_paths if '/core/' in p]}
    for p in ts_paths:
        if '/core/' not in p:groups[p]=[p]
    results=[]; inputs=[]
    for name,paths in groups.items():
        if not paths:continue
        try:
            source_text='\n'.join(repo.blob(tree[p]) for p in paths)
            request=dict(mode='dynamic',path='slice.ts',source=source_text,seed=seed,corpus=cases)
            inputs.append({'backend':'typescript', 'paths':paths,'request':request})
            r=node.call(request)
            r.update(backend='typescript_vm_source_slice',paths=paths,blob_ids={p:tree[p] for p in paths},seed_source=source)
            results.append(r)
        except Exception as e:results.append({'backend':'typescript','harness_error':str(e)})
    py={};paths={}
    for key,suffix in [('base','/schemas/base.py'),('payments','/schemas/payments.py'),('encoding','/encoding.py')]:
        choices=[p for p in tree if p.startswith('python/') and p.endswith(suffix) and '/test' not in p]
        if choices:
            path=sorted(choices,key=len)[0];py[key]=repo.blob(tree[path]);paths[key]=path
    if py:
        inputs.append({'backend':'python','request':dict(files=py,paths=paths,seed=seed,corpus=cases)})
        try:
            r=subprocess.run([str(PG/'x402/.venv/bin/python'),str(BASE/'python_probe.py')],input=json.dumps(dict(files=py,paths=paths,seed=seed,corpus=cases)),text=True,capture_output=True,timeout=15,env={**os.environ,'PYTHONDONTWRITEBYTECODE':'1'})
            probe=json.loads(r.stdout);probe.update(backend='python_component',paths=list(paths.values()),blob_ids={p:tree[p] for p in paths.values()},seed_source=source);results.append(probe)
        except Exception as e:results.append({'backend':'python','harness_error':str(e)})
    for result in results:
        for case in result.get('results',[]):
            name=case['name']
            if 'roundtrip' in name:case['assertion']='pass' if case.get('value') is True or case['behavior']=='accepted' else 'failed'
            elif name.startswith(('json_','version_99','missing_resource','network_non_caip2')):
                case['assertion']='rejected' if case['behavior'] in ('rejected','threw') else 'accepted_candidate_gap'
                case['oracle_scope']='coeval v2 object/schema requirement; component boundary only, not end-to-end bug'
            else:case['assertion']='behavior_observation_only'
    out.with_name('dynamic-inputs.json.gz').write_bytes(gzip.compress(json.dumps(inputs).encode(),mtime=0))
    out.write_text(json.dumps(results,indent=2))
    return results


def audit_event(repo,analyzer,node,sha,tags):
    dest=BASE/'events'/sha;dest.mkdir(parents=True,exist_ok=True)
    tree=repo.tree(sha);rules,errors=candidates(repo,tree)
    (dest/'candidates.json').write_text(json.dumps(rules,indent=2))
    static=[];selected=[]
    keywords=('PaymentRequired','PaymentRequirements','PaymentPayload','safe_base64','safeBase64','decodePayment','encodePayment','parseMoney','convertToTokenAmount')
    for path,obj in sorted(tree.items()):
        if not code(path):continue
        result=analyzer.parse(path,obj);static.append({'path':path,'blob':obj,'status':result['status'],'parse_errors':result['parse_errors'],'symbols':len(result['symbols']),**({'error':result['error']} if 'error' in result else {})})
        for symbol in result['symbols']:
            if any(k in symbol['name'] for k in keywords):selected.append({'path':path,'blob':obj,**symbol})
    (dest/'static.json').write_text(json.dumps(static,indent=2))
    contexts=[]
    with sqlite3.connect(dest/'contexts.db') as db:
        db.execute('CREATE TABLE IF NOT EXISTS rule_code_snippet(rule_desc TEXT PRIMARY KEY,code_snippet TEXT,call_graph TEXT,llm_response TEXT)')
        db.execute('DELETE FROM rule_code_snippet')
        for symbol in selected:
            names=[k for k in ['PaymentRequired','PaymentRequirements','PaymentPayload'] if k in symbol['name']]
            matched=[r for r in rules if any(n.lower() in r['rule'].lower() for n in names)]
            if not matched:continue
            text='\n'.join(repo.blob(symbol['blob']).splitlines()[symbol['line']-1:symbol['end']])
            for rule in matched:
                label=rule['source']+':'+str(rule['line'])+' '+rule['rule']
                code_text=f"{symbol['path']}:{symbol['line']}-{symbol['end']}\n{text}"
                db.execute('INSERT INTO rule_code_snippet VALUES(?,?,?,NULL) ON CONFLICT(rule_desc) DO UPDATE SET code_snippet=code_snippet || char(10) || excluded.code_snippet',
                           (label,code_text,json.dumps(symbol['calls'])))
            contexts.append({'symbol':symbol,'candidate_ids':[r['id'] for r in matched],'status':'lexical_association_not_semantic_validation'})
    (dest/'contexts.json').write_text(json.dumps(contexts,indent=2))
    dyn=dynamic(repo,node,tree,sha,dest/'dynamic.json')
    result=dict(sha=sha,tags=tags,spec_candidate_count=len(rules),spec_errors=errors,implementation_files=len(static),
                static_status_counts=dict(collections.Counter(x['status'] for x in static)),syntax_errors=sum(bool(x['parse_errors']) for x in static),
                contexts=len(contexts),dynamic_cases=sum(len(x.get('results',[])) for x in dyn),dynamic_harness_errors=[x['harness_error'] for x in dyn if 'harness_error' in x],
                candidate_gap_observations=sum(c.get('assertion')=='accepted_candidate_gap' for r in dyn for c in r.get('results',[])),
                roundtrip_failures=sum(c.get('assertion')=='failed' for r in dyn for c in r.get('results',[])),
                semantic_analysis='not_run_no_authorized_model',directed_fuzzing='not_run',go_dynamic='not_run_no_go_toolchain',solidity_dynamic='not_run_no_evm_harness')
    (dest/'summary.json').write_text(json.dumps(result,indent=2));return result


def interval(repo,analyzer,base,head):
    before,after=repo.tree(base),repo.tree(head);changes=[]
    for path in sorted(before.keys()|after.keys()):
        a,b=before.get(path),after.get(path)
        if a==b:continue
        if not code(path) and not manifest(path) and not(path.startswith('specs/') and path.endswith('.md')):continue
        record={'path':path,'kind':'implementation' if code(path) else 'manifest' if manifest(path) else 'specification','status':'added' if not a else 'removed' if not b else 'modified','before_blob':a,'after_blob':b}
        if code(path):
            old=analyzer.parse(path,a) if a else {'symbols':[]};new=analyzer.parse(path,b) if b else {'symbols':[]}
            o={s['name']:s for s in old['symbols']};n={s['name']:s for s in new['symbols']}
            record['symbols_added']=[n[k] for k in n.keys()-o.keys()]
            record['symbols_removed']=[o[k] for k in o.keys()-n.keys()]
            record['symbols_modified']=[{'name':k,'before':o[k],'after':n[k]} for k in o.keys()&n.keys() if o[k]['sha256']!=n[k]['sha256']]
            record['analysis_status']=[old.get('status'),new.get('status')]
        if manifest(path):
            try:
                old=repo.blob(a) if a else '';new=repo.blob(b) if b else ''
                import difflib
                record['manifest_unified_diff']='\n'.join(difflib.unified_diff(old.splitlines(),new.splitlines(),fromfile=base+'/'+path,tofile=head+'/'+path,lineterm=''))
                if path.endswith('package.json'):
                    o=json.loads(old) if old else {};n=json.loads(new) if new else {}
                    record['changed_keys']={k:{'before':o.get(k),'after':n.get(k)} for k in o.keys()|n.keys() if o.get(k)!=n.get(k)}
                record['metadata_status']='read'
            except Exception as e:record['metadata_status']='unavailable';record['metadata_error']=str(e)
        changes.append(record)
    return changes


def main():
    repo=Repo();node=Node();analyzer=Analyzer(repo,node)
    inventory=build_inventory(repo);groups=collections.defaultdict(list)
    for r in inventory:groups[r['sha']].append(r['tag'])
    head=json.loads((BASE/'official-check.json').read_text())['head']['sha']
    if head not in groups:groups[head]=['UNRELEASED-HEAD']
    summaries=[]
    try:
        for i,(sha,tags) in enumerate(groups.items(),1):
            cache=BASE/'events'/sha/'summary.json'
            result=json.loads(cache.read_text()) if cache.exists() else audit_event(repo,analyzer,node,sha,tags)
            summaries.append(result);print(f'event {i}/{len(groups)} {sha[:9]} files={result["implementation_files"]} cases={result["dynamic_cases"]}',flush=True)
        pairs={};records=[]
        for i,row in enumerate(inventory,1):
            key=row['baseline_sha']+'_'+row['sha'];path=BASE/'intervals'/(key+'.json');path.parent.mkdir(exist_ok=True)
            if not path.exists():path.write_text(json.dumps(interval(repo,analyzer,row['baseline_sha'],row['sha']),indent=2))
            stored=json.loads(path.read_text());changes=stored['changes'] if isinstance(stored,dict) else stored;pairs[key]=True
            records.append({**row,'interval_file':str(path.relative_to(BASE)),
                            'implementation_changes':sum(code(c['path']) for c in changes),'spec_changes':sum(c['path'].startswith('specs/') for c in changes),
                            'event_report':'events/'+row['sha']+'/summary.json','semantic_gap_status':'pending_semantic_review; see component observations'})
        (BASE/'results.json').write_text(json.dumps({'tags':records,'events':summaries,'distinct_intervals':len(pairs)},indent=2))
    finally:repo.close();node.close()

if __name__=='__main__':main()
