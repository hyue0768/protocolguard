"""Bounded per-source reviews, with explicit partial-context aggregation.

No model calls during planning. Original artifacts and source lines stay intact.
"""
import hashlib
import json
from pathlib import Path
from copy import deepcopy
import judge_wrapper
from context_encoding import pack_context

TARGET=55000
SUFFIX=' This is a partial source partition. Inspect all supplied lines, identify missing cross-partition context, and never infer global absence or whole-protocol compliance.'


def size(instruction,value):
    user='Return a valid json object only.\n\n'+json.dumps(pack_context(value),ensure_ascii=False,separators=(',',':'))
    request=judge_wrapper.payload(dict(model='gpt-5.6-sol',reasoning='medium'),instruction,user)
    return judge_wrapper.prompt_characters(request)


def identity(value):
    return hashlib.sha256(json.dumps(value,ensure_ascii=False,sort_keys=True).encode()).hexdigest()


def partition(value,instruction):
    original=value['slice'];code=original['code']
    all_ids={d.get('symbol_id') for d in code}
    all_locations={(d['file'],l['line']) for d in code for l in d['lines']}
    def packet(docs):
        result=deepcopy(value);s=result['slice'];s['code']=deepcopy(docs)
        ids={d.get('symbol_id') for d in docs}
        locations={(d['file'],l['line']) for d in docs for l in d['lines']}
        for name in ['unresolved','resolutions']:
            if isinstance(original.get(name),dict):
                s[name]={k:v for k,v in original[name].items() if k in ids or k not in all_ids}
        if isinstance(original.get('field_evidence'),list):
            s['field_evidence']=[e for e in original['field_evidence']
                if (e.get('file'),e.get('line')) in locations or (e.get('file'),e.get('line')) not in all_locations]
        result['partition_scope']=dict(partial_source_context=True,global_call_graph_retained=True,
            cross_partition_dispatch_proven=False,original_context_sha256=identity(value))
        return result
    pieces=[]
    def split(doc):
        if size(instruction,packet([doc]))<=TARGET:pieces.append(doc);return
        if len(doc['lines'])<2:raise ValueError('Review fixed context or one source line exceeds partition budget; no request sent')
        middle=len(doc['lines'])//2
        split(dict(doc,lines=doc['lines'][:middle]));split(dict(doc,lines=doc['lines'][middle:]))
    for doc in code:split(doc)
    packets=[];current=[]
    for doc in pieces:
        if current and size(instruction,packet(current+[doc]))>TARGET:
            packets.append(packet(current));current=[]
        current.append(doc)
    if current or not packets:packets.append(packet(current))
    if any(size(instruction,p)>TARGET for p in packets):raise ValueError('Review partition fixed context exceeds budget; no request sent')
    expected={(d.get('symbol_id'),d['file'],l['line'],l['text']) for d in code for l in d['lines']}
    supplied={(d.get('symbol_id'),d['file'],l['line'],l['text']) for p in packets for d in p['slice']['code'] for l in d['lines']}
    if expected!=supplied:raise ValueError('Review partition lost source lines')
    return packets


def inputs(folder,rule_id):
    import version_audit as a
    focus=folder/'03-slices'/(rule_id+'.relevance')/'result.json'
    return dict(rule=a.read(folder/'02-rules'/(rule_id+'.json')),
                slice=a.read(folder/'03-slices'/(rule_id+'.slice')/'slice.json'),norms=a.norms(folder),
                relevance_view=a.read(focus) if focus.is_file() else None)


def prompt():
    import version_audit as a
    return a.COMMON+''' Check this atomic rule against supplied source and coeval norms. Return rule_id, status='model_judgment_unverified', findings (at most 4 objects with id, kind implementation_support/implementation_noncompliance_candidate/trust_assumption/unknown, conclusion, assumptions, evidence, missing_context), limitations. Distinguish parser acceptance from endpoint compliance. Repeated judgments may be cached by the service and do not prove independent agreement.'''+SUFFIX


def request_budget(folder,rule_id,stage,review_mode='triple'):
    packets=partition(inputs(folder,rule_id),prompt())
    return len(packets)*(4 if stage=='review' and review_mode=='triple' else 1)


def run_review(args,folder):
    import version_audit as a
    data=inputs(folder,args.rule);packets=partition(data,prompt());out=folder/'04-consistency'/args.rule
    mode=getattr(args,'review_mode','triple');per_chunk=1 if mode=='single' else 4
    if args.max_calls<per_chunk*len(packets):raise ValueError(f'Chunked review requires explicit --max-calls {per_chunk*len(packets)} before any request')
    manifest=out/'chunk-plan.json'
    plan=dict(input_sha256=identity(data),partition_sha256=[identity(p) for p in packets],
              partition_characters=[size(prompt(),p) for p in packets],source_lines_preserved=True,
              scope='per-partition review; cross-partition semantics remain unverified')
    plan['review_mode']=mode
    if out.exists():
        if not manifest.exists() or a.read(manifest)!=plan:raise ValueError('Review attempt/input differs; inspect without overwriting')
    else:a.save(manifest,plan)
    results=[];model=a.Model(args,out)
    def call(label,instruction,value,path,docs):
        request_path=out/(label+'.request.json')
        if path.is_file():
            # An already validated checkpoint must match its original request,
            # raw model response, and permitted formatting normalization.
            from evidence_format import normalize,documents
            request=a.read(request_path)
            user='Return a valid json object only.\n\n'+json.dumps(pack_context(value),ensure_ascii=False,separators=(',',':'))
            if request.get('messages')!=[dict(role='system',content=instruction),dict(role='user',content=user)]:
                raise ValueError('Chunk checkpoint request changed')
            result=a.read(path)
            if normalize(a.read(out/(label+'.response.txt')),documents(value))!=result:raise ValueError('Chunk checkpoint response changed')
        else:
            if request_path.exists():raise ValueError('Incomplete chunk request exists; inspect before any resubmission')
            result=model.call(label,instruction,value)
        a.validate_review(result,args.rule,docs)
        if not path.is_file():a.save(path,result)
        return result
    for number,packet in enumerate(packets,1):
        part=out/'chunks'/f'{number:03}';docs=packet['norms']+packet['slice']['code'];judgments=[]
        for j in range(1,2 if mode=='single' else 4):
            label=f'chunk-{number:03}-judge{j}'
            judgments.append(call(label,prompt(),packet,part/f'judge{j}.json',docs))
        synthesis_input=dict(packet,judgments=judgments)
        instruction=prompt()+' Reconcile the supplied judgments; preserve disagreements and missing context.'
        if mode=='single':
            result=deepcopy(judgments[0]);result['review_mode']='single';result['model_synthesis_performed']=False
            a.save(part/'synthesis.json',result)
        elif size(instruction,synthesis_input)<=judge_wrapper.MAX_PROMPT_CHARACTERS:
            result=call(f'chunk-{number:03}-synthesis',instruction,synthesis_input,part/'synthesis.json',docs)
        else:
            result=aggregate(args.rule,judgments,'deterministic_union_synthesis_input_over_budget')
            a.validate_review(result,args.rule,docs);a.save(part/'synthesis.json',result)
        results.append(result)
    result=aggregate(args.rule,results,'partitioned_review_no_global_semantic_synthesis')
    result.update(partitioned_review=True,partition_count=len(packets),input_sha256=identity(data),review_mode=mode)
    a.validate_review(result,args.rule,data['norms']+data['slice']['code'])
    a.save(out/'synthesis.json',result)
    return result,model.calls


def aggregate(rule_id,values,method):
    findings=[]
    for i,value in enumerate(values,1):
        for j,finding in enumerate(value['findings'],1):
            finding=deepcopy(finding);finding['id']=f'P{i:03}-{j:03}';finding['source_partition']=i
            findings.append(finding)
    return dict(rule_id=rule_id,status='model_judgment_unverified',findings=findings,aggregation_method=method,
                limitations=['Partial-context judgments are retained, not a whole-program semantic proof. Cross-partition dependencies and conflicting conclusions remain unresolved.'],
                partition_limitations=[v.get('limitations') for v in values],
                local_evidence_corrections=[c for v in values for c in v.get('local_evidence_corrections',[])])


def run_assertions(args,folder,choices):
    import version_audit as a
    data=inputs(folder,args.rule);packets=partition(data,prompt());out=folder/'05-assertions'/args.rule
    resume=getattr(args,'resume_assertions',False)
    if out.exists() and not resume:raise ValueError('Assertion attempt exists; inspect before continuation')
    if resume:
        marker=a.read(out/'assertion-resume.json')
        if marker['input_sha256']!=identity(data) or marker['catalog_sha256']!=identity(choices):raise ValueError('Assertion checkpoint inputs changed')
        for name,digest in marker['preserved_sha256'].items():
            if Path(name).name!=name or a.sha(out/name)!=digest:raise ValueError('Assertion checkpoint changed')
    plans=[];known={c['id'] for c in choices}
    instruction=a.COMMON+''' Produce DECLARATIVE assertions only, no executable code or new attack inputs. Return rule_id, adapter_status (supported_component_cases/adapter_missing), assertions (id, case_id from catalog, predicate rejected/roundtrip_equal/observe_only, justification, assumptions, evidence), uncovered_requirements. Missing adapters are not passing tests.'''+SUFFIX
    requests=[]
    for i,packet in enumerate(packets,1):
        review=a.read(folder/'04-consistency'/args.rule/'chunks'/f'{i:03}'/'synthesis.json')
        value=dict(packet,review=review,case_catalog=choices)
        if size(instruction,value)>judge_wrapper.MAX_PROMPT_CHARACTERS:raise ValueError('Assertion chunk exceeds input budget; no request sent')
        requests.append(value)
    remaining=sum(not (out/f'part-{i:03}.json').exists() for i in range(1,len(requests)+1))
    if args.max_calls<remaining:raise ValueError('Insufficient explicit assertion request cap; no request sent')
    model=a.Model(args,out) if remaining else None
    for i,value in enumerate(requests,1):
        docs=value['norms']+value['slice']['code']
        label=f'plan-part-{i:03}';path=out/f'part-{i:03}.json'
        from assertion_validation import validate
        if path.is_file():
            from evidence_format import normalize,documents
            request=a.read(out/(label+'.request.json'))
            user='Return a valid json object only.\n\n'+json.dumps(pack_context(value),ensure_ascii=False,separators=(',',':'))
            if request.get('messages')!=[dict(role='system',content=instruction),dict(role='user',content=user)]:raise ValueError('Assertion checkpoint prompt differs')
            plan=validate(normalize(a.read(out/(label+'.response.txt')),documents(value)),args.rule,docs,choices)
        else:
            if (out/(label+'.request.json')).exists():raise ValueError('Incomplete assertion request exists; inspect before resubmission')
            plan=validate(model.call(label,instruction,value),args.rule,docs,choices)
        for item in plan['assertions']:item['id']=f'P{i:03}-'+str(item.get('id','assertion'))
        if path.is_file() and a.read(path)!=plan:raise ValueError('Assertion checkpoint differs from original response')
        a.save(out/f'part-{i:03}.json',plan);plans.append(plan)
    assertions=[x for p in plans for x in p['assertions']]
    result=dict(rule_id=args.rule,adapter_status='supported_component_cases' if assertions else 'adapter_missing',assertions=assertions,
                uncovered_requirements=[p.get('uncovered_requirements') for p in plans],partitioned_planning=True,
                non_executable_observations=[x for p in plans for x in p.get('non_executable_observations',[])],
                limitations=['Only supplied component cases; no full-protocol dynamic guarantee.'])
    a.save(out/'plan.json',result)
    return result
