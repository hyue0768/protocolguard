"""Read-only evidence aggregation into managed Markdown/JSON report sections.

Never calls a model or executes source. Existing prose, references and results
are retained. File/symbol deltas are observations, not semantic security fixes.
"""
import argparse
import collections
import hashlib
import json
import os
from pathlib import Path
import re

import version_audit as audit

BODY_START='<!-- protocolguard:live-analysis:start -->'
BODY_END='<!-- protocolguard:live-analysis:end -->'
REF_START='<!-- protocolguard:live-references:start -->'
REF_END='<!-- protocolguard:live-references:end -->'


def read(path):return json.loads(path.read_text())


def put(path,value):
    path.parent.mkdir(parents=True,exist_ok=True)
    temporary=path.with_suffix(path.suffix+'.tmp')
    temporary.write_text(json.dumps(value,ensure_ascii=False,indent=2)+'\n');temporary.replace(path)


def text(value):
    if value is None:return '未指定'
    if not isinstance(value,str):value=json.dumps(value,ensure_ascii=False)
    return value.replace('\n',' ').replace('|','\\|').replace('<','&lt;').replace('>','&gt;').replace('[','\\[').replace(']','\\]')


def paragraphs(items):
    blocks=[]
    for item in items:
        if item.startswith('|') and blocks and blocks[-1].startswith('|'):blocks[-1]+='\n'+item
        else:blocks.append(item)
    return '\n\n'.join(blocks)


def strip_region(value,start,end):
    if start not in value and end not in value:return value
    if value.count(start)!=1 or value.count(end)!=1:raise ValueError('Malformed managed report markers')
    a=value.index(start);b=value.index(end,a)+len(end)
    return value[:a]+value[b:]


class References:
    def __init__(self,folder,base):self.folder=folder;self.base=base;self.entries=[]
    def cite(self,label,path):
        path=Path(path).absolute()
        for index,(name,existing) in enumerate(self.entries):
            if path==existing:return f'[[{self.base+index+1}]](#pg-ref-{self.base+index+1})'
        self.entries.append((label,path));n=self.base+len(self.entries)
        return f'[[{n}]](#pg-ref-{n})'
    def render(self):
        lines=[];bib=[]
        for index,(label,path) in enumerate(self.entries,1):
            n=self.base+index;relative=os.path.relpath(path,self.folder)
            lines.append(f'<a id="pg-ref-{n}"></a>[{n}] ProtocolGuard 项目，“{label}”，2026。[本地证据](<{relative}>)')
            key=hashlib.sha256(relative.encode()).hexdigest()[:16]
            bib.append('@misc{pgreport'+key+',\n  author = {{ProtocolGuard Project}},\n  title = {'+label.replace('{','').replace('}','')+'},\n  year = {2026},\n  url = {'+relative+'}\n}')
        return '\n\n'.join(lines),'\n\n'.join(bib)


def install(folder,body,refs,bib):
    path=folder/'analysis.md';original=path.read_text() if path.exists() else '# ProtocolGuard 审计\n\n## References\n'
    if path.exists():
        backup=folder/'analysis.before-live-report.md'
        if not backup.exists():
            with backup.open('x') as stream:stream.write(original)
    original=strip_region(strip_region(original,BODY_START,BODY_END),REF_START,REF_END)
    if '## References' not in original:original+='\n\n## References\n'
    notice='> 原有初始化或人工记录保留如下；当前证据汇总见[自动更新区](#pg-live-analysis)。\n\n'
    if notice not in original:
        newline=original.find('\n');original=original[:newline+1]+'\n'+notice+original[newline+1:]
    offset=original.index('## References')
    updated=original[:offset].rstrip()+'\n\n'+BODY_START+'\n'+body+'\n'+BODY_END+'\n\n'+original[offset:].rstrip()+'\n\n'+REF_START+'\n'+refs+'\n'+REF_END+'\n'
    if not path.exists() or updated!=path.read_text():
        temporary=path.with_suffix('.md.tmp');temporary.write_text(updated);temporary.replace(path)
    bibpath=folder/'refs.bib';existing=bibpath.read_text() if bibpath.exists() else ''
    begin='% protocolguard:live-bibliography:start';end='% protocolguard:live-bibliography:end'
    existing=strip_region(existing,begin,end)
    updated=existing.rstrip()+'\n\n'+begin+'\n'+bib+'\n'+end+'\n'
    if not bibpath.exists() or updated!=bibpath.read_text():bibpath.write_text(updated)


class Reporter:
    def __init__(self,root):
        self.root=root;self.rows=read(root/'index.json')['versions'];self.files={};self.bundles={};self.symbols={};self.snippets={};self.source_text={}
        self.bycommit={row['commit']:row for row in self.rows}

    def file_index(self,commit):
        if commit in self.files:return self.files[commit]
        path=self.root/'shared/code'/commit/'files.json'
        value={r['file']:r for r in read(path)} if path.exists() else None
        self.files[commit]=value;return value

    def symbols_index(self,commit):
        if commit in self.symbols:return self.symbols[commit]
        result=collections.defaultdict(list);path=self.root/'shared/code'/commit/'symbols.json'
        if path.exists():
            for symbol in read(path):result[(symbol['file'],symbol['name'],symbol['kind'])].append(symbol)
        self.symbols[commit]=result;return result

    def bundle(self,row):
        key=row['spec_bundle_id']
        if key not in self.bundles:self.bundles[key]=read(Path(row['folder'])/'01-spec/bundle.json')
        return self.bundles[key]

    def evolution(self,row,meta):
        baseline=meta['mapping'].get('baseline_commit');first=meta['mapping'].get('baseline_tag','').startswith('EMPTY-TREE')
        previous=self.bycommit.get(baseline)
        current=self.file_index(row['commit']);before={} if first else self.file_index(baseline) if baseline else None
        data=dict(family=meta['mapping'].get('family'),baseline_commit=baseline,
                  baseline_tag=meta['mapping'].get('baseline_tag'),commit=row['commit'],
                  publication_time=meta['mapping'].get('publication_time'),commit_date=meta['mapping'].get('commit_date'),
                  status='first_observed_snapshot' if first else 'same_commit' if baseline==row['commit'] else 'compared' if before is not None else 'baseline_unavailable',
                  scope='indexed repository implementation files; not complete registry package or security-goal coverage',
                  semantic_security_change='unverified')
        if before is not None:
            added=sorted(set(current)-set(before));removed=sorted(set(before)-set(current))
            changed=sorted(p for p in set(current)&set(before) if current[p]['git_blob']!=before[p]['git_blob'])
            data.update(added_files=added,removed_files=removed,changed_files=changed)
            oldsymbols={} if first else self.symbols_index(baseline);newsymbols=self.symbols_index(row['commit'])
            added_symbols=[];removed_symbols=[];modified_symbols=[];ambiguous=[]
            affected=set(added+removed+changed)
            for key in sorted(set(oldsymbols)|set(newsymbols)):
                if key[0] not in affected:continue
                old=oldsymbols.get(key,[]);new=newsymbols.get(key,[])
                identity=dict(file=key[0],name=key[1],kind=key[2])
                if len(old)>1 or len(new)>1:ambiguous.append(identity);continue
                if not old:added_symbols.append(dict(identity,line=new[0]['line'],parser_status=new[0]['parser_status']));continue
                if not new:removed_symbols.append(dict(identity,line=old[0]['line'],parser_status=old[0]['parser_status']));continue
                def snippet(commit,symbol):
                    identity=(commit,key[0],symbol['line'],symbol['end'])
                    if identity not in self.snippets:
                        blob=self.file_index(commit)[key[0]]['git_blob']
                        if blob not in self.source_text:self.source_text[blob]=(self.root/'shared/code'/commit/'source'/key[0]).read_text().splitlines()
                        lines=self.source_text[blob]
                        self.snippets[identity]=hashlib.sha256('\n'.join(lines[symbol['line']-1:symbol['end']]).encode()).hexdigest()
                    return self.snippets[identity]
                if snippet(baseline,old[0])!=snippet(row['commit'],new[0]):
                    modified_symbols.append(dict(identity,before_line=old[0]['line'],after_line=new[0]['line'],parser_status=new[0]['parser_status']))
            data.update(added_symbols=added_symbols,removed_symbols=removed_symbols,modified_symbols=modified_symbols,ambiguous_symbol_matches=ambiguous)
        currentdocs={d['path']:d['git_blob'] for d in self.bundle(row)['documents']}
        olddocs={} if first else {d['path']:d['git_blob'] for d in self.bundle(previous)['documents']} if previous else None
        if olddocs is not None:data['spec_delta']=dict(added=sorted(set(currentdocs)-set(olddocs)),removed=sorted(set(olddocs)-set(currentdocs)),changed=sorted(p for p in set(olddocs)&set(currentdocs) if olddocs[p]!=currentdocs[p]))
        else:data['spec_delta']=None
        return data

    def report(self,row):
        folder=Path(row['folder']);meta=read(folder/'audit.json');original=(folder/'analysis.md').read_text()
        preserved=strip_region(strip_region(original,BODY_START,BODY_END),REF_START,REF_END)
        numbers=[int(n) for n in re.findall(r'<a id="ref-(\d+)">',preserved)]
        refs=References(folder,max(numbers,default=0));cite=refs.cite
        body=['<a id="pg-live-analysis"></a>','## 当前 spec / code 对照（自动证据汇总）',
              '本节只汇总已有产物；前文初始化或人工记录保持原样。模型判断、源码差异和限定测试观察分别记录，未执行不等于不合规，也不等于实现缺失。',
              f"固定源码提交：`{row['commit']}`；规范集合：`{row['spec_bundle_id']}`。{cite('当版身份与规范来源',folder/'audit.json')}"]
        bundle=self.bundle(row);symbols=self.symbols_index(row['commit'])
        byid={s['id']:s for group in symbols.values() for s in group}
        rulefiles=sorted((folder/'02-rules').glob('*.json'))
        locations=list((folder/'03-slices').glob('*.location/result.json'))
        stage=dict(atomic_rules=len(rulefiles),location_results=len(locations),located_handlers=sum(bool(read(p).get('handlers')) for p in locations),
                   slices=len(list((folder/'03-slices').glob('*.slice/slice.json'))),reviews=len(list((folder/'04-consistency').glob('*/synthesis.json'))),
                   assertion_plans=len(list((folder/'05-assertions').glob('*/plan.json'))),
                   dynamic_statuses=dict(collections.Counter(read(p).get('status','unknown') for p in (folder/'06-dynamic').glob('*/results.json'))))
        report=dict(version_id=row['version_id'],tag=row['tag'],commit=row['commit'],spec_bundle_id=row['spec_bundle_id'],observed=stage,rules=[],whole_protocol_compliance='unknown')
        body+=['### 阶段进度',f"原子规则 {stage['atomic_rules']}；定位结果 {stage['location_results']}，其中有 handler {stage['located_handlers']}；切片 {stage['slices']}；一致性审查 {stage['reviews']}；断言计划 {stage['assertion_plans']}。这些是产物计数，不是安全通过次数。",
               '动态阶段状态：'+text(stage['dynamic_statuses'])+'。']
        body+=['### 当版规范的处理状态','| 规范文档 | 全文解释状态 |','| --- | --- |']
        for document in bundle['documents']:
            if document['role']=='supporting_index_or_template':continue
            candidate=hashlib.sha256((row['spec_bundle_id']+':'+document['path']).encode()).hexdigest()[:16]
            result=folder/'02-rules'/candidate/'result.json'
            status='已产出模型解释，非穷尽性证明 '+cite('规范全文提取结果',result) if result.exists() else '尚无完整全文提取产物；已有候选级结果不等于全文完成'
            body.append('| '+text(document['path'])+' | '+status+' |')
        if not rulefiles:body+=['### 逐规则对照','当前没有已保存的原子规则，尚不能判断该版 spec 与代码是否对齐。']
        for path in rulefiles:
            rule=read(path);rid=path.stem;atom=rule['rule'];entry=dict(rule_id=rid,obligation=atom['obligation'],message_type=atom.get('message_type'),review_status='not_run')
            body+=['### 规则 '+rid,'规范归一化义务（模型解释，语义未证明）：'+text(atom['obligation'])+' '+cite('原子规则与规范证据',path),
                   'actor：'+text(atom.get('actor'))+'；message_type：'+text(atom.get('message_type'))+'；规范强度：'+text(atom.get('normative_strength'))+'；适用范围：'+text(atom.get('applicability'))+'。']
            for evidence in atom.get('evidence',[]):
                source=next((d for d in bundle['documents'] if d['path']==evidence['file']),None)
                reference=cite('同版本规范原文',audit.MAP/source['local_file']) if source and (audit.MAP/source['local_file']).exists() else ''
                body.append('规范原文：`'+text(evidence['file'])+':'+str(evidence['line'])+'` — '+text(evidence['quote'])+' '+reference)
            location=folder/'03-slices'/(rid+'.location/result.json')
            if location.exists():
                loc=read(location);entry['handlers']=loc.get('handlers',[])
                request=location.parent/'location.request.json'
                if request.exists():
                    payload=read(request).get('input','')
                    try:
                        sent=json.loads(payload) if payload.lstrip().startswith('{') else json.loads(payload.split('\n\n',1)[1])
                        entry['location_input_scope']='source_context_supplied' if 'source_context' in sent else 'symbol_index_only'
                    except (ValueError,IndexError):entry['location_input_scope']='unknown'
                    body.append('定位输入范围：'+text(entry['location_input_scope'])+'。'+cite('该次定位的实际请求',request))
                body.append('源码定位：'+('有 handler 候选；仍需结合源码审查。' if loc.get('handlers') else '**handler 为空；后续未获得可用映射。**')+' '+cite('handler/context 定位结果',location))
                for sid in dict.fromkeys(loc.get('handlers',[])+loc.get('context',[])):
                    if sid in byid:
                        s=byid[sid];body.append('源码'+(' handler' if sid in loc.get('handlers',[]) else ' context 候选')+'：`'+text(s['file'])+':'+str(s['line'])+'`，`'+text(s['name'])+'`。'+cite('固定提交的源码',folder/'source'/s['file']))
                body.append('定位说明：'+text(loc.get('rationale','未提供')))
                entry['location_status']=loc.get('status','model_location_unverified')
            else:body.append('源码定位：尚未运行或尚无成功产物。')
            sliced=folder/'03-slices'/(rid+'.slice/slice.json')
            body.append('切片：'+(cite('切片、调用闭包与限制',sliced) if sliced.exists() else '未生成；不能推断源码没有实现该要求。'))
            review=folder/'04-consistency'/rid/'synthesis.json'
            if review.exists():
                value=read(review);entry['review_status']=value.get('status','model_judgment_unverified');entry['findings']=value.get('findings',[])
                body.append('对齐审查：'+text(entry['review_status'])+'；以下均为模型判断。'+cite('规则一致性综合结果',review))
                for finding in value.get('findings',[]):body.append('- '+text(finding.get('kind'))+'：'+text(finding.get('conclusion'))+'；假设：'+text(finding.get('assumptions'))+'；缺少上下文：'+text(finding.get('missing_context')))
            else:body.append('对齐审查：**未运行，尚不能判断符合或不符合 spec。**')
            dynamic=folder/'06-dynamic'/rid/'results.json'
            if dynamic.exists():
                result=read(dynamic);entry['dynamic_status']=result.get('status','unknown');body.append('动态观察：'+text(entry['dynamic_status'])+'，只覆盖该适配器/断言范围。'+cite('本规则动态结果',dynamic))
            else:entry['dynamic_status']='not_run';body.append('动态观察：未运行或缺少适配器；不能当作测试通过。')
            report['rules'].append(entry)
        evolution=self.evolution(row,meta);put(folder/'evolution.json',evolution);report['evolution']=evolution
        body+=['### 该发布线的逐步代码变化',
               '对比基线采用当版身份记录中的同一发布线 baseline，不把其他语言/包的相邻 tag 当作前一版。状态：'+text(evolution['status'])+'；基线：`'+text(evolution.get('baseline_tag'))+'` / `'+text(evolution.get('baseline_commit'))+'`。'+cite('同发布线源码和规范差异',folder/'evolution.json')]
        if 'added_files' in evolution:
            body.append(f"索引范围内新增文件 {len(evolution['added_files'])}，修改文件 {len(evolution['changed_files'])}，删除文件 {len(evolution['removed_files'])}；新增符号 {len(evolution['added_symbols'])}，正文变化符号 {len(evolution['modified_symbols'])}。首次快照中的‘新增’只表示首次观察，并非此前缺少功能。")
            for label,key in [('新增符号','added_symbols'),('正文变化符号','modified_symbols')]:
                for item in evolution[key]:body.append('- '+label+'：`'+text(item['file'])+'` / `'+text(item['name'])+'`（'+text(item['parser_status'])+'）。')
            body.append('完整文件增删改及歧义符号见差异 JSON。文件移动可能表现为新增/删除，符号变化也可能来自重构或注释，不能直接写成安全补丁。')
        else:body.append('本地缺少基线源码，不能据此声称本版新增了哪些实现。')
        body.append('要称为“代码补充了某安全检查”，还需比较前后函数正文、规则适用范围及相应审查/测试证据；当前差异不提供这样的语义证明。')
        put(folder/'analysis-evidence.json',report)
        rendered,bib=refs.render();install(folder,paragraphs(body),rendered,bib)
        return report


def run(root,versions=None):
    reporter=Reporter(root);rows=reporter.rows
    if versions:rows=[r for r in rows if r['version_id'] in versions or r['tag'] in versions]
    results=[reporter.report(row) for row in rows]
    families=collections.defaultdict(list)
    # Always read existing summaries to keep a single-version refresh from
    # removing other versions from the chronological cross-version index.
    for row in reporter.rows:
        path=Path(row['folder'])/'analysis-evidence.json'
        if path.exists():families[read(path)['evolution']['family']].append((row,read(path)))
    lines=['# 按发布线观察 spec 与代码演进','本索引只读取已有规则、模型判断和源码差异；不是安全保证或确认补丁清单。每条发布线按已采集索引顺序展示，具体日期与 baseline 以每版本 evolution.json 为准。[[1]](#ref-1) 各行报告链接为具体规则、代码与差异证据的导航。[[2]](#ref-2)']
    for family,items in sorted(families.items()):
        lines+=['## '+text(family),'| 版本 | commit / 基线 | 规范文件变化（新增/修改/删除） | 源码文件变化（新增/修改/删除） | 实际审查进度 |','| --- | --- | --- | --- | --- |']
        for row,result in items:
            evo=result['evolution'];spec=evo['spec_delta']
            sd='/'.join(str(len(spec[k])) for k in ['added','changed','removed']) if spec is not None else '基线未知'
            cd='/'.join(str(len(evo[k])) for k in ['added_files','changed_files','removed_files']) if 'added_files' in evo else '基线未知'
            relative=os.path.relpath(Path(row['folder'])/'analysis.md',root)
            lines.append('| ['+text(row['tag'])+']('+relative+') | `'+row['commit'][:12]+'` / `'+str(evo.get('baseline_commit',''))[:12]+'` | '+sd+' | '+cd+' | 规则 '+str(result['observed']['atomic_rules'])+'；有 handler '+str(result['observed']['located_handlers'])+'；审查 '+str(result['observed']['reviews'])+' |')
    lines+=['## References','<a id="ref-1"></a>[1] ProtocolGuard 项目，“逐版本身份和发布线基线”，2026。[索引](index.json)',
            '<a id="ref-2"></a>[2] ProtocolGuard 项目，“逐版本规范、源码和证据差异记录”，2026。[报告与 evolution.json](versions/)']
    (root/'EVOLUTION.md').write_text(paragraphs(lines)+'\n')
    bib=root/'refs.bib';existing=bib.read_text() if bib.exists() else ''
    if '@misc{pgreportindex2026,' not in existing:bib.write_text(existing+'\n@misc{pgreportindex2026,\n  author = {{ProtocolGuard Project}},\n  title = {Version identities and release-line baselines},\n  year = {2026},\n  url = {index.json}\n}\n')
    existing=bib.read_text()
    if '@misc{pgreportdelta2026,' not in existing:bib.write_text(existing+'\n@misc{pgreportdelta2026,\n  author = {{ProtocolGuard Project}},\n  title = {Per-version specification source and evidence delta records},\n  year = {2026},\n  url = {versions/}\n}\n')
    aggregate(root,reporter.rows)
    return dict(versions_updated=len(results),models_called=0,target_executions=0,
                versions_with_reviews=sum(bool(r['observed']['reviews']) for r in results),
                warning='File/symbol changes and model judgments are not confirmed security fixes')


def aggregate(root,rows):
    """Current evidence only; aggregate counts never become compliance claims."""
    path=root/'analysis.md';original=path.read_text() if path.exists() else ''
    preserved=strip_region(strip_region(original,BODY_START,BODY_END),REF_START,REF_END)
    labels=[int(n) for n in re.findall(r'<a id="ref-(\d+)">',preserved)]
    refs=References(root,max(labels,default=0));cite=refs.cite
    active=[];counts=collections.Counter();scopes=collections.Counter();commits=set();bundles=set()
    for row in rows:
        file=Path(row['folder'])/'analysis-evidence.json'
        if not file.exists():continue
        data=read(file);observed=data['observed']
        for key in ['atomic_rules','location_results','located_handlers','slices','reviews','assertion_plans']:counts[key]+=observed[key]
        counts['dynamic_result_groups']+=sum(observed['dynamic_statuses'].values())
        if observed['atomic_rules'] or observed['location_results'] or observed['reviews']:
            active.append((row,data));commits.add(row['commit']);bundles.add(row['spec_bundle_id'])
        for rule in data['rules']:scopes[rule.get('location_input_scope','not_recorded')]+=1
    body=['<a id="pg-live-analysis"></a>','## 当前已保存结果的总分析',
          f"计划覆盖 {len(rows)} 个 tag 引用。目前 {len(active)} 个引用已有规则或定位产物，涉及 {len(commits)} 个不同源码提交、{len(bundles)} 套规范集合。本报告只总结已保存产物，不补跑模型或测试。{cite('逐版本输入身份',root/'index.json')}",
          '### 能作出的结论',
          f"已保存 {counts['atomic_rules']} 条原子规则出现次数和 {counts['location_results']} 份定位结果；有 handler 的定位 {counts['located_handlers']} 份，切片 {counts['slices']} 份，一致性综合审查 {counts['reviews']} 份，断言计划 {counts['assertion_plans']} 份，动态结果组 {counts['dynamic_result_groups']} 份。"]
    if counts['reviews']==0:
        body.append('**当前尚无有效的 spec–源码一致性审查结果，不能声称代码已实现、未实现或违反了这些规范要求。** 已完成的主要是规范解释和定位尝试；规则出现次数不能理解为不同安全目标或漏洞数量。')
    else:body.append('一致性产物仍属于模型判断，动态结果仅覆盖已有适配器和前置假设；其数量不表示全部规范均被验证。')
    body+=['### 实际进度与阻塞','| 发布引用 | 规则数 | 定位数 / 有 handler | 切片 / 审查 / 断言 | 动态结果组 |','| --- | --- | --- | --- | --- |']
    for row,data in active:
        s=data['observed'];body.append('| '+text(row['tag'])+' '+cite('本引用逐规则证据',Path(row['folder'])/'analysis.md')+' | '+str(s['atomic_rules'])+' | '+str(s['location_results'])+' / '+str(s['located_handlers'])+' | '+str(s['slices'])+' / '+str(s['reviews'])+' / '+str(s['assertion_plans'])+' | '+str(sum(s['dynamic_statuses'].values()))+' |')
    if active and len(commits)==1 and len(bundles)==1:
        body.append('上述已产生结果的发布引用使用同一个源码提交 `'+next(iter(commits))+'` 和同一套规范集合 `'+next(iter(bundles))+'`。它们是不同包的 tag 引用，**不是连续代码升级**。不同提取结果的条数变化可能来自模型拆分方式，不构成 spec 或代码新增安全能力的证据。')
    body.append('定位输入范围计数：'+text(dict(scopes))+'。`symbol_index_only` 表示该次请求只有名称/范围索引，未包含函数正文；由此得到的空 handler 不能说明实现缺失。后续输入已补充源码，但不会追溯升级旧定位结果。')
    journal=root/'scans/all-versions-001/journal.json'
    if journal.exists():
        state=read(journal);statuses=collections.Counter(t['status'] for t in state['tasks'].values())
        body.append('批次状态：`'+text(state['status'])+'`，累计预留请求 '+str(state['reserved_request_slots'])+'；任务状态 '+text(dict(statuses))+'。预留请求不等于实际计费次数，阶段完成也不等于安全验证通过。'+cite('本轮串行扫描进度',journal))
    if active:
        first=active[0][0];folder=Path(first['folder']);bundle=read(folder/'01-spec/bundle.json')
        body+=['### 已提取的规范语义',
               '下面以目前首个已处理快照为例，概括规范中的明确文字；这些不是代码合规结论，也不是所有历史版本的共同要求。规范强度保持原文，不把建议或解释性内容升级为 MUST。'+cite('当版规范集合',folder/'01-spec/bundle.json')]
        mapping={d['path']:audit.MAP/d['local_file'] for d in bundle['documents']}
        generic=mapping.get('specs/schemes/exact/scheme_exact.md');evm=mapping.get('specs/schemes/exact/scheme_exact_evm.md')
        if generic and generic.exists():body.append('`exact` 方案要求资源服务器预先知道所需转移的准确金额；文档未必为这一义务指定具体消息类型，因此允许 `message_type=null`，并将其保留为未指定信息。'+cite('当版 exact 规范',generic))
        if evm and evm.exists():
            body+=['当版 EVM 文档涉及以下条文；具体措辞、行号和归一化结果可沿各版本规则证据追溯。'+cite('当版 exact EVM 规范',evm),
                   '| 规范方面 | 原文所表达的要求或约束 | 当前代码判断 |','| --- | --- | --- |',
                   '| 付款授权 | 采用 EIP-3009；payload 带 signature 与 authorization；验证签名有效 | 未完成一致性审查 |',
                   '| 金额与余额 | 余额和授权金额足以覆盖 maxAmountRequired；不能将“足以覆盖”擅自改成严格相等 | 未完成一致性审查 |',
                   '| 参数绑定 | 资源服务器指定收款地址；验证约定 ERC20 合约与链 | 未完成一致性审查 |',
                   '| 时间与重放 | 检查授权有效时间范围、nonce 未使用 | 未完成一致性审查 |',
                   '| 验证与结算 | 模拟 transferWithAuthorization；结算使用 header 中的签名和授权参数调用合约 | 未完成一致性审查 |',
                   '| 建议性文字 | 首版推荐 EIP-3009 和特定金额支付；保留其建议性质 | 不提升为额外强制目标 |']
    body+=['### 代码逐步补充了什么',
           '目前已有结果的同提交引用之间不能描述为实现演进。其他版本的文件、规范 blob 和符号正文差异已按各自发布线的 baseline 汇总，属于离线源码差异；还需相应代码语义、前后规范适用性和审查/测试证据，才能称为补充了某安全检查。'+cite('按发布线的离线差异导航',root/'EVOLUTION.md'),
           '源码文件新增或函数正文变化不等于安全修复；某规则首次获得模型支持也不证明检查在该版首次加入。不能用其他工作区旧的三目标测试或历史组件执行填充本次逐版本审查状态。',
           '### 当前报告的可用边界',
           '可用于说明规范中已提取的内容、逐版本证据位置、流程阻塞和源码差异。不能用于宣布 750 版全部完成、确认漏洞、证明协议安全，或认定缺少审查证据就是官方代码没有实现。']
    rendered,bib=refs.render();install(root,paragraphs(body),rendered,bib)
    put(root/'analysis-summary.json',dict(active_tag_references=len(active),observed=counts,location_input_scopes=scopes,
        active_code_commits=sorted(commits),active_spec_bundles=sorted(bundles),whole_protocol_compliance='unknown'))


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--root',type=Path,default=audit.ROOT);parser.add_argument('--version',action='append')
    args=parser.parse_args();print(json.dumps(run(args.root.resolve(),args.version),ensure_ascii=False))
