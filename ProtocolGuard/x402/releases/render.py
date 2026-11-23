"""Render explicit implementation changes and evidence-bounded gaps for every tag."""
import collections,datetime,json,re
from pathlib import Path
BASE=Path(__file__).resolve().parent
EMPTY='4b825dc642cb6eb9a060e54bf8d69288fbee4904'

def write(path,text):path.parent.mkdir(parents=True,exist_ok=True);path.write_text(text)
def cell(value,n=500):return str(value).replace('|','\\|').replace('\n',' ')[:n]
def refs(head,base=None,paper=False):
    text='\n## References\n\n<a id="ref-1"></a>[1] x402 Foundation, “x402 source,” commit `'+head+'`, accessed 2026-11-13. [[url]](https://github.com/x402-foundation/x402/tree/'+head+')\n'
    number=2
    if base and base!=EMPTY:
        text+='\n<a id="ref-2"></a>[2] x402 Foundation, “Comparison baseline,” commit `'+base+'`, accessed 2026-11-13. [[url]](https://github.com/x402-foundation/x402/tree/'+base+')\n';number=3
    if paper:
        text+=f'\n<a id="ref-{number}"></a>[{number}] Xiangpu Song, Longjia Pei, Jianliang Wu, Yingpei Zeng, Gaoshuo He, Chaoshun Zuo, Xiaofeng Liu, Qingchuan Zhao, and Shanqing Guo, “ProtocolGuard: Detecting Protocol Non-compliance Bugs via LLM-guided Static Analysis and Dynamic Verification,” in *Proc. NDSS*, 2026. [[doi]](https://doi.org/10.14722/ndss.2026.240521)\n'
    return text

def role(row):
    paths=row.get('paths',[])
    return 'legacy/v1-helper' if any('/shared/base64.ts' in p for p in paths) else 'core'
def observations(sha):
    out={};path=BASE/'events'/sha/'dynamic.json'
    if not path.exists():return out
    for row in json.loads(path.read_text()):
        for c in row.get('results',[]):
            k=' / '.join([row['backend'],role(row),row.get('runtime','default'),c['name']])
            out[k]={'behavior':c['behavior'],'assertion':c.get('assertion'),'value':c.get('value'),'paths':row.get('paths',[]),'name':c['name'],'backend':row['backend'],'runtime':row.get('runtime','default'),'input_sha256':c.get('input_sha256')}
    return out

def interval_report(path):
    obj=json.loads(path.read_text());changes=obj['changes'];head,base=obj['head'],obj['baseline']
    code=[x for x in changes if x.get('kind','implementation')=='implementation' and not x['path'].startswith('specs/')];manifests=[x for x in changes if x.get('kind')=='manifest'];spec=[x for x in changes if x['path'].startswith('specs/')]
    text=f'# 实现更新：{base[:10]} → {head[:10]}\n\n目标源码固定到此提交。[[1]](#ref-1) '
    text+='基线为空树，这是首次快照，不解释成安全修复。\n' if base==EMPTY else '比较基线另行固定。[[2]](#ref-2)\n'
    text+=f'\n实现变化 {len(code)} 个文件；规范变化 {len(spec)} 个文件。下面记录真实源码结构变化；提交标题仅供导航，不代替语义结论。完整列表、条件表达式和源码行号见同名 JSON。\n'
    text+='\n[完整 implementation diff]('+path.with_suffix('.implementation.diff.gz').name+')；规范的实际 unified diff 保存在同名 JSON 的 `spec_unified_diff` 字段中。\n'
    commits=obj.get('commits',[]);commits=sorted(commits,key=lambda c:0 if re.match(r'^(fix|feat|refactor)',c['subject'],re.I) else 1)
    if commits:
        text+='\n提交主题（最多列 12 项）：\n\n'
        text+='\n'.join('- '+cell(c['subject'],220) for c in commits[:12])+'\n'
    text+='\n## 实现具体改动\n\n| 文件 | 操作 | 新增符号 | 修改符号 | 删除符号 |\n| --- | --- | --- | --- | --- |\n'
    for c in code:
        text+='| '+cell(c['path'])+' | '+c['status']+' | '+cell(', '.join(x['name'] for x in c.get('symbols_added',[])),650)+' | '+cell(', '.join(x['name'] for x in c.get('symbols_modified',[])),650)+' | '+cell(', '.join(x['name'] for x in c.get('symbols_removed',[])),650)+' |\n'
    text+='\n## 条件检查变化\n\n这些是 AST 中新增或删除的实际条件，尚未逐条证明它们落实了哪条规范义务。裁剪只用于表格展示，同名 JSON 保留完整表达式。\n\n| 文件 / 符号 | 新增条件 | 删除条件 |\n| --- | --- | --- |\n'
    count=0
    for c in code:
        for s in c.get('symbols_modified',[]):
            if s.get('guards_added') or s.get('guards_removed'):
                count+=1;text+='| '+cell(c['path']+' :: '+s['name'],250)+' | '+cell('; '.join(s.get('guards_added',[])),1000)+' | '+cell('; '.join(s.get('guards_removed',[])),1000)+' |\n'
    if not count:text+='| 无可提取条件差异 | 不表示逻辑未变 | 不表示无 gap |\n'
    text+='\n## 版本与依赖 manifest 变化\n\n'
    if not manifests:text+='没有所定义 manifest 的变化。\n'
    for item in manifests:
        text+='- `'+item['path']+'`：'+item['status']+'；变化字段：'+', '.join(item.get('changed_keys',{}))+'；读取状态：'+item.get('metadata_status','unknown')+'。\n'
    text+='\n完整依赖版本、导出、构建脚本等前后值与实际 diff 保存在同名 JSON，避免把单纯版本提升误写成协议逻辑修改。\n'
    text+='\n## 规范变化\n\n'
    text+='\n'.join('- `'+c['path']+'`：'+c['status'] for c in spec)+'\n' if spec else '这个区间没有所定义规范文件的净变化；不能据此认定代码新增义务或不合规。\n'
    text+=refs(head,base)
    write(path.with_suffix('.md'),text)
    return changes

def main():
    data=json.loads((BASE/'results.json').read_text());inventory=data['tags'];eventfiles=list((BASE/'events').glob('*/summary.json'))
    events={}
    for file in eventfiles:
        summary=json.loads(file.read_text());static=json.loads(file.with_name('static.json').read_text())
        summary.update(implementation_files=len(static),static_status_counts=dict(collections.Counter(r['status'] for r in static)),syntax_errors=sum(bool(r['parse_errors']) for r in static))
        file.write_text(json.dumps(summary,indent=2));events[summary['sha']]=summary
    intervals={str(f.relative_to(BASE)):interval_report(f) for f in (BASE/'intervals').glob('*.json')}
    matrix=[];gaps=[]
    packages={r['tag']:r for r in json.loads((BASE/'package-scope.json').read_text())} if (BASE/'package-scope.json').exists() else {}
    intro='# 每个官方 tag 的实现变化与 code/spec 差距\n\n以在线核验的 750 个 tags 为范围，归并为 81 个发布提交；另检查一个未发布主线。官方源码与发布元数据来自固定采集。[[1]](#ref-1) 采用 ProtocolGuard 的规则—源码上下文—动态检查顺序，但未调用论文中的 LLM 或执行定向 fuzzing。[[2]](#ref-2)\n\n'
    intro+='每个 tag 有独立比较基线；同一提交复用快照级执行结果，不把相同代码的多个包标签算成多次独立验证。首次标签是快照，预发布/归档标签不冒称稳定 release。实现详情包含新增、修改、删除的符号与条件表达式；没有完成完整语义审计的地方明确保留未知。\n\n'
    table='| 序号 | tag | 实现文件变化 | manifest 变化 | spec 文件变化 | 动态 case（快照级） | 组件差异观察 | 记录 |\n| --- | --- | --- | --- | --- | --- | --- | --- |\n'
    for i,row in enumerate(inventory,1):
        sha,base=row['sha'],row['baseline_sha'];event=events[sha];changes=intervals[row['interval_file']]
        code=[c for c in changes if c.get('kind','implementation')=='implementation' and not c['path'].startswith('specs/')];manifests=[c for c in changes if c.get('kind')=='manifest'];spec=[c for c in changes if c['path'].startswith('specs/')]
        obs=observations(sha);old=observations(base)
        problematic={k:v for k,v in obs.items() if v['assertion'] in ('failed','accepted_candidate_gap')}
        new=[k for k,v in problematic.items() if k in old and v.get('input_sha256') and old[k].get('input_sha256')==v.get('input_sha256') and (old[k]['behavior'],old[k]['assertion'])!=(v['behavior'],v['assertion'])]
        fixed=[k for k,v in old.items() if v['assertion'] in ('failed','accepted_candidate_gap') and k in obs and v.get('input_sha256') and v.get('input_sha256')==obs[k].get('input_sha256') and obs[k]['assertion'] not in ('failed','accepted_candidate_gap')]
        exercised={p for v in obs.values() for p in v['paths']};changed={c['path'] for c in code}
        covered=sorted(exercised&changed);notcovered=sorted(changed-exercised)
        record={**row,'implementation_changes':len(code),'manifest_changes':len(manifests),'spec_changes':len(spec),'dynamic_cases':event['dynamic_cases'],
          'candidate_component_observations':len(problematic),'changed_files_in_probe_modules':covered,'changed_files_not_in_probe_modules':notcovered,
          'new_observed_differences':new,'resolved_observed_differences':fixed,'full_semantic_review':'not_run','directed_fuzzing':'not_run',
          'package_source_scope':packages.get(row['tag'],{}),'report':f'versions/{i:04d}.md'}
        matrix.append(record)
        text=f'# {row["tag"]}\n\n固定源码 `{sha}`。[[1]](#ref-1) '
        text+='这是该发布线的首次快照，不将全量新增解释成一次更新修复。\n' if base==EMPTY else f'相对 `{row["baseline_tag"]}` / `{base}` 比较。[[2]](#ref-2)\n'
        text+=f'\n提交时间：{row["commit_date"]}；包发布时间：{row.get("publication_time") or "本轮未单独核验"}。这是包 tag，不是独立协议版本或 GitHub Release 对象。\n'
        text+=f'\n## Implementation 做了什么\n\n相对该包 tag 的基线，仓库快照中新增/修改/删除共 {len(code)} 个实现文件，{len(manifests)} 个版本/依赖 manifest，规范净变更 {len(spec)} 个文件。\n\n'
        text+=f'- [完整文件、符号与条件变化](../{Path(row["interval_file"]).with_suffix(".md")})。\n'
        text+=f'- [机器可读实际变化](../{row["interval_file"]})。\n'
        text+=f'- [本提交静态扫描](../events/{sha}/static.json)：{event["implementation_files"]} 个实现文件，状态 {event["static_status_counts"]}；语法解析不等于类型检查或安全审计。\n'
        text+=f'- [规则候选与源码关联](../events/{sha}/contexts.json)：{event["spec_candidate_count"]} 条共存规范候选、{event["contexts"]} 个关联符号；关联仅为词法定位，不是语义验证。\n'
        package=packages.get(row['tag'],{})
        text+='\n包源码定位：'+package.get('status','未检查')+'；这份记录扫描仓库快照，未下载并运行注册表包。\n'
        text+=f'\n## Code 与 spec 的差距\n\n本轮执行 {event["dynamic_cases"]} 个组件 case（与同提交其他 tag 共享），其中 {len(problematic)} 条为接受边界输入或往返失败的观察；不等于 {len(problematic)} 个漏洞。完整证据见 [动态记录](../events/{sha}/dynamic.json)。\n'
        text+='\n| 组件 / 环境 / 输入 | 观察 | 解释边界 |\n| --- | --- | --- |\n'
        for k,v in problematic.items():
            boundary='有效 Unicode 字符串不能无损往返：组件级断言失败；不推断支付安全影响' if v['assertion']=='failed' else ('schema 接受与 v2 表格约束有表面差异；外层是否拒绝尚未检查' if 'python' in v['backend'] or 'zod' in v['backend'] else 'header decoder 仅解析对象，未承诺完成 schema 验证；不能单独定为违规')
            text+='| '+cell(k,260)+' | '+v['behavior']+' | '+boundary+' |\n'
            gaps.append({'tag':row['tag'],'sha':sha,'baseline_sha':base,'case':k,**v,'interpretation':boundary,'confirmed_end_to_end_bug':False})
        if not problematic:text+='| 已选 case 无差异 | 未观察到失败 | 不表示未测试的代码与规范一致 |\n'
        text+='\n与前版具有相同输入指纹的 case 的观察比较：\n\n'
        text+='- 新出现行为差异：'+(', '.join(new) or '未检测到可对齐的新差异；首次支持的 case 不当作回归')+'。\n'
        text+='- 不再出现的行为差异：'+(', '.join(fixed) or '未检测到可对齐的消失差异')+'。\n'
        text+=f'\n本次变化中，{len(covered)} 个文件落入动态 probe 所加载的模块，{len(notcovered)} 个实现文件未被这些 probe 覆盖；加载模块也不等于全部分支覆盖。\n'
        if covered:text+='\n已加载的变更模块：'+', '.join('`'+x+'`' for x in covered)+'。\n'
        text+='\n## 尚未验证\n\n未执行 LLM 语义判断、全量规则断言生成、全量 SDK 测试、定向 fuzzing、Go/合约运行或链上支付；schema/header/helper 的结果不能推出签名、重放、金额结算和授权安全。规范只从本提交读取，不用当前 v2 义务追罚历史 v1 实现。当前所有未测试变化的 code/spec 关系仍待语义核查。\n'
        text+=refs(sha,base)
        write(BASE/record['report'],text)
        table+=f'| {i} | {cell(row["tag"])} | {len(code)} | {len(manifests)} | {len(spec)} | {event["dynamic_cases"]} | {len(problematic)} | [详情]({record["report"]}) |\n'
    head=json.loads((BASE/'official-check.json').read_text())['head']['sha']
    intro+=table+refs(head,paper=True)
    write(BASE/'ALL-RELEASES.md',intro)
    data.update(tags=matrix,events=list(events.values()));write(BASE/'results.json',json.dumps(data,indent=2))
    write(BASE/'component-observations.json',json.dumps(gaps,indent=2))
    summary={'tag_count':len(matrix),'tag_commits':len({x['sha'] for x in matrix}),'snapshot_executions':len(events),'intervals':len(intervals),
        'dynamic_case_executions':sum(x['dynamic_cases'] for x in events.values()),'roundtrip_failure_executions':sum(x['roundtrip_failures'] for x in events.values()),
        'candidate_acceptance_observations':sum(x['candidate_gap_observations'] for x in events.values()),
        'syntax_error_files':sum(x['syntax_errors'] for x in events.values()),
        'static_counts':dict(sum((collections.Counter(x['static_status_counts']) for x in events.values()),collections.Counter())),
        'harness_errors':sum(len(x['dynamic_harness_errors']) for x in events.values()),'model_calls':0,'directed_fuzzing_runs':0,'transactions':0}
    write(BASE/'validation.json',json.dumps(summary,indent=2));print(json.dumps(summary,indent=2))
if __name__=='__main__':main()
