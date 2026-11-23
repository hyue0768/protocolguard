"""Render independent, bounded expert notes and source evidence for all tags.

Inventory, exact-source-form observations and expert interpretation are kept
separate. No artifact here asserts exhaustive compliance or a verified exploit.
"""
import collections
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys

HERE=Path(__file__).resolve().parent;BASE=HERE.parent
sys.path.insert(0,str(BASE))
from map_release_specs import Sources,ENV


def read(path):return json.loads(path.read_text())


def save(path,value):
    path.parent.mkdir(parents=True,exist_ok=True)
    if path.exists():raise ValueError('Analysis exists; no overwrite: '+str(path))
    path.write_text(json.dumps(value,ensure_ascii=False,indent=2)+'\n')


def txt(value):return str(value).replace('\n',' ').replace('|','\\|').replace('<','&lt;').replace('>','&gt;').replace('[','\\[').replace(']','\\]')


class Document:
    bibliography={}
    def __init__(self,path,title):self.path=path;self.blocks=['# '+title];self.refs=[]
    def cite(self,label,path):
        path=Path(path).absolute()
        if path not in [p for _,p in self.refs]:self.refs.append((label,path))
        n=next(i for i,(_,p) in enumerate(self.refs,1) if p==path)
        return f'[[{n}]](#ref-{n})'
    def add(self,value):self.blocks.append(value)
    def write(self):
        self.add('## References')
        for n,(label,path) in enumerate(self.refs,1):
            relative=os.path.relpath(path,self.path.parent)
            self.add(f'<a id="ref-{n}"></a>[{n}] x402 / ProtocolGuard 本地证据，“{label}”，2026。[原始文件](<{relative}>)')
            self.bibliography[str(path)]=(label,path)
        self.path.parent.mkdir(parents=True,exist_ok=True)
        if self.path.exists():raise ValueError('Report already exists')
        self.path.write_text('\n\n'.join(self.blocks)+'\n')


# Expert interpretation is deliberately narrower than regex feature coverage.
# Every entry explains what the concrete check does and what it cannot prove.
INTERPRETATION={
 'recipient_guard':('协议目标的具体实现','将授权接收地址与服务方 payTo 比较；早期 TS v1 验证器没有这条显式分支，0.3.5 所在样本开始出现。','只证明该局部分支存在；调用者的 requirements、Token 和部署配置仍是前提。'),
 'network_guard':('协议检查的具体实现','v2 显式比较 accepted.network 与 requirements.network，签名域采用 requirements 的链和资产。','不能因 v2 字段出现就认定所有同树 legacy v1 或所有语言都使用这一路径。'),
 'amount_lower_bound':('历史接受策略','早期授权金额按下界比较；旧 exact EVM 文档明确写 enough to cover，不能以今天严格相等的实现倒推它必然违规。','后期仍保留 legacy 代码；同一仓库中下界比较与严格比较共存不是自动矛盾。'),
 'amount_exact':('接受策略收紧','后续 v2 与其 v1 adapter 对授权金额改为严格相等；它缩小了接受集合，强化固定金额的实现约束。','是否为不合规拒绝取决于当版规范是否保证接受超额授权；不能仅凭 enough to cover 定性漏洞。'),
 'expiry_margin':('实现侧具体安全裕量','在通常有效期检查外，使用约 6 秒的提前拒绝裕量，降低往返与出块延迟造成的过期风险。','这是部署/实现阈值，所核对方案条文未规定固定 6 秒；也可能拒绝接近到期但尚有效的授权。'),
 'reverify_settle':('实现侧时序加固','在实际提交结算前再次调用验证，减少首次验证至结算之间状态变化的影响。','再次验证不是原子性证明，不能消除所有并发、状态竞争或恶意 facilitator 风险。'),
 'evm_simulation':('补足规范已有检查','将 transferWithAuthorization 作为读调用模拟；状态检查可由模拟及失败诊断承担，不必逐条写成独立 nonce 查询。','默认 verify 模拟与可选 settle 模拟必须区分；RPC/合约正确性仍是前提，模拟成功不保证未来结算。'),
 'factory_allowlist':('facilitator 的额外部署策略','对未部署 ERC-6492 钱包的 factory 使用显式允许列表，默认空集合拒绝部署；后期 verify 与 settle 同步策略。','保护的是代提交方的交易执行边界；不是新增付款有效性公理，也不能证明获准工厂本身安全。'),
 'asset_contract':('资产身份的实现侧加固','拒绝没有代码的资产地址，避免把空地址/EOA 的调用行为当作 Token 结算证据；后期有按链隔离的正缓存。','代码存在不证明 Token 经济语义正确；缓存有 TTL 和部署假设，不能推出整个链上资产安全。'),
 'low_s':('签名接受语义收紧','对没有字节码付款人的普通 65 字节签名拒绝非规范 high-s 形式。','条件只覆盖普通 EOA 形态；不能推广为全部智能钱包签名唯一性或形式化 replay resistance。'),
 'transfer_receipt':('结算结果证据增强','有日志时核对 Token 地址、付款人、收款人和金额匹配的 Transfer 事件，强于仅看 receipt.status。','已读分支在 logs 非空时执行检查；不能写成所有 signer/日志缺失路径必然检查，也未验证最终性或真实 Token 余额。'),
 'pending_reconcile':('规范与实现共同扩展','广播后确认不明时按签名保存并复用交易哈希，再次处理优先核对原交易，降低重复广播。','不是链上 nonce 防重放的替代品；默认内存状态跨进程不共享，完整并发保证尚未验证。'),
 'pending_ttl':('默认存储与部署参数','默认 PendingSettlementStore 为进程内 Map，TTL 为 5 分钟，同时提供可替换的共享存储接口。','5 分钟不是付款可重放周期，也不是跨副本持久化保证；需要部署方提供适当存储。'),
 'buffer_end':('HTTP 交付时序措施','延迟响应输出直至结算结果；早期 Express 明确在业务 handler 运行后尝试结算。','仅拦截 end 不等于拦截所有写流/业务副作用；即使缓冲正文，应用副作用也不因此回滚。'),
 'facilitator_schema':('不可信响应的格式加固','成功 HTTP 返回先做 JSON/schema 校验，避免把任意响应强转为支付状态结构。','结构正确不证明返回状态真实，不能消除对 facilitator 和其链上观测的信任。'),
 'facilitator_deadline':('可用性与资源边界','给 verify、settle、supported 的 HTTP 处理设置截止时间，限制远程响应拖延。','不证明远端履约，也不构成对所有网络/重试路径的安全证明。'),
 'bounded_body':('可用性与资源边界','通过 readLimitedText 对控制面响应采用有界读取，当前辅助实现上限 1 MiB。','是客户端资源保护；不能等同于完整 SSRF、防重定向或恶意 facilitator 防护。'),
 'strict_1271':('签名语义的具体加固','有字节码账户走 ERC1271 验证，无代码账户走 ECDSA，失败不再对有代码账户任意回退。','这是本地分派策略；是否与具体 Token 的校验器完全一致仍需相应合约证据，未运行链上测试。'),
 'identifier_format':('扩展输入约束','校验 payment identifier 的存在/格式，供业务应用实现幂等。','helper 本身不提供持久去重事务；必须区别请求 ID、链上 nonce、请求指纹绑定和重试缓存。'),
 'pending_retry_once':('有界自动恢复策略','仅对带交易哈希的 settlement_pending 等符合条件的结果进行一次相同付款重试。','依赖 facilitator 的 pending store 与链上 nonce；不能称为任意重试安全或通用 exactly-once 证明。'),
 'permit_reentrancy':('合约实现侧防护','Permit2/批结算等入口使用 nonReentrant；exact proxy 将签名 witness 和实际接收地址联动。','不同 exact/upto witness 字段不同；某版本 exact 移除 facilitator 字段而 upto 保留，不能按统一模板判断回退。'),
}


def feature_spec_line(feature,line):
    mapping={'recipient_guard':r'payTo|recipient|destination|address specified',
      'network_guard':r'contract and chain|Token and Network|token and network',
      'amount_lower_bound':r'enough to cover|covers the payment', 'amount_exact':r'enough to cover|Amount, Validity|specific amount',
      'expiry_margin':r'valid time range|Validity Window', 'evm_simulation':r'Simulate.*transferWithAuthorization',
      'pending_reconcile':r'settlement_pending','pending_ttl':r'settlement_pending',
      'pending_retry_once':r'settlement_pending','identifier_format':r'idempot|fingerprint|Request Binding'}
    return bool(re.search(mapping[feature],line,re.I)) if feature in mapping else False


def main():
    inputs=read(HERE/'inputs.json');observations=read(HERE/'source-observations-v2.json');rows=read(BASE/'version-audits/index.json')['versions']
    commits=inputs['commits'];bycommit={x['commit']:x for x in commits};order={x['commit']:i for i,x in enumerate(commits)}
    byrow={row['commit']:row for row in rows};cache={};all_evidence=observations['evidence']
    def bundle(commit):
        key=bycommit[commit]['spec_bundle_id']
        if key not in cache:cache[key]=read(BASE/'release-spec-map/bundles'/(key+'.json'))
        return cache[key]
    def spec_matches(commit,feature):
        found=[]
        for source in bundle(commit)['documents']:
            if source['role']=='supporting_index_or_template':continue
            if not ('exact_evm' in source['path'] or 'x402-specification' in source['path'] or ('payment_identifier' in source['path'] and feature=='identifier_format')):continue
            path=BASE/'release-spec-map'/source['local_file']
            for number,line in enumerate(path.read_text().splitlines(),1):
                if feature_spec_line(feature,line):found.append(dict(file=source['path'],local_file=str(path),line=number,text=line))
        return found
    timeline=[]
    for feature,definition in observations['features'].items():
        for component in definition['components']:
            matched=[e for e in all_evidence if e['feature']==feature and e['component']==component]
            if not matched:continue
            occurrences=sorted({c for e in matched for c in e['commits']},key=order.get)
            first=occurrences[0];e=next(e for e in matched if first in e['commits'])
            timeline.append(dict(feature=feature,component=component,title=definition['title'],first_observed_commit=first,date=bycommit[first]['date'],tag_examples=bycommit[first]['tag_references'],
                                 evidence=e,interpretation=INTERPRETATION[feature],commits=occurrences,
                                 qualifier='first local tagged snapshot, not original introducing commit or package distribution proof'))
    save(HERE/'security-evolution.json',timeline)
    cases=write_expert_cases(inputs)
    for commit in commits:
        sha=commit['commit'];folder=HERE/'commits'/sha;d=Document(folder/'analysis.md',sha[:12]+'：同期 spec 与源码静态对照')
        d.add('本报告为当前助手的局部静态源码审阅及可核对的文本形态证据。全协议是否合规保持 unknown；未做目标动态实验或形式化证明。'+d.cite('源码读取范围与身份',HERE/'inputs.json'))
        d.add('提交日期：'+commit['date']+'；同树规范集合：`'+commit['spec_bundle_id']+'`。该提交对应 '+str(len(commit['tag_references']))+' 个 tag 引用；仓库同树规范不等于独立发布的规范兼容性认证。'+d.cite('同提交规范快照',BASE/'release-spec-map/snapshots'/(sha+'.json')))
        d.add('## 阅读与覆盖范围')
        d.add(f"索引源码 {len(commit['indexed_files'])} 个文件，补查本地代码 {len(commit['additional_local_code'])} 个，另有 {len(commit['unavailable_code'])} 个代码文件出现项未在本地取得。字节读取/哈希验证不等于逐行语义审计；重点是 TS EVM exact、HTTP 控制面、签名/结算状态及若干原生语言对照。未深入审阅的链、扩展和部署路径均为未验证。")
        present=[e for e in all_evidence if sha in e['commits']]
        semantic=[]
        d.add('## 具体实现及同期规范对照')
        for feature in observations['features']:
            hits=[e for e in present if e['feature']==feature]
            if not hits:continue
            title=observations['features'][feature]['title'];kind,judgment,limit=INTERPRETATION[feature]
            d.add('### '+title)
            d.add('分类：'+kind+'。'+judgment)
            # Evidence by implementation lineage, not a single boolean mixing
            # legacy v1 with v2 or with a different chain.
            for component in dict.fromkeys(e['component'] for e in hits):
                e=next(e for e in hits if e['component']==component)
                d.add('源码形态：`'+component+'`，`'+e['file']+':'+str(e['line'])+'`；`'+txt(e['quote'])+'`。'+d.cite('源码 '+e['file'],e['local_file']))
            matching=spec_matches(sha,feature)
            if matching:
                source=matching[0]
                d.add('同期条文入口：`'+source['file']+':'+str(source['line'])+'`。这里定位相关文字，不将正则命中当作完整规范解释；legacy v1 与 v2 必须分别确定适用性。'+d.cite('同期规范 '+source['file'],source['local_file']))
            else:d.add('所选条文定位未获得直接的具体阈值/策略条款；这只说明需要人工确定规范强度，不能推断全部官方文档未覆盖。')
            d.add('判断边界：'+limit)
            semantic.append(dict(feature=feature,components=sorted({e['component'] for e in hits}),classification=kind,judgment=judgment,limitations=limit,evidence=hits,spec_text_entries=matching))
        # Entire historical function revisions were compared for these scoped
        # observations. Do not project modern scheme documents onto legacy code.
        legacy=[f for f in commit['indexed_files'] if f['component']=='ts_evm_v1']
        modern=any(f['component']=='ts_evm_v2' for f in commit['indexed_files'])
        if legacy and not modern:
            f=legacy[0];d.add('## 早期实现与条文的差异候选')
            d.add('对已核对的 legacy verify/settle 修订，验证函数没有专门的 authorizationState 未用 nonce 查询，也没有 transferWithAuthorization 的事前模拟调用；旧 EVM 文档列出这两类验证步骤。结算仍会调用 Token，Token 可以承担实际 nonce 拒绝，因此这是本地预验证与条文的差异候选，尚未确认真实漏洞或全调用链不合规。'+d.cite('legacy EVM 源码',f['local_file']))
            if not any(e['feature']=='recipient_guard' and e['component']=='ts_evm_v1' for e in present):
                d.add('这个早期 verify 修订也没有显式比较 authorization.to 与 requirements.payTo；同期共享 findMatchingPaymentRequirements 只匹配 scheme/network。后续样本加入了 recipient guard。这里记录局部检查边界的补齐，不提供漏洞利用结论。')
        d.add('## 当前不能下的结论')
        d.add('未匹配某个源码形态不能解释为检查不存在；它可能位于 helper、其他语言或链上合约。某检查存在也不证明全流程调用、配置启用、真实链行为或恶意参与者安全。这里只把已读局部行为与当版规范关联，不使用另一提交的测试结果填补证据。')
        relevant_cases=[case for case in cases if sha in case['applicable_commits']]
        if relevant_cases:
            d.add('## 已人工核对的具体差异/边界')
            for case in relevant_cases:d.add('**'+case['id']+' '+case['title']+'**：'+case['conclusion']+' '+d.cite('具体源码与规范核对案例',HERE/'DEEP-REVIEW.md'))
        save(folder/'judgment.json',dict(commit=sha,spec_bundle_id=commit['spec_bundle_id'],method='bounded expert source reading with exact-form locators',findings=semantic,expert_cases=[c['id'] for c in relevant_cases],
             unreviewed_scope='other mechanisms/languages and unexamined call paths',whole_protocol_compliance='unknown',confirmed_vulnerabilities=0,model_api_calls=0,target_executions=0))
        d.write()
    # Per-package-line deltas; same-commit tags are never upgrades.
    byfiles={c['commit']:{f['file']:f['git_blob'] for f in c['indexed_files']+c['additional_local_code']+c['unavailable_code']} for c in commits}
    byfeature={c['commit']:{(e['feature'],e['component']) for e in all_evidence if c['commit'] in e['commits']} for c in commits}
    ancestry={};repo=BASE/'releases/upstream.git'
    for row in rows:
        meta=read(Path(row['folder'])/'audit.json');base=meta['mapping'].get('baseline_commit');initial=meta['mapping'].get('baseline_tag','').startswith('EMPTY-TREE')
        old={} if initial else byfiles.get(base);current=byfiles[row['commit']]
        delta=dict(tag=row['tag'],commit=row['commit'],family=meta['mapping'].get('family'),baseline_tag=meta['mapping'].get('baseline_tag'),baseline_commit=base,
                   status='first_observed_package_line_snapshot' if initial else 'same_source_commit' if base==row['commit'] else 'compared' if old is not None else 'baseline_unavailable',
                   new_source_forms=[],removed_source_forms=[],semantic_change_verified=False)
        if old is not None:
            delta.update(added_files=sorted(set(current)-set(old)),removed_files=sorted(set(old)-set(current)),changed_files=sorted(p for p in set(current)&set(old) if current[p]!=old[p]))
            before=set() if initial else byfeature.get(base,set());after=byfeature[row['commit']]
            delta['new_source_forms']=[list(x) for x in sorted(after-before)];delta['removed_source_forms']=[list(x) for x in sorted(before-after)]
        if base and not initial and base!=row['commit']:
            pair=(base,row['commit'])
            if pair not in ancestry:
                result=subprocess.run(['git','-C',str(repo),'merge-base','--is-ancestor',*pair],env=ENV,capture_output=True)
                ancestry[pair]='ancestor' if result.returncode==0 else 'not_ancestor' if result.returncode==1 else 'unknown_local_history'
            delta['ancestry']=ancestry[pair]
        p=HERE/'releases'/row['version_id'];save(p/'evolution.json',delta)
        d=Document(p/'analysis.md',row['tag']+'：独立静态审阅与发布线变化')
        d.add('提交：`'+row['commit']+'`；规范集合：`'+row['spec_bundle_id']+'`。源码与规范对照复用本提交的独立审阅，不伪装成同提交多个包的独立代码审计。'+d.cite('本提交对照分析',HERE/'commits'/row['commit']/'analysis.md'))
        d.add('包来源边界：'+txt(meta['mapping'].get('historical_package_scope'))+'。registry 分发物等价性未验证。'+d.cite('发布引用身份与包作用域',Path(row['folder'])/'audit.json'))
        d.add('## 与本发布线前一引用相比')
        d.add('基线：`'+str(delta['baseline_tag'])+'` / `'+str(base)+'`；状态：`'+delta['status']+'`；祖先关系：`'+delta.get('ancestry','same_or_initial')+'`。'+d.cite('本发布线完整差异',p/'evolution.json'))
        if 'added_files' in delta:
            d.add(f"实现路径新增 {len(delta['added_files'])}、正文 blob 改变 {len(delta['changed_files'])}、删除 {len(delta['removed_files'])}。比较保留未取得正文的 Git blob 元数据，避免把缓存缺失误写成源码不存在；缺失正文仍不能给出语义结论。完整清单在差异 JSON。")
        if delta['status']=='same_source_commit':d.add('同一个源码提交，没有可据此声称的新代码能力；包版本/tag 变化不等于协议升级。')
        elif initial:d.add('这是该包发布线首个本地观察点，不能把全部既有代码写成这一版首次引入的安全特性。')
        for feature,component in delta['new_source_forms']:
            d.add('- 新观察到源码形式：'+observations['features'][feature]['title']+'（`'+component+'`）；'+INTERPRETATION[feature][1])
        if delta.get('ancestry')=='not_ancestor':d.add('基线不是当前提交的祖先；可能是分支或 tag 指向变化，不能把文件减少直接写成安全回退。')
        d.add('## 结论边界')
        d.add('“新观察到形式”与“首次实现安全能力”不同；它可能来自重构、helper 迁移或适配器变化。源码静态对照给出支持/差异候选和具体配置约束，未确认漏洞，也不证明全协议安全。')
        d.write()
    write_overview(inputs,observations,timeline,rows)
    write_indexes(inputs,timeline,rows)
    bib=[]
    for path,(label,_) in sorted(Document.bibliography.items()):
        key='judge'+hashlib.sha256(path.encode()).hexdigest()[:16]
        bib.append('@misc{'+key+',\n  author = {{x402 / ProtocolGuard Project}},\n  title = {'+label.replace('{','').replace('}','')+'},\n  year = {2026},\n  url = {'+path+'}\n}')
    (HERE/'refs.bib').write_text('\n\n'.join(bib)+'\n')
    save(HERE/'completion.json',dict(commit_reports=len(commits),tag_reports=len(rows),scope='bounded static comparison, not exhaustive semantic review',models_called=0,target_executions=0,confirmed_vulnerabilities=0))
    print(json.dumps(dict(commit_reports=len(commits),tag_reports=len(rows),models_called=0,target_executions=0)))


def write_overview(inputs,observations,timeline,rows):
    d=Document(HERE/'analysis.md','llm-judge：已保存 release 源码与同期规范的独立静态对照')
    d.add('当前助手以软件工程视角直接核对固定源码、历史修订和同期规范。结论是有范围的静态判断：没有调用付费模型、没有运行目标测试、没有上链或生成攻击输入。'+d.cite('输入与读取范围',HERE/'inputs.json'))
    d.add('## 实际范围与阅读方式')
    totals=inputs['totals']
    d.add(f"覆盖 750 个已采集 tag 引用，去重为 81 个源码提交；逐一读取并校验 {totals['indexed_file_occurrences']} 个索引源码出现项、{totals['unique_indexed_blobs']} 个不同 blob，并补查 {totals['additional_code_occurrences']} 个 Java/JavaScript 等出现项。仍有 {totals['missing_code_occurrences']} 个本地缺失出现项。172 个规范 blob 核对了身份。")
    d.add('字节读取、源码形式定位与深入语义审阅分别记录。深入判断重点为 EVM exact 验证/结算、HTTP 边界、签名与状态辅助路径、早期 Go/Python 差异和最新 Java 接口；其他链、全部扩展、链上 Token 依赖及未展开路径保持未验证。209 个选定组件变体是定位清单，不能声称全部已逐行语义审计。'+d.cite('安全相关组件变体',HERE/'component-variants.json'))
    d.add('每个提交有独立对照报告，每个 tag 有发布线差异报告；同提交引用共享静态审阅。GitHub Release 与 tag/registry 分发物不同，本数据中的 alpha/archive 引用不冒充正式生产发布。'+d.cite('原始 tag 与规范映射',BASE/'release-spec-map/mapping.json'))
    d.add('## 总体判断')
    d.add('代码并非只机械实现三条抽象条件。除授权、绑定与重放相关检查外，还逐步加入代提交方工厂策略、签名分派、响应资源上限、回执检查和 pending 状态恢复。它们分别是协议检查落地、实现接受策略或部署加固，不能全部称为新的协议安全目标。'+d.cite('精确源码证据与解释范围',HERE/'source-observations-v2.json'))
    d.add('旧版 TS 验证器与其同期规范存在局部预验证步骤差异候选；跨语言对 RPC 失败和 nonce/余额检查的处理也不同。后期 spec 本身增加了 Permit2、ERC7710 和 settlement_pending 等内容，不能一概说官方后续规范没有安全补充。所有候选均未用攻击输入复现。')
    d.add('逐条人工核对案例及精确适用范围见深入审阅：包括跨语言失败策略、Java 客户端形状、响应缓冲、ERC7710 文档与内置路由的能力差异。'+d.cite('具体源码/规范审阅案例',HERE/'DEEP-REVIEW.md'))
    d.add('## 可以确认的逐步变化（首次本地样本）')
    table=['| 提交 / 日期 | 组件与具体变化 | 工程解释 |','| --- | --- | --- |']
    selected=['recipient_guard','amount_exact','evm_simulation','factory_allowlist','strict_1271','transfer_receipt','pending_reconcile','facilitator_schema','facilitator_deadline','asset_contract','low_s','bounded_body']
    events=[]
    for key in selected:
        entries=[e for e in timeline if e['feature']==key and e['component']!='ts_evm_v1_adapter']
        if not entries:continue
        events.append(entries[0])
    rank={c['commit']:i for i,c in enumerate(inputs['commits'])}
    for e in sorted(events,key=lambda e:rank[e['first_observed_commit']]):
        source=e['evidence'];table.append('| `'+e['first_observed_commit'][:12]+'` / '+e['date'][:10]+' | '+e['title']+'（'+e['component']+'） '+d.cite('首见源码 '+source['file'],source['local_file'])+' | '+txt(INTERPRETATION[e['feature']][1])+' |')
    d.add('\n'.join(table))
    d.add('这里的时间是最早本地 tag 快照，不是引入该功能的原始提交时间；例如某 Go tag 的仓库里出现 TS 检查，并不证明相同编号的 TS registry 包包含它。完整标签及逐组件序列可核对 JSON。'+d.cite('逐组件安全演进',HERE/'security-evolution.json'))
    d.add('## 具体差异与实现侧补充')
    d.add('### 早期预验证覆盖不等于链上最终拒绝')
    d.add('最早 TS v1 verify 的签名、时间和金额检查可以直接读到，但没有显式 recipient guard、独立 nonce 查询或 transfer 模拟。0.3.5 所在样本加入收款地址比较。旧规范列出了 nonce 未用和模拟验证；这是应继续核对完整调用链的差异候选。Token 结算仍可能拒绝已用 nonce，不能将局部预检查缺口直接写成成功双花。'+d.cite('最早 TS v1 源码',BASE/'version-audits/shared/code/500a93e236844526b17635cfbd54e7e798486e8a/source/typescript/packages/x402/src/schemes/exact/evm/facilitator.ts')+d.cite('同期旧 EVM 规范',BASE/'release-spec-map/documents/d082b1f60a254fd9d8640d1b8b8862d5af801033.md'))
    d.add('### 金额策略与部署安全裕量')
    d.add('旧规范的授权金额文字是 enough to cover，早期实现使用下界比较；后续 v2 与其 v1 adapter 改为严格相等。判断这类变化时要区分固定金额目标、必须拒绝的付款与规范是否保证接受超额付款。6 秒有效期裕量、结算前复验是具体时序措施；它们不提供原子性或全部并发安全证明。')
    d.add('### 钱包、资产及回执的防御性检查')
    d.add('工厂允许列表默认拒绝未获准的 ERC6492 部署，保护 facilitator 的交易执行范围。后来增加严格 ERC1271 分派、普通 EOA high-s 拒绝、资产代码检查及 Transfer 事件参数匹配。后者仅在日志存在的分支执行；资产有代码也不证明其经济语义正确。默认缓存仍有 TTL/共享部署前提。')
    d.add('### 网络响应、幂等与 pending 状态')
    d.add('HTTP 成功响应 schema、截止时间和 1 MiB 有界读取主要补强解析/可用性边界，不能证明 facilitator 说的结算状态真实。payment identifier helper 是格式/要求校验，持久去重与请求指纹仍需应用实现。Pending store 按付款签名保存广播哈希，默认进程内 5 分钟 TTL；这不是新的链上 nonce 规则，也不是 exactly-once 证明。')
    d.add('## 如何阅读每一版的结论')
    d.add('从每个源码提交报告查看同期规范和局部检查，再按每个 package family 的 baseline 查看增删改。v1 legacy 与 v2 同树并存时不能互相套用条文；包元数据异常、非祖先基线、重构迁移和首次快照单独标明。'+d.cite('逐提交报告目录',HERE/'commits')+d.cite('逐 tag 报告目录',HERE/'releases'))
    d.add('“未匹配到源码形式”保持 unknown，不等于实现缺失；“观察到保护分支”不等于完整路径安全。报告给出可核对的实现措施和差异候选，不给出未经证实的漏洞或形式化保证。')
    d.write()


def write_expert_cases(inputs):
    """Concrete code readings; byte-identical reuse is explicit and bounded."""
    commits=inputs['commits'];bycommit={c['commit']:c for c in commits};cases=[]
    def source(commit,path,needle):
        item=next(f for f in bycommit[commit]['indexed_files']+bycommit[commit]['additional_local_code'] if f['file']==path)
        local=Path(item['local_file']) if 'local_file' in item else BASE.parents[1]/'x402_upstream_20261113_07c4caf_snapshot'/path
        if not local.is_file():raise ValueError('Expert case requires a local source file')
        raw=local.read_bytes();assert hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()==item['git_blob']
        lines=raw.decode().splitlines();line=next(i for i,value in enumerate(lines,1) if needle in value)
        return dict(commit=commit,file=path,git_blob=item['git_blob'],local_file=str(local),line=line,quote=lines[line-1])
    def matching(evidence):
        result=[]
        for commit in commits:
            files={f['file']:f['git_blob'] for f in commit['indexed_files']+commit['additional_local_code']}
            if all(files.get(e['file'])==e['git_blob'] for e in evidence):result.append(commit['commit'])
        return result
    def case(id,title,conclusion,evidence,scope_note,applicable=None,spec=None):
        cases.append(dict(id=id,title=title,conclusion=conclusion,evidence=evidence,
                          applicable_commits=matching(evidence) if applicable is None else applicable,
                          scope_note=scope_note,spec_evidence=spec or [],status='expert_static_judgment_unverified',confirmed_vulnerability=False))
    early='500a93e236844526b17635cfbd54e7e798486e8a';alpha='a4a1bcfcb9fa304bd0f3965ce012505e5c5b9a51';py='dd49a436183aaa72f3a8e2d8b82d8cc226fb6e5e';latest='07c4cafccdb41012fafc2c84252cc5ac1954c810'
    case('J01','早期需求选择器与地址校验补齐',
         '最早 findMatchingPaymentRequirements 只比较 scheme/network；同快照 TS EVM verify 没有显式 to/payTo 比较。后续 67378d 样本加入地址 guard，是可定位的局部绑定检查补齐；尚未确认完整部署可被利用。',
         [source(early,'typescript/packages/x402/src/shared/middleware.ts','value => value.scheme === payment.scheme && value.network === payment.network'),source(early,'typescript/packages/x402/src/schemes/exact/evm/facilitator.ts','const recoveredAddress = await verifyTypedData')],
         '精确复用只限两个文件均字节一致的快照；判定对象是显式局部检查，不是链上转移结果。')
    case('J02','早期 Go 与 TS 的 nonce 查询策略不同',
         '已读 Go Verify 在 nonce 查询失败时返回错误，已用 nonce 也拒绝；同树早期 TS v2 Verify 没有对应的独立查询。两者不能仅因共享协议或包版本就被视作完全相同的预验证保证。Token 最终拒绝与调用者政策仍需另证。',
         [source(alpha,'go/mechanisms/evm/exact/facilitator/scheme.go','nonceUsed, err := f.checkNonceUsed'),source(alpha,'typescript/packages/mechanisms/evm/src/exact/facilitator/scheme.ts','if (BigInt(exactEvmPayload.authorization.value) < BigInt(requirements.amount))')],
         'alpha 是首次本地样本，不冒充稳定发布；相关字节一致的后续 tag 引用见适用列表。')
    case('J03','Python nonce/余额读取失败会继续',
         '已读 Python verify 捕获 nonce 或余额查询异常后继续，而已读 Go 对相应错误返回失败。这是失败策略差异；不能把 Python 文档字符串写着检查 nonce 等同于每条路径都检查成功，也不能由此直接断言可重复结算。',
         [source(py,'python/x402/mechanisms/evm/exact/facilitator.py','pass  # Continue if nonce check fails')],
         '仅适用源码 blob 一致的 Python 模块；未用 RPC 故障输入或运行测试验证外部行为。')
    case('J04','Java 通用客户端不是现成的标准 EVM payload 构造器',
         'Java X402HttpClient 将 amount/asset/payTo/resource/UUID nonce 放进通用 map，并调用注入的 CryptoSigner；这段默认构造不同于 exact EVM 文档中嵌套 authorization 的完整字段形状。需要 scheme-specific 适配和签名实现，不能仅凭 Java SDK 存在就声称标准 EVM 互操作已完成。',
         [source(latest,'java/src/main/java/org/x402/client/X402HttpClient.java','pl.put("amount"')],
         'CryptoSigner 或业务层可另行适配；这里不是宣称所有 Java 客户端都不兼容。')
    case('J05','Java 新增结算后正文释放',
         '最新本地 tag 的 PaymentFilter 用响应包装器缓冲正文，结算失败不释放成功正文，成功后才 flush；这一 helper 在本地快照中首次出现于 07c4caf。仍不能回滚先前业务副作用，且对 4xx/5xx 有不结算而释放错误正文的分支。',
         [source(latest,'java/src/main/java/org/x402/server/PaymentFilter.java','BufferingHttpServletResponseWrapper buffered ='),source(latest,'java/src/main/java/org/x402/server/BufferingHttpServletResponseWrapper.java','final class BufferingHttpServletResponseWrapper')],
         '首次本地出现不是原始引入 commit；未执行 Servlet 容器或集成测试。')
    delegation=[]
    for commit in commits:
        scheme=next((f for f in commit['indexed_files'] if f['file']=='typescript/packages/mechanisms/evm/src/exact/facilitator/scheme.ts'),None)
        if not scheme:continue
        code=Path(scheme['local_file']).read_text()
        bundle=read(BASE/'release-spec-map/bundles'/(commit['spec_bundle_id']+'.json'))
        doc=next((x for x in bundle['documents'] if x['path']=='specs/schemes/exact/scheme_exact_evm.md'),None)
        if doc and 'ERC-7710' in (BASE/'release-spec-map'/doc['local_file']).read_text() and 'ExactEIP3009Payload | ExactPermit2Payload' in code:
            evm=[f for f in commit['indexed_files'] if 'mechanisms/evm/' in f['file']]
            if not any('redeemDelegations' in Path(f['local_file']).read_text() or 'permissionContext' in Path(f['local_file']).read_text() for f in evm):delegation.append(commit['commit'])
    specpath=BASE/'release-spec-map/documents/cda2ed42b0169e8db05969c193a8012f74fb0b20.md'
    case('J06','ERC7710 文档与内置 TS 路由范围不同',
         '后期 exact EVM 文档描述三种转移方法并单列 ERC7710；已核对的内置 TS ExactEvmScheme 路由为 EIP3009/Permit2 二分，索引 EVM 实现未出现 permissionContext/redeemDelegations 接口字段。属于文档支持范围与该内置适配器的能力差异，不自动等于必须支持全部机制的规范违例；服务可以提供其他自定义实现。',
         [source(latest,'typescript/packages/mechanisms/evm/src/exact/facilitator/scheme.ts','const body = payload.payload as ExactEIP3009Payload | ExactPermit2Payload')],
         '按相关分派形式和 EVM 目录文本核对；其他路径/第三方插件保持未知。',applicable=delegation,spec=[dict(local_file=str(specpath),line=7),dict(local_file=str(specpath),line=309)])
    case('J07','回执检查存在明确条件',
         '当前 EIP3009 结算只在 receipt.logs 非 null 时调用 Transfer 匹配；辅助检查校验事件 token/from/to/value。不能把这个实现写成无条件证明链上到账；缺日志、Token 行为、确认深度和 signer 适配均需分别说明。',
         [source(latest,'typescript/packages/mechanisms/evm/src/exact/facilitator/eip3009.ts','receipt.logs != null &&'),source(latest,'typescript/packages/mechanisms/evm/src/exact/facilitator/eip3009-utils.ts','logs: logs.filter(log => isAddressEqual(log.address, erc20Address))')],
         '精确文件 hash 相同才继承本条源码判断；不继承任何其他工作区的动态测试。')
    case('J08','HTTP 校验不消除 facilitator 信任',
         '当前 HTTP 客户端会校验 JSON/schema、设置超时和限制响应体积，但仍消费远端支付状态；这些资源与格式检查不证明远端诚实。构造器只归一化 URL 且 fetch 可跟随重定向，URL 配置仍应视为受信部署输入，不能自动宣称具备完整 SSRF 防护。',
         [source(latest,'typescript/packages/core/src/http/httpFacilitatorClient.ts','const parsed = schema.safeParse(data)'),source(latest,'typescript/packages/core/src/http/httpFacilitatorClient.ts','this.url = (config?.url || DEFAULT_FACILITATOR_URL)')],
         '仅描述已经读到的本地校验与信任界面，未构造恶意响应或网络请求。')
    save(HERE/'expert-cases.json',cases)
    d=Document(HERE/'DEEP-REVIEW.md','具体源码 / spec 的专家静态核对案例')
    d.add('以下是具体源码读取后的局部判断，适用性按精确 blob 或明确接口条件记录。不存在动态复现、漏洞确认或全协议证明。'+d.cite('逐案例适用性和证据',HERE/'expert-cases.json'))
    for entry in cases:
        d.add('## '+entry['id']+' '+entry['title']);d.add(entry['conclusion']);d.add('适用范围：'+entry['scope_note']+'；匹配 '+str(len(entry['applicable_commits']))+' 个源码快照。')
        for evidence in entry['evidence']:d.add('源码：`'+evidence['file']+':'+str(evidence['line'])+'`，`'+txt(evidence['quote'])+'`。'+d.cite('源码 '+evidence['file'],evidence['local_file']))
        for evidence in entry['spec_evidence']:d.add('同期规范第 '+str(evidence['line'])+' 行附近。'+d.cite('同树 exact EVM 规范',evidence['local_file']))
    d.add('## 同期规范自身也演进了')
    d.add('当前 EVM 文档直接讨论 ERC7710 的委托撤销竞态和恶意 Delegation Manager 消耗 gas，给出 gas limit 等运维建议。这些是对不同角色风险的具体提醒；不能声称后续官方文档只重复了三句付款有效性条件。这里不据此建立完整形式化威胁模型。'+d.cite('同树 EVM security considerations',specpath))
    d.write();return cases


def write_indexes(inputs,timeline,rows):
    rank={c['commit']:i for i,c in enumerate(inputs['commits'])}
    d=Document(HERE/'EVOLUTION.md','安全相关实现的逐步演进：本地快照观察序列')
    d.add('以下按提交时间展示不同组件中首次观察到的具体源码形式。时间不是原始引入 commit，缺少某种形式也不等于完全没有相应能力。'+d.cite('逐组件证据和时间序列',HERE/'security-evolution.json'))
    table=['| 日期 / 提交 | 组件 | 具体实现 | 对照报告 |','| --- | --- | --- | --- |']
    for item in sorted(timeline,key=lambda e:(rank[e['first_observed_commit']],e['component'],e['feature'])):
        sha=item['first_observed_commit'];e=item['evidence']
        table.append('| '+item['date'][:10]+' / `'+sha[:12]+'` | '+item['component']+' | '+txt(item['title'])+' '+d.cite('源码 '+e['file'],e['local_file'])+' | [本提交分析](commits/'+sha+'/analysis.md) |')
    d.add('\n'.join(table));d.add('v1 legacy、v1 adapter 和 v2 均分别列出；不要把旧目录保留的下界金额比较误当作 v2 严格金额检查被删除。包发布线、分支祖先与完整增删改见逐 tag 报告。'+d.cite('逐 tag 演进记录',HERE/'releases'))
    d.write()
    d=Document(HERE/'RELEASES.md','全部已保存 tag 的逐发布线分析入口')
    d.add('750 个引用对应 81 个源码快照，包括非生产引用。每项源码对照共享对应提交的专家静态判断；各包 baseline 分开比较，不把 Git tag 当作 registry 分发物证明。'+d.cite('tag 与同期规范映射',BASE/'release-spec-map/mapping.json'))
    families=collections.defaultdict(list)
    for row in rows:
        meta=read(Path(row['folder'])/'audit.json');families[meta['mapping'].get('family','unknown')].append(row)
    d.add('每行是对应静态报告的导航，具体原始来源和差异证据在该报告的参考文献中。'+d.cite('逐发布引用证据集合',HERE/'releases'))
    for family,items in sorted(families.items()):
        d.add('## '+txt(family));table=['| tag | 固定提交 | 发布线比较状态 |','| --- | --- | --- |']
        for row in items:
            delta=read(HERE/'releases'/row['version_id']/'evolution.json')
            table.append('| ['+txt(row['tag'])+'](releases/'+row['version_id']+'/analysis.md) | `'+row['commit'][:12]+'` | '+delta['status']+'；'+delta.get('ancestry','same_or_initial')+' |')
        d.add('\n'.join(table))
    d.write()
    d=Document(HERE/'README.md','llm-judge 阅读入口')
    d.add('新建的独立只读源码审阅工作区；输出为有范围的专家静态判断，不调用付费 API、不执行目标测试。覆盖和未覆盖事项见主分析。'+d.cite('主分析',HERE/'analysis.md'))
    d.add('- [analysis.md](analysis.md)：整体结论、规范差异候选、实现侧安全补充和边界。\n- [DEEP-REVIEW.md](DEEP-REVIEW.md)：八个具体源码/规范案例。\n- [EVOLUTION.md](EVOLUTION.md)：按日期观察到的实现变化。\n- [RELEASES.md](RELEASES.md)：全部发布引用的分析入口。\n- `commits/<sha>/analysis.md`：81 个去重源码提交的对照。\n- `releases/<id>/analysis.md`：750 个 tag 的作用域和同发布线演进。')
    d.add('输入与证据分为 inputs.json（读取/身份）、component-variants.json（定位清单）、source-observations-v2.json（源码形态）、expert-cases.json（人工解释及精确适用性）。较早的 source-observations.json 是首轮有限定位结果，最终报告使用 v2，不能把首次正则未识别的调用形态当作实现不存在。'+d.cite('最终源码形式证据',HERE/'source-observations-v2.json')+d.cite('人工核对案例',HERE/'expert-cases.json'))
    d.add('未取得正文、其他链/机制、未展开调用路径、生产部署与 registry 内容等仍未验证。不能把读取了文件字节、文件名命中或静态分支存在写成完整代码安全保证。')
    d.write()


if __name__=='__main__':main()
