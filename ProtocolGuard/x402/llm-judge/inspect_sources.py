"""Source evidence locators, not automatic semantic compliance verdicts."""
import hashlib
import json
from pathlib import Path
import re

HERE=Path(__file__).resolve().parent

# Exact implementation forms only. A missing match is not an absent defense.
FEATURES={
 'recipient_guard':dict(title='EVM 收款地址显式比较',components=['ts_evm_v1','ts_evm_v2','ts_evm_v1_adapter'],pattern=r'if \(getAddress\([^\n]*authorization\.to\) !== getAddress\([^\n]*payTo\)\)'),
 'network_guard':dict(title='EVM payload 与 requirements 网络显式比较',components=['ts_evm_v2'],pattern=r'if \(payload\.accepted\.network !== requirements\.network\)'),
 'amount_lower_bound':dict(title='授权金额下界比较',components=['ts_evm_v1','ts_evm_v2','ts_evm_v1_adapter'],pattern=r'if \(BigInt\([^\n]*authorization\.value\) < BigInt\([^\n]*(?:maxAmountRequired|amount)\)\)'),
 'amount_exact':dict(title='授权金额严格相等检查',components=['ts_evm_v1','ts_evm_v2','ts_evm_v1_adapter'],pattern=r'if \(BigInt\([^\n]*authorization\.value\) !== BigInt\([^\n]*(?:maxAmountRequired|amount)\)\)'),
 'expiry_margin':dict(title='到期时间额外提前 6 秒拒绝',components=['ts_evm_v1','ts_evm_v2','ts_evm_v1_adapter'],pattern=r'BigInt\([^\n]*authorization\.validBefore\) < BigInt\([^\n]*\+ 6\)'),
 'reverify_settle':dict(title='结算前再次验证',components=['ts_evm_v1','ts_evm_v2','ts_evm_v1_adapter'],pattern=r'const valid = await (?:verify|this\.verify|verifyEIP3009)\(|const \{ response: valid(?:, classification)? \} = await verifyEIP3009\('),
 'evm_simulation':dict(title='EVM 交易模拟调用',components=['ts_evm_v2','ts_evm_v1_adapter'],pattern=r'await (?:this\.signer\.simulateContract|signer\.simulateContract|simulateEip3009Transfer(?:Result)?)\('),
 'factory_allowlist':dict(title='部署工厂策略门禁',components=['ts_evm_v2','ts_evm_v1_adapter'],pattern=r'if \(!isAllowed\)|if \(!factoryAllowed\)'),
 'asset_contract':dict(title='支付资产合约身份检查',components=['ts_evm_v2','ts_evm_v1_adapter'],pattern=r'const assetReason = await assetCheck\.await\(\)'),
 'low_s':dict(title='拒绝非规范 ECDSA 签名',components=['ts_evm_v2','ts_evm_v1_adapter'],pattern=r'if \(isPlainNonCanonicalEcdsaSignature\('),
 'transfer_receipt':dict(title='回执 Transfer 事件参数检查',components=['ts_evm_v2','ts_eip3009_utils'],pattern=r'!verifyEip3009TransferEvent\('),
 'pending_reconcile':dict(title='待确认交易按签名复用',components=['ts_evm_v2'],pattern=r'const cachedTx = await store\.get\(signature\)'),
 'pending_ttl':dict(title='默认待确认缓存 5 分钟 TTL',components=['ts_pending_store'],pattern=r'export const PENDING_SETTLEMENT_TTL_MS = 5 \* 60 \* 1000'),
 'buffer_end':dict(title='HTTP 延迟 end 输出',components=['ts_http_middleware'],pattern=r'res\.end = (?:function|\()|res\.end = \(\(.*'),
 'facilitator_schema':dict(title='facilitator 成功响应 schema 校验',components=['ts_http_facilitator'],pattern=r'const parsed = schema\.safeParse\(data\)'),
 'facilitator_deadline':dict(title='facilitator 请求截止时间',components=['ts_http_facilitator'],pattern=r'const signal = AbortSignal\.timeout\(this\.timeoutMs\)'),
 'bounded_body':dict(title='facilitator 响应体积上限读取',components=['ts_http_facilitator'],pattern=r'await readLimitedText\(response, MAX_CONTROL_PLANE_RESPONSE_BYTES\)'),
 'strict_1271':dict(title='有代码钱包使用严格 ERC1271 分支',components=['ts_signature'],pattern=r'return verifyERC1271\(signer, address, digest, signature\)'),
 'identifier_format':dict(title='payment identifier 格式检查',components=['ts_identifier'],pattern=r'if \(!isValidPaymentId\(id\)\)'),
 'pending_retry_once':dict(title='settlement_pending 条件下一次重试',components=['ts_resource_server'],pattern=r'private async settleWithPendingRetry\('),
 'permit_reentrancy':dict(title='Permit2/批结算外部入口重入防护',components=['contracts'],pattern=r'\) external nonReentrant \{'),
}


def main():
    inputs=json.loads((HERE/'inputs.json').read_text());variants=json.loads((HERE/'component-variants.json').read_text())
    evidence=[]
    for variant in variants:
        path=Path(variant['local_file']);source=path.read_text()
        if hashlib.sha1(b'blob '+str(len(source.encode())).encode()+b'\0'+source.encode()).hexdigest()!=variant['git_blob']:
            raise ValueError('Source text identity changed')
        lines=source.splitlines()
        for key,feature in FEATURES.items():
            if variant['component'] not in feature['components']:continue
            for match in re.finditer(feature['pattern'],source):
                line=source.count('\n',0,match.start())+1
                # Operational patterns above start with actual statements;
                # reject matches located inside ordinary line/doc comments.
                if lines[line-1].lstrip().startswith(('//','*')):continue
                evidence.append(dict(feature=key,component=variant['component'],file=variant['file'],git_blob=variant['git_blob'],local_file=variant['local_file'],
                     line=line,end=line+match.group().count('\n'),quote=match.group(),
                     context=[dict(line=n,text=lines[n-1]) for n in range(max(1,line-2),min(len(lines),line+8)+1)],
                     commits=variant['commits'],interpretation='exact source form located; semantic analysis is in expert review, not inferred by regex'))
    order={e['commit']:i for i,e in enumerate(inputs['commits'])}
    timeline={}
    for key,feature in FEATURES.items():
        found=sorted({commit for e in evidence if e['feature']==key for commit in e['commits']},key=order.get)
        timeline[key]=dict(title=feature['title'],first_observed_commit=found[0] if found else None,commits=found,
                          coverage='only selected implementation forms; no match is not absence')
    out=HERE/'source-observations-v2.json'
    if out.exists():raise ValueError('Observation file exists; no overwrite')
    out.write_text(json.dumps(dict(features=FEATURES,timeline=timeline,evidence=evidence),ensure_ascii=False,indent=2)+'\n')
    print(json.dumps({key:dict(first=value['first_observed_commit'],commits=len(value['commits'])) for key,value in timeline.items()},ensure_ascii=False))


if __name__=='__main__':main()
