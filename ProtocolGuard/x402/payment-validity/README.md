# 三项支付有效性分析

本目录只处理用户给定的三条要求：付款人或 delegate 授权、付款匹配服务端广告条件、同一付款不能重复结算。原文位于 `spec.json`。[[1]](#ref-1)

## 从哪里开始

| 想看什么 | 位置 |
| --- | --- |
| 分析正文、证据与适用范围 | [analysis.md](analysis.md) |
| 三条原始 spec | [spec.json](spec.json) |
| handler/context、源码切片和规则 | [slices/](slices/) |
| 人工源码复核 | [static-review.json](static-review.json) |
| 模型审查输入 | [prepared/](prepared/) |
| 仅准备请求、没有模型调用的记录 | [preflight/](preflight/) |
| 待执行的八案例动态计划 | [dynamic-plan/plan.json](dynamic-plan/plan.json) |
| 以后每次执行的模型结果、动态结果和 trace | `runs/<run-id>/` |
| 唯一手动运行入口 | [run.py](run.py) |

切片、输入和计划已准备，不代表模型或动态执行已完成。实际状态按 `runs/` 内文件判断；查看状态命令不读取凭据、不调用模型、不执行 SDK。当前静态材料和适用范围见分析正文。[[2]](#ref-2)

## 手动执行

在项目根目录执行，默认批次是 `run-001`：

```bash
cd /home/yly/atelier/research/projects/x402_experiment

python3 ProtocolGuard/x402/payment-validity/run.py status

python3 ProtocolGuard/x402/payment-validity/run.py review \
  --key-file /home/yue/yue-k --allow-paid

python3 ProtocolGuard/x402/payment-validity/run.py dynamic --execute

python3 ProtocolGuard/x402/payment-validity/run.py status
```

逐步执行：先审查，再确认三项 review 成功，最后手动开启 dynamic。review 使用 `gpt-6.1-sol`、reasoning `low`，三项目标各一次请求；遇到失败即停，不自动重试。dynamic 只运行本地 HTTP/mock-ledger 测试，不调用模型或真实链。实现入口保留显式执行开关。[[3]](#ref-3)

新批次为每条命令加相同的 `--run-id run-002`。如果某次 review 部分完成，只补一个尚未执行的目标时，可以加 `--goal PAYER_AUTHORIZATION`、`--goal PAYMENT_BINDING` 或 `--goal REPLAY_RESISTANCE`。已有输出不会覆盖，失败的目标也不会自动重试。

执行结果统一落在：

```text
runs/run-001/
├── reviews/
│   ├── PAYER_AUTHORIZATION/
│   ├── PAYMENT_BINDING/
│   └── REPLAY_RESISTANCE/
└── dynamic/
    ├── results.json
    └── traces/
```

## 与历史材料的关系

旧 `security/payment-validity/` 是指向本目录的兼容符号链接，已有命令、绝对路径和引用仍可解析。共享实现继续位于 `../security/`，本目录的 `run.py` 调用它们；不复制第二套实现。更正范围前的扩展 spec、模型审查、动态结果和历史发布分析没有搬入当前工作目录，其历史地位见原样归档。[[4]](#ref-4)

## References

<a id="ref-1"></a>[1] ProtocolGuard 项目，“三条用户原始支付有效性要求”，2026。[spec](spec.json)

<a id="ref-2"></a>[2] ProtocolGuard 项目，“三项支付有效性分析及本地证据”，2026。[analysis](analysis.md) [切片身份](slices/manifest.json)

<a id="ref-3"></a>[3] ProtocolGuard 项目，“手动审查与动态验证入口”，2026。[run.py](run.py) [API实现](../security/codex_api_user_spec.py) [动态实现](../security/validate_payment_validity.py)

<a id="ref-4"></a>[4] ProtocolGuard 项目，“范围更正前的历史分析”，2026。[历史归档](../analysis.legacy-expanded.md)
