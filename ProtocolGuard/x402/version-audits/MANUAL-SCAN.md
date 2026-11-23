# 手动串行扫描命令

统一入口按“版本 → 当版规范文档 → 已提取原子规则 → 支持的验证阶段”串行执行，不需要逐条复制 rule ID。默认依次执行 `extract`、`locate`、`slice`、有条件的 `prune`、`review`、`assert`、`dynamic`，最后检查该版本是否支持 `payment`。只生成计划不会调用模型、读取凭据或执行 SDK。[[1]](#ref-1)

已准备的全量计划包含 **750 个 tag 引用、81 个源码提交、23,074 个规范文档出现次数**。相同提交的不同 tag 仍有各自的审计目录；这里只共享只读输入，不把一次模型或动态运行写成多个独立运行。这个数字也不是安全目标数量或已完成审计数量。[[2]](#ref-2)

串行入口通过 6 项合成测试，覆盖规则动态发现、付费与动态门禁、累计请求上限、预算暂停后续跑、不重试失败请求及计划身份校验。本轮没有执行下面的付费或 x402 动态命令。[[3]](#ref-3)

## 1. 开始扫描

全量计划已经生成，直接运行以下命令。`100` 是本计划累计预留的 API 请求次数上限，可在手动启动前改为自己接受的值；它不是美元账单上限，也不足以扫描完所有文档和规则：

```bash
cd /home/yly/atelier/research/projects/x402_experiment

python3 ProtocolGuard/x402/batch_scan.py run \
  --plan ProtocolGuard/x402/version-audits/scans/all-versions-001/plan.json \
  --key-file /home/yue/yue-k \
  --allow-paid \
  --max-paid-calls 100 \
  --execute
```

这条命令会启动付费模型审查和所支持的本地动态验证。模型沿用 `gpt-6.1-sol`、reasoning `low`。全篇规范提取每个文档最多一次请求；每条规则最多预留定位 1 次、相关性 1 次、审查 4 次、断言计划 1 次。相关性阶段没有匹配依赖视图时不会请求模型。保留完整源码，不能把自动提取出的字段名当作已经证明正确的 handler/context 映射。

请求预留在启动阶段前落盘，即使进程中断也不退回，以免续跑超出累计上限。失败或中断的阶段不自动重试；预算不足时尚未启动的阶段可以在明确提高累计上限后继续。

## 2. 达到请求上限后续跑

如果停止原因明确是 `Request cap reached`，可将累计上限改为 `200` 并继续同一计划。已完成的任务不会重新付费；这里的 `200` 是累计上限，不是另加 200 次：

```bash
python3 ProtocolGuard/x402/batch_scan.py run \
  --plan ProtocolGuard/x402/version-audits/scans/all-versions-001/plan.json \
  --key-file /home/yue/yue-k \
  --allow-paid \
  --max-paid-calls 200 \
  --execute
```

如果停止原因是模型/API 失败、拒绝、输入过大、已有不完整尝试、切片超限或源码身份变化，查看记录并处理具体问题；提高预算不会重试失败请求。不得用新计划、换提示词或改输出目录来规避已拒绝的请求。运行锁会阻止两个进程同时执行同一计划。

## 3. 查看进度和结果

```bash
python3 -m json.tool ProtocolGuard/x402/version-audits/scans/all-versions-001/summary.json
```

`summary.json` 在首次运行结束、暂停或异常停止后生成；尚未手动启动时不存在。详细任务记录在同目录 `journal.json`，子进程日志在 `logs/`；各阶段产物仍写入原来的每版本目录。`completed` 表示阶段产物已生成；要同时看 `artifact_status_counts` 中的模型判断、未执行等实际状态，不能把它解读为安全检查通过。

已有完整结果只记录引用，不覆盖。`started` 或 `failed` 的旧任务以及不完整阶段目录会阻止自动重发。缺少 handler、规范文档、字段 criterion 或支付适配器的项目会记录缺口，不标为通过。全文提取仍可能报告未处理章节；扫描器不会自动追加模型请求，因此遍历完成不证明规范提取穷尽。

## 4. 单版本或仅静态扫描

创建一个新计划时输出目录必须尚不存在。以下是单版本、仅静态审查的完整命令；它不包含 `dynamic` 或 `payment`，因此运行时不需要 `--execute`：

```bash
python3 ProtocolGuard/x402/batch_scan.py plan \
  --version 'npm-@x402/core@v2.31.0' \
  --stages extract locate slice prune review assert \
  --output ProtocolGuard/x402/version-audits/scans/core-static-001

python3 ProtocolGuard/x402/batch_scan.py run \
  --plan ProtocolGuard/x402/version-audits/scans/core-static-001/plan.json \
  --key-file /home/yue/yue-k \
  --allow-paid \
  --max-paid-calls 100
```

可以重复 `--version` 选择多个明确版本。`--all-versions` 选择全部 tag 引用；`--per-commit` 只选择每个提交的一个代表 tag，不能当作逐 tag 独立审计。仅保留 `slice` 等某个阶段时，必须事先拥有它所依赖的已完成产物。

## 5. 全量扫描没有自动包含的能力

历史 EOA harness 的源码门禁目前只匹配 1 个提交、26 个 tag 引用；其余记录 `not_executed_adapter_missing`。这也不代表这些 tag 的所有语言和链均被测试。四语言回归、原生 LLVM 变异以及支付安全 oracle 的边界仍以能力记录为准。[[4]](#ref-4)

`native-test` 必须明确选择语言、当版项目目录、本地 Git store 和离线依赖；它不是安全目标专用 oracle，不能盲目对全部版本指定相同目录。保留逐条执行入口，例如：[[5]](#ref-5)

```bash
python3 ProtocolGuard/x402/version_audit.py capabilities \
  --version 'npm-@x402/core@v2.31.0'

python3 ProtocolGuard/x402/version_audit.py native-test \
  --version 'npm-@x402/core@v2.31.0' \
  --native-language go --native-subdir go \
  --git-store ProtocolGuard/x402/releases/upstream.git \
  --execute
```

原生 LLVM 入口需要明确的编译桥接、criterion 和 corpus，尚不能自动将各 SDK 编译为被测原生目标。串行扫描器不调用输入生成或原生变异，也不会自动安装缺失工具链。不能将 `serial_traversal_finished_not_security_proof` 写为全协议安全证明或全部能力已补齐。

## 6. 更新逐版本 analysis.md

扫描结束、失败或预算暂停时会离线刷新本次遍历版本的报告。也可随时单独运行以下命令，汇总所有已保存结果，无需凭据、不调用模型、不执行 SDK：[[6]](#ref-6)

```bash
python3 ProtocolGuard/x402/report_audits.py
```

查看各版本的 `analysis.md`、`analysis-evidence.json` 和 `evolution.json`，或从 `EVOLUTION.md` 按发布线进入对应版本。早期空 handler 记录仍保留，并标注该次输入是否只有索引；报告不会据此声称实现缺失或安全验证通过。后续新定位会提供函数正文，旧定位不自动重发。

## References

<a id="ref-1"></a>[1] ProtocolGuard 项目，“手动串行扫描入口”，2026。[实现](../batch_scan.py)

<a id="ref-2"></a>[2] ProtocolGuard 项目，“全部版本的逐文档扫描计划”，2026。[计划](scans/all-versions-001/plan.json)

<a id="ref-3"></a>[3] ProtocolGuard 项目，“串行扫描合成测试”，2026。[结果](scans/BATCH-VALIDATION.json) [测试代码](../tests/test_batch_scan.py)

<a id="ref-4"></a>[4] ProtocolGuard 项目，“补充实现的能力及缺口”，2026。[记录](IMPLEMENTATION-STATUS.md) [能力盘点](CAPABILITY-INVENTORY.json)

<a id="ref-5"></a>[5] ProtocolGuard 项目，“逐版本单阶段入口”，2026。[实现](../version_audit.py)

<a id="ref-6"></a>[6] ProtocolGuard 项目，“逐版本证据分析与发布线差异汇总”，2026。[生成器](../report_audits.py) [演进索引](EVOLUTION.md)
