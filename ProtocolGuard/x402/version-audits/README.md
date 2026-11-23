# 逐版本 ProtocolGuard 审计工作区

本目录以固定采集的 750 个官方 tag 与各提交自带的 specification 为输入。每个 tag 有独立的审计目录和报告；同一提交的源码、解析索引及相同规范的词法候选按内容复用，新的模型判断和动态输出不冒充已执行。本批范围、版本对应关系和逐 tag 身份见本地索引。[[1]](#ref-1)

## 1. 当前完成程度

已经离线准备 **750 个版本目录、81 个源码提交、41 套规范集合**。按不同源码提交累计生成 **26,544 条词法候选出现次数**，不是已确认的原子规则；保存并核对 **4,222 个去重实现源码 blob**。没有调用模型或执行目标 SDK。源码采用既有历史解析缓存，重新核对原始 blob 与每段索引源码的 hash，并非本次重新运行全量 parser。[[1]](#ref-1)

“目录存在”“阶段入口可用”不等于完整审计已完成。当前语义规则、模型 handler/context 定位、规则导向切片、三判断加综合、断言计划与新动态证据均待手动运行；初始 analysis.md 明确写出这些状态。不得把原 releases/ 下历史的组件观察填成新的完整运行结果。

## 2. 按版本组织

从 [ALL-VERSIONS.md](ALL-VERSIONS.md) 或 [index.json](index.json) 选择一个 tag。目录示例：

```text
versions/0733-npm--x402-core-v2.31.0-e2b26acb/
├── audit.json                 # tag、提交、spec、初始阶段状态及来源边界
├── analysis.md                # 本版本初始审计记录
├── source/                    # 对应提交的实现源码，只读共享输入
├── 01-spec/                   # 同版本规范集合、词法候选
├── 02-rules/                  # 模型原子规则与来源证据
├── 03-slices/                 # handler/context、调用闭包切片、SQLite
├── 04-consistency/            # 3 份判断及 synthesis
├── 05-assertions/             # 声明式断言和所需适配器
└── 06-dynamic/                # 新执行结果、组件输入与轨迹
```

Code SHA 是源码身份，spec bundle 是同提交规范集合身份；package version 不当作协议版本。90 个 tag 的提交没有独立 core 文档，47 个有 core 文档但无显式版本头，14 个 npm tag 有历史包元数据对应异常，均保留在每版本的 mapping 字段。审计对象默认是该 tag 指向的仓库实现快照，不宣称等同于 registry 分发包内容。[[2]](#ref-2)

## 3. 阶段链条及实际支持

| 阶段 | 输入 → 输出 | 当前实现性质 |
| --- | --- | --- |
| Spec provenance / segmentation | 同提交官方规范 → 原文、blob 身份、带行号候选 | 所有版本已准备；词法候选不保证穷尽语义要求 |
| Semantic rule extraction | 全文或单候选 → 原子义务、actor、message/fields、适用范围、条件/例外、证据 | 手动模型调用；非规范/歧义和未处理章节必须保留 |
| Handler/context location | 原子规则 + 当版符号索引 → 显式 handler/context ID | 手动模型定位；未找到 handler 时不得伪造切片 |
| Forward context slicing | 显式位置 + 调用索引 → 保守前向调用闭包、完整函数/文件、未解析项、SQLite | 本地静态处理；不是 field-level def-use/alias 精确切片 |
| Inconsistency detection | 规则 + 切片 + 当版规范 → 3 次判断 + 1 次综合 | 手动付费，检查来源引用；多次判断不等于形式证明或统计独立 |
| Assertion planning | 综合判断 + 当版组件 case 目录 → 声明式断言或 adapter_missing | 手动模型调用；不执行模型生成代码或任意输入 |
| Dynamic verification | 当版保存源码与显式断言 → 新组件执行及结果 | 手动开启；当前适配器限于已有 TS/Python helper/header/schema |

语义抽取既可选择全文 `--document`，也可选择词法候选 `--candidate`。全文模式避免只依赖 MUST/SHOULD 正则，但返回的有界模型解释仍不能证明提取穷尽。未处理部分和跨章节引用保留为限制。所有义务必须来自当版规范，不能用今天 v2 的要求追罚历史 v1。源码、spec 和 quote 身份在相应阶段重新检查。[[3]](#ref-3)

## 4. 与论文完整流程的差距

本实现提供上述阶段的适配入口，但**尚不是完整论文复现，也没有对全部版本完成完整审计**。缺失能力单独列在 [WORKFLOW-GAPS.json](WORKFLOW-GAPS.json)：精确 MessageCG/SVF、字段级依赖切片、自动语义裁剪、全语言 LLVM/Scapy/DFUZZ 定向 fuzzing，以及各历史支付状态/链/语言的动态 harness 尚未统一实现。[[4]](#ref-4)

原有 `dynamic` 阶段重放已保存、且来源与当版代码一致的 TS/Python 组件输入。新增 `payment` 阶段仅允许所需模块全部匹配的历史提交使用 EOA mock harness；新增 `native-test` 阶段可手动运行固定提交的原生项目回归测试，但没有自动的支付安全目标 oracle。缺少适配器仍记录为 unknown，不能靠 helper 或项目测试进程成功代替支付验证。Java/JS 等未进入既有实现索引的文件也不能被声称完成源码覆盖。本次新增能力、命令和具体缺口见补充记录。[[5]](#ref-5)

因此，对“完整 ProtocolGuard 流程”的准确交付状态是：逐版本输入和阶段骨架已建立；支持路径可以逐步执行；不支持路径明确留下实现缺口。任何版本只有在所需语义规则、切片、判断及相应动态适配均完成后，才可描述其限定范围的完整执行，不得从目录数量推导完成数量。

## 5. 手动串行扫描全部版本和规则

已准备逐版本、逐规范文档、逐原子规则的串行计划。最新的全量、单版本、仅静态、累计预算续跑和逐条原生测试命令统一放在手动扫描说明中；不再需要手工复制每个 rule ID。[[6]](#ref-6)

```bash
cd /home/yly/atelier/research/projects/x402_experiment
python3 ProtocolGuard/x402/batch_scan.py run \
  --plan ProtocolGuard/x402/version-audits/scans/all-versions-001/plan.json \
  --key-file /home/yue/yue-k --allow-paid \
  --max-paid-calls 100 --execute
```

该命令会启动付费模型和支持的本地动态验证；100 是累计预留请求上限，不是美元账单上限，也不足以完成全量扫描。遇到失败会停止，不自动重试、改写提示词或覆盖结果。达到预算上限后，明确提高累计上限可继续尚未启动的任务；已完成结果只引用。未支持路径保留 unknown/adapter_missing。实际范围与命令细节见说明。[[6]](#ref-6)

## 6. 全量审计如何计数

目前 750 个目录都只有输入准备与词法/索引阶段完成。它们引用 81 个源码提交和 41 个规范集合；该去重仅用于共享只读输入，不把相同 tag 的模型或动态执行自动复用成“独立验证”。同一规则是否适用于一个具体 npm 包，还需要结合 package scope；不能因整个仓库里存在某实现便声称该包发布了它。[[1]](#ref-1)[[2]](#ref-2)

每个原子规则后续有自己的定位、切片、4 次判断、断言及动态结果。一份文档的提取完成不代表该版全部 spec 完成；一条规则的动态观察也不代表全部机制、扩展和语言完成。对 actor、前置条件、规范强度、组件职责边界或 missing adapter 存疑时，保持 unknown，不标为漏洞或安全证明。

## 7. 第一轮切片补充记录

切片现在对每个调用保留索引内全部短名称匹配候选及其传递调用，避免同名调用的候选上下文缺失；名称匹配不作为接收者、导入或别名解析的证明。无候选调用显式保留为 unresolved，超过 `--max-symbols` 时整体停止，不输出截断切片。新增 `resolutions`、`dispatch_complete=false` 和 `completeness` 字段；字段访问记录保存原文件、行、列，属于词法导航证据，字符串与注释中的匹配也可能出现，不能当作字段 def-use，也不用于删除代码。既有结果保持原样，不追溯升级。实现及离线测试见执行入口对应目录。[[3]](#ref-3)

上一轮运行了 4 项新增合成索引测试与 4 项已有版本工作区测试，均通过；没有执行目标 SDK、付费模型或动态实验。新切片仍使用原来的手动 `slice --version "$TAG" --rule "$RULE"` 入口，既有输出目录仍拒绝覆盖。

上一轮之后仍缺精确 alias/间接调用解析、字段 def-use、语义裁剪、历史支付状态 harness、多语言适配及原始二进制定向模糊测试链。本轮补充的有界实现和剩余范围见第 8 节；最新状态保留在 gap manifest 中。[[4]](#ref-4)

## 8. 新增入口和验证边界

新增 AST 字段/行依赖视图、人工启动的模型相关性标注、历史 EOA 身份门禁、四语言原生回归适配，以及 LLVM18 原生距离插桩/有界变异入口。31 项离线及合成程序测试通过；新增能力仍不等于全部版本的完整审计或原论文复现。具体命令、证据和剩余实现需求见补充记录。[[5]](#ref-5)

## 9. 逐版本分析和发布线演进

每个版本的 `analysis.md` 现在有自动证据汇总区，列出当版规范处理状态、逐规则义务、handler/context、源码位置、一致性审查、动态观察和未执行事项。原有初始化/人工内容保留，首次更新前另存 `analysis.before-live-report.md`；只更新带明确标记的自动区及其参考文献。机器证据保存在 `analysis-evidence.json`，源码/规范差异保存在 `evolution.json`，按发布线的索引见演进表。[[7]](#ref-7)

```bash
python3 ProtocolGuard/x402/report_audits.py
```

该命令只读已有结果和源码，不调用模型或执行 SDK。串行扫描结束、预算暂停或失败时，也会刷新本次遍历版本的报告。代码符号新增、函数正文变化和模型认为支持某规则都不是确认安全补丁；早期缺少源正文的定位会标为 `symbol_index_only`，不自动重跑。[[7]](#ref-7)

## References

<a id="ref-1"></a>[1] ProtocolGuard 项目，“逐版本输入和审计目录索引”，2026。[index](index.json) [全部版本](ALL-VERSIONS.md) [目录](versions/)

<a id="ref-2"></a>[2] ProtocolGuard 项目，“官方 tag 与同提交规范映射及来源边界”，2026。[映射](../release-spec-map/mapping.json) [方法](../release-spec-map/README.md)

<a id="ref-3"></a>[3] ProtocolGuard 项目，“逐版本阶段执行入口”，2026。[实现](../version_audit.py) [离线检查](../tests/test_version_audit.py)

<a id="ref-4"></a>[4] ProtocolGuard 项目，“完整论文流程与当前适配的能力差距”，2026。[gap manifest](WORKFLOW-GAPS.json)

<a id="ref-5"></a>[5] ProtocolGuard 项目，“补充实现、验证状态与手动执行入口”，2026。[记录](IMPLEMENTATION-STATUS.md)

<a id="ref-6"></a>[6] ProtocolGuard 项目，“手动逐版本逐规则串行扫描命令”，2026。[命令](MANUAL-SCAN.md) [入口](../batch_scan.py)

<a id="ref-7"></a>[7] ProtocolGuard 项目，“逐版本证据分析与发布线差异汇总”，2026。[生成器](../report_audits.py) [演进索引](EVOLUTION.md)
