# 补充实现与实际完成状态

本轮补充了若干可执行适配能力，**没有完成“全部历史版本、全部语言的完整安全验证”**。固定提交的规范、源码、模型审查与实际执行是不同证据；新增入口不会将旧结果升级为新验证。全部入口仍由用户手动启动，既有尝试目录拒绝覆盖。[[1]](#ref-1)

## 已实现的范围

| 项目 | 实现与结果 | 仍不支持的范围 |
| --- | --- | --- |
| 调用上下文 | 全部短名称候选的传递闭包；无候选显式 unresolved；超限停止 | 接收者/导入身份解析、精确间接调用和 SVF points-to |
| 字段依赖视图 | TypeScript/Python AST、赋值 may-alias、读写路径、控制依赖、有界反向闭包；保留完整源码 | 全程序、跨语言、流敏感的 sound alias/def-use 分析 |
| 相关性标注 | 手动模型标注；依赖节点、调用、终止效果和不支持的上下文禁止排除；完整代码仍送审 | 可靠语义删除及其正确性证明 |
| 历史 EOA 支付状态 | 41 个模块全部匹配才允许使用已有 8 个 fixture；每次加载重新核对 hash | 其余历史 API/schema、智能账户、其他机制、实际链状态 |
| 原生回归测试 | Go、Rust、Solidity、Java 命令适配；从指定 Git 提交归档至临时工作副本；强制网络隔离与清空继承环境 | 将项目测试自动映射为支付安全 oracle；当前缺失的编译器/离线依赖 |
| LLVM 原生依赖 | 函数内 LLVM AA may-alias；局部函数指针来源与类型兼容候选；参数和返回传播 | SVF、闭世界调用图和精确跨过程 points-to |
| 原生距离与变异 | LLVM18 CFG 距离、基本块插桩、既有 corpus 重放、显式启用的有界字节变异与覆盖/距离调度 | 原始 LLVM10/SelectFuzz/AFLNet/Scapy 复现；自动 SDK-to-LLVM 桥接 |

字段分析是有界的、过程内、流不敏感的 may-dependency 视图。解析失败、无匹配 criterion、别名展开超限、AST 节点超限或语言不支持时回退为完整上下文，不能声称获得精确切片。JavaScript AST 入口可分析显式提供的文本，但既有逐版本实现索引没有因此自动扩展为 JavaScript 全覆盖。[[2]](#ref-2)

相关性阶段输出 `model_relevance_judgment_unverified`；它检查模型输出身份、证据和结构保留约束，但不证明标注语义正确。后续一致性审阅仍包含完整原始上下文，不根据标注删除源码。[[3]](#ref-3)

历史支付适配复用已有 fixture，不生成新 x402 输入。成功通过源码门禁仅表示可尝试运行，运行时依赖、接口行为与 mock oracle 的适用性仍需要实际观察；签名/账本见证依赖显式 mock 假设，不是链上或形式化证明。[[4]](#ref-4)

原生适配器执行的是项目回归测试。`process_completed` 仅记录进程结束，`returncode=0` 也不能证明测试覆盖了某条规范；结果固定保留 `rules_covered=[]` 和 `payment_validity=unknown`。依赖缓存必须显式提供并只读挂载，缺失工具、manifest、本地 Git 对象或依赖时停止，不自动联网安装或下载。Git 归档中的链接暂不支持，遇到链接会停止，不跳过文件冒充完整源码。[[5]](#ref-5)

原生距离使用直接调用、类型兼容的取地址函数候选与上下文不敏感的返回近似、单位边权反向 BFS。未知间接调用和外部函数仍是缺口；距离不是可达性证明。变异器只在同时提供 `--execute --generate-inputs` 时运行，观察到非零退出或超时不自动归类为确认漏洞。它没有实现规范到原生断言表达式的可靠自动翻译。[[6]](#ref-6)

## 离线盘点与验证

扫描 81 个源码提交后，只有 1 个提交的 41 个所需模块全部匹配现有 EOA profile，对应 26 个 tag 引用。这是整个仓库的源码身份匹配，不表示这些 tag 对应的 Go/Python/其他链分发包都获得了 EVM TypeScript 验证。其余 80 个提交保持 `adapter_missing`。本轮未执行任何历史支付 case。[[7]](#ref-7)

31 项检查全部通过、无跳过，包括合成源码 AST 依赖、相关性保留约束、源码身份门禁、临时 SQLite 切片集成、LLVM18 合成 C 距离/插桩/重放/变异，以及合成程序的网络命名空间和环境隔离。未调用付费模型、未执行 x402 SDK、未上链或发交易、未创建 x402 攻击输入。[[8]](#ref-8)

LLVM 原生切片还接入了函数内 may-alias 查询，以及全局/局部存储、PHI、select、实参等可追踪函数指针来源的候选传播；类型兼容候选用于补充未知来源，未知外部调用仍显式保留。新增合成 C 测试检查了间接调用参数传播及距离候选，不宣称完整函数指针分析或消息来源证明。[[9]](#ref-9)

环境有 LLVM18、Node 和 Java runtime；没有 Go、Cargo、Forge/solc、Maven。因此四语言原生入口的规划与隔离机制已测试，但目标工具链及真实项目回归测试尚未验证。安装工具并准备依赖也不等于补齐支付 oracle。[[7]](#ref-7)

## 手动入口

最新的全量逐文档、逐规则扫描命令已统一更新；下方保留单阶段入口供定位问题。累计预算、续跑及失败不重试的行为见手动扫描说明。[[10]](#ref-10)

先看具体版本的能力，以下 tag 只是当前 EOA 源码门禁可匹配的一个仓库引用：

```bash
TAG='npm-@x402/core@v2.31.0'
python3 ProtocolGuard/x402/version_audit.py capabilities --version "$TAG"
```

已有原子规则和定位结果时，选择实际字段 criterion；`RULE` 必须来自该版本 `rules` 的输出，下面字段需按实际源码调整。多个 `--criterion-field` 可并列指定。`--criterion-line` 是原源码行号，会用于闭包内每个文件的对应行，不能当作跨文件唯一定位：

```bash
python3 ProtocolGuard/x402/version_audit.py rules --version "$TAG"
RULE='替换为该版本实际的原子规则ID'
python3 ProtocolGuard/x402/version_audit.py slice \
  --version "$TAG" --rule "$RULE" --criterion-field 'payload.authorization.value'
```

新增 `flow-views.json` 与完整代码保存在该规则的 `.slice/` 中。若该目录已存在，不会覆盖旧切片。

可选相关性标注是付费阶段，需手动提供凭据文件路径；本轮未运行：

```bash
python3 ProtocolGuard/x402/version_audit.py prune \
  --version "$TAG" --rule "$RULE" --key-file /home/yue/yue-k --allow-paid
python3 ProtocolGuard/x402/version_audit.py review \
  --version "$TAG" --rule "$RULE" --key-file /home/yue/yue-k --allow-paid --max-calls 4
```

通过 EOA 源码门禁的版本可手动运行已有八个支付状态 case；这条命令不会要求或调用模型：

```bash
python3 ProtocolGuard/x402/version_audit.py payment --version "$TAG" --execute
```

原生回归示例需要指定本地 Git store，且 store 必须拥有该 tag 对应的完整提交对象。下面路径是本工程已有历史缓存，若缺少对象会停止；不会自动 fetch。其他语言使用 `rust`、`solidity`、`java`，项目子目录必须来自当版实际源码，不能因存在 Rust 工具项目便声称覆盖 Rust 协议实现：

```bash
python3 ProtocolGuard/x402/version_audit.py native-test \
  --version "$TAG" --native-language go --native-subdir go \
  --git-store ProtocolGuard/x402/releases/upstream.git --execute
```

离线依赖缓存可用 `--dependency-cache /绝对路径/缓存目录` 指定。原生结果写入版本目录下的 `06-dynamic/native-语言/`；支付状态结果写入 `06-dynamic/payment-state/`。模型规则审查与这两个结果仍需人工核对适用范围。

原生 LLVM 入口是 `dynamic_verification/DFUZZ/directed.py` 的 `prepare`、`replay`、`fuzz` 子命令。`prepare` 要求实际 C 编译入口和显式 `{"function":"函数名","line":原源码行号}` criterion；`replay` 消费已有 corpus；`fuzz` 另需显式输入生成标志。x402 SDK 尚没有自动到该原生入口的桥接，不能直接把它称为 x402 全协议动态验证。

## 未完成的具体工作

1. 为其余 80 个历史提交适配支付 API、schema、签名域、结算状态与重试/并发调度，并实现与被测实现独立的版本适用 oracle。
2. 为 Go、Solidity、Rust、Java 的实际协议实现建立安全目标专用测试；项目回归适配器不能替代它们。
3. 接入并验证真实 points-to/alias/间接调用引擎及消息 buffer 来源；过程内 AST 视图不能替代全程序分析。
4. 实现可靠的语义裁剪、规范到断言的翻译及相应正确性证据；模型相关性标注不是证明。
5. 接通并验证原始二进制定向 fuzzing 的依赖、网络消息模型及各 SDK 编译桥接；现有 LLVM18 适配不冒充原始工具链。

这些是尚未完成的实现和验证工作，并非已经确认“官方代码没有实现”的安全要求。当前无法将这批补充报告为“全部缺口已关闭”。

## References

<a id="ref-1"></a>[1] ProtocolGuard 项目，“逐版本阶段入口”，2026。[实现](../version_audit.py)

<a id="ref-2"></a>[2] ProtocolGuard 项目，“AST 依赖视图”，2026。[Python 实现](../flow_analysis.py) [TypeScript 实现](../flow_probe.cjs)

<a id="ref-3"></a>[3] ProtocolGuard 项目，“模型相关性保留约束”，2026。[实现](../relevance_view.py)

<a id="ref-4"></a>[4] ProtocolGuard 项目，“历史 EOA 源码身份适配”，2026。[适配器](../payment_adapter.py) [加载门禁](../../dynamic_verification/x402_guard/loader.cjs)

<a id="ref-5"></a>[5] ProtocolGuard 项目，“原生离线回归适配”，2026。[实现](../native_adapters.py)

<a id="ref-6"></a>[6] ProtocolGuard 项目，“LLVM18 原生距离与有界变异适配”，2026。[驱动](../../dynamic_verification/DFUZZ/directed.py) [插桩](../../dynamic_verification/DFUZZ/Directed18.cpp) [runtime](../../dynamic_verification/DFUZZ/trace_runtime.c)

<a id="ref-7"></a>[7] ProtocolGuard 项目，“历史源码能力离线盘点”，2026。[盘点](CAPABILITY-INVENTORY.json)

<a id="ref-8"></a>[8] ProtocolGuard 项目，“补充实现离线检查汇总”，2026。[结果](IMPLEMENTATION-VALIDATION.json) [测试代码](../tests/)

<a id="ref-9"></a>[9] ProtocolGuard 项目，“LLVM 原生依赖与调用候选分析”，2026。[实现](../../program_slicing/src/Passes.cpp) [测试](../tests/test_llvm.py)

<a id="ref-10"></a>[10] ProtocolGuard 项目，“手动逐版本逐规则串行扫描命令”，2026。[命令](MANUAL-SCAN.md)
