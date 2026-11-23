# 逐发布检查：实现变化与 code/spec 差距

本次线上 tags 的固定采集时点为 `2026-11-13T09:24:11.232948Z`。核对官方仓库后，按 **750 个 tags、81 个不同发布提交** 执行检查，另外单列未发布主线 `2178d4b77aff61395c375bbdf30757876393b85d`。[[1]](#ref-1) 本轮采用 ProtocolGuard 的“规范候选 → 规则相关源码 → 独立断言与执行观察”顺序，但没有调用其 LLM 语义判断或运行定向 fuzzing；这是可离线复现的组件级适配，不能称为完整论文复现或协议安全证明。[[2]](#ref-2)

官方 GitHub Release 列表仍为空，因此这里的“每个 release”具体指全部官方 Git tags；包含包版本、预发布及归档标记，不把它们统称为稳定协议版本。[[3]](#ref-3) 原有 `x402_release_history/` 仅作为只读缓存，所有新增结果位于本目录。缺失的版本/依赖 manifest 通过固定提交的官方 raw 接口补取并核对 Git blob 身份，保存于 `blob-cache/` 和 `manifest-fetch.json`。没有写其他 Coordinator 的代码或历史索引。

## 从哪里看每次改动

| 文件/目录 | 记录内容 |
| --- | --- |
| [ALL-RELEASES.md](ALL-RELEASES.md) | 全部 750 个 tag 的索引，每个都有独立报告 |
| `versions/0001.md` … `versions/0750.md` | 每个 tag 的源码 SHA、同一发布线基线、implementation 变化、code/spec 观察、前后变化与未验证项 |
| `intervals/*.md` | 116 个不同区间中每个文件新增/修改/删除的函数、类、变量、实际条件表达式变化，以及版本、依赖、导出和构建 manifest 的前后变化；标题是结构事实，不代替语义解释 |
| `intervals/*.json` | 完整符号、源码行号、前后 hash、条件表达式、manifest 字段前后值及规范实际 unified diff |
| `intervals/*.implementation.diff.gz` | 完整实际实现 diff，避免只凭提交标题推测“做了什么” |
| `events/<SHA>/static.json` | 该快照每个所定义实现文件的语法分析/词法扫描状态；不等于编译成功 |
| `events/<SHA>/candidates.json`、`contexts.json`、`contexts.db` | 本提交规范候选与源码关联；关联是词法定位，数据库未填造模型结论 |
| `events/<SHA>/dynamic.json` | 每个实际执行输入、组件、环境、返回或异常、断言状态、源码 blob 和规范示例来源 |
| [FINDINGS.md](FINDINGS.md) | 已复现差异、历史变化和解释边界 |
| [results.json](results.json)、[validation.json](validation.json) | 机器可读全量结果与计数 |
| [package-scope.json](package-scope.json) | tag 名称与目标快照内包元数据的对应；不把仓库测试冒称注册表发布包测试 |

每次记录直接回答：**implementation 新增、修改、删除了什么；相关 spec 有何净变化；选定输入下前后行为如何变化；哪些差距只是边界观察、哪些仍未知。** 同一源码提交的多个包 tag 复用执行结果；文件变化按各包 tag 的基线比较，所列变化是整个仓库快照的净变化，不是声称该包自身包含所有变更。首次 tag 是全量快照，不当作一次增量修复。提交时间不冒充包发布时间。

## 本轮执行范围与结果

| 项目 | 实际结果 |
| --- | --- |
| tag / 发布提交 / 快照执行 | 750 / 81 / 82（含一个未发布主线） |
| 不同 baseline → target 区间 | 116 |
| TypeScript、Python、Go 语法解析文件出现次数 | 43,468；跨快照重复，不是独立文件数；诊断为零，不等于类型检查、编译或语义通过 |
| Solidity / Rust 等仅词法扫描出现次数 | 587；没有标记成解析或编译通过 |
| 规范候选 | 28,196 条次；取各提交自带 `specs/`，包含共存的 v1/v2、机制与扩展；未语义消歧 |
| 本地组件 case | 4,776 次，包括 TS helper/header、部分 V2 Zod schema、Python helper/schema、Web Base64 globals 和 Buffer 对照分支 |
| 断言失败观察 | 159 次；主要是重复快照中的 Unicode 往返失败，不等于 159 个漏洞 |
| 接受边界输入的候选观察 | 847 次；decoder/schema 的职责不同，不自动判违规；同一输入在不同版本/环境中重复计数 |
| 动态 harness 错误 | 0 |
| 单独发布归档补测 | `@x402/core@2.1.0`，SRI SHA-512 校验通过；36 个补充 case，单独保存，不混入 4,776 次快照计数 |
| 工具回归 | `tests.log`：4 项通过；覆盖 tag 完整性、结构条件提取、真实失败与 Buffer 对照、没有伪造模型结果 |
| 模型调用 / 定向 fuzzing / 交易 | 0 / 0 / 0 |

动态测试只加载所选函数或 schema 模块，记录的“已加载变更文件”不等于分支覆盖。每份报告还列出该更新中多少实现文件根本不在动态 probe 的模块内；未测试的金额结算、签名、重放、授权、链上与集成路径均不能被这些 case 代表。TypeScript 模块经 TypeScript 5.9.3 转译；V2 Zod 组件使用固定的 Zod 4.6.6，记录 declared dependency 与 test dependency，未声称恢复每个版本的精确 lockfile 环境。Python 使用固定 Pydantic 2.12.5；Go 仅用语法树分析，因为本机无 Go toolchain。

## 离线复现

当前结果、源码切片和依赖已保留。以下命令从项目根目录运行，不访问商户、facilitator、RPC 或模型。

```bash
# 复现 core@2.0.0 的有效 Unicode header 往返失败，以及 Buffer 分支通过
ProtocolGuard/x402/.venv/bin/python ProtocolGuard/x402/releases/reproduce.py

# 验证检查工具与记录完整性；通过包含了“确实能复现失败”的测试
ProtocolGuard/x402/.venv/bin/python -m unittest discover -s ProtocolGuard/x402/releases/tests -v

# 重跑固定的全部历史快照；不刷新线上 tags，不读 API key，不调用模型
ProtocolGuard/x402/.venv/bin/python ProtocolGuard/x402/releases/run_offline.py

# 重新执行已保存的、SRI 校验过的 core@2.1.0 内嵌源码补测
ProtocolGuard/x402/.venv/bin/python ProtocolGuard/x402/releases/package_probe.py
```

`run_offline.py` 依赖项目里只读的 `x402_release_history/upstream.git/` 对象缓存，以及前次取得的两个独立固定源码快照；本目录 bare repo 使用 Git alternates 读取旧缓存，未修改其 refs 或 objects。新增提交通过已验证快照读取，不强行 checkout 或 pull 用户仓库。首次尝试在独立缓存增量 fetch 遇到 unresolved deltas，已记录在 `acquisition.log`；最终分析不依赖这次失败的 fetch。

`events/*/dynamic-inputs.json.gz` 保存实际源码切片和输入，`reproduce.py` 不依赖 Git 就能重放对应组件。下载依赖只发生在准备阶段，使用普通公开包，没有收费服务；版本和 npm lock 见 `tools/package-lock.json`、`requirements.lock`。

## 如何解释差距

- Unicode 往返失败是实际运行得到的组件级不正确行为，具有独立 oracle 和分支对照；没有证明它可以绕过支付或窃取资产。
- Python V2 schema 接受 `x402Version=99` 或缺失 `resource`，与同版本 core 表格约束有表面差异；仍需验证外围入口是否拒绝，不能先写成端到端 bug。
- TS header decoder 接受对象但不执行完整 schema 验证，不自动构成违规。当前 TS Zod schema 拒绝上述输入；这是职责边界需要区分的直接证据。
- 没有观察到新差异，不代表 code/spec 已一致；规范与实现同改或没有同步改 spec，也不能代替逐条语义核查。
- 本轮发现 14 个 npm tag 的名称没有对应到目标快照内同名 package metadata，其中 4 个是早期命名标记，10 个是 `@x402/*@2.1.0`。已额外核对一个实际发布归档；这是来源映射问题，不是认定它们没有发布、没有代码或存在漏洞。

## 还需要用户决定的后续部分

若要继续论文原版的模型消歧、handler/criterion 语义识别、自一致性判断和断言生成，需要明确模型服务、模型名称、规则量及预算；本轮不自动使用现成 key。定向 fuzzing 还需要相应语言的运行 harness、真实协议状态和独立 oracle；部署、链上交易、真实支付或付费 RPC 均未执行。

后续涉及 `@x402/*@2.1.0` 等 tag/发布物来源差异时，应决定以“Git tag 目标源码”还是“注册表实际分发物”为 release 主证据；本轮保留两套证据而不混为一份版本安全结论。

## References

<a id="ref-1"></a>[1] x402 Foundation, “x402 source repository and tags,” accessed 2026-11-13. [[url]](https://github.com/x402-foundation/x402/tags)

<a id="ref-2"></a>[2] Xiangpu Song, Longjia Pei, Jianliang Wu, Yingpei Zeng, Gaoshuo He, Chaoshun Zuo, Xiaofeng Liu, Qingchuan Zhao, and Shanqing Guo, “ProtocolGuard: Detecting Protocol Non-compliance Bugs via LLM-guided Static Analysis and Dynamic Verification,” in *Proc. NDSS*, 2026. [[doi]](https://doi.org/10.14722/ndss.2026.240521)

<a id="ref-3"></a>[3] x402 Foundation, “GitHub Releases API,” accessed 2026-11-13. [[url]](https://api.github.com/repos/x402-foundation/x402/releases?per_page=100)
