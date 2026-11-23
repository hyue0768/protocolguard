# Released code ↔ specification 对应关系

采集时点：`2026-11-15T06:32:44.190697+00:00`。本目录将官方代码 tag 对应到同一个固定源码提交下的 `specs/`，并保存规范原文及身份 hash。它提供源码—文档来源关系，不把共处同一提交当成语义一致性证明或官方兼容性承诺。官方采集响应完整保存在本地。[[1]](#ref-1)

## 1. 已完成的对应

| 项目 | 数量/状态 |
| --- | --- |
| 官方 tags | 750 |
| 不同源码提交 | 81 |
| 不同 spec 文件集合 | 41 |
| 排除索引/模板后的不同正文集合 | 41 |
| 去重后实际保存的规范文档 blob | 172 |
| 提交中无独立 core spec 文档的 tags | 90 |
| 有 core 文档但无显式协议版本头的 tags | 47 |
| 复用历史记录的 npm 包元数据对应异常 | 14 |
| 新增/移除/改指向的 tag | 0 / 0 / 0，相对前次 2026-11-13 采集 |
| 本轮模型调用/目标执行 | 0 / 0 |

这些计数直接来自映射和去重结果。750 个 tag 并非 750 套独立代码；多个包的 tag 可以指向同一源码提交，多份实现也可以带着完全相同的规范集合。规范正文分类按路径识别 core/scheme/transport/extension，排除 README、CONTRIBUTING 和模板；并非对所有句子逐条判定规范强度。[[2]](#ref-2)

## 2. 从哪里查看

| 需求 | 文件 |
| --- | --- |
| 每个 code tag 对应哪套 spec | [ALL-MAPPINGS.md](ALL-MAPPINGS.md) |
| 41 套不同规范快照 | [SPEC-BUNDLES.md](SPEC-BUNDLES.md) |
| 表格工具处理 | [mapping.csv](mapping.csv) |
| 全字段机器可读映射 | [mapping.json](mapping.json) |
| 每个源码提交及归档下载地址 | [snapshots/](snapshots/) |
| 每套规范包含的路径、角色与 blob | [bundles/](bundles/) |
| 172 份去重规范原文 | [documents/](documents/) |
| 文档 hash 与来源路径索引 | [documents.json](documents.json) |
| 本次官方元数据响应 | [acquisition.json](acquisition.json) |
| 统计和检查 | [summary.json](summary.json)、[validation.json](validation.json) |

## 3. “Released specification”的准确含义

本次官方 GitHub Releases 接口返回空列表；当前证据里没有一套独立 GitHub Release 版本序列可与代码包逐项配对。因此，本目录对应的是 **tag → code commit → 该提交附带的 spec snapshot**，不是“SDK 版本 X 官方承诺实现独立 spec release Y”。字段 `independently_released_spec_version` 保持空值。[[1]](#ref-1)

协议版本、SDK/package 版本和规范文本修订身份是三个不同维度。613 个 tag 的快照同时带有显式 v1/v2 core 文档，这只说明两份文档共存，不证明该 tag 对应包同时实现两版协议。没有版本头的历史 core 文档也保持未知，不从包版本推测协议版本。[[2]](#ref-2)

每套 spec 使用排序后的“路径 + Git blob”集合计算完整 SHA-256 身份；即使协议主版本仍为 2，规范内容变化也会形成不同快照。另有排除索引/模板后的正文 fingerprint，帮助区分正文与辅助文件变化。每份保存文档均重新验证 Git blob hash，另记 SHA-256。[[2]](#ref-2)

## 4. 部分对应实例

| Code tag | 固定源码提交 | Spec bundle 前缀 | Core 显式版本头 | 正文文件数 |
| --- | --- | --- | --- | --- |
| npm-x402@v0.3.0 | 500a93e236844526b17635cfbd54e7e798486e8a | c1799ff80389 | 没有独立 core 文档 | 2 |
| npm-@x402/core@v2.1.0 | 55e7d0fe75762acbff962ac981e84f591435e191 | 29b978f620b6 | 无显式版本头 | 8 |
| npm-@x402/core@v2.31.0 | 07c4cafccdb41012fafc2c84252cc5ac1954c810 | a4642c63ea93 | 1、2 共存 | 45 |
| pypi-x402@v2.28.0 | 07c4cafccdb41012fafc2c84252cc5ac1954c810 | a4642c63ea93 | 1、2 共存 | 45 |

这些实例来自全量映射；第一个快照只带 exact 的通用/EVM 规范，不能拿今天的 core v2 文本补充成其发布时已有的规范。core 2.1.0 还涉及下述 tag/包元数据来源问题。[[2]](#ref-2)

## 5. 代码可获取性和包分发物边界

本次读取了全部 81 个固定提交的文件树，并为每个提交给出官方 SHA 归档下载 URL。规范原文已经实际保存；本轮没有把 81 个完整代码归档全部再次下载，也没有声称所有 npm/PyPI 分发包均与 Git tag 源码逐字节相同。现有 Git 对象与源码快照继续作为只读来源，不做 checkout/fetch/pull。[[2]](#ref-2)

14 个 npm tag 的名称在目标快照里找不到对应同名 package metadata；历史分析包含一个 core 2.1.0 实际分发归档的单独补测。此处保留该元数据异常和来源记录，不将其解释为“没有发布”或“代码漏洞”。其余 tag 的同名 package metadata 对应也不等于构建产物或 registry 归档等价证明。本轮 registry publication time 沿用前次记录，没有逐包刷新。[[3]](#ref-3)

## 6. 如何使用这份对应做后续分析

选择一个 tag，先按 `mapping.json` 找到 code commit 和 spec bundle，再从对应 bundle 读取当时存在的 core/scheme/transport/extension 文档；各文档原文通过 `local_file` 指向 `documents/`。需要比较发布更新时，使用同一包发布线的 baseline 和 `spec_changes_against_package_line_baseline`，不把不同包的相邻 tag 当作连续版本。规范缺失或没有可比较基线时显式保留未知。

已有历史版本报告仍在原 `releases/` 中，本目录通过链接关联，未改写历史报告。这里没有重新运行一致性模型或动态测试；来源对应关系不能替代“这版代码是否满足这版 spec”的语义判断。[[3]](#ref-3)

## 7. 生成入口

以下命令只读公开元数据和本地源码缓存，写入新的输出目录；不调用模型或执行目标代码。已经存在的目录会被拒绝覆盖。

```bash
# 使用已有采集离线重建到新目录
python3 ProtocolGuard/x402/map_release_specs.py \
  --output ProtocolGuard/x402/release-spec-map-offline

# 如需未来刷新官方 tags，明确使用刷新开关并选择新目录
python3 ProtocolGuard/x402/map_release_specs.py \
  --refresh-tags \
  --output ProtocolGuard/x402/release-spec-map-refresh
```

若未来有新 tag 的提交或规范 blob 不在本地，入口会停止并报告缺失对象，不用其他版本替代，也不自动 fetch。届时需要先取得该固定提交的源码或对象，再生成对应。生成算法保存在项目内。[[4]](#ref-4)

## References

<a id="ref-1"></a>[1] x402 Foundation，“官方 tags、GitHub Releases 与 main 元数据”，本地采集时点 2026-11-15T06:32:44.190697+00:00。[保存的响应](acquisition.json) [官方 Releases](https://github.com/x402-foundation/x402/releases)

<a id="ref-2"></a>[2] ProtocolGuard 项目，“逐 tag 源码与同提交规范快照映射”，2026。[mapping](mapping.json) [summary](summary.json) [规范原文索引](documents.json)

<a id="ref-3"></a>[3] ProtocolGuard 项目，“历史发布清单及包来源边界”，2026。[inventory](../releases/inventory.json) [package scope](../releases/package-scope.json) [历史方法和补测说明](../releases/README.md)

<a id="ref-4"></a>[4] ProtocolGuard 项目，“源码发布与规范映射生成器”，2026。[实现](../map_release_specs.py)
