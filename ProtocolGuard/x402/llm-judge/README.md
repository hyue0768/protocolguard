# llm-judge 阅读入口

新建的独立只读源码审阅工作区；输出为有范围的专家静态判断，不调用付费 API、不执行目标测试。覆盖和未覆盖事项见主分析。[[1]](#ref-1)

- [analysis.md](analysis.md)：整体结论、规范差异候选、实现侧安全补充和边界。
- [DEEP-REVIEW.md](DEEP-REVIEW.md)：八个具体源码/规范案例。
- [EVOLUTION.md](EVOLUTION.md)：按日期观察到的实现变化。
- [RELEASES.md](RELEASES.md)：全部发布引用的分析入口。
- `commits/<sha>/analysis.md`：81 个去重源码提交的对照。
- `releases/<id>/analysis.md`：750 个 tag 的作用域和同发布线演进。

输入与证据分为 inputs.json（读取/身份）、component-variants.json（定位清单）、source-observations-v2.json（源码形态）、expert-cases.json（人工解释及精确适用性）。较早的 source-observations.json 是首轮有限定位结果，最终报告使用 v2，不能把首次正则未识别的调用形态当作实现不存在。[[2]](#ref-2)[[3]](#ref-3)

未取得正文、其他链/机制、未展开调用路径、生产部署与 registry 内容等仍未验证。不能把读取了文件字节、文件名命中或静态分支存在写成完整代码安全保证。

## References

<a id="ref-1"></a>[1] x402 / ProtocolGuard 本地证据，“主分析”，2026。[原始文件](<analysis.md>)

<a id="ref-2"></a>[2] x402 / ProtocolGuard 本地证据，“最终源码形式证据”，2026。[原始文件](<source-observations-v2.json>)

<a id="ref-3"></a>[3] x402 / ProtocolGuard 本地证据，“人工核对案例”，2026。[原始文件](<expert-cases.json>)
