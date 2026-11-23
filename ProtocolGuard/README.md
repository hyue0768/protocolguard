# ProtocolGuard：x402 接入

当前入口使用固定的官方主线 `2178d4b77aff61395c375bbdf30757876393b85d`、协议 v2；官方源码在项目根目录 `x402_upstream_20261113_2178d4b_snapshot/`。[[1]](#ref-1) 完整组件说明、版本核验、覆盖范围、改动、运行命令、测试结果与待决定问题见 [x402 接入报告](x402/REPORT.md)。

```bash
# 从 x402_experiment 项目根目录运行，不调用模型或支付服务
python3 ProtocolGuard/rule_extraction/main.py --protocol x402 --version 2
ProtocolGuard/program_slicing/build_local.sh
python3 -m unittest discover -s ProtocolGuard/x402/tests -v
ProtocolGuard/x402/.venv/bin/python ProtocolGuard/x402/verify_sdk.py
```

缺失的切片组件按论文方法重建了可运行的保守实现。[[2]](#ref-2) LLVM 后端和 Python 源码后端的支持范围不同；目前没有复现论文的完整精度、所有原插件接口或定向 fuzzing，也没有进行模型调用。4 项离线回归通过，不代表协议安全证明。

[旧 README](README.legacy.md) 是原文归档；`example/` 和旧抽取目录中的 MQTT 数据保持原位。单快照 x402 入口输出进入 `x402/output/`，逐发布检查结果位于 `x402/releases/`。依赖首次安装与环境要求见接入报告；旧归档中的绝对路径和环境说明不作为新入口的运行要求。

[逐发布检查与差距记录](x402/releases/README.md)：750 个 tags 的独立记录、实现/规范实际 diff、组件验证及未覆盖范围。

## References

<a id="ref-1"></a>[1] x402 Foundation, “x402,” fixed commit, accessed 2026-11-13. [[url]](https://github.com/x402-foundation/x402/tree/2178d4b77aff61395c375bbdf30757876393b85d)

<a id="ref-2"></a>[2] Xiangpu Song, Longjia Pei, Jianliang Wu, Yingpei Zeng, Gaoshuo He, Chaoshun Zuo, Xiaofeng Liu, Qingchuan Zhao, and Shanqing Guo, “ProtocolGuard: Detecting Protocol Non-compliance Bugs via LLM-guided Static Analysis and Dynamic Verification,” in *Proc. NDSS*, 2026. [[doi]](https://doi.org/10.14722/ndss.2026.240521)
