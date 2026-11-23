# ProtocolGuard 的 DeepSeek 凭据与 LLM 用途

用户于 2026-11-13 明确指定其提供的 DeepSeek API key 专用于 ProtocolGuard 的 LLM 工作。用途绑定记录在 `credential-binding.json`；服务地址为官方 API，当前受限样本使用 `deepseek-flash`，模型名称和计费资料已在线核验。[[1]](#ref-1)[[2]](#ref-2)

密钥不写入源码、配置、报告或日志，不用于其他项目。独立凭据引用为 `PROTOCOLGUARD_DEEPSEEK_API_KEY`；本次通过关闭终端回显的标准输入交给进程，仅在进程内存中使用。这里记录的是用途绑定，并未建立跨会话的秘密存储。

`run_sample.py` 对 12 条当前固定规范的候选进行一次语义整理：补充 actor、message_type、fields、applicability、preconditions、obligation、exceptions、normative_strength、未解决引用和逐行证据。每条输出状态仍为 `model_interpreted_unverified`，不等于语义已被证明正确，也不自动改写历史审计的未验证结论。

本次样本限制为一次调用、最多 6,500 个输出 token、请求体小于 100,000 字节，并用已核验的峰值费率作保守估计，调用前费用上界必须小于 US$0.05。没有自动重试、模型自动 web tools 或额外收费工具。全量历史语义分析的预算仍待用户指定。

结果位置：`sample/request.json` 保存公开规范输入与提示词；`sample/semantic-rules.json` 保存成功解析且证据引用通过本地校验的解释；`sample/usage.json` 保存请求状态、usage、模型和估算费用。HTTP 错误只记录状态码，不打印可能包含凭据信息的响应体。

```bash
# 无网络、无需 key：准备输入检查
python3 ProtocolGuard/x402/llm/run_sample.py --prepare-only

# 已由用户设置专用环境变量时，运行受限样本；不要将 key 放进命令参数
python3 ProtocolGuard/x402/llm/run_sample.py
```

## References

<a id="ref-1"></a>[1] DeepSeek, “Models & Pricing,” accessed 2026-11-13. [[url]](https://api-docs.deepseek.com/quick_start/pricing/)

<a id="ref-2"></a>[2] DeepSeek, “Chat Completions API,” accessed 2026-11-13. [[url]](https://api-docs.deepseek.com/api/create-chat-completion/)
