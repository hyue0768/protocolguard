# ProtocolGuard

ProtocolGuard organizes protocol implementation analysis into specification-rule extraction, source localization and slicing, LLM-assisted consistency review, and assertion-oriented dynamic verification. This repository contains the original components together with local conservative slicing and LLVM 18 integration work based on the published method. [[1]](#ref-1)

Start with [HOW_TO_USE.md](HOW_TO_USE.md). The guide includes a runnable offline Python source-context example and separate instructions for model-assisted extraction, LLVM slicing, consistency review, and dynamic-verification preparation.

## Repository layout

| Directory | Purpose |
| --- | --- |
| `ProtocolGuard/rule_extraction/` | HTML preprocessing, keyword analysis, and rule-candidate extraction |
| `ProtocolGuard/program_slicing/` | Conservative Python context and LLVM 18 slicing integrations |
| `ProtocolGuard/inconsistency_detection/` | Model-assisted rule/code consistency review |
| `ProtocolGuard/dynamic_verification/` | Assertion prompts, packet tooling, and directed-verification integrations |
| `ProtocolGuard/config/` | Generic target and provider configuration |
| `ProtocolGuard/example/` | Legacy protocol examples and a minimal offline Python example |
| `ProtocolGuard/tests/` | Offline regression checks for the general workflow |

## Scope

Rule candidates and model judgments require review. A source slice retains analysis context; it is not a compliance verdict. The Python backend resolves only local calls and explicitly supplied context. LLVM integrations are paper-guided reimplementations and do not establish full reproduction of the published evaluation. Dynamic validation requires a target-specific build, assertions and an existing corpus; generating prompts does not execute or validate a test.

Python 3.11 or later is required for the complete set of drivers. LLVM-based components additionally require LLVM/Clang 18. Dependencies are listed in `requirements.txt`; upstream targets, model credentials, tokenizer assets, and target-specific build tools are supplied separately. The original license is in [ProtocolGuard/LICENSE](ProtocolGuard/LICENSE).

## References

<a id="ref-1"></a>[1] Xiangpu Song, Longjia Pei, Jianliang Wu, Yingpei Zeng, Gaoshuo He, Chaoshun Zuo, Xiaofeng Liu, Qingchuan Zhao, and Shanqing Guo, “ProtocolGuard: Detecting Protocol Non-compliance Bugs via LLM-guided Static Analysis and Dynamic Verification,” in *Proc. NDSS*, 2026. [doi](https://doi.org/10.14722/ndss.2026.240521)
