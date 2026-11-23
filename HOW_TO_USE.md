# How to use ProtocolGuard

This guide describes the interfaces available in this repository; the original method is described in the ProtocolGuard paper. [[1]](#ref-1)

Run commands from the repository root. Choose the protocol specification, implementation revision, and source language before starting. Keep the specification and implementation identities with your output; changes between revisions require a fresh applicability check.

## 1. Install dependencies

The offline Python source-context example requires only Python 3.11 or later and its standard library. For model extraction, consistency review and packet tooling, create an environment and install the shared dependencies:

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -r requirements.txt
```

For LLVM slicing and native preparation, install LLVM/Clang 18 development tools appropriate to your operating system. The build scripts use `clang++-18`, `clang-18`, `opt-18`, and `llvm-config-18`. The older standalone `DFUZZPASS.cpp` is retained separately and is not the LLVM 18 integration.

## 2. Obtain and review specification rules

### Use an existing rule list

For the generic slicers, prepare a JSON array of rules. Each rule needs an `id` and a natural-language `rule`:

```json
[
  {"id": "length-check", "rule": "The handler must reject a negative declared length."}
]
```

Record the relevant specification section, normative strength, prerequisites, and exceptions alongside your input records. Do not silently promote recommendations into mandatory requirements. The slicer preserves the rule text; it does not check whether the rule correctly represents the specification.

### Extract candidates from an HTML specification

The legacy extraction modules perform model calls and use DeepSeek defaults. Review the provider/model settings in the extraction sources and `ProtocolGuard/rule_extraction/keywordProcess/directoryStore/config.json` before execution. Generic target support does not imply that every model provider is interchangeable.

After setting `OPENAI_API_KEY` in your shell without committing it:

```bash
python3 ProtocolGuard/rule_extraction/main.py \
  --protocol mqtt \
  --version 5.0 \
  --html-file /absolute/path/to/specification.html
```

The entry point runs document processing, keyword processing, and rule processing in order. It resolves stage working directories internally. The document stage can fetch a protocol dissector and needs network access; protocols without a suitable dissector need manual keyword input or an adapted extraction stage.

Intermediate outputs are under the three `directoryStore/` directories. The final legacy extraction output is `ProtocolGuard/rule_extraction/ruleProcess/directoryStore/processed_results.json`. Review it and normalize accepted candidates into the rule-array schema above before slicing; it is not automatically the slicer input.

The document processor persists its API key in a generated local `config.json`; the directory is ignored by Git. Keep it private and remove credentials after the run. Model extraction has no shared request-budget controller in this general workflow.

## 3. Locate handlers and collect source context

### Offline Python example

A complete small example is included in `ProtocolGuard/example/python-context/`. First list available selectors:

```bash
python3 ProtocolGuard/program_slicing/src/source_slicer.py \
  --source ProtocolGuard/example/python-context \
  --list-functions
```

Selectors use `relative_file.py::function` or `relative_file.py::Class.method`. Map each rule ID to explicit handler and context selectors. For example:

```json
{
  "length-check": {"handlers": ["handler.py::handle_message"], "context": []}
}
```

Run the example:

```bash
python3 ProtocolGuard/program_slicing/src/source_slicer.py \
  --source ProtocolGuard/example/python-context \
  --rules ProtocolGuard/example/python-context/rules.json \
  --decisions ProtocolGuard/example/python-context/decisions.json \
  --database work/python/slices.db \
  --report work/python/slice-report.json
```

This writes full-function context and a local call graph to SQLite, with an explicit unresolved-call list in the JSON report. Imported functions, dynamic dispatch and external services require separately supplied context. Missing decisions remain pending. This example performs no model calls and does not execute the target handler.

### C/C++ through LLVM 18

Build the local pass integrations:

```bash
sh ProtocolGuard/program_slicing/build_local.sh
```

Compile your own target to LLVM bitcode using its actual build system, with debug information and optimization settings compatible with the analysis. A single C translation unit can be prepared as follows:

```bash
clang-18 -g -O0 -Xclang -disable-O0-optnone \
  -emit-llvm -c /absolute/path/to/target.c -o /absolute/path/to/target.bc
```

Copy `ProtocolGuard/config/config.toml` to `work/config.toml`, then set `project.rule_path`, `project.original_llvm_ir_path`, and target identity fields. Use absolute paths for target inputs. Decisions are keyed by rule ID and use the LLVM handler name:

```json
{
  "length-check": {"handler": "handle_message", "variable": "", "clang_flags": []}
}
```

Run the bridge:

```bash
python3 ProtocolGuard/program_slicing/src/llvm_driver.py \
  --config work/config.toml \
  --decisions /absolute/path/to/llvm-decisions.json \
  --output work/llvm
```

The output includes `slices.db`, per-rule slice records, and `report.json`. Referenced source files must remain available. Missing decisions are reported instead of inferred. C/C++ compilation flags, include paths, linked translation units, and source locations must match the target build; the bridge is not a universal build-system adapter.

## 4. Review rule/code consistency with a model

The review script consumes the `rule_code_snippet` SQLite table produced by either slicer. Configure `llm.llm_api_platform` as the selected SDK base URL, `llm.llm_model_deepseek_r1` as the selected model name, and `llm.tokenizer_path` as an existing local tokenizer directory. That field name is retained for compatibility. The tokenizer must be supplied separately; the script does not download one. Set protocol identity, retry counts, repeat counts, and the desired result-replacement behavior in the config.

With `OPENAI_API_KEY` set locally, explicitly request model review:

```bash
python3 ProtocolGuard/inconsistency_detection/violation_check.py \
  --config work/config.toml \
  --database work/python/slices.db \
  --max-rules 1 \
  --workers 1 \
  --allow-paid
```

For the LLVM workflow, substitute `work/llvm/slices.db`. Start with one rule and inspect the stored `llm_response` before increasing concurrency or rule count. Existing responses are governed by `debug.code_slice_replace_mode`. Repeat/retry settings can generate more calls than `max-rules`; that flag is a rule-count limit, not a paid-request cap.

A response identifies a model judgment for the supplied context. It does not establish a confirmed vulnerability or complete compliance. Check the original rule, applicability, selected handlers, unresolved calls and external dependencies before accepting a finding.

## 5. Prepare bounded dynamic verification

The assertion generator reads reviewed database rows and writes agent prompt tasks. It does not insert or prove assertions automatically:

```bash
python3 ProtocolGuard/dynamic_verification/assert_generate/gen_assert_prompt.py \
  --db_path work/python/slices.db \
  --output_dir /absolute/path/to/controlled-target \
  --compile_command "your target's compilation command"
```

Review each task, add an appropriate assertion in a controlled target checkout, and check that the assertion expresses the claimed discrepancy. Packet-task generators under `dynamic_verification/packet_generate/` require protocol-specific setup and an existing packet workflow; use their `--help` output for the actual arguments.

The local native LLVM 18 driver can prepare and replay an existing corpus for a compatible C target:

```bash
sh ProtocolGuard/dynamic_verification/DFUZZ/build_directed18.sh
python3 ProtocolGuard/dynamic_verification/DFUZZ/directed.py --help
python3 ProtocolGuard/dynamic_verification/DFUZZ/directed.py prepare --help
python3 ProtocolGuard/dynamic_verification/DFUZZ/directed.py replay --help
```

Preparation requires a target source and explicit criterion; replay requires an existing corpus and `--execute`. External dependencies, target input format, transport behavior, assertions, and execution isolation remain target-specific. Use the original fuzzing integrations only with their matching toolchains. No full-protocol validation follows from compilation, a generated prompt, or a bounded local replay alone.

## 6. Verify the local general workflow

```bash
python3 -m unittest discover -s ProtocolGuard/tests -v
```

The included checks cover offline rule-to-handler context and stage path handling. They do not call a model, generate protocol traffic, or run a target service. Keep rules, decisions, source identity, context reports, model responses, and any later execution evidence separate in your own experiment records.

## References

<a id="ref-1"></a>[1] Xiangpu Song, Longjia Pei, Jianliang Wu, Yingpei Zeng, Gaoshuo He, Chaoshun Zuo, Xiaofeng Liu, Qingchuan Zhao, and Shanqing Guo, “ProtocolGuard: Detecting Protocol Non-compliance Bugs via LLM-guided Static Analysis and Dynamic Verification,” in *Proc. NDSS*, 2026. [doi](https://doi.org/10.14722/ndss.2026.240521)
