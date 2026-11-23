# Rule extraction

This module preprocesses a protocol HTML specification, constructs keywords, and extracts rule candidates. Its legacy language-model stages use the DeepSeek service defaults in the module sources and keyword configuration; inspect those settings before supplying credentials. Generated candidates require human review before they become slicing rules.

From the repository root, after installing dependencies and setting `OPENAI_API_KEY`, run:

```bash
python3 ProtocolGuard/rule_extraction/main.py --protocol mqtt --version 5.0 --html-file /absolute/path/to/specification.html
```

This command performs model calls. The generic workflow, intermediate paths, rule JSON schema, and offline alternative are documented in [HOW_TO_USE.md](../../HOW_TO_USE.md). The document processor writes a local configuration containing its API key; that generated directory is ignored by Git and should remain private.
