# ProtocolGuard x402 experiment code

Existing ProtocolGuard components, x402 experiment drivers, tests, static inputs, and usage documentation are under `ProtocolGuard/`. Run documented commands from this repository root.

The drivers cover specification extraction, source localization and slicing, consistency review, assertion planning, bounded dynamic validation, release/specification mapping, and batch execution. Pipeline results are not a protocol-security proof or confirmed vulnerability report.

## Contents and setup

- `ProtocolGuard/rule_extraction/`: extraction and preprocessing.
- `ProtocolGuard/program_slicing/`: slicing and build configuration.
- `ProtocolGuard/inconsistency_detection/`: consistency analysis.
- `ProtocolGuard/dynamic_verification/`: original dynamic-verification components.
- `ProtocolGuard/x402/`: x402 drivers, API clients, adapters, tests and static inputs.
- `EXPORT-MANIFEST.json`: exported file inventory and placeholder substitutions.

See component READMEs and requirements files for dependencies and commands. Some historical configurations use machine-specific paths; configure them locally. Upstream source snapshots, generated model responses and result datasets, runtime ledgers, installed environments, compiled dependencies and manuscripts are outside this source-code export. Obtain the upstream inputs required by your selected driver before execution.

Credentials are excluded. Exported examples with credential-like literals use `SET_LOCALLY`; supply local configuration or environment variables as supported by the relevant driver. Paid calls and dynamic execution remain explicit opt-in actions.

The original license is preserved in `ProtocolGuard/LICENSE`.
