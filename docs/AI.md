# Optional model assistance and privacy boundary

All model features default **off**. `--format plan` and `--list-rules` are
deterministic catalog functions, not AI. `--ai-export new-prompt.json` writes a
local model-input bundle and performs no network call or model evaluation.

Only known rule IDs, severity levels, opaque evidence IDs, fixed allowed actions,
scan completeness and issue-code enums enter the bundle. No source, JAR bytes,
entry paths, configuration values, raw messages or credentials are serialized.
The initial bundle limit is 200 findings. Over-budget export fails explicitly;
nothing is silently truncated. Exported documents never overwrite existing files.

Model output is advisory. It cannot alter deterministic findings, severities,
completeness, baselines or gate exit codes. Evidence numbers refer to the local
report; a model cannot infer filenames from them. Model explanations can still be
wrong and require human review. No source edits or commands are applied.

`--ai-import model-response.json --ai-output new-advice.json` validates an offline
response against the current report. Only known evidence IDs and their matching
catalog action IDs are accepted. Duplicate/hallucinated citations, unknown fields,
oversized prose and terminal/format controls are rejected. The sidecar contains
fixed actions/references plus explicitly untrusted model rationale, safe JSON
escaping and coverage counts. It cannot replace the scan or its exit policy.
See [the response schema](ai-response.schema.json); semantic reference checks are
additional to that schema. Import itself performs no model call.
