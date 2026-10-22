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
