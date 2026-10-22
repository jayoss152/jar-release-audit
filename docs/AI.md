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

An existing user-managed local model service can be enabled explicitly:

```sh
java -jar target/jar-release-audit-0.1.0.jar --allow-ai --ai-endpoint http://127.0.0.1:1234/v1/chat/completions --ai-model YOUR_LOCAL_MODEL --ai-output new-advice.json release.jar
```

This is a real optional chat-completions-compatible HTTP adapter, not a built-in
model. It only accepts literal loopback addresses and the exact endpoint path;
there are no credentials, automatic service discovery, proxies or redirects.
Timeouts cover the whole asynchronous response, with a 64 KiB response cap.
Tool calls/refusals/truncated output are unsupported. Tests use a controlled
protocol stub, not model weights or a paid service. No model has been installed,
downloaded or evaluated by this project. A local server can itself forward data;
review its configuration before voluntarily enabling it.

Valid advice never changes deterministic gates. An explicitly requested advice
operation that fails is an operational error (exit 2); the deterministic report
is still rendered and no fabricated successful model result is written.

Model-input bundles use a fresh random `requestId` (a correlation
identifier, not a credential). Advice must echo it exactly. Offline import now
requires `--ai-request original-prompt.json`, whose inventory is checked against
the selected local report. A stale response from another request is rejected.
Only anonymized inventory is bound: this is not a cryptographic signature or
artifact attestation. Keep the original request file for replay and review.

For large reports, `--ai-export-batches new-directory --ai-batch-size 100` writes
up to 100 request files (1..200 findings each) and a completion manifest **last**.
No model call is made. Current bundle schema v3 marks full/batch scope and total
evidence; full-inventory v2 requests remain readable. IDs retain their positions
in the whole report. Each selected batch must match existing evidence and advice
coverage reports available versus total findings. A partial export lacks its
completion manifest; existing directories are never reused. Process each chosen
batch explicitly with `--ai-request`; no automatic fan-out/network loop occurs.

`--ai-cache chosen-local-directory` is optional and requires an original
`--ai-request` plus the usual explicit local-model consent. Cache keys bind the
request, endpoint and model; stored advice is validated again on every hit.
A valid hit makes no HTTP request. A corrupt entry fails rather than silently
calling a model or overwriting the file. Cache files contain sanitized inventory
context and model-provided prose; keep the chosen directory private and review
it before sharing. There is no credential storage or automatic default cache.

`--ai-config chosen-file.json` reads only an explicitly selected, bounded JSON
configuration. See `examples/local-model.example.json`; it contains no credentials.
The only fields are schema version, loopback endpoint, model identifier and
timeout. Unknown fields (including API-key fields) are rejected. Configuration
does not grant consent: `--allow-ai` and a new advisory output path remain
required. Endpoint/model/timeout CLI overrides cannot be mixed with a config.
There is no home-directory lookup, environment-variable lookup or key creation.

Security regressions exercise the complete CLI/HTTP boundary with synthetic
inputs: absent consent, instruction-like archive names, malformed request
contracts, redirected/oversized/error responses, a stalled body deadline and XXE
attempts. The tests prove those controlled behaviors, not resistance to every
model hallucination or service defect. Duplicate CLI options are rejected to
avoid ambiguous endpoint/config selection. No real model-quality claim is made.
