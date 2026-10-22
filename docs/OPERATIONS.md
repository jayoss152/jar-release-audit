# Release review and optional model workflow

1. Build/test the scanner with `mvn -B verify` using JDK 17 or 21.
2. Audit an authorized release offline. Start with the default MEDIUM gate; inspect
   LOW metadata findings against your framework/diagnostics requirements.
3. Save `--format json --output new-scan.json`, or use `--format plan` for reviewed
   deterministic actions and evidence IDs. `--format sarif` supports code-scanning
   consumers. No format uploads anything.
4. Review incomplete issues before relying on a result. Raise explicit budgets
   only when appropriate; cancellation, malformed input and timeouts never become
   successful clean scans.
5. If intentionally accepting existing findings, review a complete `--baseline`
   report or an explicit `--policy` file. These change gates, not scanner evidence.
6. Use `--redact-paths` for local sharing. For optional model assistance, export
   `--ai-export new-request.json` or bounded offline batches. Review the anonymized
   inventory; it has no archive paths, raw messages, source/JAR content or values.
7. Choose either offline response import with the original `--ai-request`, or an
   explicitly enabled existing local model service. Never insert an API key into
   configuration; credential fields and non-loopback endpoints are unsupported.
8. Review the advisory sidecar against the local evidence IDs. The program accepts
   only known actions/citations and labels model rationale as untrusted. It does
   not apply patches, execute suggestions, accept baselines or change the scan.

## Runnable privacy/protocol demonstration

After the build, on Windows or Linux:

```sh
java --class-path target/jar-release-audit-0.1.0.jar examples/ModelProtocolDemo.java
```

This creates an ignored synthetic fixture directory and a **canned loopback
protocol stub, not an AI model**. It verifies no call without consent, no raw
path/config-secret payload, correctly cited suggestions, offline response replay,
and the same deterministic finding exit status before/after assistance. CI runs
this on all four OS/JDK combinations. The test does not install or evaluate model
weights, use credentials, contact external model APIs or establish model quality.

For genuine model assistance, a user may voluntarily provide their own existing
chat-completions-compatible local service using [AI.md](AI.md). This project does
not start, install or pay for that service. A local service may itself forward
data, so review its operation before consent. Requests carry only the allow-listed
inventory, chosen model identifier, fixed instructions and correlation ID.

## Operational failure and audit authority

Exit 0/1 denotes a complete scan and the selected deterministic gate outcome.
Exit 2 includes scan/input/output/config failures and explicitly requested model
operations that fail. In the latter case the original deterministic report is
still rendered; no successful advice is fabricated. Never interpret absence of
advice as absence of findings. Keep reports/cache/advisory files local unless
reviewed for sharing. They are not signed attestations of artifact provenance.

`Main.run(args, out, err)` is public for embedding and returns a status without
terminating the caller JVM. It has the same explicit consent and output rules as
the packaged CLI. The scan remains a hygiene heuristic and cannot prevent
decompilation or prove absence of secrets.
