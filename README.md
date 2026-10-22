# JAR Release Audit

An offline Java 17 CLI that checks release JARs for accidental information exposure:
packaged sources, debug metadata, potential credential files and literal config
secrets. Zero runtime dependencies. MIT licensed.

面向 Java / Spring Boot 发布流程的离线检查工具：减少源码、调试信息及敏感配置误打包。
**不承诺防止反编译。** 混淆只能提高部分分析成本，不能保护发布包中的真实秘密。

**Status:** new 0.1.0 MVP, intended for evaluation and contribution. No adoption,
production use, maintenance history or independent security review is claimed.

## Build and use

Requires a JDK 17+ and Maven 3.9+. The first Maven build needs dependency access;
the packaged scanner runs offline.

```sh
mvn -B verify
java -jar target/jar-release-audit-0.1.0.jar path/to/release.jar
java -jar target/jar-release-audit-0.1.0.jar --format json --fail-on high path/to/release.jar
```

The default failure threshold is `medium`. Findings at or above the selected level
cause exit 1. `--fail-on low|medium|high|none` changes that threshold; `none` still
returns exit 2 on incomplete scans. `--help` and `--version` are available.

| Exit | Meaning |
| --- | --- |
| 0 | Complete scan; nothing meets the failure threshold |
| 1 | Complete scan; one or more findings meet the threshold |
| 2 | Invalid command/input, malformed inspected content, or incomplete scan due to limits |

JSON reports use **schemaVersion 2**, adding a severity/issue `summary` and stable
issue `code` values to the original report. Findings have `severity`, `rule`,
`entry` and `message`; issues have `code`, `entry` and `message`. See the
[JSON Schema](docs/report.schema.json). Consumers upgrading from version 1 must
accept version 2 and use codes (e.g. `ENTRY_SIZE_LIMIT`, `INVALID_TEXT`) rather
than parsing human messages. Output ordering is deterministic for the same entries.
Input/argument errors go to stderr and do not produce a JSON report. Consumers
must check the process exit code as well as `complete`.

For larger Spring Boot releases, explicitly adjust resource budgets when needed:

```sh
java -jar target/jar-release-audit-0.1.0.jar --max-entry-bytes 16777216 --max-expanded-bytes 134217728 target/my-service.jar
```

`--max-archive-bytes`, `--max-entry-bytes`, `--max-expanded-bytes` and
`--max-entries` accept positive decimal integers; `--max-depth` accepts 0..8.
`--help` lists all defaults. Raising budgets increases resource use; the CLI
never silently skips oversized entries or changes limits automatically.

Use `--output report.json --format json` to save a UTF-8 report without shell
encoding differences. The destination must be a **new file** in an existing
directory; existing files (including the input JAR) are never overwritten. Standard
output is empty when saving to a file. Incomplete scans still save their report
and exit 2; an input error creates no report. A write failure exits 2 and may leave
a partial file, which must not be consumed as a successful scan. Use `--` before
an input filename starting with `-`.

## Rules

`--list-rules` lists stable IDs and reviewed remediation actions without opening a
JAR. The `Rules` catalog is deterministic guidance, not an AI model or a guarantee
that a suggested change is appropriate without application tests.

| Rule | Severity | Review action |
| --- | --- | --- |
| `SOURCE_FILE` | MEDIUM | Exclude source resources from executable releases unless intentional |
| `DEBUG_METADATA` | LOW | Review source, line, local-variable and method-parameter metadata versus diagnostics/framework needs |
| `SENSITIVE_FILE` | HIGH | Review `.env`, private key and keystore filenames |
| `SECRET_ASSIGNMENT` | HIGH | Externalize literal credential-like assignments; values are redacted |
| `PRIVATE_KEY` | HIGH | Remove PEM private key material and rotate any real exposed credential |
| `DEVELOPMENT_ARTIFACT` | MEDIUM | Review VCS metadata, dumps, logs, backups, mappings and source maps unintentionally packaged |
| `MANIFEST_CLASSPATH` | MEDIUM | Review external URLs, absolute paths or parent-directory references in Manifest Class-Path |

Checks are heuristics. A public certificate, demo credential or deliberately
published source can be intentional; there is no blanket automatic remediation.
See the [threat model and limits](docs/THREAT_MODEL.md) before using this as a CI gate.

## Reproducible synthetic demo

From the repository root, on Windows, Linux or macOS:

```sh
java examples/demo/Demo.java
java -cp examples/demo/target/leaky.jar Hello
java -cp examples/demo/target/hardened.jar Hello
java -jar target/jar-release-audit-0.1.0.jar examples/demo/target/leaky.jar
java -jar target/jar-release-audit-0.1.0.jar --fail-on low examples/demo/target/hardened.jar
```

Both application runs print `hello release`. The leaky audit returns **1** with
`SOURCE_FILE`, `DEBUG_METADATA` and `SECRET_ASSIGNMENT`. The hardened audit returns
**0**, with zero findings. The demo removes the source resource, compiles without
debug metadata, and replaces a fake password with an environment placeholder.
It does not obfuscate or prove the absence of all secrets. All fixtures are newly
generated synthetic material. ZIP timestamps are fixed; the same JDK/toolchain
produces repeatable demo archives (cross-JDK byte identity is not promised).

An optional [ProGuard configuration](examples/proguard-demo.pro) and
[verified transformation walkthrough](docs/OBFUSCATION.md) rename the demo helper,
check unchanged program output, and audit the transformed JAR. ProGuard 7.10.0 is
resolved separately for this optional example; the scanner retains zero runtime
dependencies. The real transformation is also checked in CI on Ubuntu/JDK 17.

## Spring Boot

```sh
java -jar target/jar-release-audit-0.1.0.jar --format json target/my-service.jar
```

The tool inspects `BOOT-INF/classes` and nested libraries in `BOOT-INF/lib`.
Metadata from dependencies may produce LOW findings; the default MEDIUM gate
allows those. Large applications can hit the deliberate resource limits and
return exit 2. Method parameter names and annotations may be required by Spring,
Jackson or persistence frameworks; preserve needed metadata and test the final
application. Do not blindly apply a plain-JAR obfuscation configuration to a Boot
executable JAR.

## Development

`--format plan` generates a deterministic Markdown remediation plan grouped by
rule and priority, with evidence IDs, verification steps and first-party references.
It is not AI output. Archive names remain local report data and are escaped;
incomplete inspection is always shown and still exits 2.

`mvn -B verify` runs JUnit tests using real compiler-generated classes and synthetic
archives. Coverage includes metadata parsing versus string literals, externalized
values, nested Boot libraries, malformed data, budgets, deterministic/redacted
output and CLI exit policies. CI additionally builds and runs the packaged CLI and
demo on Windows/Linux with JDK 17/21.

The code is split into class metadata parsing, archive scanning, report records and
CLI rendering. Contributions should include behavior-focused tests and update
the rule/limitation documentation. See [CONTRIBUTING.md](CONTRIBUTING.md),
[SECURITY.md](SECURITY.md) and [LICENSE](LICENSE).
