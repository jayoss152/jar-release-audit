# Threat model and limits

## Purpose and trust boundary

A recipient can read every byte of a distributed JAR, extract its resources, inspect
constant pools, decompile bytecode, or observe the program at runtime. This project
helps a release engineer catch **accidental information exposure** before publishing
an artifact they own or are authorized to inspect. It does not prevent reverse
engineering. Shipping secrets, encryption keys, or critical trust decisions in a
client is not made safe by obfuscation.

The CLI reads an archive locally. It never executes class files, extracts archive
entries to the filesystem, rewrites an input, or calls a network service. Build tools
download their own dependencies separately. Archive names and paths appear in
reports; matched config values and class string constants do not. Treat reports as
potentially confidential because names can themselves contain private information.

## Covered evidence

* Source extensions: Java, Kotlin (including scripts), Scala and Groovy.
* Actual class attributes: SourceFile, SourceDebugExtension, LineNumberTable,
  LocalVariableTable, LocalVariableTypeTable and MethodParameters. Attribute names
  found only in constant-pool strings do not count. This parser is a metadata reader,
  not a complete JVM class verifier.
* Potential private credential files: `.env*`, `id_rsa`, `id_ed25519`, `.key`,
  `.p12`, `.pfx`, `.jks` and `.keystore`. Some are intentional public/demo resources.
* UTF-8 text (with or without BOM), and BOM-marked UTF-16LE/BE resources, with properties/YAML-like credential assignments and PEM
  private-key markers. Rules are intentionally heuristic; a finding is a review
  request, not proof of a usable secret. Whole `${NAME}` references (or empty
  `${NAME:}` fallbacks), empty values and unquoted `null` / `~` are excluded.
  Nonempty placeholder defaults, concatenated references, malformed references
  and arbitrary `#{...}` expressions require review and are reported. Nested
  external fallback expressions can therefore produce conservative false positives.
  Malformed text, UTF-32 and NUL-containing resources are incomplete scans;
  BOM-less UTF-16 and legacy encodings are unsupported. Invalid bytes are never
  silently replaced before checking credential assignments.
* Nested `.jar` / `.zip` entries and ZIP signatures under other extensions,
  including `BOOT-INF/lib`, up to depth 2. Depth
  zero is the input archive. `BOOT-INF/classes` is inspected like any other path.

## Resource and malformed-input behavior

Defaults: input file at most 128 MiB, each expanded entry at most 8 MiB, total read
expanded bytes at most 64 MiB, 10,000 entries (directories included), nesting at
most two levels. Nested archive bytes count once as their parent entry and again
as their contents. Limits are configurable through the library constructor and
explicit CLI flags documented in `--help`. A limit, invalid class, or invalid nested archive produces an
incomplete report and exit 2 even with `--fail-on none`. An unreadable/invalid outer
ZIP produces exit 2 and a generic stderr error without a report.

Nested ZIP64, split archives and self-extracting/prefixed nested ZIPs are unsupported.
Nested archives require a consistent end record, central-directory structure,
local-header names, flags, methods, offsets and declared sizes/checksums. The
streamed entry count must match the central directory. Encrypted nested entries
are unsupported and produce an incomplete result;
the streaming reader checks entry payloads. This is not a forensic ZIP validator,
nor a cryptographic signature verifier. Outer entry expanded size and CRC-32 are
checked against the central directory, including directory payloads; mismatches
produce an incomplete result. CRC-32 detects corruption, not malicious tampering
by an attacker who can rewrite the checksum. The JDK `ZipFile`
reads an outer central directory; memory/CPU are not a formal hard sandbox. Use
OS/container memory and time limits for untrusted inputs. Do not run as administrator.

## Deliberate gaps

Absolute/drive-qualified paths, traversal segments, control/format characters and
literal nested-archive delimiters in entry names yield `PATH_INVALID` and an
incomplete scan. This avoids consumer-dependent path and evidence interpretation;
the scanner still never extracts entries.

Duplicate names, slash/backslash aliases and leading `./` aliases within an
archive make the scan incomplete because consumers can disagree about which
entry is selected. Names remain case-sensitive. No archive paths are extracted.

No dataflow/entropy analysis, encrypted or encoded secret detection, arbitrary
binary/class constant scanning, multiline or fully parsed JSON/YAML/XML secret
analysis, certificate validity checks, dependency vulnerability scanning, license
auditing, signature validation, native/Dex inspection, malicious-code detection,
or automatic patching. A report with no findings is **not a security guarantee**.
Not all archive formats, language metadata or future class attributes are covered.

Debug metadata can be essential for stack traces, incident response, reflection,
framework binding and serialization. Especially for Spring Boot, `-parameters`,
annotations, class names and resources may be required. Apply exclusions or
obfuscation selectively, preserve private mapping files, and run integration tests
on the actual production package. Source JARs intentionally published for an open
source library may be legitimate; audit the executable release separately.

Javac retains `MethodParameters` for a record's canonical constructor even with
`-g:none`. The scanner's own report records therefore produce LOW metadata
findings when it audits itself. This is expected and passes the default MEDIUM
threshold; metadata removal is not a universal success condition.

This project does not implement malware evasion, persistence, anti-debugging,
security-tool bypasses or executable packers.
