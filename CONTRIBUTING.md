# Contributing

This is a new 0.1.0 MVP. Small, evidence-backed fixes are welcome. Use Java 17+ and
Maven 3.9+; run `mvn -B verify` and `java examples/demo/Demo.java` before opening a
pull request. CI verifies Windows/Linux and Java 17/21. Do not add real credentials,
customer archives, production source or private mapping files as test fixtures.

Rules should have stable identifiers, actionable fixed descriptions, synthetic
fixtures, false-positive and false-negative discussion, and tests of incomplete
scan behavior where applicable. Avoid printing matched secret values. Runtime
dependencies require a clear benefit and compatible license. Do not add network
telemetry or execution of inspected classes.

Changes to rules/thresholds can affect CI exit codes; document them. JSON schema
changes require a schemaVersion decision. No stability guarantee is made before
1.0. Use local tests and the final packaged CLI, not only IDE runs.
