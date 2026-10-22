# Verification scope

Unit tests compile real JDK classes and use newly generated synthetic archives.
The deterministic mutation corpus uses fixed seeds and bounded inputs: 150 ZIP
mutations (including nested/truncated archives) and 100 class-file mutations.
Invalid outer archives may be explicitly rejected; otherwise entry limits,
completion state and JSON report invariants must hold without unchecked parser
crashes. Loose suite deadlines detect hangs without asserting benchmark timings.
This is a regression corpus, not a proof that every malformed ZIP/class is safe.

Model tests run only controlled loopback protocol stubs. They verify privacy,
consent, response limits, timeouts, reference validation and exit behavior. They do
not evaluate a real model's reasoning, hallucination rate or quality. The optional
ProGuard demo does execute the separately resolved actual transformation tool.

CI covers Windows/Linux on JDK 17/21. Run `mvn -B verify` locally; generated
artifacts and test receipts belong under ignored `target` directories. Never use
production archives, credentials or private mapping files as fixtures.
