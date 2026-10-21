# Optional obfuscation

Packaging hygiene is useful before considering obfuscation: exclude source files,
externalize credentials, and decide which diagnostics to retain. Obfuscation makes
some names less informative; it does not encrypt business logic or prevent
decompilation. No ProGuard/R8 code or binaries are bundled in this MIT project.

`examples/proguard-demo.pro` is an original minimal configuration for the plain
`Hello` / `Greeting` demo. It preserves the public entry point while allowing other names to
change, disables shrinking/optimization to keep the example narrow, and omits
debug attributes. To resolve the separately invoked external tool from Maven
Central and verify the transformation, run from the repository root:

```sh
mvn -B verify
mvn -B -ntp -f examples/proguard/pom.xml generate-resources
java examples/proguard/Verify.java
```

The verifier runs ProGuard **7.10.0**, checks that `Greeting.class` was renamed and
`Hello` was preserved, compares actual application output (`hello release`) before
and after, and audits the resulting JAR at LOW threshold. CI runs this additional
verification on Ubuntu/JDK 17; it is also runnable on Windows. The configuration
uses an explicit base directory so paths do not depend on the invoking shell.

ProGuard is an external tool with its own license and transitive dependencies;
the optional example POM resolves it separately. No ProGuard binaries or source
are bundled in the scanner JAR or copied into this MIT repository. This narrow
plain-JAR demo does not validate a Spring Boot production configuration. Other
ProGuard/JDK combinations require their own tests. The default JDK-only demo
still proves packaging hygiene without running any external obfuscator.
`mapping.txt` under the demo target directory is ignored by Git; store production
mappings in access-controlled build storage.

For Spring Boot, process application classes **before** Boot repackaging rather
than blindly processing an executable fat JAR. Review reflection, configuration
property binding, proxies, AOP, persistence entity names, Jackson models, service
loader files and resource paths. Keep required annotations, signatures, parameter
names and application entry points. Do not use blanket `-dontwarn` to hide missing
dependencies; test startup and representative requests using the final artifact.
There is no safe universal keep configuration for all Spring applications.

R8 is primarily used in Android builds and is not a drop-in replacement for a
Spring Boot server build. Use your platform's documented build integration rather
than assuming ProGuard options have identical semantics.

Primary references:

* [ProGuard usage and options](https://www.guardsquare.com/manual/configuration/usage)
* [ProGuard attribute reference](https://www.guardsquare.com/manual/configuration/attributes)
* [Android R8 documentation](https://developer.android.com/topic/performance/app-optimization/enable-app-optimization)
