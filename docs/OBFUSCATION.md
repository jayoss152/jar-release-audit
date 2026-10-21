# Optional obfuscation

Packaging hygiene is useful before considering obfuscation: exclude source files,
externalize credentials, and decide which diagnostics to retain. Obfuscation makes
some names less informative; it does not encrypt business logic or prevent
decompilation. No ProGuard/R8 code or binaries are bundled in this MIT project.

`examples/proguard-demo.pro` is an original minimal configuration for the plain
`Hello` demo. It preserves the public entry point while allowing other names to
change, disables shrinking/optimization to keep the example narrow, and omits
debug attributes. Install ProGuard separately, then from `examples/demo/target`:

```sh
proguard @../../proguard-demo.pro
java -cp obfuscated.jar Hello
```

The expected application output is `hello release`. The config is optional and
must be tested against your chosen ProGuard/JDK version; it is not part of the
default demo or a verified Spring Boot production configuration. The default demo
requires only the JDK and proves source/config/debug hygiene, not obfuscation.
`mapping.txt` is ignored by Git; store mappings in access-controlled build storage.

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
