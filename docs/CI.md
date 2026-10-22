# CI maintenance

The workflow uses hosted Windows/Linux runners with JDK 17/21. Actions are pinned
to exact commits rather than floating major tags:

* [checkout v6.1.0](https://github.com/actions/checkout/tree/v6.1.0):
  `d23441a48e516b6c34aea4fa41551a30e30af803`
* [setup-java v5.7.0](https://github.com/actions/setup-java/tree/v5.7.0):
  `b6effb05e454b25005698d916606bdc6ffcbf961`

Both official `action.yml` manifests at these commits declare `using: node24`.
They replace the original Node 20 actions. Self-hosted runners must meet the
actions' documented runner requirements; this project uses current hosted images.
Checkout does not persist Git credentials, and workflow permissions stay at
`contents: read`. Tests never need access to existing user repositories or secrets.

For an upgrade, resolve the official version tag, inspect that commit's manifest
and upstream release notes, update the pinned SHA and version comment together,
and run the full matrix. Do not bypass warnings with a runtime override.

After the full build, every matrix job runs `java examples/VerifyReproducible.java`.
It hashes the JAR, forces offline Maven JAR repackaging, and requires byte identity.
It does not delete target files, skip the initial full tests, claim cross-JDK byte
identity or certify an independent clean-room build. The fixed output timestamp
is reproducible archive metadata, not a fabricated commit or maintenance date.
