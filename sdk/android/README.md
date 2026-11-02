# viadere-android (`com.viadere.sdk`)

Kotlin SDK for the Viadere authentication-delivery contract (ADR-0030): contract models, strict create-request validation and JSON, webhook signature v2
verification, a replay store (**on by default**, review R23-06), the per-requester throttle (C-14) and idempotency keys. No runtime dependency (Kotlin
stdlib and `java.security` only), no permissions, no components. `minSdk 30`. Webhook secrets and API keys belong on a server: use this on Kotlin/JVM
backends or in tooling, never ship a secret in an app.

Tests (`library/src/test`) run the shared vectors `docs/protocol/vectors/webhook-v2.json` and `webhook-v2-negative.json` and a contract parity check.

## Build status: NOT YET BUILT

The sources and tests were written on 2026-11-02 but could not be compiled: the Android SDK (cmdline-tools 23.0, platform 37.2, build-tools 36.0.0 from
dl.google.com, sha1 verified) installed fine, but every Gradle run failed resolving AGP dependencies from Maven Central with HTTP 429. Still to do, from `sdk/android`:

    export ANDROID_HOME=<sdk>
    ./gradlew :library:assembleRelease :library:testDebugUnitTest :library:lint :library:dependencies --write-locks --write-verification-metadata sha256

then fix whatever the first compile reports (explicit-API mode may ask for `public` on constructor properties), commit `gradle/dependency-locks/`,
`settings-gradle.lockfile` and `gradle/verification-metadata.xml`, and update the CLAUDE.md row.
