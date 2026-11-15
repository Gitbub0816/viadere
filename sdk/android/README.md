# viadere-android (`com.viadere.sdk`)

Kotlin SDK for the Viadere authentication-delivery contract (ADR-0030): contract models, strict create-request validation and JSON, webhook signature v2
verification, a replay store (**on by default**, review R23-06), the per-requester throttle (C-14), idempotency keys and opt-in RFC 9421 request
signing. No runtime dependency (Kotlin stdlib and `java.security` only), no permissions, no components. `minSdk 30`. Webhook secrets and API keys
belong on a server: use this on Kotlin/JVM backends or in tooling, never ship a secret in an app.

Tests (`library/src/test`) run the shared vectors `docs/protocol/vectors/webhook-v2.json`, `webhook-v2-negative.json` and `http-signatures-v1.json`
and a contract parity check.

## Webhook events

`WebhookEventType` lists every `auth.delivery.*` type of `contracts/schemas/auth-delivery-event-v1.schema.json`, including
`FallbackUsed` (`auth.delivery.fallback_used`, additive in contract v1.x): the code of a delivery that asked for the email fallback left by email
(`assurance: email`, ADR-0020 section 7). It is sent once, when the email provider accepted the email, never when it was suppressed or failed; it is
not a state transition, so `endsDelivery` is `false` and the throttle keeps the slot.

## Request signing (RFC 9421, `docs/SECURITY.md` section 2.112)

What a live key needs on the auth-delivery routes when it is not bound to mutual TLS. The SDK has no HTTP client: `RequestSigning.sign` returns the
fields to add to **each attempt** (a fresh nonce every time), in order `Content-Type` and `Content-Digest` (only with a non-empty body),
`Signature-Input`, `Signature`. Send exactly these values and the same body bytes.

```kotlin
val key = JcaRequestSigningKey("vsk_0123456789abcdef", privateKey, publicKey)   // java.security EC P-256 (software or the Android Keystore)
val proof = RequestSigning.signingKeyProof(challenge, key)                       // console, Security > Request signing
val fields = RequestSigning.sign(key, "POST", "https://viadere.com/v1/business/auth-deliveries", bodyBytes)
```

A KMS or HSM implements `RequestSigningKey` (`keyId`, `publicKey`, `sign(message)`) and may return DER or raw `r||s` with either `s`: the SDK converts
to raw, folds to low S and verifies the result against `publicKey` before returning any field (`RequestSigningException` otherwise, and nothing must
be sent). Profile: `ecdsa-p256-sha256`; components `@method @authority @path @query content-digest content-type` (bodiless:
the first four); parameters `created`, `expires` (at most 300 s later), `keyid`, `nonce`, `tag="viadere-api-v1"`; `@authority` is the lowercase host
without the default port, `@path`/`@query` exactly as sent (`?` when there is no query). `RequestSigningTest` reproduces every positive vector of
`docs/protocol/vectors/http-signatures-v1.json` byte for byte (signature base, `Signature-Input`, `Signature`, `Content-Digest`; DER, raw and
high-S signer outputs) and checks real signatures with the JDK's own P1363 verifier.

## Build status

Built and tested for real on 2026-11-15 (Linux, JDK 21, Gradle 9.8.2 from the pinned wrapper, AGP 9.5.0, Kotlin 2.4.21; Android SDK command-line
tools 23.0 build 16111833, sha1 from `repository2-3.xml`; platform 37.2; build-tools 36.0.0): from `sdk/android`

    export ANDROID_HOME=<sdk>
    ./gradlew clean :library:assembleRelease test

passes with no Kotlin compiler warnings; 28/28 unit tests pass. Dependency locks (`gradle/dependency-locks/library.lockfile`,
`settings-gradle.lockfile`) and `gradle/verification-metadata.xml` (sha256) were generated with
`./gradlew :library:assembleRelease :library:testDebugUnitTest :library:lint :library:dependencies --write-locks --write-verification-metadata sha256`
and are committed. The first compile found one pre-existing error, fixed: a KDoc in `IdempotencyKey.kt` contained `/*`, which Kotlin reads as a
nested comment opener.

**Not passing:** `:library:lint` (`warningsAsErrors`) reports two `AndroidGradlePluginVersion` errors: Gradle 9.9.1 and AGP 9.5.1 are newer than the
pinned 9.8.2 / 9.5.0. That is a toolchain upgrade for this project and `Packages/android/viadere-verify` together (CLAUDE.md "Current versions"),
not done here. No device or emulator run (the library has no Android component).
