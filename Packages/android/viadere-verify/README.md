# viadere-verify (Android)

"Verify with Viadere" for Android apps: a Jetpack Compose button, the App Link hand-off and the QR-first panel. Integration, security model and
the hand-off table are in [`docs/VERIFY-BUTTON.md`](../../../docs/VERIFY-BUTTON.md).

| | |
|---|---|
| Module | `:library`, namespace `com.viadere.verify`, `minSdk 30`, compile SDK 37.2 |
| Toolchain | Gradle 9.8.2, AGP 9.5.0 (built-in Kotlin), Kotlin 2.4.21 (Compose compiler plugin), Compose BOM 2026.09.00 (`ui`, `foundation`), JUnit 4.13.2 |
| Dependencies | Compose `ui` and `foundation` only. No Material, no networking, no QR library (`QrCode.kt` is a dependency-free encoder) |
| Pure logic | `VerifyModel.kt` (session link, hand-off rule, panel state, return check, colours, mark paths), `QrCode.kt` |
| Android | `VerifyLauncher.kt` (`FLAG_ACTIVITY_REQUIRE_NON_BROWSER`), `VerifyWithViadereButton.kt` (Compose button and panel) |

## Build status

- **Compiled and tested here:** `QrCode.kt`, `VerifyModel.kt` and the unit tests under `library/src/test` (Kotlin 2.4.21 on a JVM-only Gradle
  build, 6/6 passing; the QR vectors are the web encoder's output cross-checked against the `qrcode` reference library).
- **Not compiled here** (no Android SDK in the dev container): `VerifyLauncher.kt`, `VerifyWithViadereButton.kt`, and the Android Gradle build
  itself (`compileSdk { version = release(37) { minorApiLevel = 2 } }` uses the AGP 9 DSL). Build it once in Android Studio or CI before release.
- The Gradle wrapper JAR and scripts are not committed: run `gradle wrapper --gradle-version 9.8.2` once (the properties pin the distribution
  checksum), then `./gradlew :library:testDebugUnitTest`.
