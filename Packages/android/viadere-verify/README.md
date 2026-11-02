# viadere-verify (Android)

"Verify with Viadere" for Android apps: a Jetpack Compose button, the App Link hand-off and the QR-first panel. Integration, security model and
the hand-off table are in [`docs/VERIFY-BUTTON.md`](../../../docs/VERIFY-BUTTON.md).

| | |
|---|---|
| Module | `:library`, namespace `com.viadere.verify`, `minSdk 30`, compile SDK 37.2 |
| Toolchain | Gradle 9.8.2, AGP 9.5.0 (built-in Kotlin), Kotlin 2.4.21 (Compose compiler plugin), Compose BOM 2026.09.00 (`ui`, `foundation`), JUnit 4.13.2 |
| Dependencies | Compose `ui` and `foundation` only (CLAUDE.md rule 4 justification: the deliverable is a Jetpack Compose component, so the integrating app already ships both; nothing else). No Material, no networking, no QR library (`QrCode.kt` is a dependency-free encoder) |
| Pure logic | `VerifyModel.kt` (session link, hand-off rule, panel state, return check, colours, mark paths), `QrCode.kt` |
| Android | `VerifyLauncher.kt` (`FLAG_ACTIVITY_REQUIRE_NON_BROWSER`), `VerifyWithViadereButton.kt` (Compose button and panel) |

## Build status

Built and tested for real on 2026-11-02 (Linux, JDK 21, Android SDK command-line tools 23.0, platform 37.2, build-tools 36.0.0):
`./gradlew :library:assembleRelease :library:testDebugUnitTest :library:lint` passes with no compiler warnings and no lint findings
(`lint { warningsAsErrors = true }`); 6/6 unit tests pass (the QR vectors are the web encoder's output cross-checked against the `qrcode`
reference library). That covers `VerifyLauncher.kt`, `VerifyWithViadereButton.kt`, the Android Gradle build and the `compileSdk` DSL.

- **Not covered:** no emulator or device run (the App Link hand-off and the Compose UI are compiled and linted, not exercised); do that
  once in Android Studio or CI before release.
- **Setup:** `export ANDROID_HOME=<sdk>` (or `local.properties`) with the platform and build-tools above; AGP installs missing licensed
  components itself once the licenses are accepted (`sdkmanager --licenses`).
- **Reproducibility:** the wrapper JAR and scripts are committed (distribution SHA-256 pinned in `gradle-wrapper.properties`);
  `gradle/dependency-locks/` and `settings-gradle.lockfile` lock every configuration (regenerate with
  `./gradlew :library:assembleRelease :library:testDebugUnitTest :library:lint :library:dependencies --write-locks`);
  `gradle/verification-metadata.xml` holds sha256 checksums for every artifact and plugin (regenerate by adding
  `--write-verification-metadata sha256`). A dependency upgrade means re-running both and reviewing the diff.
