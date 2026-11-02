// "Verify with Viadere" for Android apps (docs/VERIFY-BUTTON.md): Jetpack Compose UI on foundation only (no Material: the brand's own
// components), App Link hand-off, QR-first panel, a dependency-free QR encoder. AGP 9 compiles Kotlin itself (built-in Kotlin), so only the
// Compose compiler plugin is applied.
plugins {
    alias(libs.plugins.android.library)
    alias(libs.plugins.kotlin.compose)
}

android {
    namespace = "com.viadere.verify"
    compileSdk {
        version = release(37) { minorApiLevel = 2 }
    }
    defaultConfig {
        // FLAG_ACTIVITY_REQUIRE_NON_BROWSER (the App Link hand-off that never falls back to a browser tab) needs API 30.
        minSdk = 30
        consumerProguardFiles("consumer-rules.pro")
    }
    buildFeatures { compose = true }
    lint {
        warningsAsErrors = true
        abortOnError = true
        // AndroidX's own lifecycle lint registry references Kotlin analysis APIs that lint 32.5 no longer has; lint skips it and says so.
        // That is a tooling notice about a transitive library, not an issue in this code.
        disable += "ObsoleteLintCustomCheck"
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_21
        targetCompatibility = JavaVersion.VERSION_21
    }
}

kotlin {
    jvmToolchain(21)
}

dependencies {
    implementation(platform(libs.compose.bom))
    implementation(libs.compose.ui)
    implementation(libs.compose.foundation)
    testImplementation(libs.junit)
}
