// Viadere Android/JVM SDK (ADR-0030): contract models, webhook signature v2 verification, replay store, per-requester throttle. No runtime
// dependencies at all (java.security / javax.crypto and the Kotlin standard library only), no permissions, no components.
plugins {
    alias(libs.plugins.android.library)
}

android {
    namespace = "com.viadere.sdk"
    compileSdk {
        version = release(37) { minorApiLevel = 2 }
    }
    defaultConfig {
        // Product decision for device reach, like the iOS target (CLAUDE.md exceptions table).
        minSdk = 30
        consumerProguardFiles("consumer-rules.pro")
    }
    lint {
        warningsAsErrors = true
        abortOnError = true
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_21
        targetCompatibility = JavaVersion.VERSION_21
    }
    testOptions {
        // The unit tests read the shared vectors from docs/protocol/vectors and the contract from contracts/.
        unitTests.all { it.systemProperty("viadere.repoRoot", rootProject.projectDir.resolve("../..").canonicalPath) }
    }
}

kotlin {
    jvmToolchain(21)
    explicitApi()
}

dependencies {
    testImplementation(libs.junit)
}
