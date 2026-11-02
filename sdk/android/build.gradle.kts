// AGP 9 compiles Kotlin itself (built-in Kotlin). The Kotlin Gradle plugin is put on the build classpath at the pinned version so the compiler is
// the current stable release rather than AGP's default.
buildscript {
    repositories {
        mavenCentral()
        gradlePluginPortal()
    }
    dependencies {
        classpath(libs.kotlin.gradle.plugin)
    }
}

plugins {
    alias(libs.plugins.android.library) apply false
}

// Reproducible dependency resolution (CLAUDE.md rules 4/5): every resolvable configuration is locked (gradle/dependency-locks; regenerate
// with `./gradlew :library:dependencies --write-locks`) and every artifact is checked against gradle/verification-metadata.xml (sha256).
subprojects {
    dependencyLocking {
        lockAllConfigurations()
        lockFile = rootProject.file("gradle/dependency-locks/${project.name}.lockfile")
    }
}
