plugins {
    alias(libs.plugins.android.library) apply false
    alias(libs.plugins.kotlin.compose) apply false
}

// Reproducible dependency resolution (CLAUDE.md rules 4/5): every resolvable configuration is locked (gradle/dependency-locks; regenerate
// with `./gradlew :library:dependencies --write-locks`) and every artifact is checked against gradle/verification-metadata.xml (sha256).
subprojects {
    dependencyLocking {
        lockAllConfigurations()
        lockFile = rootProject.file("gradle/dependency-locks/${project.name}.lockfile")
    }
}
