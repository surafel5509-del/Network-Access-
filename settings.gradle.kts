// SentinelNet — multi-module Android project.
// Every engine is an independent Gradle module behind a stable interface in :engine:api.
pluginManagement {
    repositories {
        google()
        mavenCentral()
        gradlePluginPortal()
    }
}
dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
        google()
        mavenCentral()
        // Rust JNI artifacts are published locally by `scripts/build-native.sh` (no remote needed).
        maven { url = uri("$rootDir/native/out/maven") }
    }
}

rootProject.name = "SentinelNet"

include(":core:pure")
include(":core:android")
include(":engine:api")
include(":engine:wifi")
include(":engine:scanner")
include(":engine:capture")
include(":engine:audit")
include(":app")
