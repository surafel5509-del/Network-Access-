// Root build: plugins are declared here and applied in leaf modules.
plugins {
    alias(libs.plugins.android.application) apply false
    alias(libs.plugins.android.library) apply false
    alias(libs.plugins.kotlin.android) apply false
    alias(libs.plugins.kotlin.jvm) apply false
    alias(libs.plugins.ksp) apply false
    alias(libs.plugins.hilt) apply false
    alias(libs.plugins.detekt) apply false
}

tasks.register("verifyDomain") {
    group = "verification"
    description = "Runs the pure-Kotlin conformance suite (no Android SDK required for the algorithms)."
    dependsOn(":core:pure:conformance")
}
