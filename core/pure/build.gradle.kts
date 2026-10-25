import org.jetbrains.kotlin.gradle.tasks.KotlinCompile

plugins {
    alias(libs.plugins.kotlin.jvm)
}

java {
    sourceCompatibility = JavaVersion.VERSION_17
    targetCompatibility = JavaVersion.VERSION_17
}

tasks.withType<KotlinCompile>().configureEach {
    kotlinOptions {
        jvmTarget = "17"
        // Pure Kotlin/JVM: intentionally ZERO Android and ZERO third-party dependencies.
        // The legal/consent gate, crypto lab, scoring and packet parser can therefore be
        // compiled and executed on a plain JDK (see scripts/verify_domain.sh).
        freeCompilerArgs = freeCompilerArgs + listOf("-Xjsr305=strict")
    }
}

// Self-contained conformance suite: the same Kotlin code runs locally with kotlinc
// and in CI via Gradle. No JUnit dependency, so it also works in air-gapped CI.
val conformance by tasks.registering(JavaExec::class) {
    group = "verification"
    description = "Runs the SentinelNet domain conformance suite (consent, crypto, scoring, pcap, reports)."
    dependsOn(tasks.named("testClasses"))
    classpath = sourceSets["test"].runtimeClasspath
    mainClass.set("com.sentinelnet.verification.ConformanceSuiteKt")
    workingDir = project.projectDir
    outputs.upToDateWhen { false }
}
