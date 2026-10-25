package com.sentinelnet.verification

import java.io.File
import kotlin.system.exitProcess

/**
 * Entry point for `./gradlew :core:pure:conformance` and for
 * `scripts/verify_domain.sh` (which runs it on a bare JDK, no Gradle needed).
 *
 * Optional: `--emit-samples=<dir>` regenerates docs/samples from real domain code.
 */
fun main(args: Array<String>) {
    Harness.reset()
    consentTests()
    domainTests()
    cryptoTests()
    pcapTests()
    reportingTests()

    val text = Harness.report()
    println(text)

    try {
        val reportDir = File("build/reports")
        if (reportDir.parentFile != null) {
            reportDir.mkdirs()
            File(reportDir, "conformance.txt").writeText(text)
        }
    } catch (t: Throwable) {
        println("note: could not write build/reports/conformance.txt: ${t.message}")
    }

    args.firstOrNull { it.startsWith("--emit-samples=") }?.let { arg ->
        val dir = File(arg.substringAfter('='))
        SampleReports.writeAll(dir)
        println("Wrote sample reports to ${dir.absolutePath}")
    }

    if (Harness.failures > 0) {
        System.err.println("${Harness.failures} conformance check(s) FAILED")
        exitProcess(1)
    }
}
