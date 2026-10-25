package com.sentinelnet.verification

/** Dependency-free test harness so the domain can be verified on a bare JDK. */
object Harness {
    data class Result(val section: String, val name: String, val passed: Boolean, val detail: String)

    private val results = mutableListOf<Result>()
    var section: String = "general"
        private set

    fun section(name: String, block: () -> Unit) {
        val previous = section
        section = name
        try { block() } finally { section = previous }
    }

    fun test(name: String, block: () -> Unit) {
        try {
            block()
            results += Result(section, name, true, "")
        } catch (t: Throwable) {
            results += Result(section, name, false, "${t.javaClass.simpleName}: ${t.message}")
        }
    }

    fun assertTrue(condition: Boolean, message: String = "expected true") {
        if (!condition) throw AssertionError(message)
    }

    fun <T> assertEquals(expected: T, actual: T, message: String = "") {
        if (expected != actual) {
            throw AssertionError("${if (message.isBlank()) "" else "$message: "}expected <$expected> but was <$actual>")
        }
    }

    fun assertContains(haystack: String, needle: String) {
        if (!haystack.contains(needle)) throw AssertionError("expected to contain '$needle' in: ${haystack.take(200)}")
    }

    fun report(): String = buildString {
        appendLine("SentinelNet domain conformance suite")
        appendLine("=".repeat(60))
        results.groupBy { it.section }.forEach { (sec, list) ->
            appendLine("[$sec]")
            list.forEach { r ->
                appendLine("  ${if (r.passed) "PASS" else "FAIL"}  ${r.name}${if (r.detail.isBlank()) "" else " -> ${r.detail}"}")
            }
        }
        val passed = results.count { it.passed }
        appendLine("=".repeat(60))
        appendLine("TOTAL: $passed/${results.size} passed, ${results.size - passed} failed")
    }

    val failures: Int get() = results.count { !it.passed }
    val total: Int get() = results.size

    fun reset() { results.clear() }
}
