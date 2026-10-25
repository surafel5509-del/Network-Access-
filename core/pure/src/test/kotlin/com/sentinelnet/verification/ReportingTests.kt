package com.sentinelnet.verification

import com.sentinelnet.core.crypto.HashTools
import com.sentinelnet.core.model.AuditEvent
import com.sentinelnet.core.model.DiscoveredDevice
import com.sentinelnet.core.model.Finding
import com.sentinelnet.core.model.PortResult
import com.sentinelnet.core.model.PortState
import com.sentinelnet.core.model.ScoreCategory
import com.sentinelnet.core.model.SecurityScore
import com.sentinelnet.core.model.Severity
import com.sentinelnet.core.model.WifiNetwork
import com.sentinelnet.core.model.WifiSecurity
import com.sentinelnet.core.reporting.JsonObjectBuilder
import com.sentinelnet.core.reporting.ReportBuilder
import com.sentinelnet.core.reporting.buildJson

private fun balanced(json: String): Boolean {
    var depth = 0
    var inString = false
    var escape = false
    for (c in json) {
        if (escape) { escape = false; continue }
        if (c == '\\' && inString) { escape = true; continue }
        if (c == '"') { inString = !inString; continue }
        if (inString) continue
        if (c == '{' || c == '[') depth++
        if (c == '}' || c == ']') depth--
        if (depth < 0) return false
    }
    return depth == 0 && !inString
}

fun reportingTests() = Harness.section("reporting") {
    val networks = listOf(
        WifiNetwork("Home-5G", "00:1A:2B:00:00:01", -45, 5180, 80, WifiSecurity.WPA3,
            com.sentinelnet.core.model.WifiStandard.WIFI_6, timestampMillis = 1_700_000_000_000L),
        WifiNetwork("Guest", "C0:25:E9:00:00:02", -70, 2437, 20, WifiSecurity.OPEN,
            timestampMillis = 1_700_000_000_000L)
    )
    val findings = listOf(
        Finding("wifi.open.guest", "Open network: Guest", "No encryption", Severity.CRITICAL,
            ScoreCategory.WIFI, "Use WPA3", mapOf("ssid" to "Guest")),
        Finding("port.23", "Telnet open", "Cleartext", Severity.HIGH,
            ScoreCategory.NETWORK, "Disable Telnet", referenceUrl = "https://nvd.nist.gov/")
    )
    val score = SecurityScorerHelper.score(findings)

    Harness.test("security report is well-formed JSON with chain-of-custody hash") {
        val json = ReportBuilder.securityReport(score, networks, emptyList(), emptyList(), 1_700_000_000_000L)
        Harness.assertTrue(balanced(json))
        Harness.assertContains(json, "\"reportType\": \"security-audit\"")
        Harness.assertContains(json, "\"overall\":")
        Harness.assertContains(json, "sha256")
        Harness.assertContains(json, "CRITICAL")
    }
    Harness.test("security report is byte-for-byte reproducible") {
        val a = ReportBuilder.securityReport(score, networks, generatedAtMillis = 1L)
        val b = ReportBuilder.securityReport(score, networks, generatedAtMillis = 1L)
        Harness.assertEquals(a, b)
        Harness.assertEquals(64, HashTools.sha256(a.toByteArray()).length)
    }
    Harness.test("Wi-Fi scan report contains channels, bands and security") {
        val json = ReportBuilder.wifiScanReport(networks, 1L)
        Harness.assertTrue(balanced(json))
        Harness.assertContains(json, "\"channel\": 36")
        Harness.assertContains(json, "2.4 GHz")
        Harness.assertContains(json, "WPA3")
    }
    Harness.test("port-scan JSON report counts open ports") {
        val json = ReportBuilder.portScanReport(listOf(
            PortResult("192.168.1.1", 80, "tcp", PortState.OPEN, "nginx", "1.18"),
            PortResult("192.168.1.1", 22, "tcp", PortState.CLOSED)
        ), 1L)
        Harness.assertTrue(balanced(json))
        Harness.assertContains(json, "\"reportType\": \"port-scan\"")
        Harness.assertContains(json, "\"openPorts\": 1")
    }
    Harness.test("capture report and audit log are valid JSON") {
        val events = listOf(AuditEvent(1, 1L, "local", "wifi.scan", "-", "OBSERVED", "passive", "s1"))
        Harness.assertTrue(balanced(ReportBuilder.captureReport(emptyList(), 0L, 1L)))
        Harness.assertTrue(balanced(ReportBuilder.auditLogReport(events)))
        Harness.assertContains(ReportBuilder.auditLogReport(events), "OBSERVED")
    }
    Harness.test("CSV exports quote commas, quotes and newlines") {
        val csv = ReportBuilder.devicesCsv(listOf(
            DiscoveredDevice("192.168.1.1", hostname = "router, main", vendor = "Acme \"Corp\"")
        ))
        Harness.assertContains(csv, "\"router, main\"")
        Harness.assertContains(csv, "\"Acme \"\"Corp\"\"\"")
        Harness.assertTrue(csv.startsWith("ip,mac,hostname"))
    }
    Harness.test("port CSV contains one row per result plus header") {
        val csv = ReportBuilder.portsCsv(listOf(
            PortResult("192.168.1.1", 80, "tcp", PortState.OPEN),
            PortResult("192.168.1.1", 443, "tcp", PortState.OPEN)
        ))
        Harness.assertEquals(3, csv.trim().lines().size)
    }
    Harness.test("JSON writer escapes control characters") {
        val json = buildJson { str("value", "line1\nline2\t\"quoted\"\\") }.toJson(pretty = false)
        Harness.assertEquals("{\"value\":\"line1\\nline2\\t\\\"quoted\\\"\\\\\"}", json)
        Harness.assertTrue(balanced(json))
    }
    Harness.test("JSON writer handles nested objects and arrays") {
        val json = buildJson {
            num("a", 1); bool("b", true)
            obj("c") { strings("d", listOf("x", "y")) }
            arr("e", listOf(JsonObjectBuilder().apply { str("f", "g") }.build()))
        }.toJson(pretty = false)
        Harness.assertEquals("{\"a\":1,\"b\":true,\"c\":{\"d\":[\"x\",\"y\"]},\"e\":[{\"f\":\"g\"}]}", json)
    }
    Harness.test("ISO timestamps are UTC and stable") {
        Harness.assertEquals("1970-01-01T00:00:00Z", ReportBuilder.iso(0L))
        Harness.assertEquals("2023-11-14T22:13:20Z", ReportBuilder.iso(1_700_000_000_000L))
    }
}

/** Local alias so the test file reads cleanly. */
private object SecurityScorerHelper {
    fun score(findings: List<Finding>): SecurityScore =
        com.sentinelnet.core.domain.SecurityScorer.score(findings, 1_700_000_000_000L)
}
