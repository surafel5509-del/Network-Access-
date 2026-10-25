package com.sentinelnet.core.reporting

import com.sentinelnet.core.crypto.HashTools
import com.sentinelnet.core.model.AuditEvent
import com.sentinelnet.core.model.DiscoveredDevice
import com.sentinelnet.core.model.Finding
import com.sentinelnet.core.model.FlowStats
import com.sentinelnet.core.model.PortResult
import com.sentinelnet.core.model.PortState
import com.sentinelnet.core.model.SecurityScore
import com.sentinelnet.core.model.WifiNetwork
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.TimeZone

/** Module I3: JSON/CSV exports. PDF rendering lives in :core:android (Android PdfDocument). */
object ReportBuilder {
    private const val SCHEMA = "sentinelnet.report/1"

    fun iso(millis: Long): String {
        val fmt = SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'", Locale.US)
        fmt.timeZone = TimeZone.getTimeZone("UTC")
        return fmt.format(Date(millis))
    }

    fun securityReport(
        score: SecurityScore,
        networks: List<WifiNetwork> = emptyList(),
        devices: List<DiscoveredDevice> = emptyList(),
        ports: List<PortResult> = emptyList(),
        generatedAtMillis: Long = 0L
    ): String {
        val document = buildJson {
            str("schema", SCHEMA)
            str("reportType", "security-audit")
            str("generatedAt", iso(generatedAtMillis))
            obj("score") {
                num("overall", score.overall)
                str("grade", score.grade)
                str("inputFingerprint", score.inputFingerprint)
                arr("categories", score.categories.map { c ->
                    buildJson {
                        str("category", c.category.displayName)
                        num("rawScore", c.rawScore)
                        num("weight", c.category.weight)
                        num("findingCount", c.findingCount)
                    }
                })
            }
            arr("findings", score.findings.map { findingJson(it) })
            strings("remediation", com.sentinelnet.core.domain.SecurityScorer.prioritizedRemediation(score.findings))
            obj("inputs") {
                num("wifiNetworks", networks.size)
                num("devices", devices.size)
                num("portResults", ports.size)
            }
        }
        val body = document.toJson()
        // Chain-of-custody: the report hash is printed in the UI and stored in the audit log.
        val hash = HashTools.sha256(body.toByteArray(Charsets.UTF_8))
        return buildJson {
            put("document", document)
            str("sha256", hash)
        }.toJson()
    }

    fun findingJson(f: Finding): JObj = buildJson {
        str("id", f.id)
        str("title", f.title)
        str("detail", f.detail)
        str("severity", f.severity.name)
        str("category", f.category.name)
        str("remediation", f.remediation)
        nullableStr("referenceUrl", f.referenceUrl)
        obj("evidence") { f.evidence.forEach { (k, v) -> str(k, v) } }
    }

    fun wifiScanReport(networks: List<WifiNetwork>, generatedAtMillis: Long): String = buildJson {
        str("schema", SCHEMA)
        str("reportType", "wifi-scan")
        str("generatedAt", iso(generatedAtMillis))
        num("count", networks.size)
        arr("networks", networks.map { n ->
            buildJson {
                str("ssid", n.ssid); str("bssid", n.bssid)
                num("rssiDbm", n.rssiDbm); num("frequencyMhz", n.frequencyMhz)
                num("channel", n.channel); str("band", n.band.label)
                num("channelWidthMhz", n.channelWidthMhz)
                str("security", n.security.name); str("standard", n.standard.name)
                bool("wps", n.wpsEnabled); bool("hidden", n.isHidden)
                nullableStr("vendor", n.vendor); num("maxPhyRateMbps", n.maxPhyRateMbps)
            }
        })
    }.toJson()

    fun portScanReport(results: List<PortResult>, generatedAtMillis: Long): String = buildJson {
        str("schema", SCHEMA)
        str("reportType", "port-scan")
        str("generatedAt", iso(generatedAtMillis))
        num("count", results.size)
        num("openPorts", results.count { it.state == PortState.OPEN })
        arr("results", results.map { r ->
            buildJson {
                str("target", r.target); num("port", r.port); str("protocol", r.protocol)
                str("state", r.state.name); nullableStr("service", r.service)
                nullableStr("version", r.version); nullableStr("banner", r.banner)
                num("latencyMs", r.latencyMs); nullableStr("tlsSubject", r.tlsSubject)
            }
        })
    }.toJson()

    fun captureReport(flows: List<FlowStats>, packetCount: Long, generatedAtMillis: Long): String = buildJson {
        str("schema", SCHEMA)
        str("reportType", "capture-summary")
        str("generatedAt", iso(generatedAtMillis))
        num("packetCount", packetCount)
        arr("flows", flows.map { f ->
            buildJson {
                str("srcIp", f.key.srcIp); str("dstIp", f.key.dstIp)
                num("srcPort", f.key.srcPort); num("dstPort", f.key.dstPort)
                num("protocol", f.key.protocol)
                num("packets", f.packets); num("bytes", f.bytes)
                str("firstSeen", iso(f.firstSeen)); str("lastSeen", iso(f.lastSeen))
            }
        })
    }.toJson()

    fun auditLogReport(events: List<AuditEvent>): String = buildJson {
        str("schema", SCHEMA)
        str("reportType", "audit-log")
        num("count", events.size)
        arr("events", events.map { e ->
            buildJson {
                num("sequence", e.sequence); str("timestamp", iso(e.timestampMillis))
                str("actor", e.actor); str("capability", e.capability)
                str("target", e.target); str("decision", e.decision); str("reason", e.reason)
                str("sessionId", e.sessionId)
            }
        })
    }.toJson()

    fun networksCsv(networks: List<WifiNetwork>): String = csv(
        listOf("ssid", "bssid", "rssi_dbm", "channel", "band", "security", "standard", "wps", "vendor"),
        networks.map { listOf(it.ssid, it.bssid, it.rssiDbm, it.channel, it.band.label,
            it.security.name, it.standard.name, it.wpsEnabled, it.vendor ?: "") }
    )

    fun devicesCsv(devices: List<DiscoveredDevice>): String = csv(
        listOf("ip", "mac", "hostname", "vendor", "type", "open_ports", "sources"),
        devices.map { listOf(it.ip, it.mac ?: "", it.hostname ?: "", it.vendor ?: "",
            it.deviceType.name, it.openPorts.joinToString(";"), it.discoverySources.joinToString(";")) }
    )

    fun portsCsv(results: List<PortResult>): String = csv(
        listOf("target", "port", "protocol", "state", "service", "version", "banner", "latency_ms"),
        results.map { listOf(it.target, it.port, it.protocol, it.state.name, it.service ?: "",
            it.version ?: "", it.banner ?: "", it.latencyMs) }
    )

    fun findingsCsv(findings: List<Finding>): String = csv(
        listOf("id", "severity", "category", "title", "remediation", "reference"),
        findings.map { listOf(it.id, it.severity.name, it.category.name, it.title,
            it.remediation, it.referenceUrl ?: "") }
    )

    fun csv(headers: List<String>, rows: List<List<Any?>>): String = buildString {
        append(headers.joinToString(",") { escape(it) }).append('\n')
        rows.forEach { row -> append(row.joinToString(",") { escape(it?.toString() ?: "") }).append('\n') }
    }

    private fun escape(value: String): String {
        val needsQuote = value.any { it == ',' || it == '"' || it == '\n' || it == '\r' }
        val escaped = value.replace("\"", "\"\"")
        return if (needsQuote) "\"$escaped\"" else escaped
    }
}
