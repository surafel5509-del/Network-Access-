package com.sentinelnet.verification

import com.sentinelnet.core.crypto.WpaPskLab
import com.sentinelnet.core.domain.CveHintMatcher
import com.sentinelnet.core.domain.DeviceFingerprinter
import com.sentinelnet.core.domain.OuiLookup
import com.sentinelnet.core.domain.PortRisk
import com.sentinelnet.core.domain.SecurityScorer
import com.sentinelnet.core.domain.WifiSecurityAuditor
import com.sentinelnet.core.model.AuditEvent
import com.sentinelnet.core.model.DiscoveredDevice
import com.sentinelnet.core.model.PortResult
import com.sentinelnet.core.model.PortState
import com.sentinelnet.core.model.WifiNetwork
import com.sentinelnet.core.model.WifiSecurity
import com.sentinelnet.core.model.WifiStandard
import com.sentinelnet.core.pcap.PacketParser
import com.sentinelnet.core.pcap.FlowTracker
import com.sentinelnet.core.reporting.ReportBuilder
import java.io.File

/**
 * Generates the docs/samples files from the real domain code (never hand-edited), so
 * the shipped example reports always match the schema the app actually emits.
 * Run: ./gradlew :core:pure:conformance --args="--emit-samples=../../docs/samples"
 */
object SampleReports {
    private const val T = 1_700_000_000_000L

    private val networks = listOf(
        WifiNetwork("SentinelLab-5G", "00:1A:2B:3C:4D:5E", -42, 5180, 80,
            WifiSecurity.WPA3, WifiStandard.WIFI_6, vendor = "Cisco Systems", timestampMillis = T),
        WifiNetwork("SentinelLab-IoT", "C0:25:E9:11:22:33", -61, 2437, 20,
            WifiSecurity.WPA2, WifiStandard.WIFI_4, wpsEnabled = true, vendor = "TP-Link", timestampMillis = T),
        WifiNetwork("Cafe Free WiFi", "02:11:22:33:44:55", -55, 2412, 20,
            WifiSecurity.OPEN, timestampMillis = T),
        WifiNetwork("Legacy-WEP", "00:1B:44:66:77:88", -78, 2462, 20,
            WifiSecurity.WEP, timestampMillis = T)
    )

    private val ports = listOf(
        PortResult("192.168.1.1", 80, "tcp", PortState.OPEN, "nginx", "1.18.0", latencyMs = 4),
        PortResult("192.168.1.1", 443, "tcp", PortState.OPEN, "nginx", "1.18.0", latencyMs = 5),
        PortResult("192.168.1.1", 22, "tcp", PortState.CLOSED),
        PortResult("192.168.1.20", 445, "tcp", PortState.OPEN, "Samba", "4.3.11", latencyMs = 7),
        PortResult("192.168.1.20", 23, "tcp", PortState.OPEN, "BusyBox telnetd", "", latencyMs = 6)
    )

    private val devices = listOf(
        DiscoveredDevice("192.168.1.1", "00:1A:2B:3C:4D:5E", "SentinelLab-Router",
            openPorts = listOf(80, 443), discoverySources = setOf("ARP", "mDNS")),
        DiscoveredDevice("192.168.1.20", "DC:A6:32:AA:BB:CC", "lab-nas.local",
            openPorts = listOf(23, 445), discoverySources = setOf("ICMP", "NetBIOS"))
    ).map { DeviceFingerprinter.enrich(it, OuiLookup()) }

    private fun findings() = buildList {
        addAll(WifiSecurityAuditor().audit(networks, T))
        addAll(PortRisk.assess(ports, T))
        addAll(CveHintMatcher().match("Samba", "4.3.11", "Samba 4.3.11", "192.168.1.20", T))
    }

    fun writeAll(dir: File) {
        dir.mkdirs()
        val findings = findings()
        val score = SecurityScorer.score(findings, T)
        val events = listOf(
            AuditEvent(1, T, "local-user", "wifi.scan", "-", "OBSERVED", "passive", "sample-session"),
            AuditEvent(2, T + 1000, "local-user", "net.portscan", "192.168.1.0/24", "ALLOWED",
                "OWN_NETWORK / LOCAL_PRIVATE", "sample-session"),
            AuditEvent(3, T + 2000, "local-user", "net.portscan", "8.8.8.8", "DENIED",
                "PUBLIC_TARGET_NOT_ACKNOWLEDGED: Public target needs explicit acknowledgement", "sample-session"),
            AuditEvent(4, T + 3000, "local-user", "lab.wpa_psk", "local-synthetic", "ALLOWED",
                "LOCAL_LAB / LOCAL_LAB", "sample-session")
        )

        File(dir, "wifi_scan_report.json").writeText(ReportBuilder.wifiScanReport(networks, T))
        File(dir, "wifi_scan_report.csv").writeText(ReportBuilder.networksCsv(networks))
        File(dir, "security_audit_report.json").writeText(ReportBuilder.securityReport(score, networks, devices, ports, T))
        File(dir, "security_findings.csv").writeText(ReportBuilder.findingsCsv(score.findings))
        File(dir, "port_scan_report.csv").writeText(ReportBuilder.portsCsv(ports))
        File(dir, "port_scan_report.json").writeText(ReportBuilder.portScanReport(ports, T))
        File(dir, "device_discovery.csv").writeText(ReportBuilder.devicesCsv(devices))
        File(dir, "audit_log.json").writeText(ReportBuilder.auditLogReport(events))

        // A capture summary from synthetic packets so the sample is reproducible.
        val tracker = FlowTracker()
        repeat(4) { i ->
            val packet = ByteArray(20 + 8 + 12)
            packet[0] = 0x45; packet[2] = 0; packet[3] = 40; packet[8] = 64; packet[9] = 17
            packet[12] = 192.toByte(); packet[13] = 168.toByte(); packet[14] = 1; packet[15] = 20
            packet[16] = 192.toByte(); packet[17] = 168.toByte(); packet[18] = 1; packet[19] = 1
            packet[23] = 53
            PacketParser.parse(packet, T + i)?.let { tracker.onPacket(it) }
        }
        File(dir, "capture_summary.json").writeText(
            ReportBuilder.captureReport(tracker.snapshot(), tracker.snapshot().sumOf { it.packets }, T))

        // Educational lab walkthrough: shows the derivation, not an attack on any network.
        val sample = WpaPskLab.syntheticHandshake("SentinelLab", "password123")
        val good = WpaPskLab.verify(sample, "password123")
        val report = com.sentinelnet.core.reporting.buildJson {
            str("schema", "sentinelnet.lab/1")
            str("generatedAt", ReportBuilder.iso(T))
            str("lesson", "Why weak WPA2-PSK passphrases are recoverable offline, and why WPA3-SAE fixes it")
            bool("syntheticHandshake", true)
            str("ssid", sample.ssid)
            num("pbkdf2Iterations", WpaPskLab.WPA_ITERATIONS)
            num("pmkBytes", WpaPskLab.PMK_LENGTH)
            str("verifiedPmkHex", good.pmkHex)
            str("verifiedMicHex", good.computedMicHex)
            str("expectedMicHex", good.expectedMicHex)
            bool("micMatched", good.matched)
            str("note", "Offline verification of a locally generated handshake. " +
                "No frames were captured from the air and no nearby network was targeted.")
            str("mitigation", "Use WPA3-SAE and a 16+ character random passphrase; disable WPS PIN.")
        }.toJson()
        File(dir, "security_lab_walkthrough.json").writeText(report)
    }
}
