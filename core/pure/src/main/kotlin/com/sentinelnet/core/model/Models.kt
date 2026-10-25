@file:Suppress("unused")
package com.sentinelnet.core.model

/**
 * Canonical domain models shared by every engine.
 *
 * Design rule (see ADR-0002): these types contain NO Android classes and NO
 * third-party annotations. They are the wire format between engines, the domain
 * layer, exports and the local HTTP API.
 */

enum class Severity(val weight: Int) {
    INFO(0), LOW(2), MEDIUM(5), HIGH(12), CRITICAL(25);

    companion object {
        fun from(value: String): Severity =
            entries.firstOrNull { it.name.equals(value, ignoreCase = true) } ?: INFO
    }
}

enum class WifiSecurity {
    OPEN, WEP, WPA, WPA2, WPA3, WPA2_ENTERPRISE, WPA3_ENTERPRISE, OWE, WPS, UNKNOWN;

    /** True when this configuration offers no meaningful confidentiality. */
    val isInsecure: Boolean get() = this == OPEN || this == WEP || this == WPA || this == WPS
}

enum class WifiStandard { WIFI_4, WIFI_5, WIFI_6, WIFI_6E, WIFI_7, LEGACY, UNKNOWN }

enum class Band(val label: String) {
    GHZ_2_4("2.4 GHz"), GHZ_5("5 GHz"), GHZ_6("6 GHz"), UNKNOWN("unknown");

    companion object {
        fun fromFrequencyMhz(freq: Int): Band = when {
            freq in 2400..2499 -> GHZ_2_4
            freq in 5000..5899 -> GHZ_5
            freq in 5900..7125 -> GHZ_6
            else -> UNKNOWN
        }
    }
}

enum class DeviceType { ROUTER, PHONE, PC, IOT, TV, PRINTER, CAMERA, SERVER, UNKNOWN }

/** A single observed Wi-Fi network. All fields are passive scan observations. */
data class WifiNetwork(
    val ssid: String,
    val bssid: String,
    val rssiDbm: Int,
    val frequencyMhz: Int,
    val channelWidthMhz: Int = 20,
    val security: WifiSecurity = WifiSecurity.UNKNOWN,
    val standard: WifiStandard = WifiStandard.UNKNOWN,
    val wpsEnabled: Boolean = false,
    val isHidden: Boolean = false,
    val vendor: String? = null,
    val maxPhyRateMbps: Int = 0,
    val countryCode: String? = null,
    val timestampMillis: Long = 0L
) {
    val band: Band get() = Band.fromFrequencyMhz(frequencyMhz)
    val channel: Int get() = WifiChannels.frequencyToChannel(frequencyMhz)
}

object WifiChannels {
    /** 802.11 channel/frequency mapping for 2.4/5/6 GHz. */
    fun frequencyToChannel(freqMhz: Int): Int = when {
        freqMhz == 2484 -> 14
        freqMhz in 2412..2472 -> (freqMhz - 2407) / 5
        freqMhz in 5000..5895 -> (freqMhz - 5000) / 5
        freqMhz in 5955..7115 -> (freqMhz - 5955) / 5 + 1
        else -> -1
    }

    fun channelToFrequency(channel: Int, band: Band): Int = when (band) {
        Band.GHZ_2_4 -> if (channel == 14) 2484 else 2407 + channel * 5
        Band.GHZ_5 -> 5000 + channel * 5
        Band.GHZ_6 -> 5955 + (channel - 1) * 5
        Band.UNKNOWN -> -1
    }

    /** The three non-overlapping 20 MHz channels in the 2.4 GHz band. */
    val NON_OVERLAPPING_2_4 = listOf(1, 6, 11)

    /** DFS-free 5 GHz channels available on most client devices. */
    val COMMON_5 = listOf(36, 40, 44, 48, 149, 153, 157, 161, 165)
}

data class ChannelLoad(val channel: Int, val band: Band, val apCount: Int, val weightedCongestion: Double)

data class ChannelRecommendation(
    val band: Band,
    val channel: Int,
    val frequencyMhz: Int,
    val score: Double,
    val reason: String,
    val alternatives: List<Int> = emptyList()
)

/** A host observed on the local network. */
data class DiscoveredDevice(
    val ip: String,
    val mac: String? = null,
    val hostname: String? = null,
    val vendor: String? = null,
    val deviceType: DeviceType = DeviceType.UNKNOWN,
    val openPorts: List<Int> = emptyList(),
    val httpTitle: String? = null,
    val ttl: Int? = null,
    val rssiDbm: Int? = null,
    val discoverySources: Set<String> = emptySet(),
    val firstSeenMillis: Long = 0L,
    val lastSeenMillis: Long = 0L
)

enum class PortState { OPEN, CLOSED, FILTERED, ERROR }

data class PortResult(
    val target: String,
    val port: Int,
    val protocol: String,
    val state: PortState,
    val banner: String? = null,
    val service: String? = null,
    val version: String? = null,
    val latencyMs: Long = 0L,
    val tlsSubject: String? = null
)

/** A single actionable observation produced by any auditor. */
data class Finding(
    val id: String,
    val title: String,
    val detail: String,
    val severity: Severity,
    val category: ScoreCategory,
    val remediation: String,
    val evidence: Map<String, String> = emptyMap(),
    val referenceUrl: String? = null,
    val detectedAtMillis: Long = 0L
)

enum class ScoreCategory(val displayName: String, val weight: Double) {
    WIFI("Wi-Fi security", 0.20),
    NETWORK("Network exposure", 0.20),
    DEVICE("Device hardening", 0.20),
    APPS("App & permission hygiene", 0.15),
    PRIVACY("Privacy & tracking", 0.15),
    CRYPTO("Cryptography & credentials", 0.10);

    init { require(weight > 0.0) }

    companion object {
        val TOTAL_WEIGHT: Double = entries.sumOf { it.weight }
    }
}

data class CategoryScore(
    val category: ScoreCategory,
    val rawScore: Int,
    val findingCount: Int,
    val weightedContribution: Double
)

data class SecurityScore(
    val overall: Int,
    val categories: List<CategoryScore>,
    val findings: List<Finding>,
    val computedAtMillis: Long,
    val inputFingerprint: String
) {
    val grade: String get() = when {
        overall >= 90 -> "A"
        overall >= 80 -> "B"
        overall >= 70 -> "C"
        overall >= 60 -> "D"
        else -> "F"
    }
}

/** The locally-stored, exportable audit trail. Never contains IMSI/IMEI/serial. */
data class AuditEvent(
    val sequence: Long,
    val timestampMillis: Long,
    val actor: String,
    val capability: String,
    val target: String,
    val decision: String,
    val reason: String,
    val sessionId: String
)

data class CveHint(
    val cveId: String,
    val servicePattern: String,
    val versionPattern: String,
    val summary: String,
    val severity: Severity
) {
    val nvdUrl: String get() = "https://nvd.nist.gov/vuln/detail/$cveId"
}

data class FlowKey(
    val srcIp: String, val dstIp: String, val srcPort: Int, val dstPort: Int, val protocol: Int
)

data class FlowStats(
    val key: FlowKey, val packets: Long, val bytes: Long, val firstSeen: Long, val lastSeen: Long
)

/** Result of a packet-capture parse. `raw` is intentionally not retained in flows. */
data class ParsedPacket(
    val timestampMillis: Long,
    val length: Int,
    val srcIp: String,
    val dstIp: String,
    val protocol: Int,
    val srcPort: Int? = null,
    val dstPort: Int? = null,
    val tcpFlags: Int = 0,
    val dnsQueries: List<String> = emptyList(),
    val applicationProtocol: String = "unknown"
)
