package com.sentinelnet.engine.api

import com.sentinelnet.core.consent.Capability
import com.sentinelnet.core.consent.ConsentRequest
import com.sentinelnet.core.model.ChannelRecommendation
import com.sentinelnet.core.model.DiscoveredDevice
import com.sentinelnet.core.model.Finding
import com.sentinelnet.core.model.PortResult
import com.sentinelnet.core.model.SecurityScore
import com.sentinelnet.core.model.WifiNetwork
import kotlinx.coroutines.flow.Flow

/* ---------------------------------------------------------------------------
 * MODULE A — multi-network discovery & analysis
 * ------------------------------------------------------------------------- */

interface WifiEngine : SentinelEngine {
    /** Passive scan. Gated by ConsentGate.observe(WIFI_SCAN). */
    suspend fun scan(): Result<List<WifiNetwork>>
    fun observeNetworks(): Flow<List<WifiNetwork>>
    fun recommendChannel(band: com.sentinelnet.core.model.Band): ChannelRecommendation
    suspend fun captivePortalCheck(): Boolean
}

interface BleEngine : SentinelEngine {
    fun observeDevices(): Flow<DiscoveredDevice>
    suspend fun exploreGatt(mac: String): Result<List<String>>
}

interface NfcEngine : SentinelEngine {
    fun tagTechs(): List<String>
    fun ndefSupported(): Boolean
}

interface CellularEngine : SentinelEngine {
    /** Non-sensitive fields ONLY. IMSI/IMEI are explicitly excluded. */
    data class CellInfo(
        val networkType: String, val operator: String?, val mccMnc: String?,
        val band: String?, val rsrp: Int?, val rsrq: Int?, val sinr: Int?,
        val pci: Int?, val tac: String?, val roaming: Boolean
    )
    fun observeCellInfo(): Flow<CellInfo>
}

interface WifiDirectEngine : SentinelEngine { fun observePeers(): Flow<DiscoveredDevice> }
interface EthernetEngine : SentinelEngine { fun interfaceList(): List<String> }

interface DeviceDiscoveryEngine : SentinelEngine {
    /** Consent-gated by DEVICE_DISCOVERY. */
    fun discover(subnetCidr: String, consent: ConsentRequest): Flow<DiscoveredDevice>
    suspend fun fingerprint(device: DiscoveredDevice): DiscoveredDevice
}

/* ---------------------------------------------------------------------------
 * MODULE B — port scanning & service fingerprinting
 * ------------------------------------------------------------------------- */

data class ScanConfig(
    val target: String,
    val ports: List<Int> = com.sentinelnet.core.domain.PortRisk.TOP_100,
    val concurrency: Int = 64,
    val connectTimeoutMs: Int = 700,
    val grabBanner: Boolean = true,
    val inspectTls: Boolean = true
)

interface PortScanEngine : SentinelEngine {
    /** Consent-gated by PORT_SCAN; emits partial results as they arrive. */
    fun scan(config: ScanConfig, consent: ConsentRequest): Flow<PortResult>
}

/* ---------------------------------------------------------------------------
 * MODULE C — packet capture & analysis
 * ------------------------------------------------------------------------- */

interface CaptureEngine : SentinelEngine {
    fun start(consent: ConsentRequest): Flow<String>       // status lines
    fun stop()
    fun isRunning(): Boolean
    fun exportPcap(): java.io.File?
}

/* ---------------------------------------------------------------------------
 * MODULE D — audit, firewall, threat intelligence
 * ------------------------------------------------------------------------- */

interface SecurityAuditEngine : SentinelEngine {
    suspend fun runFullAudit(): Result<SecurityScore>
    suspend fun networkAudit(): List<Finding>
    suspend fun deviceAudit(): List<Finding>
    suspend fun appAudit(): List<Finding>
}

interface FirewallEngine : SentinelEngine {
    override fun status(): EngineStatus
    fun blockedPackages(): Set<String>
}

/* ---------------------------------------------------------------------------
 * MODULES E-H — tools, crypto, automation, servers, messaging, device mgmt
 * ------------------------------------------------------------------------- */

interface NetworkToolsEngine : SentinelEngine {
    suspend fun ping(host: String, count: Int = 4): List<Long?>
    suspend fun dnsLookup(host: String): List<String>
    suspend fun httpHeaders(url: String): Map<String, String>
    suspend fun rdap(domain: String): String
}

interface CryptoEngine : SentinelEngine { /* pure-Kotlin implementation lives in :core:pure */ }
interface AutomationEngine : SentinelEngine { fun scripts(): List<String> }
interface ServerEngine : SentinelEngine { fun runningServers(): List<String> }
interface MessagingEngine : SentinelEngine { fun connectedPeers(): List<String> }
interface DeviceManagerEngine : SentinelEngine { fun installedPackages(): List<String> }

/** Honest placeholder used by engines not yet delivered in the foundation phase. */
abstract class PlannedEngine(
    override val id: String,
    override val displayName: String,
    override val requiredCapability: Capability,
    private val phase: String
) : SentinelEngine {
    override fun status(): EngineStatus =
        EngineStatus(false, Requirement.NOT_IMPLEMENTED, "Planned for $phase — see docs/ROADMAP.md")
}
