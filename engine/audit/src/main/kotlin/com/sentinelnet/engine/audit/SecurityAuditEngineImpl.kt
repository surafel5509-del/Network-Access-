package com.sentinelnet.engine.audit

import com.sentinelnet.core.consent.Capability
import com.sentinelnet.core.consent.ConsentGate
import com.sentinelnet.core.consent.ConsentRequests
import com.sentinelnet.core.consent.ConsentResult
import com.sentinelnet.core.domain.SecurityScorer
import com.sentinelnet.core.model.Finding
import com.sentinelnet.core.model.SecurityScore
import com.sentinelnet.core.model.WifiNetwork
import com.sentinelnet.engine.api.EngineStatus
import com.sentinelnet.engine.api.SecurityAuditEngine
import com.sentinelnet.engine.api.WifiEngine
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import javax.inject.Inject
import javax.inject.Singleton

/** Aggregates all passive auditors into a reproducible SecurityScore. */
@Singleton
class SecurityAuditEngineImpl @Inject constructor(
    private val deviceAuditor: AndroidDeviceAudit,
    private val networkAuditor: NetworkAudit,
    private val wifiEngine: WifiEngine,
    private val consentGate: ConsentGate
) : SecurityAuditEngine {

    override val id = "audit"
    override val displayName = "Security audit"
    override val requiredCapability = Capability.WIFI_SECURITY_AUDIT
    override fun status(): EngineStatus = EngineStatus.ok()

    override suspend fun runFullAudit(): Result<SecurityScore> = withContext(Dispatchers.Default) {
        try {
            val findings = networkAudit() + deviceAudit() + appAudit()
            Result.success(SecurityScorer.score(findings.distinctBy { it.id }, System.currentTimeMillis()))
        } catch (t: Throwable) { Result.failure(t) }
    }

    override suspend fun networkAudit(): List<Finding> = withContext(Dispatchers.IO) {
        val scan = consentGate.observe(ConsentRequests.passive(Capability.WIFI_SCAN)) {
            wifiEngineStatusNetworks()
        }
        val networks = when (scan) {
            is ConsentResult.Allowed -> scan.value
            is ConsentResult.Denied -> emptyList()
        }
        networkAuditor.audit(networks = networks)
    }

    /** Wi-Fi scan is suspend; the gate wraps a synchronous read of the last known results. */
    private fun wifiEngineStatusNetworks(): List<WifiNetwork> {
        // Cached results are refreshed by WifiViewModel; audits use the most recent observation.
        return lastKnownNetworks
    }

    @Volatile var lastKnownNetworks: List<WifiNetwork> = emptyList()
        private set

    suspend fun refreshWifiCache() {
        lastKnownNetworks = wifiEngine.scan().getOrDefault(emptyList())
    }

    override suspend fun deviceAudit(): List<Finding> = withContext(Dispatchers.IO) { deviceAuditor.audit() }

    override suspend fun appAudit(): List<Finding> = withContext(Dispatchers.IO) {
        // Phase 3 adds the per-app permission matrix / tracker signature scan.
        // Returning an explicit informational finding is honest about the gap.
        listOf(
            Finding(
                id = "apps.matrix_pending",
                title = "Per-app permission matrix not yet collected",
                detail = "The foundation build deliberately does not request QUERY_ALL_PACKAGES. " +
                    "The app permission matrix (Module D3) is scheduled for Phase 3.",
                severity = com.sentinelnet.core.model.Severity.INFO,
                category = com.sentinelnet.core.model.ScoreCategory.APPS,
                remediation = "Enable the optional app audit in a later build; review permissions in Android Settings meanwhile."
            )
        )
    }
}
