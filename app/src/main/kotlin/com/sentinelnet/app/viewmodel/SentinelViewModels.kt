package com.sentinelnet.app.viewmodel

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.sentinelnet.core.android.data.SentinelDatabase
import com.sentinelnet.core.android.di.ConsentRepository
import com.sentinelnet.core.android.security.SecureFileStorage
import com.sentinelnet.core.consent.AuditLog
import com.sentinelnet.core.consent.Capability
import com.sentinelnet.core.consent.ConsentDecision
import com.sentinelnet.core.consent.ConsentGate
import com.sentinelnet.core.consent.ConsentPolicy
import com.sentinelnet.core.consent.ConsentRequest
import com.sentinelnet.core.crypto.WpaPskLab
import com.sentinelnet.core.domain.CveHintMatcher
import com.sentinelnet.core.domain.PortRisk
import com.sentinelnet.core.domain.WifiSecurityAuditor
import com.sentinelnet.core.model.AuditEvent
import com.sentinelnet.core.model.Band
import com.sentinelnet.core.model.ChannelRecommendation
import com.sentinelnet.core.model.DiscoveredDevice
import com.sentinelnet.core.model.Finding
import com.sentinelnet.core.model.PortResult
import com.sentinelnet.core.model.SecurityScore
import com.sentinelnet.core.model.WifiNetwork
import com.sentinelnet.core.reporting.ReportBuilder
import com.sentinelnet.engine.api.BleEngine
import com.sentinelnet.engine.api.CaptureEngine
import com.sentinelnet.engine.api.DeviceDiscoveryEngine
import com.sentinelnet.engine.api.EngineStatus
import com.sentinelnet.engine.api.FirewallEngine
import com.sentinelnet.engine.api.PortScanEngine
import com.sentinelnet.engine.api.ScanConfig
import com.sentinelnet.engine.api.SecurityAuditEngine
import com.sentinelnet.engine.api.ServerEngine
import com.sentinelnet.engine.api.WifiEngine
import com.sentinelnet.engine.audit.SecurityLabController
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.catch
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import javax.inject.Inject

private const val SESSION = "ui-session"
private const val ACTOR = "local-user"

@HiltViewModel
class OnboardingViewModel @Inject constructor(
    private val repository: ConsentRepository
) : ViewModel() {
    fun accept(onDone: () -> Unit) = viewModelScope.launch {
        repository.acceptLegalNotice(ConsentPolicy.CURRENT_NOTICE_VERSION)
        onDone()
    }
}

/* ------------------------------------------------------------------ Dashboard */

data class DashboardState(
    val policy: ConsentPolicy = ConsentPolicy(),
    val score: SecurityScore? = null,
    val networks: List<WifiNetwork> = emptyList(),
    val alerts: List<Finding> = emptyList(),
    val modules: List<Pair<String, EngineStatus>> = emptyList(),
    val loading: Boolean = false,
    val message: String? = null
)

@HiltViewModel
class DashboardViewModel @Inject constructor(
    private val wifiEngine: WifiEngine,
    private val auditEngine: SecurityAuditEngine,
    private val portScanner: PortScanEngine,
    private val captureEngine: CaptureEngine,
    private val serverEngine: ServerEngine,
    private val firewallEngine: FirewallEngine,
    private val bleEngine: BleEngine,
    private val repository: ConsentRepository
) : ViewModel() {
    private val _state = MutableStateFlow(DashboardState())
    val state: StateFlow<DashboardState> = _state.asStateFlow()

    init {
        _state.update { it.copy(modules = listOf(
            wifiEngine.displayName to wifiEngine.status(),
            portScanner.displayName to portScanner.status(),
            captureEngine.displayName to captureEngine.status(),
            serverEngine.displayName to serverEngine.status(),
            firewallEngine.displayName to firewallEngine.status(),
            bleEngine.displayName to bleEngine.status()
        )) }
        viewModelScope.launch {
            repository.policyFlow.collect { policy -> _state.update { it.copy(policy = policy) } }
        }
        refresh()
    }

    fun refresh() {
        viewModelScope.launch {
            _state.update { it.copy(loading = true) }
            val networks = wifiEngine.scan().getOrDefault(emptyList())
            val score = auditEngine.runFullAudit().getOrNull()
            _state.update {
                it.copy(
                    networks = networks, score = score,
                    alerts = score?.findings?.take(5).orEmpty(),
                    loading = false
                )
            }
        }
    }

    fun message(text: String) = _state.update { it.copy(message = text) }
    fun clearMessage() = _state.update { it.copy(message = null) }
}

/* ------------------------------------------------------------------ Wi-Fi */

data class WifiState(
    val networks: List<WifiNetwork> = emptyList(),
    val findings: List<Finding> = emptyList(),
    val recommendation: ChannelRecommendation? = null,
    val band: Band = Band.GHZ_2_4,
    val loading: Boolean = false,
    val error: String? = null
)

@HiltViewModel
class WifiViewModel @Inject constructor(
    private val wifiEngine: WifiEngine,
    private val auditor: WifiSecurityAuditor
) : ViewModel() {
    private val _state = MutableStateFlow(WifiState())
    val state: StateFlow<WifiState> = _state.asStateFlow()

    fun scan() {
        viewModelScope.launch {
            _state.update { it.copy(loading = true, error = null) }
            wifiEngine.scan()
                .onSuccess { networks ->
                    _state.update { it.copy(networks = networks,
                        findings = auditor.audit(networks), loading = false) }
                }
                .onFailure { e -> _state.update { it.copy(error = e.message, loading = false) } }
        }
    }

    fun selectBand(band: Band) {
        _state.update { it.copy(band = band) }
        recommend(band)
    }

    private fun recommend(band: Band) {
        viewModelScope.launch {
            val rec = withContext(Dispatchers.Default) { wifiEngine.recommendChannel(band) }
            _state.update { it.copy(recommendation = rec) }
        }
    }
}

/* ------------------------------------------------------------------ Scanner */

data class ScannerState(
    val target: String = "192.168.1.1",
    val preset: String = "Top 100",
    val ports: List<PortResult> = emptyList(),
    val hints: List<Finding> = emptyList(),
    val devices: List<DiscoveredDevice> = emptyList(),
    val running: Boolean = false,
    val error: String? = null
)

@HiltViewModel
class ScannerViewModel @Inject constructor(
    private val portScanner: PortScanEngine,
    private val discovery: DeviceDiscoveryEngine,
    private val hintMatcher: CveHintMatcher
) : ViewModel() {
    private val _state = MutableStateFlow(ScannerState())
    val state: StateFlow<ScannerState> = _state.asStateFlow()

    val presets = mapOf(
        "Top 100" to PortRisk.TOP_100,
        "Web + admin" to listOf(80, 443, 8080, 8443, 22, 3389, 5900),
        "Common IoT" to listOf(21, 22, 23, 53, 80, 443, 445, 1883, 1900, 5353, 8080, 9200),
        "Single port" to listOf(80)
    )

    fun setTarget(value: String) = _state.update { it.copy(target = value) }
    fun setPreset(name: String) = _state.update { it.copy(preset = name) }

    /** The nonce is created by the UI and shared with the ConsentDialog. */
    fun startPortScan(nonce: String, decision: ConsentDecision) {
        val s = _state.value
        val config = ScanConfig(s.target, presets[s.preset].orEmpty(), concurrency = 64)
        val request = ConsentRequest(Capability.PORT_SCAN, nonce, s.target, ACTOR, SESSION, decision)
        _state.update { it.copy(running = true, ports = emptyList(), hints = emptyList(), error = null) }
        viewModelScope.launch {
            portScanner.scan(config, request)
                .catch { e -> _state.update { it.copy(error = e.message, running = false) } }
                .collect { result ->
                    _state.update {
                        val all = it.ports + result
                        it.copy(ports = all, hints = all.flatMap { r ->
                            hintMatcher.match(r.service, r.version, r.banner, r.target)
                        }.distinctBy { f -> f.id })
                    }
                }
            _state.update { it.copy(running = false) }
        }
    }

    fun startDiscovery(nonce: String, decision: ConsentDecision, cidr: String = "192.168.1.0/24") {
        val request = ConsentRequest(Capability.DEVICE_DISCOVERY, nonce, cidr, ACTOR, SESSION, decision)
        _state.update { it.copy(running = true, devices = emptyList(), error = null) }
        viewModelScope.launch {
            discovery.discover(cidr, request)
                .catch { e -> _state.update { it.copy(error = e.message, running = false) } }
                .collect { device -> _state.update { it.copy(devices = (it.devices + device).distinctBy { d -> d.ip }) } }
            _state.update { it.copy(running = false) }
        }
    }
}

/* ------------------------------------------------------------------ Audit */

data class AuditState(
    val score: SecurityScore? = null,
    val auditTrail: List<AuditEvent> = emptyList(),
    val loading: Boolean = false
)

@HiltViewModel
class AuditViewModel @Inject constructor(
    private val auditEngine: SecurityAuditEngine,
    private val auditLog: AuditLog,
    private val database: SentinelDatabase
) : ViewModel() {
    private val _state = MutableStateFlow(AuditState())
    val state: StateFlow<AuditState> = _state.asStateFlow()

    fun runAudit() {
        viewModelScope.launch {
            _state.update { it.copy(loading = true) }
            auditEngine.runFullAudit().onSuccess { score ->
                withContext(Dispatchers.IO) {
                    database.scoreDao().insert(
                        com.sentinelnet.core.android.data.ScoreHistoryEntity(
                            overall = score.overall, fingerprint = score.inputFingerprint,
                            computedAtMillis = score.computedAtMillis
                        )
                    )
                }
                _state.update { it.copy(score = score, loading = false) }
            }.onFailure { _state.update { it.copy(loading = false) } }
            _state.update { it.copy(auditTrail = auditLog.all().takeLast(50)) }
        }
    }

    fun refreshTrail() = viewModelScope.launch {
        _state.update { it.copy(auditTrail = auditLog.all().takeLast(50)) }
    }
}

/* ------------------------------------------------------------------ Security Lab */

data class LabState(
    val sample: WpaPskLab.HandshakeSample? = null,
    val result: WpaPskLab.LabExercise? = null,
    val verdict: com.sentinelnet.core.crypto.PassphraseAudit.Verdict? = null,
    val lesson: String = "",
    val error: String? = null
)

@HiltViewModel
class SecurityLabViewModel @Inject constructor(
    private val controller: SecurityLabController
) : ViewModel() {
    private val _state = MutableStateFlow(LabState())
    val state: StateFlow<LabState> = _state.asStateFlow()

    fun syntheticLesson(ssid: String = "SentinelLab", passphrase: String = "password123") {
        _state.update {
            it.copy(sample = controller.syntheticLesson(ssid, passphrase),
                lesson = "Synthetic handshake for '$ssid'. The passphrase above is deliberately weak " +
                    "so the offline exercise can find it. Try a 5-word passphrase next and watch it fail.",
                result = null, error = null)
        }
    }

    fun importHandshake(text: String) {
        val sample = controller.importHandshake(text)
        _state.update { it.copy(sample = sample, error = if (sample == null) "Could not parse handshake file" else null,
            lesson = if (sample != null) "Imported a handshake from your file. No live capture occurred." else "") }
    }

    fun auditOwnPassphrase(value: String) {
        _state.update { it.copy(verdict = controller.auditOwnPassphrase(value)) }
    }

    fun runExercise(wordlist: List<String>, nonce: String, decision: ConsentDecision) {
        val sample = _state.value.sample ?: return
        val request = ConsentRequest(Capability.SECURITY_LAB, nonce, "local-synthetic", ACTOR, SESSION, decision)
        viewModelScope.launch {
            controller.runExercise(sample, wordlist, request)
                .onSuccess { exercise ->
                    _state.update {
                        it.copy(result = exercise, error = null,
                            lesson = if (exercise.found != null)
                                "Found '${exercise.found}' after ${exercise.tested} guesses in ${exercise.elapsedMs} ms. " +
                                    "That is exactly why WPA3-SAE and long random passphrases matter."
                            else "No match in ${exercise.tested} guesses (${exercise.elapsedMs} ms). " +
                                    "A strong passphrase makes offline guessing impractical.")
                    }
                }
                .onFailure { e -> _state.update { it.copy(error = e.message) } }
        }
    }
}

/* ------------------------------------------------------------------ Settings / Reports */

data class SettingsState(
    val safeMode: Boolean = true,
    val online: Boolean = false,
    val highContrast: Boolean = false,
    val amoled: Boolean = false,
    val noticeVersion: Int = ConsentPolicy.CURRENT_NOTICE_VERSION
)

@HiltViewModel
class SettingsViewModel @Inject constructor(
    private val repository: ConsentRepository,
    private val consentGate: ConsentGate,
    private val auditLog: AuditLog,
    private val storage: SecureFileStorage,
    private val database: SentinelDatabase
) : ViewModel() {
    private val _state = MutableStateFlow(SettingsState())
    val state: StateFlow<SettingsState> = _state.asStateFlow()

    init {
        viewModelScope.launch {
            repository.policyFlow.collect { p -> _state.update { it.copy(safeMode = p.safeMode) } }
        }
        viewModelScope.launch {
            repository.onlineFeatures().collect { on -> _state.update { it.copy(online = on) } }
        }
        viewModelScope.launch {
            repository.highContrast().collect { hc -> _state.update { it.copy(highContrast = hc) } }
        }
    }

    fun setSafeMode(enabled: Boolean) = viewModelScope.launch { repository.setSafeMode(enabled) }
    fun setOnline(enabled: Boolean) = viewModelScope.launch { repository.setOnlineFeatures(enabled) }
    fun setHighContrast(enabled: Boolean) = viewModelScope.launch { repository.setHighContrast(enabled) }
    fun setAmoled(enabled: Boolean) = _state.update { it.copy(amoled = enabled) }

    fun exportAuditLog(): String = ReportBuilder.auditLogReport(auditLog.all())

    fun deleteAllData() = viewModelScope.launch(Dispatchers.IO) {
        auditLog.clear()
        database.clearAllTables()
        storage.deleteAllExports()
    }
}

@HiltViewModel
class ReportsViewModel @Inject constructor(
    private val auditLog: AuditLog,
    private val storage: SecureFileStorage
) : ViewModel() {
    private val _state = MutableStateFlow("")
    val state: StateFlow<String> = _state.asStateFlow()

    fun exportWifiCsv(networks: List<WifiNetwork>) = write("wifi-scan.csv", ReportBuilder.networksCsv(networks))
    fun exportAuditLog() = write("audit-log.json", ReportBuilder.auditLogReport(auditLog.all()))

    private fun write(name: String, content: String) = viewModelScope.launch(Dispatchers.IO) {
        try {
            storage.create(name).openFileOutput().use { it.write(content.toByteArray(Charsets.UTF_8)) }
            _state.value = "Saved encrypted export: $name"
        } catch (t: Throwable) { _state.value = "Export failed: ${t.message}" }
    }
}
