package com.sentinelnet.app.ui.screens

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.AssistChip
import androidx.compose.material3.AssistChipDefaults
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.FilterChip
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.sentinelnet.app.R
import com.sentinelnet.app.ui.components.ConsentDialog
import com.sentinelnet.app.viewmodel.AuditViewModel
import com.sentinelnet.app.viewmodel.DashboardViewModel
import com.sentinelnet.app.viewmodel.OnboardingViewModel
import com.sentinelnet.app.viewmodel.ReportsViewModel
import com.sentinelnet.app.viewmodel.ScannerViewModel
import com.sentinelnet.app.viewmodel.SecurityLabViewModel
import com.sentinelnet.app.viewmodel.SettingsViewModel
import com.sentinelnet.app.viewmodel.WifiViewModel
import com.sentinelnet.core.android.ui.KeyValueRow
import com.sentinelnet.core.android.ui.ScoreGauge
import com.sentinelnet.core.android.ui.SectionCard
import com.sentinelnet.core.android.ui.SentinelAmber
import com.sentinelnet.core.android.ui.SentinelBlue
import com.sentinelnet.core.android.ui.SentinelGreen
import com.sentinelnet.core.android.ui.SentinelRed
import com.sentinelnet.core.android.ui.SeverityChip
import com.sentinelnet.core.android.ui.SignalGraph
import com.sentinelnet.core.consent.Capability
import com.sentinelnet.core.consent.ConsentDecision
import com.sentinelnet.core.consent.ConsentPolicy
import com.sentinelnet.core.consent.ConsentRequests
import com.sentinelnet.core.model.Band
import com.sentinelnet.engine.api.EngineStatus
import com.sentinelnet.engine.api.Requirement

/* --------------------------------------------------------------- Onboarding */

@Composable
fun OnboardingScreen(vm: OnboardingViewModel = hiltViewModel(), onFinished: () -> Unit) {
    var checked by remember { mutableStateOf(false) }
    val scope = androidx.compose.runtime.rememberCoroutineScope()
    Column(
        Modifier.fillMaxSize().padding(24.dp),
        verticalArrangement = Arrangement.Center
    ) {
        Text(stringResource(R.string.app_name), style = MaterialTheme.typography.headlineMedium,
            color = SentinelGreen, fontWeight = FontWeight.Bold)
        Text(stringResource(R.string.app_tagline), style = MaterialTheme.typography.bodyMedium)
        Spacer(Modifier.height(24.dp))
        Text(stringResource(R.string.legal_notice_title), style = MaterialTheme.typography.titleMedium)
        Spacer(Modifier.height(8.dp))
        Text(stringResource(R.string.legal_notice_body), style = MaterialTheme.typography.bodyMedium)
        Spacer(Modifier.height(16.dp))
        Row(verticalAlignment = Alignment.CenterVertically) {
            Switch(checked = checked, onCheckedChange = { checked = it },
                modifier = Modifier.semantics { contentDescription = "Accept legal notice switch" })
            Spacer(Modifier.padding(8.dp))
            Text(stringResource(R.string.consent_authorised_only), style = MaterialTheme.typography.bodyMedium)
        }
        Spacer(Modifier.height(24.dp))
        Button(
            enabled = checked,
            onClick = { vm.accept(onFinished) },
            modifier = Modifier.fillMaxWidth()
        ) { Text(stringResource(R.string.accept_continue)) }
        Spacer(Modifier.height(12.dp))
        Text(stringResource(R.string.safe_mode_desc), style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.6f))
    }
}

/* --------------------------------------------------------------- Dashboard */

@Composable
fun DashboardScreen(vm: DashboardViewModel = hiltViewModel(), onNavigate: (String) -> Unit) {
    val state by vm.state.collectAsStateWithLifecycle()
    ScreenList {
        item {
            SectionCard(stringResource(R.string.security_score)) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Box(contentAlignment = Alignment.Center) {
                        ScoreGauge(state.score?.overall ?: 0)
                        Text("${state.score?.overall ?: 0}", style = MaterialTheme.typography.headlineMedium)
                    }
                    Spacer(Modifier.padding(12.dp))
                    Column {
                        Text("Grade ${state.score?.grade ?: "—"}", style = MaterialTheme.typography.titleMedium)
                        Text("${state.alerts.size} recent alerts", style = MaterialTheme.typography.bodyMedium)
                        Text(if (state.policy.safeMode) "Safe Mode ON" else "Safe Mode OFF",
                            color = if (state.policy.safeMode) SentinelGreen else SentinelAmber,
                            style = MaterialTheme.typography.bodyMedium)
                    }
                }
            }
        }
        item {
            SectionCard(stringResource(R.string.quick_actions)) {
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    Button(onClick = { vm.refresh() }) { Text(stringResource(R.string.run_scan)) }
                    OutlinedButton(onClick = { onNavigate("audit") }) { Text(stringResource(R.string.run_audit)) }
                }
                Spacer(Modifier.height(6.dp))
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    OutlinedButton(onClick = { onNavigate("lab") }) { Text("Security Lab") }
                    OutlinedButton(onClick = { onNavigate("reports") }) { Text("Reports") }
                }
                if (state.loading) LinearProgressIndicator(Modifier.fillMaxWidth().padding(top = 8.dp))
                state.message?.let { Text(it, color = SentinelAmber) }
            }
        }
        item {
            SectionCard(stringResource(R.string.recent_alerts)) {
                if (state.alerts.isEmpty()) Text(stringResource(R.string.empty_results))
                else state.alerts.forEach { f ->
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        SeverityChip(f.severity)
                        Spacer(Modifier.padding(6.dp))
                        Text(f.title, style = MaterialTheme.typography.bodyMedium)
                    }
                }
            }
        }
        item {
            SectionCard(stringResource(R.string.active_engines), "Planned modules are shown honestly as unavailable") {
                state.modules.forEach { (name, status) ->
                    Row(verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.SpaceBetween,
                        modifier = Modifier.fillMaxWidth()) {
                        Text(name, style = MaterialTheme.typography.bodyMedium)
                        RequirementChip(status)
                    }
                }
            }
        }
        item {
            SectionCard("Wi-Fi signal (last scan)") {
                SignalGraph(state.networks.map { it.rssiDbm })
                Text("${state.networks.size} networks observed", style = MaterialTheme.typography.bodyMedium)
            }
        }
    }
}

@Composable
fun RequirementChip(status: EngineStatus) {
    val (label, color) = when (status.requirement) {
        Requirement.NONE -> "Ready" to SentinelGreen
        Requirement.PERMISSION -> "Permission" to SentinelAmber
        Requirement.BIOMETRIC -> "Biometric" to SentinelBlue
        Requirement.ROOT -> "Root" to SentinelRed
        Requirement.SHIZUKU -> "Shizuku" to SentinelBlue
        Requirement.HARDWARE -> "Hardware" to SentinelRed
        Requirement.CONSENT -> "Consent" to SentinelAmber
        Requirement.NOT_IMPLEMENTED -> "Planned" to Color.Gray
    }
    AssistChip(onClick = { }, label = { Text(label, style = MaterialTheme.typography.labelSmall) },
        colors = AssistChipDefaults.assistChipColors(labelColor = color))
}

/* --------------------------------------------------------------- Wi-Fi */

@Composable
fun WifiScreen(vm: WifiViewModel = hiltViewModel()) {
    val state by vm.state.collectAsStateWithLifecycle()
    ScreenList {
        item {
            SectionCard("Wi-Fi scanner", "Passive scan — no frames are transmitted") {
                Button(onClick = { vm.scan() }) { Text(stringResource(R.string.run_scan)) }
                if (state.loading) LinearProgressIndicator(Modifier.fillMaxWidth().padding(top = 8.dp))
                state.error?.let { Text(it, color = MaterialTheme.colorScheme.error) }
                SignalGraph(state.networks.map { it.rssiDbm })
            }
        }
        item {
            SectionCard("Best channel") {
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    Band.entries.filter { it != Band.UNKNOWN }.forEach { band ->
                        FilterChip(selected = state.band == band,
                            onClick = { vm.selectBand(band) }, label = { Text(band.label) })
                    }
                }
                state.recommendation?.let { r ->
                    KeyValueRow("Recommended channel", "${r.channel} (${r.frequencyMhz} MHz)")
                    KeyValueRow("Score", "%.1f / 100".format(r.score))
                    Text(r.reason, style = MaterialTheme.typography.bodyMedium)
                }
            }
        }
        item {
            SectionCard("Networks (${state.networks.size})") {
                if (state.networks.isEmpty()) Text(stringResource(R.string.empty_results))
            }
        }
        items(state.networks) { n ->
            SectionCard(n.ssid, "${n.bssid} · ${n.security} · ${n.band.label}") {
                KeyValueRow("RSSI", "${n.rssiDbm} dBm")
                KeyValueRow("Channel", "${n.channel} @ ${n.frequencyMhz} MHz")
                KeyValueRow("Standard", n.standard.name)
                KeyValueRow("Vendor", n.vendor ?: "Randomized / unknown")
                if (n.wpsEnabled) Text("WPS enabled", color = SentinelRed)
                if (n.isHidden) Text("Hidden SSID", color = SentinelAmber)
            }
        }
        item {
            SectionCard("Security findings (${state.findings.size})") {
                state.findings.forEach { f ->
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        SeverityChip(f.severity)
                        Spacer(Modifier.padding(6.dp))
                        Column { Text(f.title); Text(f.remediation, style = MaterialTheme.typography.bodyMedium) }
                    }
                }
            }
        }
    }
}

/* --------------------------------------------------------------- Scanner */

@Composable
fun ScannerScreen(vm: ScannerViewModel = hiltViewModel()) {
    val state by vm.state.collectAsStateWithLifecycle()
    var pending by remember { mutableStateOf<Pair<String, String>?>(null) } // nonce to (target|kind)
    ScreenList {
        item {
            SectionCard("Port scanner", "TCP Connect (no root). Consent + audit log required.") {
                OutlinedTextField(value = state.target, onValueChange = { vm.setTarget(it) },
                    label = { Text("Target IP or hostname") }, singleLine = true,
                    modifier = Modifier.fillMaxWidth())
                Row(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                    vm.presets.keys.forEach { name ->
                        FilterChip(selected = state.preset == name, onClick = { vm.setPreset(name) },
                            label = { Text(name, style = MaterialTheme.typography.labelSmall) })
                    }
                }
                Spacer(Modifier.height(8.dp))
                Button(onClick = { pending = ConsentRequests.newNonce() to "port" },
                    enabled = !state.running) { Text(stringResource(R.string.start_port_scan)) }
                Button(onClick = { pending = ConsentRequests.newNonce() to "discover" },
                    enabled = !state.running) { Text("Discover devices (/24)") }
                if (state.running) CircularProgressIndicator(Modifier.padding(top = 8.dp))
                state.error?.let { Text(stringResource(R.string.scan_denied) + ": $it", color = MaterialTheme.colorScheme.error) }
            }
        }
        item {
            SectionCard("Open ports (${state.ports.count { it.state == com.sentinelnet.core.model.PortState.OPEN }})") {
                if (state.ports.isEmpty()) Text(stringResource(R.string.empty_results))
                state.ports.filter { it.state == com.sentinelnet.core.model.PortState.OPEN }.forEach { p ->
                    Column(Modifier.padding(vertical = 4.dp)) {
                        Text("${p.port}/${p.protocol}  ${p.service ?: "unknown"}  ${p.version ?: ""}",
                            fontWeight = FontWeight.SemiBold)
                        p.banner?.let { Text(it.take(160), style = MaterialTheme.typography.bodyMedium) }
                        p.tlsSubject?.let { Text("TLS: ${it.take(120)}", style = MaterialTheme.typography.bodyMedium) }
                    }
                }
            }
        }
        item {
            SectionCard("CVE hints (passive only)") {
                state.hints.forEach { h ->
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        SeverityChip(h.severity); Spacer(Modifier.padding(6.dp)); Text(h.title)
                    }
                }
                if (state.hints.isEmpty()) Text("No version-string hints yet.")
            }
        }
        item {
            SectionCard("Discovered devices (${state.devices.size})") {
                state.devices.forEach { d -> KeyValueRow(d.ip, d.hostname ?: d.vendor ?: d.deviceType.name) }
            }
        }
    }

    pending?.let { (nonce, kind) ->
        val capability = if (kind == "port") Capability.PORT_SCAN else Capability.DEVICE_DISCOVERY
        val target = if (kind == "port") state.target else "192.168.1.0/24"
        ConsentDialog(capability = capability, target = target, nonce = nonce,
            onDismiss = { pending = null },
            onDecision = { decision: ConsentDecision ->
                if (kind == "port") vm.startPortScan(nonce, decision) else vm.startDiscovery(nonce, decision)
                pending = null
            })
    }
}

/* --------------------------------------------------------------- Audit */

@Composable
fun AuditScreen(vm: AuditViewModel = hiltViewModel()) {
    val state by vm.state.collectAsStateWithLifecycle()
    ScreenList {
        item {
            SectionCard("Full security audit") {
                Button(onClick = { vm.runAudit() }) { Text(stringResource(R.string.run_audit)) }
                if (state.loading) LinearProgressIndicator(Modifier.fillMaxWidth().padding(top = 8.dp))
                state.score?.let { s ->
                    KeyValueRow("Overall", "${s.overall} / 100 (${s.grade})")
                    KeyValueRow("Fingerprint", s.inputFingerprint)
                }
            }
        }
        item {
            SectionCard("Category breakdown") {
                state.score?.categories?.forEach { c ->
                    Column(Modifier.padding(vertical = 4.dp)) {
                        KeyValueRow(c.category.displayName, "${c.rawScore}/100")
                        LinearProgressIndicator(progress = { c.rawScore / 100f }, modifier = Modifier.fillMaxWidth())
                    }
                }
            }
        }
        item {
            SectionCard("Prioritised remediation") {
                state.score?.findings?.forEach { f ->
                    Row { SeverityChip(f.severity); Spacer(Modifier.padding(6.dp)); Text(f.remediation) }
                }
            }
        }
        item {
            SectionCard("Audit trail (${state.auditTrail.size})", "Every action — allowed or denied") {
                Button(onClick = { vm.refreshTrail() }) { Text("Refresh") }
                state.auditTrail.takeLast(20).forEach { e ->
                    Text("${e.sequence} · ${e.decision} · ${e.capability} · ${e.target}",
                        style = MaterialTheme.typography.bodyMedium)
                }
            }
        }
    }
}

/* --------------------------------------------------------------- Security Lab */

@Composable
fun SecurityLabScreen(vm: SecurityLabViewModel = hiltViewModel()) {
    val state by vm.state.collectAsStateWithLifecycle()
    var passphrase by remember { mutableStateOf("") }
    var wordlistText by remember { mutableStateOf("password\npassword123\nadmin\nletmein\nwifipassword") }
    var pendingNonce by remember { mutableStateOf<String?>(null) }
    ScreenList {
        item {
            SectionCard(stringResource(R.string.lab_title), stringResource(R.string.lab_disclaimer)) {
                Text(stringResource(R.string.lab_intro), style = MaterialTheme.typography.bodyMedium)
                Spacer(Modifier.height(10.dp))
                Button(onClick = { vm.syntheticLesson() }) { Text(stringResource(R.string.lab_synthetic)) }
                state.sample?.let {
                    KeyValueRow("SSID", it.ssid)
                    KeyValueRow("Handshake", if (it.synthetic) "Synthetic (generated on-device)" else "Imported by you")
                    KeyValueRow("KDV", it.keyDescriptorVersion.toString())
                }
                state.lesson.let { if (it.isNotBlank()) Text(it, style = MaterialTheme.typography.bodyMedium,
                    color = SentinelBlue, modifier = Modifier.padding(top = 8.dp)) }
            }
        }
        item {
            SectionCard("Check YOUR OWN passphrase", "Never transmitted or stored") {
                OutlinedTextField(value = passphrase, onValueChange = {
                    passphrase = it; vm.auditOwnPassphrase(it)
                }, label = { Text(stringResource(R.string.lab_passphrase_hint)) },
                    modifier = Modifier.fillMaxWidth(), singleLine = true)
                state.verdict?.let { v ->
                    KeyValueRow("Rating", v.rating)
                    KeyValueRow("Estimated entropy", "%.1f bits".format(v.entropyBits))
                    v.issues.forEach { Text("• $it", style = MaterialTheme.typography.bodyMedium) }
                    v.recommendations.take(2).forEach { Text("→ $it", style = MaterialTheme.typography.bodyMedium) }
                }
            }
        }
        item {
            SectionCard("Offline dictionary exercise", "Your own wordlist · your own handshake · capped at 200k/30s") {
                OutlinedTextField(value = wordlistText, onValueChange = { wordlistText = it },
                    label = { Text("Candidate passphrases (one per line)") },
                    modifier = Modifier.fillMaxWidth(), minLines = 3)
                Spacer(Modifier.height(8.dp))
                Button(
                    enabled = state.sample != null,
                    onClick = { pendingNonce = ConsentRequests.newNonce() }
                ) { Text(stringResource(R.string.lab_run)) }
                state.result?.let { r ->
                    KeyValueRow("Tested", "${r.tested}")
                    KeyValueRow("Elapsed", "${r.elapsedMs} ms")
                    KeyValueRow("Found", r.found ?: "no match")
                    if (r.capped) Text("Exercise hit the safety cap.", color = SentinelAmber)
                }
                state.error?.let { Text(it, color = MaterialTheme.colorScheme.error) }
            }
        }
        item {
            SectionCard("Why WPA3-SAE is different") {
                Text("WPA/WPA2 derive the PMK with PBKDF2-HMAC-SHA1(passphrase, SSID, 4096). " +
                    "An attacker with one captured handshake can test guesses offline. " +
                    "WPA3's SAE handshake has no offline-guessable transcript: each guess " +
                    "requires a fresh interaction with the AP, and it provides forward secrecy. " +
                    "Use WPA3 with a 16+ character random passphrase and disable WPS PIN.",
                    style = MaterialTheme.typography.bodyMedium)
            }
        }
    }
    pendingNonce?.let { nonce ->
        ConsentDialog(capability = Capability.SECURITY_LAB, target = "local-synthetic", nonce = nonce,
            onDismiss = { pendingNonce = null },
            onDecision = { decision ->
                vm.runExercise(wordlistText.lines().map { it.trim() }.filter { it.isNotEmpty() }, nonce, decision)
                pendingNonce = null
            })
    }
}

/* --------------------------------------------------------------- Reports / Settings */

@Composable
fun ReportsScreen(vm: ReportsViewModel = hiltViewModel(), dashboard: DashboardViewModel = hiltViewModel()) {
    val state by vm.state.collectAsStateWithLifecycle()
    val dash by dashboard.state.collectAsStateWithLifecycle()
    ScreenList {
        item {
            SectionCard("Export", "Files are stored with EncryptedFile (AES-256-GCM)") {
                Button(onClick = { vm.exportWifiCsv(dash.networks) }) { Text("Wi-Fi scan CSV") }
                OutlinedButton(onClick = { vm.exportAuditLog() }) { Text(stringResource(R.string.export_audit_log)) }
                if (state.isNotBlank()) Text(state, color = SentinelGreen)
            }
        }
        item {
            SectionCard("Sample report schema") {
                Text("All exports use sentinelnet.report/1. JSON reports include a SHA-256 " +
                    "chain-of-custody hash; the same findings always produce the same hash.",
                    style = MaterialTheme.typography.bodyMedium)
            }
        }
    }
}

@Composable
fun SettingsScreen(vm: SettingsViewModel = hiltViewModel()) {
    val state by vm.state.collectAsStateWithLifecycle()
    ScreenList {
        item {
            SectionCard(stringResource(R.string.safe_mode), stringResource(R.string.safe_mode_desc)) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Switch(checked = state.safeMode, onCheckedChange = { vm.setSafeMode(it) })
                    Spacer(Modifier.padding(8.dp))
                    Text(if (state.safeMode) "ON — invasive features blocked" else "OFF — consent required per action")
                }
            }
        }
        item {
            SectionCard("Appearance & accessibility") {
                SettingToggle(stringResource(R.string.high_contrast), state.highContrast) { vm.setHighContrast(it) }
                SettingToggle(stringResource(R.string.amoled), state.amoled) { vm.setAmoled(it) }
            }
        }
        item {
            SectionCard("Online features") {
                SettingToggle(stringResource(R.string.online_features), state.online) { vm.setOnline(it) }
                Text("Disabled by default. When enabled, RDAP/CVE lookups are still audited and rate-limited.",
                    style = MaterialTheme.typography.bodyMedium)
            }
        }
        item {
            SectionCard("Privacy") {
                Text("No IMSI, IMEI, serial number, advertising ID or analytics are collected. " +
                    "Everything is stored locally in a SQLCipher database.",
                    style = MaterialTheme.typography.bodyMedium)
                OutlinedButton(onClick = { vm.deleteAllData() }) { Text(stringResource(R.string.delete_all_data)) }
            }
        }
    }
}

@Composable
private fun SettingToggle(label: String, value: Boolean, onChange: (Boolean) -> Unit) {
    Row(verticalAlignment = Alignment.CenterVertically, modifier = Modifier.fillMaxWidth().padding(vertical = 4.dp)) {
        Text(label, modifier = Modifier.weight(1f), style = MaterialTheme.typography.bodyMedium)
        Switch(checked = value, onCheckedChange = onChange)
    }
}

/* --------------------------------------------------------------- Shared layout */

@Composable
fun ScreenList(content: androidx.compose.foundation.lazy.LazyListScope.() -> Unit) {
    LazyColumn(
        modifier = Modifier.fillMaxSize(),
        contentPadding = PaddingValues(12.dp),
        verticalArrangement = Arrangement.spacedBy(4.dp),
        content = content
    )
}
