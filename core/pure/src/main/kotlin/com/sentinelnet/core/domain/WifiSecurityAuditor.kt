package com.sentinelnet.core.domain

import com.sentinelnet.core.model.Finding
import com.sentinelnet.core.model.ScoreCategory
import com.sentinelnet.core.model.Severity
import com.sentinelnet.core.model.WifiNetwork
import com.sentinelnet.core.model.WifiSecurity

/** Passive Wi-Fi configuration audit + evil-twin heuristics. No frames are injected. */
class WifiSecurityAuditor(private val oui: OuiLookup = OuiLookup()) {

    fun audit(networks: List<WifiNetwork>, nowMillis: Long = 0L): List<Finding> {
        val findings = mutableListOf<Finding>()
        for (n in networks) findings += auditOne(n, nowMillis)
        findings += RogueApDetector(oui).detect(networks, nowMillis)
        return findings.distinctBy { it.id }
    }

    private fun auditOne(n: WifiNetwork, now: Long): List<Finding> {
        val out = mutableListOf<Finding>()
        val key = n.bssid.ifBlank { n.ssid }
        when (n.security) {
            WifiSecurity.OPEN -> out += finding(
                "wifi.open.$key", "Open network: ${n.ssid}",
                "No encryption. All traffic, DNS queries and session cookies are visible to anyone in range.",
                Severity.CRITICAL,
                "Use WPA3-SAE (or WPA2-AES at minimum). Never use an open network for sensitive traffic.",
                n, now
            )
            WifiSecurity.WEP -> out += finding(
                "wifi.wep.$key", "WEP is broken: ${n.ssid}",
                "WEP's RC4 IV can be recovered from a few minutes of traffic; the key falls trivially.",
                Severity.CRITICAL,
                "Replace the AP or switch to WPA2-AES/WPA3 immediately. WEP cannot be made safe.",
                n, now
            )
            WifiSecurity.WPA -> out += finding(
                "wifi.wpa1.$key", "WPA/TKIP legacy: ${n.ssid}",
                "First-generation WPA with TKIP has known weaknesses and no forward secrecy.",
                Severity.HIGH, "Migrate to WPA3-SAE or WPA2-AES/CCMP with a strong random passphrase.",
                n, now
            )
            WifiSecurity.WPS -> out += finding(
                "wifi.wps.$key", "WPS enabled: ${n.ssid}",
                "Wi-Fi Protected Setup PIN mode is subject to online brute-force (the PIN is 10^7 keyspace, effectively 10^4).",
                Severity.HIGH, "Disable WPS PIN in the router admin page; use WPS push-button only if required.",
                n, now
            )
            else -> Unit
        }
        if (n.wpsEnabled && n.security != WifiSecurity.WPS) {
            out += finding(
                "wifi.wps_flag.$key", "WPS advertised: ${n.ssid}",
                "This AP advertises WPS support even though its primary security is ${n.security}.",
                Severity.MEDIUM, "Turn off WPS in the AP configuration.", n, now
            )
        }
        if (n.security == WifiSecurity.WPA2 && n.standard == com.sentinelnet.core.model.WifiStandard.WIFI_7) {
            out += finding(
                "wifi.legacy_sec.$key", "Legacy security on Wi-Fi 7 hardware: ${n.ssid}",
                "Wi-Fi 7 requires WPA3 (or OWE) for its full feature set; WPA2 holds the link back.",
                Severity.LOW, "Enable WPA3-SAE / WPA3-Enterprise.", n, now
            )
        }
        if (n.isHidden) {
            out += finding(
                "wifi.hidden.$key", "Hidden SSID: ${n.ssid}",
                "Hiding the SSID does not secure the network; clients leak the name in probe requests.",
                Severity.LOW, "Broadcast the SSID and rely on WPA3 for confidentiality.", n, now
            )
        }
        return out
    }

    private fun finding(
        id: String, title: String, detail: String, severity: Severity,
        remediation: String, n: WifiNetwork, now: Long
    ) = Finding(
        id = id, title = title, detail = detail, severity = severity,
        category = ScoreCategory.WIFI, remediation = remediation,
        evidence = mapOf("ssid" to n.ssid, "bssid" to n.bssid, "security" to n.security.name),
        detectedAtMillis = now
    )
}

/**
 * Evil-twin / rogue AP heuristics. These are *hints*, not proof: a legitimate
 * multi-AP mesh legitimately shares an SSID. We only flag when vendor OUIs or
 * signal levels disagree strongly, and always phrase the result as "investigate".
 */
class RogueApDetector(private val oui: OuiLookup = OuiLookup()) {

    fun detect(networks: List<WifiNetwork>, nowMillis: Long = 0L): List<Finding> {
        val out = mutableListOf<Finding>()
        val groups = networks.filter { it.ssid.isNotBlank() }.groupBy { it.ssid }
        for ((ssid, group) in groups) {
            if (group.size < 2) continue
            val vendors = group.map { oui.lookup(it.bssid) }.toSet()
            if (vendors.size > 1 && vendors.any { it != null }) {
                out += Finding(
                    id = "wifi.eviltwin.vendor.$ssid",
                    title = "Possible evil twin: $ssid",
                    detail = "${group.size} BSSIDs advertise '$ssid' with inconsistent vendor OUIs " +
                        "(${vendors.joinToString { it ?: "randomized/unknown" }}). Verify with the owner.",
                    severity = Severity.HIGH,
                    category = ScoreCategory.WIFI,
                    remediation = "Confirm each BSSID with the network owner; disable auto-join for this SSID.",
                    evidence = mapOf("ssid" to ssid, "bssids" to group.joinToString { it.bssid }),
                    referenceUrl = "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
                    detectedAtMillis = nowMillis
                )
            }
            val strong = group.maxByOrNull { it.rssiDbm }
            val median = group.map { it.rssiDbm }.sorted()[group.size / 2]
            if (strong != null && strong.rssiDbm - median > 25) {
                out += Finding(
                    id = "wifi.eviltwin.signal.$ssid",
                    title = "Unusually strong AP for '$ssid'",
                    detail = "${strong.bssid} is ${strong.rssiDbm - median} dBm stronger than the median " +
                        "for this SSID. A nearby transmitter impersonating the network is one possible cause.",
                    severity = Severity.MEDIUM,
                    category = ScoreCategory.WIFI,
                    remediation = "Verify the BSSID physically; use WPA3-Enterprise or a VPN on untrusted networks.",
                    evidence = mapOf("bssid" to strong.bssid, "rssi" to strong.rssiDbm.toString()),
                    detectedAtMillis = nowMillis
                )
            }
        }
        // Randomized BSSIDs are common for hotspots; flag only if the same SSID also has a real OUI.
        for (n in networks) {
            if (oui.isRandomized(n.bssid) && n.security != WifiSecurity.OPEN) continue
            if (oui.isRandomized(n.bssid)) {
                out += Finding(
                    id = "wifi.random_bssid.${n.bssid}",
                    title = "Open network with a randomized BSSID",
                    detail = "BSSID ${n.bssid} has the locally-administered bit set and offers no encryption.",
                    severity = Severity.MEDIUM,
                    category = ScoreCategory.WIFI,
                    remediation = "Treat as untrusted. Check for rogue DHCP/DNS before connecting.",
                    evidence = mapOf("bssid" to n.bssid, "ssid" to n.ssid),
                    detectedAtMillis = nowMillis
                )
            }
        }
        return out
    }
}
