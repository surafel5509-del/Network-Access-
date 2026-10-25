package com.sentinelnet.engine.audit

import android.content.Context
import android.net.ConnectivityManager
import android.net.DhcpInfo
import android.net.LinkProperties
import android.net.wifi.WifiManager
import com.sentinelnet.core.domain.PortRisk
import com.sentinelnet.core.domain.WifiSecurityAuditor
import com.sentinelnet.core.model.Finding
import com.sentinelnet.core.model.PortResult
import com.sentinelnet.core.model.ScoreCategory
import com.sentinelnet.core.model.Severity
import com.sentinelnet.core.model.WifiNetwork
import dagger.hilt.android.qualifiers.ApplicationContext
import java.io.BufferedReader
import java.io.FileReader
import javax.inject.Inject
import javax.inject.Singleton

/** Module D1 — passive network security audit (no packets injected). */
@Singleton
class NetworkAudit @Inject constructor(
    @ApplicationContext private val context: Context,
    private val wifiAuditor: WifiSecurityAuditor
) {
    @Volatile private var baselineGatewayMac: String? = null

    fun audit(
        networks: List<WifiNetwork> = emptyList(),
        ports: List<PortResult> = emptyList(),
        now: Long = System.currentTimeMillis()
    ): List<Finding> = buildList {
        addAll(wifiAuditor.audit(networks, now))
        addAll(PortRisk.assess(ports, now))
        addAll(gatewayChecks(now))
        addAll(dnsChecks(now))
        addAll(dhcpChecks(now))
    }

    /** ARP spoofing hint: a changed gateway MAC. Baseline is set on first observation. */
    private fun gatewayChecks(now: Long): List<Finding> {
        val mac = readArpGatewayMac() ?: return emptyList()
        val baseline = baselineGatewayMac
        if (baseline == null) { baselineGatewayMac = mac; return emptyList() }
        if (mac.equals(baseline, ignoreCase = true)) return emptyList()
        return listOf(Finding(
            id = "net.gateway_mac_change",
            title = "Gateway MAC address changed",
            detail = "Gateway MAC changed from $baseline to $mac. This can be caused by ARP spoofing, " +
                "but also by a router reboot, mesh handover or a new AP — verify before concluding an attack.",
            severity = Severity.HIGH, category = ScoreCategory.NETWORK,
            remediation = "Confirm with the network owner. Use WPA3-Enterprise/PMF and a static gateway ARP entry where possible.",
            evidence = mapOf("previous" to baseline, "current" to mac), detectedAtMillis = now
        ))
    }

    private fun readArpGatewayMac(): String? = try {
        val wm = context.applicationContext.getSystemService(Context.WIFI_SERVICE) as? WifiManager
        @Suppress("DEPRECATION")
        val gateway = intToIp(wm?.dhcpInfo?.gateway ?: 0)
        if (gateway == null) {
            null
        } else {
            BufferedReader(FileReader("/proc/net/arp")).useLines { lines ->
                lines.drop(1).firstNotNullOfOrNull { line ->
                    val c = line.trim().split(Regex("\\s+"))
                    if (c.size >= 4 && c[0] == gateway && c[2] == "0x1" &&
                        c[3] != "00:00:00:00:00:00") c[3] else null
                }
            }
        }
    } catch (t: Throwable) { null }

    @Suppress("DEPRECATION")
    private fun intToIp(value: Int): String? {
        if (value == 0) return null
        return "${value and 255}.${(value shr 8) and 255}.${(value shr 16) and 255}.${(value shr 24) and 255}"
    }

    /** DNS servers outside the local subnet can indicate a leak or a hijacked resolver. */
    private fun dnsChecks(now: Long): List<Finding> {
        val cm = context.getSystemService(Context.CONNECTIVITY_SERVICE) as? ConnectivityManager ?: return emptyList()
        val active = cm.activeNetwork ?: return emptyList()
        val lp: LinkProperties = cm.getLinkProperties(active) ?: return emptyList()
        val servers = lp.dnsServers.mapNotNull { it.hostAddress }
        val suspicious = servers.filter { it.startsWith("0.") || it == "::" }
        if (suspicious.isNotEmpty()) {
            return listOf(Finding(
                id = "net.dns_invalid", title = "Invalid DNS resolver configured",
                detail = "Suspicious DNS servers: ${suspicious.joinToString(", ")}.",
                severity = Severity.HIGH, category = ScoreCategory.NETWORK,
                remediation = "Check router DHCP options and VPN DNS settings.",
                evidence = mapOf("dns" to servers.joinToString(",")), detectedAtMillis = now))
        }
        if (servers.isEmpty()) return emptyList()
        return listOf(Finding(
            id = "net.dns_info", title = "DNS resolvers in use: ${servers.size}",
            detail = "Resolvers: ${servers.joinToString(", ")}. A VPN should replace these with its own resolver; " +
                "if they still point at the ISP while a VPN is active, that is a DNS leak.",
            severity = Severity.INFO, category = ScoreCategory.PRIVACY,
            remediation = "Use a trusted DoH/DoT resolver or your VPN provider's DNS.",
            evidence = mapOf("dns" to servers.joinToString(",")), detectedAtMillis = now))
    }

    @Suppress("DEPRECATION")
    private fun dhcpChecks(now: Long): List<Finding> {
        val wm = context.applicationContext.getSystemService(Context.WIFI_SERVICE) as? WifiManager ?: return emptyList()
        val dhcp: DhcpInfo = wm.dhcpInfo ?: return emptyList()
        val lease = dhcp.leaseDuration
        // A very short lease is a classic rogue-DHCP symptom.
        return if (lease in 1..60) listOf(Finding(
            id = "net.short_lease", title = "Very short DHCP lease ($lease s)",
            detail = "The DHCP server advertises a ${lease}s lease. Rogue DHCP servers often use short leases " +
                "to redirect clients quickly; congested networks can also do this legitimately.",
            severity = Severity.MEDIUM, category = ScoreCategory.NETWORK,
            remediation = "Check which DHCP server answered (server address) and confirm it with the owner.",
            evidence = mapOf("leaseSeconds" to lease.toString()), detectedAtMillis = now))
        else emptyList()
    }
}
