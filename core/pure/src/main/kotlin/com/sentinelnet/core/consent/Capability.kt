package com.sentinelnet.core.consent

/**
 * The capability registry is the single place where "invasive" is defined.
 * Adding a new engine feature without adding a capability here means it cannot
 * be gated, and the conformance suite fails (see scripts/verify_project.py).
 */
enum class Capability(
    val id: String,
    val invasive: Boolean,
    val requiresBiometric: Boolean,
    val noticeRef: String
) {
    WIFI_SCAN("wifi.scan", false, false, "legal.notice.wifi"),
    WIFI_SECURITY_AUDIT("wifi.audit", false, false, "legal.notice.audit"),
    DEVICE_DISCOVERY("net.discovery", true, false, "legal.notice.discovery"),
    PORT_SCAN("net.portscan", true, false, "legal.notice.portscan"),
    SERVICE_PROBE("net.serviceprobe", true, false, "legal.notice.serviceprobe"),
    TRACEROUTE("net.traceroute", false, false, "legal.notice.traceroute"),
    PACKET_CAPTURE("capture.vpn", true, true, "legal.notice.capture"),
    ROOT_CAPTURE("capture.root", true, true, "legal.notice.capture"),
    MITM_PROXY("capture.mitm", true, true, "legal.notice.mitm"),
    FIREWALL_CHANGE("firewall.rule", true, true, "legal.notice.firewall"),
    SECURITY_LAB("lab.wpa_psk", true, true, "legal.notice.lab"),
    SERVER_START("server.start", false, true, "legal.notice.server"),
    THREAT_INTEL("intel.lookup", false, false, "legal.notice.intel"),
    EXPORT("report.export", false, false, "legal.notice.export");

    companion object {
        fun fromId(id: String): Capability? = entries.firstOrNull { it.id == id }
        val INVASIVE_IDS: Set<String> = entries.filter { it.invasive }.map { it.id }.toSet()
    }
}
