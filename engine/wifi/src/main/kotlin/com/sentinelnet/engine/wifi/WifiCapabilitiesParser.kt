package com.sentinelnet.engine.wifi

import com.sentinelnet.core.model.WifiSecurity

/** Pure (Android-free) parser for WifiManager capability strings — unit-testable on the JVM. */
object WifiCapabilitiesParser {
    fun parse(caps: String): WifiSecurity {
        val c = caps.uppercase()
        return when {
            "SAE" in c || "WPA3" in c -> WifiSecurity.WPA3
            "OWE" in c -> WifiSecurity.OWE
            "SUITE_B_192" in c || "WPA3-ENTERPRISE" in c -> WifiSecurity.WPA3_ENTERPRISE
            "EAP" in c && "WPA2" in c -> WifiSecurity.WPA2_ENTERPRISE
            "WPA2" in c -> WifiSecurity.WPA2
            "WPA" in c -> WifiSecurity.WPA
            "WEP" in c -> WifiSecurity.WEP
            "WPS" in c -> WifiSecurity.WPS
            else -> WifiSecurity.OPEN
        }
    }

    fun hasWps(caps: String): Boolean = caps.contains("WPS", ignoreCase = true)
}
