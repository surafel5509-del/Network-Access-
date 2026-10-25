package com.sentinelnet.core.domain

import com.sentinelnet.core.model.DeviceType
import com.sentinelnet.core.model.DiscoveredDevice

/**
 * Passive device fingerprinting from TTL, open ports, vendor and mDNS/SSDP names.
 * No active OS probes are performed here (active stack probing is root-only and
 * out of scope for the foundation phase).
 */
object DeviceFingerprinter {

    fun guessOsFromTtl(ttl: Int?): String = when (ttl) {
        null -> "unknown"
        in 0..64 -> "Linux/Android/Unix-like (initial TTL 64)"
        in 65..128 -> "Windows/macOS/iOS (initial TTL 128)"
        in 129..255 -> "Network equipment / Solaris (initial TTL 255)"
        else -> "unknown"
    }

    fun guessType(device: DiscoveredDevice): DeviceType {
        val ports = device.openPorts.toSet()
        val name = "${device.hostname ?: ""} ${device.vendor ?: ""} ${device.httpTitle ?: ""}".lowercase()
        return when {
            name.contains("router") || name.contains("gateway") || name.contains("fritz") ||
                name.contains("openwrt") || name.contains("ubiquiti") || name.contains("mikrotik") -> DeviceType.ROUTER
            name.contains("chromecast") || name.contains("roku") || name.contains("tv") ||
                name.contains("firetv") -> DeviceType.TV
            name.contains("printer") || name.contains("hp ") || name.contains("canon") ||
                515 in ports || 631 in ports || 9100 in ports -> DeviceType.PRINTER
            name.contains("camera") || name.contains("hikvision") || name.contains("dahua") ||
                554 in ports -> DeviceType.CAMERA
            name.contains("hue") || name.contains("nest") || name.contains("tuya") ||
                name.contains("esp") || name.contains("sonoff") || name.contains("tasmota") ||
                name.contains("smart") -> DeviceType.IOT
            name.contains("iphone") || name.contains("android") || name.contains("pixel") ||
                name.contains("galaxy") || name.contains("phone") -> DeviceType.PHONE
            3389 in ports || 445 in ports || 1433 in ports || 5432 in ports ||
                3306 in ports || 27017 in ports -> DeviceType.SERVER
            name.contains("windows") || name.contains("macbook") || name.contains("pc") -> DeviceType.PC
            ports.isEmpty() && device.mac == null -> DeviceType.UNKNOWN
            80 in ports || 443 in ports || 8080 in ports -> DeviceType.IOT
            else -> DeviceType.UNKNOWN
        }
    }

    fun enrich(device: DiscoveredDevice, oui: OuiLookup = OuiLookup()): DiscoveredDevice {
        val vendor = device.vendor ?: device.mac?.let { oui.lookup(it) }
        return device.copy(vendor = vendor, deviceType = guessType(device.copy(vendor = vendor)))
    }
}
