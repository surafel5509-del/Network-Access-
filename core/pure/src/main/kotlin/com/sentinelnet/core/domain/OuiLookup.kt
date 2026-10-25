package com.sentinelnet.core.domain

/**
 * Bundled OUI (MAC prefix) database. The shipped table is a small seed covering
 * the most common infrastructure vendors; the Android implementation layers an
 * updateable copy from assets/oui.csv on top of it (ADR-0006).
 *
 * A locally-administered bit means the address is randomized/spoofed, so vendor
 * lookup is intentionally refused for those addresses.
 */
class OuiLookup(extra: Map<String, String> = emptyMap()) {
    private val table: Map<String, String> = (SEED + extra.mapKeys { it.key.normalizePrefix() })
        .mapKeys { it.key.normalizePrefix() }

    fun lookup(mac: String): String? {
        if (isLocallyAdministered(mac)) return null
        val prefix = mac.normalizePrefix().take(6)
        return table[prefix]
    }

    fun isLocallyAdministered(mac: String): Boolean {
        val digits = mac.filter { it.isLetterOrDigit() }
        if (digits.length < 2) return false
        val firstOctet = digits.take(2).toIntOrNull(16) ?: return false
        return (firstOctet and 0x02) != 0
    }

    /** Android 10+ and iOS/macOS randomize per-network MACs for scan frames. */
    fun isRandomized(mac: String): Boolean = isLocallyAdministered(mac)

    private fun String.normalizePrefix(): String =
        filter { it.isLetterOrDigit() }.uppercase().take(6)

    companion object {
        val SEED: Map<String, String> = mapOf(
            "00:1A:2B" to "Cisco Systems", "00:1B:21" to "Intel", "00:1C:B3" to "D-Link",
            "00:1D:7E" to "Cisco-Linksys", "00:22:6B" to "Cisco", "00:24:01" to "Dell",
            "00:25:9C" to "Cisco", "00:26:5A" to "Google", "00:50:56" to "VMware",
            "00:0C:29" to "VMware", "00:15:5D" to "Microsoft Hyper-V", "00:1E:65" to "Apple",
            "3C:22:FB" to "Apple", "F0:18:98" to "Apple", "A4:83:E7" to "Apple",
            "8C:85:90" to "Apple", "DC:A6:32" to "Raspberry Pi Foundation",
            "B8:27:EB" to "Raspberry Pi Foundation", "00:17:88" to "Signify (Philips Hue)",
            "18:B4:30" to "Nest Labs", "60:A4:4C" to "Google", "F4:F5:D8" to "Google",
            "AC:DE:48" to "Privacy-randomized (h2g2)", "DA:A1:19" to "Arris",
            "00:1E:46" to "ZTE", "28:6C:07" to "Ubiquiti", "FC:EC:DA" to "Ubiquiti",
            "74:83:C2" to "Ubiquiti", "00:27:22" to "Ubiquiti", "04:18:D6" to "Ubiquiti",
            "C0:25:E9" to "TP-Link", "50:C7:BF" to "TP-Link", "98:DA:C4" to "TP-Link",
            "A0:F3:C1" to "TP-Link", "CC:32:E5" to "TP-Link", "00:31:92" to "TP-Link",
            "08:00:27" to "Oracle VirtualBox", "52:54:00" to "QEMU/KVM",
            "00:16:3E" to "Xen", "02:42:AC" to "Docker", "00:1B:44" to "SanDisk",
            "7C:2E:BD" to "Amazon", "68:37:E9" to "Amazon", "44:65:0D" to "Amazon",
            "34:D2:70" to "Amazon", "00:FC:8B" to "Amazon", "38:F7:3D" to "Amazon",
            "9C:30:5B" to "Huawei", "00:E0:FC" to "Huawei", "48:46:FB" to "Huawei",
            "30:B5:C2" to "Samsung", "5C:49:7D" to "Samsung", "00:12:FB" to "Samsung",
            "64:BC:0C" to "LG Electronics", "10:FE:ED" to "Nintendo", "00:1F:32" to "Netgear"
        ).mapKeys { (k, _) -> k.replace(":", "").uppercase().take(6) }
    }
}
