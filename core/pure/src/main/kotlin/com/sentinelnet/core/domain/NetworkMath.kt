package com.sentinelnet.core.domain

/** Small, allocation-light IPv4 helpers used by the target validator and the /24 sweeper. */
object NetworkMath {
    fun ipv4ToLong(ip: String): Long? {
        val parts = ip.trim().split('.')
        if (parts.size != 4) return null
        var value = 0L
        for (part in parts) {
            val octet = part.toIntOrNull() ?: return null
            if (octet !in 0..255) return null
            value = (value shl 8) or octet.toLong()
        }
        return value and 0xFFFFFFFFL
    }

    fun longToIpv4(value: Long): String {
        val v = value and 0xFFFFFFFFL
        return "${(v shr 24) and 255}.${(v shr 16) and 255}.${(v shr 8) and 255}.${v and 255}"
    }

    /** RFC 1918, loopback, link-local, carrier-grade NAT shared range and TEST-NET ranges. */
    fun isPrivateOrLab(ip: String): Boolean {
        // IPv6 checks come first: ipv4ToLong() legitimately returns null for IPv6,
        // and an early return there would misclassify fe80::/10 and fc00::/7 as public.
        val lower = ip.trim().lowercase().substringBefore('%')
        if (lower == "::1" || lower.startsWith("fc") || lower.startsWith("fd") ||
            lower.startsWith("fe80") || lower.startsWith("fe90") ||
            lower.startsWith("fea0") || lower.startsWith("feb0")) return true
        val v = ipv4ToLong(ip) ?: return false
        val a = (v shr 24).toInt() and 255
        val b = (v shr 16).toInt() and 255
        return a == 10 ||
            a == 127 ||
            (a == 172 && b in 16..31) ||
            (a == 192 && b == 168) ||
            (a == 169 && b == 254) ||
            (a == 100 && b in 64..127) ||
            (a == 192 && b == 0 && ((v shr 8).toInt() and 255) == 2) ||
            (a == 198 && (b == 18 || b == 19)) ||
            (a == 203 && b == 0 && ((v shr 8).toInt() and 255) == 113) ||
            a == 0
    }

    fun isMulticastOrBroadcast(ip: String): Boolean {
        val v = ipv4ToLong(ip) ?: return ip.trim().lowercase().startsWith("ff")
        val a = (v shr 24).toInt() and 255
        return a in 224..239 || ip.trim() == "255.255.255.255" || (v and 0xFFL) == 0xFFL
    }

    fun isValidIp(ip: String): Boolean = ipv4ToLong(ip) != null || looksLikeIpv6(ip)

    fun looksLikeIpv6(ip: String): Boolean {
        val s = ip.trim().lowercase()
        if ('%' in s) return true // zone id, e.g. fe80::1%wlan0
        return s.contains(':') && s.all { it in "0123456789abcdef:.%" }
    }

    /** Expands an IPv4 CIDR into hosts, excluding network and broadcast addresses. */
    fun cidrHosts(cidr: String, limit: Int = 4096): List<String> {
        val parts = cidr.trim().split('/')
        val base = ipv4ToLong(parts[0]) ?: return emptyList()
        val prefix = parts.getOrNull(1)?.toIntOrNull() ?: return listOf(longToIpv4(base))
        if (prefix !in 0..32) return emptyList()
        val size = 1L shl (32 - prefix)
        if (size > limit) return emptyList()
        val network = base and (0xFFFFFFFFL shl (32 - prefix)) and 0xFFFFFFFFL
        return (1L until size - 1).map { longToIpv4(network + it) }
    }

    /** Guards against accidentally sweeping a public /8 from the UI. */
    fun sweepSize(cidr: String): Long {
        val parts = cidr.trim().split('/')
        if (ipv4ToLong(parts[0]) == null) return 0
        val prefix = parts.getOrNull(1)?.toIntOrNull() ?: return 1
        if (prefix !in 0..32) return 0
        return 1L shl (32 - prefix)
    }
}
