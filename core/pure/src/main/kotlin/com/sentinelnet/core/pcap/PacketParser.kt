package com.sentinelnet.core.pcap

import com.sentinelnet.core.crypto.Bytes
import com.sentinelnet.core.model.ParsedPacket

/**
 * Zero-copy-ish protocol dissector for VpnService packets (raw IPv4/IPv6) and
 * Ethernet frames (pcap import). Only metadata is retained — payload bytes are
 * never logged, which is both a privacy requirement and an OOM safeguard.
 *
 * The native Rust crate in native/rust/sentinel-parser implements the same
 * grammar for the hot path; this Kotlin version is the reference implementation
 * used by the conformance suite and as a fallback (ADR-0003).
 */
object PacketParser {
    const val ETHERTYPE_IPV4 = 0x0800
    const val ETHERTYPE_IPV6 = 0x86DD
    const val PROTO_ICMP = 1
    const val PROTO_TCP = 6
    const val PROTO_UDP = 17

    /** VpnService delivers raw IP packets; pcap imports may arrive as Ethernet. */
    fun parse(packet: ByteArray, timestampMillis: Long = 0L, linkType: Int = 101): ParsedPacket? {
        if (packet.isEmpty()) return null
        val ipStart = when (linkType) {
            1 -> { // LINKTYPE_ETHERNET
                if (packet.size < 14) return null
                val etherType = Bytes.readU16be(packet, 12)
                if (etherType != ETHERTYPE_IPV4 && etherType != ETHERTYPE_IPV6) {
                    return ParsedPacket(timestampMillis, packet.size, "", "", -1,
                        applicationProtocol = "ethertype:0x${etherType.toString(16)}")
                }
                14
            }
            else -> 0 // LINKTYPE_RAW (101) / NULL / LOOP
        }
        val version = (packet[ipStart].toInt() and 0xFF) ushr 4
        return when (version) {
            4 -> parseIpv4(packet, ipStart, timestampMillis)
            6 -> parseIpv6(packet, ipStart, timestampMillis)
            else -> ParsedPacket(timestampMillis, packet.size, "", "", -1, applicationProtocol = "ip-version:$version")
        }
    }

    private fun parseIpv4(packet: ByteArray, start: Int, ts: Long): ParsedPacket? {
        if (start + 20 > packet.size) return null
        val ihl = (packet[start].toInt() and 0x0F) * 4
        if (ihl < 20 || start + ihl > packet.size) return null
        val totalLength = Bytes.readU16be(packet, start + 2)
        val protocol = packet[start + 9].toInt() and 0xFF
        val src = ipv4(packet, start + 12)
        val dst = ipv4(packet, start + 16)
        val transportStart = start + ihl
        val payloadEnd = if (totalLength in 1..packet.size - start) start + totalLength else packet.size
        return parseTransport(packet, transportStart, payloadEnd, protocol, src, dst, ts)
    }

    private fun parseIpv6(packet: ByteArray, start: Int, ts: Long): ParsedPacket? {
        if (start + 40 > packet.size) return null
        val nextHeader = packet[start + 6].toInt() and 0xFF
        val payloadLength = Bytes.readU16be(packet, start + 4)
        val src = ipv6(packet, start + 8)
        val dst = ipv6(packet, start + 24)
        val transportStart = start + 40
        val payloadEnd = (transportStart + payloadLength).coerceAtMost(packet.size)
        return parseTransport(packet, transportStart, payloadEnd, nextHeader, src, dst, ts)
    }

    private fun parseTransport(
        packet: ByteArray, start: Int, end: Int, protocol: Int,
        src: String, dst: String, ts: Long
    ): ParsedPacket {
        if (start >= end) return ParsedPacket(ts, packet.size, src, dst, protocol)
        return when (protocol) {
            PROTO_TCP -> {
                if (start + 20 > end) return ParsedPacket(ts, packet.size, src, dst, protocol)
                val srcPort = Bytes.readU16be(packet, start)
                val dstPort = Bytes.readU16be(packet, start + 2)
                val dataOffset = ((packet[start + 12].toInt() and 0xFF) ushr 4) * 4
                val flags = packet[start + 13].toInt() and 0xFF
                val payloadStart = (start + dataOffset).coerceAtMost(end)
                val app = classifyTcp(packet, payloadStart, end, srcPort, dstPort)
                val queries = if (app == "DNS") DnsParser.queries(packet, payloadStart + 2, end) else emptyList()
                ParsedPacket(ts, packet.size, src, dst, protocol, srcPort, dstPort, flags,
                    dnsQueries = queries, applicationProtocol = app)
            }
            PROTO_UDP -> {
                if (start + 8 > end) return ParsedPacket(ts, packet.size, src, dst, protocol)
                val srcPort = Bytes.readU16be(packet, start)
                val dstPort = Bytes.readU16be(packet, start + 2)
                val queries = if (srcPort == 53 || dstPort == 53) DnsParser.queries(packet, start + 8, end) else emptyList()
                val app = when {
                    srcPort == 53 || dstPort == 53 -> "DNS"
                    srcPort == 1900 || dstPort == 1900 -> "SSDP"
                    srcPort == 5353 || dstPort == 5353 -> "mDNS"
                    srcPort == 67 || dstPort == 67 || srcPort == 68 || dstPort == 68 -> "DHCP"
                    srcPort == 123 || dstPort == 123 -> "NTP"
                    srcPort == 443 || dstPort == 443 -> "QUIC?"
                    else -> "UDP"
                }
                ParsedPacket(ts, packet.size, src, dst, protocol, srcPort, dstPort,
                    dnsQueries = queries, applicationProtocol = app)
            }
            PROTO_ICMP -> ParsedPacket(ts, packet.size, src, dst, protocol, applicationProtocol = "ICMP")
            else -> ParsedPacket(ts, packet.size, src, dst, protocol,
                applicationProtocol = "IP-proto-$protocol")
        }
    }

    private fun classifyTcp(packet: ByteArray, start: Int, end: Int, srcPort: Int, dstPort: Int): String {
        if (start >= end) return "TCP"
        val b0 = packet[start].toInt() and 0xFF
        if (b0 == 0x16 && start + 2 < end && (packet[start + 1].toInt() and 0xFF) == 3) return "TLS"
        val prefix = String(packet, start, (end - start).coerceAtMost(12), Charsets.ISO_8859_1)
        return when {
            prefix.startsWith("GET ") || prefix.startsWith("POST ") || prefix.startsWith("HEAD ") ||
                prefix.startsWith("PUT ") || prefix.startsWith("HTTP/") -> "HTTP"
            dstPort == 443 || srcPort == 443 || dstPort == 8443 -> "TLS"
            dstPort == 22 || srcPort == 22 -> "SSH"
            dstPort == 53 || srcPort == 53 -> "DNS"
            else -> "TCP"
        }
    }

    private fun ipv4(packet: ByteArray, offset: Int): String = buildString {
        for (i in 0..3) {
            if (i > 0) append('.')
            append(packet[offset + i].toInt() and 0xFF)
        }
    }

    private fun ipv6(packet: ByteArray, offset: Int): String {
        val groups = (0 until 8).map { Bytes.readU16be(packet, offset + it * 2).toString(16) }
        return groups.joinToString(":")
    }
}
