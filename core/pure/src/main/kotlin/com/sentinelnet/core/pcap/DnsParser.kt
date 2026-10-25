package com.sentinelnet.core.pcap

import com.sentinelnet.core.crypto.Bytes

/** DNS question-section parser with compression-pointer loop protection. */
object DnsParser {
    fun queries(packet: ByteArray, start: Int, end: Int): List<String> {
        if (start + 12 > end) return emptyList()
        val qdCount = Bytes.readU16be(packet, start + 4)
        if (qdCount == 0 || qdCount > 64) return emptyList()
        var pos = start + 12
        val out = mutableListOf<String>()
        repeat(qdCount) {
            val parsed = readName(packet, pos, end) ?: return out
            out += parsed.first
            pos = parsed.second + 4 // QTYPE + QCLASS
            if (pos > end) return out
        }
        return out
    }

    /** Returns (name, offset-after-name). */
    fun readName(packet: ByteArray, start: Int, end: Int): Pair<String, Int>? {
        var pos = start
        val labels = mutableListOf<String>()
        var jumps = 0
        var nextPos = -1
        while (pos < end && jumps <= 16) {
            val len = packet[pos].toInt() and 0xFF
            when {
                len == 0 -> { pos++; break }
                (len and 0xC0) == 0xC0 -> {
                    if (pos + 1 >= end) return null
                    val pointer = ((len and 0x3F) shl 8) or (packet[pos + 1].toInt() and 0xFF)
                    if (pointer >= end || pointer < 0) return null
                    if (nextPos < 0) nextPos = pos + 2
                    pos = pointer
                    jumps++
                }
                len > 63 -> return null
                else -> {
                    if (pos + 1 + len > end) return null
                    labels += String(packet, pos + 1, len, Charsets.ISO_8859_1)
                    pos += 1 + len
                }
            }
        }
        if (labels.isEmpty() || jumps > 16) return null
        return labels.joinToString(".") to (if (nextPos >= 0) nextPos else pos)
    }
}
