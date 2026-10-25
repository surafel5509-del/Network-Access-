package com.sentinelnet.core.crypto

/** Hex/byte helpers shared by the crypto lab, packet parser and pcap writer. */
object Bytes {
    private val HEX = "0123456789ABCDEF".toCharArray()

    fun toHex(data: ByteArray, lowerCase: Boolean = false): String {
        val sb = StringBuilder(data.size * 2)
        for (b in data) {
            val v = b.toInt() and 0xFF
            sb.append(HEX[v ushr 4]); sb.append(HEX[v and 0x0F])
        }
        return if (lowerCase) sb.toString().lowercase() else sb.toString()
    }

    fun fromHex(hex: String): ByteArray {
        val clean = hex.replace(Regex("[^0-9a-fA-F]"), "")
        require(clean.length % 2 == 0) { "Odd-length hex string" }
        return ByteArray(clean.length / 2) { i ->
            ((Character.digit(clean[i * 2], 16) shl 4) or Character.digit(clean[i * 2 + 1], 16)).toByte()
        }
    }

    fun fromMac(mac: String): ByteArray {
        val b = fromHex(mac)
        require(b.size == 6) { "MAC address must be 6 bytes" }
        return b
    }

    fun concat(vararg parts: ByteArray): ByteArray {
        val total = parts.sumOf { it.size }
        val out = ByteArray(total)
        var pos = 0
        for (p in parts) { p.copyInto(out, pos); pos += p.size }
        return out
    }

    fun xor(a: ByteArray, b: ByteArray): ByteArray {
        require(a.size == b.size) { "xor length mismatch" }
        return ByteArray(a.size) { (a[it].toInt() xor b[it].toInt()).toByte() }
    }

    /** Constant-time comparison — avoids leaking the matching MIC prefix via timing. */
    fun constantTimeEquals(a: ByteArray, b: ByteArray): Boolean {
        if (a.size != b.size) return false
        var diff = 0
        for (i in a.indices) diff = diff or (a[i].toInt() xor b[i].toInt())
        return diff == 0
    }

    fun u32be(value: Int): ByteArray = byteArrayOf(
        (value ushr 24).toByte(), (value ushr 16).toByte(), (value ushr 8).toByte(), value.toByte()
    )

    fun u16be(value: Int): ByteArray = byteArrayOf((value ushr 8).toByte(), value.toByte())

    fun readU16be(data: ByteArray, offset: Int): Int {
        if (offset + 1 >= data.size) return -1
        return ((data[offset].toInt() and 0xFF) shl 8) or (data[offset + 1].toInt() and 0xFF)
    }

    fun readU32be(data: ByteArray, offset: Int): Long {
        if (offset + 3 >= data.size) return -1
        return ((data[offset].toLong() and 0xFF) shl 24) or
            ((data[offset + 1].toLong() and 0xFF) shl 16) or
            ((data[offset + 2].toLong() and 0xFF) shl 8) or
            (data[offset + 3].toLong() and 0xFF)
    }

    /** Unsigned lexicographic comparison, as required by 802.11i Min()/Max(). */
    fun compareUnsigned(a: ByteArray, b: ByteArray): Int {
        require(a.size == b.size) { "Min/Max operands must have equal length" }
        for (i in a.indices) {
            val x = a[i].toInt() and 0xFF
            val y = b[i].toInt() and 0xFF
            if (x != y) return if (x < y) -1 else 1
        }
        return 0
    }

    fun min(a: ByteArray, b: ByteArray): ByteArray = if (compareUnsigned(a, b) <= 0) a else b
    fun max(a: ByteArray, b: ByteArray): ByteArray = if (compareUnsigned(a, b) >= 0) a else b
}
