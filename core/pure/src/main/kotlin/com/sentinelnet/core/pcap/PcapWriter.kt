package com.sentinelnet.core.pcap

import com.sentinelnet.core.crypto.Bytes
import java.io.OutputStream

/**
 * Classic libpcap writer (Wireshark-compatible). VpnService traffic is emitted
 * as LINKTYPE_RAW (101) because we see IP packets, not Ethernet frames.
 * Exports are written to an EncryptedFile on Android; this class only needs an
 * OutputStream, so it is testable without Android.
 */
class PcapWriter(private val out: OutputStream, private val linkType: Int = LINKTYPE_RAW) {
    var packetsWritten: Long = 0L
        private set

    /**
     * Writes the 24-byte global header in little-endian pcap byte order.
     * (pcap magic 0xA1B2C3D4 is stored as d4 c3 b2 a1 for little-endian files.)
     */
    fun writeGlobalHeader(snapLen: Int = 65535) {
        val header = ByteArray(24)
        le32(header, 0, 0xA1B2C3D4L)
        le16(header, 4, 2)  // version major
        le16(header, 6, 4)  // version minor
        le32(header, 8, 0)  // thiszone
        le32(header, 12, 0) // sigfigs
        le32(header, 16, snapLen.toLong())
        le32(header, 20, linkType.toLong())
        out.write(header)
        out.flush()
    }

    fun writePacket(packet: ByteArray, timestampMillis: Long = System.currentTimeMillis()) {
        val record = ByteArray(16)
        le32(record, 0, timestampMillis / 1000L)
        le32(record, 4, timestampMillis % 1000L * 1000L) // microseconds
        le32(record, 8, packet.size.toLong())
        le32(record, 12, packet.size.toLong())
        out.write(record)
        out.write(packet)
        packetsWritten++
    }

    fun close() { out.flush(); out.close() }

    private fun le16(buf: ByteArray, offset: Int, value: Int) {
        buf[offset] = (value and 0xFF).toByte()
        buf[offset + 1] = ((value shr 8) and 0xFF).toByte()
    }

    private fun le32(buf: ByteArray, offset: Int, value: Long) {
        buf[offset] = (value and 0xFF).toByte()
        buf[offset + 1] = ((value shr 8) and 0xFF).toByte()
        buf[offset + 2] = ((value shr 16) and 0xFF).toByte()
        buf[offset + 3] = ((value shr 24) and 0xFF).toByte()
    }

    companion object {
        const val LINKTYPE_RAW = 101
        const val LINKTYPE_ETHERNET = 1
    }
}
