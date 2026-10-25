package com.sentinelnet.verification

import com.sentinelnet.core.crypto.Bytes
import com.sentinelnet.core.pcap.CaptureFilter
import com.sentinelnet.core.pcap.DnsParser
import com.sentinelnet.core.pcap.FlowTracker
import com.sentinelnet.core.pcap.PacketParser
import com.sentinelnet.core.pcap.PcapWriter
import java.io.ByteArrayOutputStream

private fun ipBytes(ip: String): ByteArray = ip.split('.').map { it.toInt().toByte() }.toByteArray()

private fun ipv4Udp(src: String, dst: String, srcPort: Int, dstPort: Int, payload: ByteArray): ByteArray {
    val total = 20 + 8 + payload.size
    val p = ByteArray(total)
    p[0] = 0x45
    p[2] = (total shr 8).toByte(); p[3] = total.toByte()
    p[8] = 64; p[9] = 17
    ipBytes(src).copyInto(p, 12); ipBytes(dst).copyInto(p, 16)
    p[20] = (srcPort shr 8).toByte(); p[21] = srcPort.toByte()
    p[22] = (dstPort shr 8).toByte(); p[23] = dstPort.toByte()
    val udpLen = 8 + payload.size
    p[24] = (udpLen shr 8).toByte(); p[25] = udpLen.toByte()
    payload.copyInto(p, 28)
    return p
}

private fun ipv4Tcp(src: String, dst: String, srcPort: Int, dstPort: Int, payload: ByteArray, flags: Int = 0x02): ByteArray {
    val total = 20 + 20 + payload.size
    val p = ByteArray(total)
    p[0] = 0x45
    p[2] = (total shr 8).toByte(); p[3] = total.toByte()
    p[8] = 64; p[9] = 6
    ipBytes(src).copyInto(p, 12); ipBytes(dst).copyInto(p, 16)
    p[20] = (srcPort shr 8).toByte(); p[21] = srcPort.toByte()
    p[22] = (dstPort shr 8).toByte(); p[23] = dstPort.toByte()
    p[32] = 0x50; p[33] = flags.toByte()
    payload.copyInto(p, 40)
    return p
}

private fun dnsQuery(name: String): ByteArray {
    val labels = name.split('.').flatMap { label -> listOf(label.length.toByte()) + label.toByteArray().toList() }
    val out = ByteArray(12 + labels.size + 1 + 4)
    out[0] = 0x12; out[1] = 0x34; out[2] = 0x01; out[3] = 0x00
    out[5] = 0x01 // QDCOUNT = 1
    labels.forEachIndexed { i, b -> out[12 + i] = b }
    out[12 + labels.size] = 0
    val tail = 12 + labels.size + 1
    out[tail + 1] = 1 // QTYPE A
    out[tail + 3] = 1 // QCLASS IN
    return out
}

fun pcapTests() = Harness.section("packet-parser") {
    Harness.test("IPv4/UDP packet fields are dissected") {
        val p = ipv4Udp("192.168.1.10", "192.168.1.1", 43210, 1900, "hello".toByteArray())
        val parsed = PacketParser.parse(p, 555L)!!
        Harness.assertEquals("192.168.1.10", parsed.srcIp)
        Harness.assertEquals("192.168.1.1", parsed.dstIp)
        Harness.assertEquals(17, parsed.protocol)
        Harness.assertEquals(43210, parsed.srcPort)
        Harness.assertEquals(1900, parsed.dstPort)
        Harness.assertEquals("SSDP", parsed.applicationProtocol)
        Harness.assertEquals(555L, parsed.timestampMillis)
        Harness.assertEquals(p.size, parsed.length)
    }
    Harness.test("IPv4/TCP SYN flags and HTTP classification") {
        val p = ipv4Tcp("10.0.0.2", "10.0.0.1", 51000, 80, "GET / HTTP/1.1\r\n".toByteArray())
        val parsed = PacketParser.parse(p, 1L)!!
        Harness.assertEquals(6, parsed.protocol)
        Harness.assertEquals(0x02, parsed.tcpFlags)
        Harness.assertEquals("HTTP", parsed.applicationProtocol)
    }
    Harness.test("TLS ClientHello is recognised by metadata only") {
        val tls = byteArrayOf(0x16, 0x03, 0x01, 0x00, 0x05, 1, 2, 3, 4, 5)
        val p = ipv4Tcp("10.0.0.2", "10.0.0.1", 51000, 443, tls)
        Harness.assertEquals("TLS", PacketParser.parse(p)!!.applicationProtocol)
    }
    Harness.test("DNS query names are extracted, payload is not retained") {
        val p = ipv4Udp("192.168.1.10", "192.168.1.1", 53000, 53, dnsQuery("api.example.com"))
        val parsed = PacketParser.parse(p)!!
        Harness.assertEquals("DNS", parsed.applicationProtocol)
        Harness.assertEquals(listOf("api.example.com"), parsed.dnsQueries)
    }
    Harness.test("Ethernet-framed packets (pcap LINKTYPE_ETHERNET) are supported") {
        val ip = ipv4Udp("192.168.1.10", "8.8.8.8", 1234, 53, dnsQuery("example.com"))
        val eth = ByteArray(14) + ip
        eth[12] = 0x08; eth[13] = 0x00
        val parsed = PacketParser.parse(eth, 0L, linkType = 1)!!
        Harness.assertEquals("192.168.1.10", parsed.srcIp)
        Harness.assertEquals("DNS", parsed.applicationProtocol)
    }
    Harness.test("IPv6 packets parse addresses and next header") {
        val p = ByteArray(40 + 8)
        p[0] = 0x60
        p[4] = 0; p[5] = 8
        p[6] = 17
        p[8 + 15] = 1 // src ::1
        p[24 + 15] = 2 // dst ::2
        val parsed = PacketParser.parse(p)!!
        Harness.assertEquals(17, parsed.protocol)
        Harness.assertContains(parsed.srcIp, "1")
        Harness.assertEquals(8, parsed.length - 40)
    }
    Harness.test("truncated / empty packets fail safely (no OOM, no exception)") {
        Harness.assertEquals(null, PacketParser.parse(ByteArray(0)))
        Harness.assertEquals(null, PacketParser.parse(byteArrayOf(0x45, 0x00)))
        Harness.assertEquals(null, PacketParser.parse(ByteArray(5), 0L, linkType = 1))
    }
    Harness.test("DNS compression pointers are followed with loop protection") {
        val q = dnsQuery("example.com")
        val buf = q.copyOf(q.size + 12)
        // Insert a pointer record at offset 12 pointing to the original name at offset 24.
        buf[12] = 0xC0.toByte(); buf[13] = 24
        val nameAt24 = ByteArray(13)
        nameAt24[0] = 7
        "example".toByteArray().copyInto(nameAt24, 1)
        nameAt24[8] = 3
        "com".toByteArray().copyInto(nameAt24, 9)
        nameAt24.copyInto(buf, 24)
        val read = DnsParser.readName(buf, 12, buf.size)
        Harness.assertEquals("example.com", read?.first)
        Harness.assertEquals(14, read?.second)
    }

    Harness.section("pcap-and-flows") {
        Harness.test("pcap global header is Wireshark-compatible LINKTYPE_RAW") {
            val out = ByteArrayOutputStream()
            val writer = PcapWriter(out)
            writer.writeGlobalHeader()
            val header = out.toByteArray()
            Harness.assertEquals(24, header.size)
            Harness.assertEquals("d4c3b2a1", Bytes.toHex(header.copyOfRange(0, 4), true))
            Harness.assertEquals(101, header[20].toInt() and 0xFF)
            Harness.assertEquals(65535, (header[16].toInt() and 0xFF) or ((header[17].toInt() and 0xFF) shl 8) or
                ((header[18].toInt() and 0xFF) shl 16) or ((header[19].toInt() and 0xFF) shl 24))
        }
        Harness.test("pcap packet records carry timestamp and captured length") {
            val out = ByteArrayOutputStream()
            val writer = PcapWriter(out)
            writer.writeGlobalHeader()
            val packet = ipv4Udp("10.0.0.1", "10.0.0.2", 1234, 53, dnsQuery("x.test"))
            writer.writePacket(packet, 1_700_000_000_123L)
            writer.close()
            val bytes = out.toByteArray()
            Harness.assertEquals(24 + 16 + packet.size, bytes.size)
            Harness.assertEquals(packet.size, bytes[32].toInt() and 0xFF or ((bytes[33].toInt() and 0xFF) shl 8))
            Harness.assertEquals(1L, writer.packetsWritten)
        }
        Harness.test("flow tracker aggregates a 5-tuple and reports top talkers") {
            val tracker = FlowTracker()
            repeat(3) { i ->
                val p = ipv4Udp("192.168.1.10", "192.168.1.1", 4000, 53, dnsQuery("a.test"))
                tracker.onPacket(PacketParser.parse(p, 1000L + i)!!)
            }
            Harness.assertEquals(1, tracker.size())
            val flow = tracker.snapshot().single()
            Harness.assertEquals(3L, flow.packets)
            Harness.assertTrue(flow.bytes > 0)
            Harness.assertEquals("192.168.1.10", tracker.topTalkers().first().first)
        }
        Harness.test("capture filter matches host/port/proto/app") {
            val p = PacketParser.parse(ipv4Udp("192.168.1.10", "192.168.1.1", 4000, 53, dnsQuery("a.test")))!!
            Harness.assertTrue(CaptureFilter(host = "192.168.1.10").matches(p))
            Harness.assertTrue(CaptureFilter(port = 53, protocol = 17).matches(p))
            Harness.assertTrue(CaptureFilter(app = "DNS").matches(p))
            Harness.assertTrue(!CaptureFilter(excludeDns = true).matches(p))
            Harness.assertTrue(!CaptureFilter(host = "10.0.0.1").matches(p))
            Harness.assertContains(CaptureFilter(port = 53).toDisplayString(), "port 53")
        }
    }
}
