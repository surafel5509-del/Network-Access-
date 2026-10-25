package com.sentinelnet.core.pcap

import com.sentinelnet.core.model.FlowKey
import com.sentinelnet.core.model.FlowStats
import com.sentinelnet.core.model.ParsedPacket

/** In-memory 5-tuple flow tracking with a bounded map (avoids OOM on long captures). */
class FlowTracker(private val maxFlows: Int = 10_000) {
    private val lock = Any()
    private val flows = LinkedHashMap<FlowKey, MutableFlow>()

    fun onPacket(packet: ParsedPacket) {
        val key = FlowKey(
            packet.srcIp, packet.dstIp,
            packet.srcPort ?: 0, packet.dstPort ?: 0, packet.protocol
        )
        synchronized(lock) {
            val f = flows.getOrPut(key) {
                if (flows.size >= maxFlows) evictOldest()
                MutableFlow(key, packet.timestampMillis)
            }
            f.packets++
            f.bytes += packet.length
            f.lastSeen = packet.timestampMillis
        }
    }

    fun snapshot(): List<FlowStats> = synchronized(lock) {
        flows.values.map { FlowStats(it.key, it.packets, it.bytes, it.firstSeen, it.lastSeen) }
            .sortedByDescending { it.bytes }
    }

    fun topTalkers(limit: Int = 10): List<Pair<String, Long>> = synchronized(lock) {
        val byIp = mutableMapOf<String, Long>()
        flows.values.forEach { f -> byIp[f.key.srcIp] = (byIp[f.key.srcIp] ?: 0) + f.bytes }
        byIp.entries.sortedByDescending { it.value }.take(limit).map { it.key to it.value }
    }

    fun size(): Int = synchronized(lock) { flows.size }
    fun clear() = synchronized(lock) { flows.clear() }

    private fun evictOldest() {
        val oldest = flows.entries.minByOrNull { it.value.lastSeen }?.key ?: return
        flows.remove(oldest)
    }

    private class MutableFlow(val key: FlowKey, val firstSeen: Long) {
        var packets: Long = 0
        var bytes: Long = 0
        var lastSeen: Long = firstSeen
    }
}

/** Tiny BPF-like filter evaluator for the capture UI (no native compiler needed). */
data class CaptureFilter(
    val host: String? = null,
    val port: Int? = null,
    val protocol: Int? = null,
    val app: String? = null,
    val excludeDns: Boolean = false
) {
    fun matches(p: ParsedPacket): Boolean {
        if (host != null && p.srcIp != host && p.dstIp != host) return false
        if (port != null && p.srcPort != port && p.dstPort != port) return false
        if (protocol != null && p.protocol != protocol) return false
        if (app != null && !p.applicationProtocol.equals(app, ignoreCase = true)) return false
        if (excludeDns && p.applicationProtocol == "DNS") return false
        return true
    }

    fun toDisplayString(): String = buildList {
        protocol?.let { add("proto $it") }
        host?.let { add("host $it") }
        port?.let { add("port $it") }
        app?.let { add("app $it") }
        if (excludeDns) add("not dns")
    }.joinToString(" and ").ifEmpty { "all" }
}
