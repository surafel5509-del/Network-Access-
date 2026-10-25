package com.sentinelnet.engine.scanner

import android.content.Context
import android.net.wifi.WifiManager
import com.sentinelnet.core.consent.Capability
import com.sentinelnet.core.consent.ConsentGate
import com.sentinelnet.core.consent.ConsentRequest
import com.sentinelnet.core.consent.ConsentResult
import com.sentinelnet.core.domain.DeviceFingerprinter
import com.sentinelnet.core.domain.NetworkMath
import com.sentinelnet.core.domain.OuiLookup
import com.sentinelnet.core.model.DiscoveredDevice
import com.sentinelnet.engine.api.DeviceDiscoveryEngine
import com.sentinelnet.engine.api.EngineStatus
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.channels.channelFlow
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Semaphore
import kotlinx.coroutines.sync.withPermit
import java.io.BufferedReader
import java.io.FileReader
import java.net.DatagramPacket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.MulticastSocket
import javax.inject.Inject
import javax.inject.Singleton

/** Unified discovery: ARP table + ICMP reachability + SSDP/mDNS hints. */
@Singleton
class AndroidDeviceDiscovery @Inject constructor(
    @ApplicationContext private val context: Context,
    private val consentGate: ConsentGate,
    private val ouiLookup: OuiLookup
) : DeviceDiscoveryEngine {

    override val id = "discovery"
    override val displayName = "Device discovery"
    override val requiredCapability = Capability.DEVICE_DISCOVERY
    override fun status(): EngineStatus = EngineStatus.ok()

    override fun discover(subnetCidr: String, consent: ConsentRequest): Flow<DiscoveredDevice> = channelFlow {
        val verdict = consentGate.guard(consent) { true }
        if (verdict is ConsentResult.Denied) {
            throw SecurityException("Discovery denied: ${verdict.reason.name}")
        }
        val arp = readArpTable()
        val hosts = NetworkMath.cidrHosts(subnetCidr, limit = 1024)
        val semaphore = Semaphore(48)
        coroutineScope {
            for (host in hosts) {
                launch(Dispatchers.IO) {
                    semaphore.withPermit {
                        val mac = arp[host]
                        val reachable = mac != null || isReachable(host)
                        if (reachable) {
                            val device = DiscoveredDevice(
                                ip = host, mac = mac, vendor = mac?.let { ouiLookup.lookup(it) },
                                discoverySources = setOf(if (mac != null) "ARP" else "ICMP"),
                                firstSeenMillis = System.currentTimeMillis(),
                                lastSeenMillis = System.currentTimeMillis()
                            )
                            send(DeviceFingerprinter.enrich(device, ouiLookup))
                        }
                    }
                }
            }
            launch(Dispatchers.IO) { ssdpHints().forEach { send(it) } }
        }
    }

    override suspend fun fingerprint(device: DiscoveredDevice): DiscoveredDevice =
        DeviceFingerprinter.enrich(device, ouiLookup)

    /** /proc/net/arp is world-readable and needs no root on Android 10+. */
    private fun readArpTable(): Map<String, String> = try {
        BufferedReader(FileReader("/proc/net/arp")).useLines { lines ->
            lines.drop(1).mapNotNull { line ->
                val cols = line.trim().split(Regex("\\s+"))
                if (cols.size >= 4 && cols[2] == "0x1" && cols[3] != "00:00:00:00:00:00") {
                    cols[0] to cols[3]
                } else null
            }.toMap()
        }
    } catch (t: Throwable) { emptyMap() }

    private fun isReachable(host: String): Boolean = try {
        InetAddress.getByName(host).isReachable(600)
    } catch (t: Throwable) { false }

    /** Best-effort SSDP M-SEARCH. Requires a MulticastLock; failures are non-fatal. */
    private fun ssdpHints(): List<DiscoveredDevice> {
        var lock: WifiManager.MulticastLock? = null
        return try {
            val wm = context.applicationContext.getSystemService(Context.WIFI_SERVICE) as? WifiManager
            lock = wm?.createMulticastLock("sentinelnet-ssdp")?.also { it.acquire() }
            val socket = MulticastSocket().also { it.soTimeout = 1200 }
            val target = InetSocketAddress("239.255.255.250", 1900)
            val request = ("M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\n" +
                "MAN: \"ssdp:discover\"\r\nMX: 1\r\nST: ssdp:all\r\n\r\n").toByteArray()
            @Suppress("DEPRECATION")
            socket.send(DatagramPacket(request, request.size, target.address, target.port))
            val found = mutableListOf<DiscoveredDevice>()
            repeat(6) {
                try {
                    val buf = ByteArray(2048)
                    val reply = DatagramPacket(buf, buf.size)
                    socket.receive(reply)
                    val text = String(reply.data, 0, reply.length, Charsets.ISO_8859_1)
                    val ip = reply.address.hostAddress ?: return@repeat
                    val server = Regex("SERVER:\\s*(.+)", RegexOption.IGNORE_CASE).find(text)?.groupValues?.get(1)
                    found += DiscoveredDevice(ip, hostname = server,
                        discoverySources = setOf("SSDP"), lastSeenMillis = System.currentTimeMillis())
                } catch (t: Throwable) { return@repeat }
            }
            socket.close()
            found.distinctBy { it.ip }
        } catch (t: Throwable) {
            emptyList()
        } finally {
            try { if (lock?.isHeld == true) lock.release() } catch (t: Throwable) { Unit }
        }
    }
}
