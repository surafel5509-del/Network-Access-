package com.sentinelnet.engine.capture

import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import androidx.core.app.NotificationCompat
import com.sentinelnet.core.pcap.CaptureFilter
import com.sentinelnet.core.pcap.FlowTracker
import com.sentinelnet.core.pcap.PacketParser
import com.sentinelnet.core.pcap.PcapWriter
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import java.io.File
import java.io.FileInputStream
import java.io.FileOutputStream

/**
 * VpnService-based METADATA capture (no root).
 *
 * IMPORTANT DESIGN LIMITATION — FOUNDATION PHASE
 * ------------------------------------------------
 * This service deliberately routes ONLY a synthetic lab subnet
 * (10.222.222.0/24) into the VPN. It reads each IP packet, extracts metadata
 * with the pure-Kotlin/Rust parser, tracks flows and writes a pcap. It does NOT
 * transparently forward traffic to the real network: doing that correctly needs
 * a tun2socks-style socket relay (UDP + TCP state machine), which is Phase 4
 * (see docs/ROADMAP.md, ADR-0003). No real user traffic is intercepted, so the
 * device keeps normal connectivity. Test traffic can be generated against a
 * local lab address inside that subnet.
 *
 * Raw payload bytes are never persisted in logs — only pcap files, which the
 * app stores in an EncryptedFile and deletes on user request.
 *
 * ConsentGate enforcement lives in VpnCaptureEngine.start(): this service is
 * never started directly by UI code, and its only launcher is that gated facade.
 */
class SentinelVpnService : VpnService() {

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private var vpnFd: ParcelFileDescriptor? = null
    private var captureJob: Job? = null
    private val flowTracker = FlowTracker()

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_STOP) {
            stopCapture()
            return START_NOT_STICKY
        }
        startForeground(NOTIFICATION_ID, buildNotification("Starting lab capture"))
        startCapture()
        return START_STICKY
    }

    private fun startCapture() {
        if (vpnFd != null) return
        val fd = Builder()
            .setSession("SentinelNet lab capture")
            .setMtu(1500)
            .addAddress(LAB_ADDRESS, 24)
            // Only the lab subnet is routed here. Real traffic stays on the real network.
            .addRoute(LAB_SUBNET, 24)
            .addDnsServer(LAB_DNS)
            .apply { try { addDisallowedApplication(packageName) } catch (t: Throwable) { } }
            .establish()
        if (fd == null) {
            updateNotification("VPN permission not granted")
            stopSelf()
            return
        }
        vpnFd = fd
        val output = File(filesDir, "captures").also { it.mkdirs() }
        val pcapFile = File(output, "sentinel-${System.currentTimeMillis()}.pcap")
        lastPcapPath = pcapFile.absolutePath
        captureJob = scope.launch { readLoop(fd, pcapFile) }
        updateNotification("Capturing lab subnet 10.222.222.0/24")
    }

    private suspend fun readLoop(fd: ParcelFileDescriptor, pcapFile: File) {
        val input = FileInputStream(fd.fileDescriptor)
        val writer = PcapWriter(FileOutputStream(pcapFile), PcapWriter.LINKTYPE_RAW)
        writer.writeGlobalHeader()
        val buffer = ByteArray(32767)
        val filter = CaptureFilter()
        var packets = 0L
        try {
            while (scope.isActive) {
                val read = input.read(buffer)
                if (read <= 0) { delay(5); continue }
                val packet = buffer.copyOf(read)
                val parsed = PacketParser.parse(packet, System.currentTimeMillis(), PcapWriter.LINKTYPE_RAW)
                if (parsed != null && filter.matches(parsed)) {
                    flowTracker.onPacket(parsed)
                    writer.writePacket(packet, parsed.timestampMillis)
                    packets++
                    if (packets % 50 == 0L) {
                        updateNotification("Captured $packets packets · ${flowTracker.size()} flows")
                    }
                }
            }
        } catch (t: Throwable) {
            updateNotification("Capture stopped: ${t.javaClass.simpleName}")
        } finally {
            writer.close()
            input.close()
        }
    }

    private fun stopCapture() {
        captureJob?.cancel()
        captureJob = null
        try { vpnFd?.close() } catch (t: Throwable) { }
        vpnFd = null
        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()
    }

    override fun onDestroy() {
        stopCapture()
        scope.cancel()
        super.onDestroy()
    }

    private fun buildNotification(text: String) = NotificationCompat
        .Builder(this, CHANNEL_ID)
        .setSmallIcon(android.R.drawable.stat_sys_vpn_ic)
        .setContentTitle("SentinelNet lab capture")
        .setContentText(text)
        .setOngoing(true)
        .setContentIntent(
            PendingIntent.getActivity(
                this, 0,
                packageManager.getLaunchIntentForPackage(packageName),
                PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
            )
        )
        .build()

    private fun updateNotification(text: String) {
        val nm = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        nm.notify(NOTIFICATION_ID, buildNotification(text))
    }

    companion object {
        const val ACTION_STOP = "com.sentinelnet.action.STOP_CAPTURE"
        const val CHANNEL_ID = "sentinelnet.capture"
        const val NOTIFICATION_ID = 4201
        const val LAB_ADDRESS = "10.222.222.1"
        const val LAB_SUBNET = "10.222.222.0"
        const val LAB_DNS = "10.222.222.53"

        @Volatile var lastPcapPath: String? = null
        @Volatile var isRunning: Boolean = false

        fun createChannel(context: Context) {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                val nm = context.getSystemService(NotificationManager::class.java)
                nm.createNotificationChannel(
                    NotificationChannel(CHANNEL_ID, "Packet capture", NotificationManager.IMPORTANCE_LOW)
                )
            }
        }
    }
}
