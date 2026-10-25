package com.sentinelnet.engine.scanner

import com.sentinelnet.core.consent.Capability
import com.sentinelnet.core.consent.ConsentGate
import com.sentinelnet.core.consent.ConsentRequest
import com.sentinelnet.core.consent.ConsentResult
import com.sentinelnet.core.domain.CveHintMatcher
import com.sentinelnet.core.model.PortResult
import com.sentinelnet.core.model.PortState
import com.sentinelnet.engine.api.EngineStatus
import com.sentinelnet.engine.api.PortScanEngine
import com.sentinelnet.engine.api.ScanConfig
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.channelFlow
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Semaphore
import kotlinx.coroutines.sync.withPermit
import java.net.InetSocketAddress
import java.net.Socket
import javax.inject.Inject
import javax.inject.Singleton

/**
 * TCP Connect scan — the only port-scan technique that needs no root or raw
 * sockets, so it works on every device from minSdk 26. SYN/FIN/NULL/XMAS scans
 * are root-only and intentionally NOT implemented in the foundation phase
 * (see docs/ROADMAP.md and ADR-0004).
 *
 * The ConsentGate is evaluated inside the cold flow, at collection time, so a
 * scan can never start without a fresh decision bound to this exact target.
 */
@Singleton
class TcpConnectScanner @Inject constructor(
    private val consentGate: ConsentGate,
    private val cveHintMatcher: CveHintMatcher
) : PortScanEngine {

    override val id = "portscan"
    override val displayName = "TCP Connect port scanner"
    override val requiredCapability = Capability.PORT_SCAN

    override fun status(): EngineStatus = EngineStatus.ok()

    override fun scan(config: ScanConfig, consent: ConsentRequest): Flow<PortResult> = channelFlow {
        val verdict = consentGate.guard(consent) { true }
        if (verdict is ConsentResult.Denied) {
            throw SecurityException("Port scan denied: ${verdict.reason.name} — ${verdict.detail}")
        }
        require(config.concurrency in 1..512) { "concurrency out of range" }
        require(config.ports.size <= 65_535) { "too many ports" }
        val semaphore = Semaphore(config.concurrency)
        coroutineScope {
            for (port in config.ports.distinct().sorted()) {
                launch(Dispatchers.IO) {
                    semaphore.withPermit { send(probe(config, port)) }
                }
            }
        }
    }

    private fun probe(config: ScanConfig, port: Int): PortResult {
        val start = System.currentTimeMillis()
        return try {
            Socket().use { socket ->
                socket.connect(InetSocketAddress(config.target, port), config.connectTimeoutMs)
                socket.soTimeout = config.connectTimeoutMs
                val banner = if (config.grabBanner && isPlaintextBannerPort(port)) {
                    BannerGrabber.grab(socket, config.target, port)
                } else null
                val version = BannerGrabber.versionFrom(banner)
                val tls = if (config.inspectTls && port in TLS_PORTS) {
                    BannerGrabber.tlsSubject(config.target, port, config.connectTimeoutMs * 2)
                } else null
                PortResult(
                    target = config.target, port = port, protocol = "tcp", state = PortState.OPEN,
                    banner = banner, service = BannerGrabber.serviceFor(port), version = version,
                    latencyMs = System.currentTimeMillis() - start, tlsSubject = tls
                )
            }
        } catch (e: java.net.ConnectException) {
            PortResult(config.target, port, "tcp", PortState.CLOSED, latencyMs = System.currentTimeMillis() - start)
        } catch (e: java.net.SocketTimeoutException) {
            PortResult(config.target, port, "tcp", PortState.FILTERED, latencyMs = System.currentTimeMillis() - start)
        } catch (e: Throwable) {
            PortResult(config.target, port, "tcp", PortState.ERROR, banner = e.javaClass.simpleName,
                latencyMs = System.currentTimeMillis() - start)
        }
    }

    private fun isPlaintextBannerPort(port: Int): Boolean = port !in TLS_PORTS

    /** Passive hints are attached to the result list by the audit engine, not here. */
    fun hintsFor(result: PortResult) = cveHintMatcher.match(
        result.service, result.version, result.banner, result.target)

    companion object {
        val TLS_PORTS = setOf(443, 8443, 993, 995, 465, 587, 636)
    }
}
