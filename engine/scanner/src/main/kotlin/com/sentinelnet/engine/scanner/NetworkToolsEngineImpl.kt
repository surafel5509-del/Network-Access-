package com.sentinelnet.engine.scanner

import com.sentinelnet.core.consent.Capability
import com.sentinelnet.core.consent.ConsentGate
import com.sentinelnet.core.consent.ConsentRequests
import com.sentinelnet.core.consent.ConsentResult
import com.sentinelnet.engine.api.EngineStatus
import com.sentinelnet.engine.api.NetworkToolsEngine
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import okhttp3.OkHttpClient
import okhttp3.Request
import java.net.InetAddress
import java.util.concurrent.TimeUnit
import javax.inject.Inject
import javax.inject.Singleton

/**
 * Module E1 basics. Traceroute/MTR need raw sockets or a TTL-settable socket;
 * those are root-only and documented as a later phase (ADR-0004) rather than
 * faked with an incorrect implementation.
 *
 * Online tools (RDAP, HTTP headers) are opt-in: THREAT_INTEL is only allowed
 * when the user enabled online features in Settings, and every call is audited.
 */
@Singleton
class NetworkToolsEngineImpl @Inject constructor(
    private val consentGate: ConsentGate,
    private val client: OkHttpClient
) : NetworkToolsEngine {

    override val id = "nettools"
    override val displayName = "Network tools"
    override val requiredCapability = Capability.TRACEROUTE
    override fun status(): EngineStatus = EngineStatus.ok()

    override suspend fun ping(host: String, count: Int): List<Long?> = withContext(Dispatchers.IO) {
        (1..count.coerceIn(1, 20)).map {
            try {
                val start = System.nanoTime()
                val ok = InetAddress.getByName(host).isReachable(1000)
                if (ok) (System.nanoTime() - start) / 1_000_000 else null
            } catch (t: Throwable) { null }
        }
    }

    override suspend fun dnsLookup(host: String): List<String> = withContext(Dispatchers.IO) {
        try { InetAddress.getAllByName(host).mapNotNull { it.hostAddress } }
        catch (t: Throwable) { emptyList() }
    }

    override suspend fun httpHeaders(url: String): Map<String, String> = online {
        val request = Request.Builder().url(url).head()
            .header("User-Agent", "SentinelNet/0.1 (authorized audit)").build()
        client.newBuilder().callTimeout(6, TimeUnit.SECONDS).build().newCall(request).execute().use { response ->
            response.headers.toMultimap().mapValues { it.value.joinToString(", ") }
        }
    } ?: emptyMap()

    override suspend fun rdap(domain: String): String = online {
        val request = Request.Builder().url("https://rdap.org/domain/$domain").build()
        client.newBuilder().callTimeout(8, TimeUnit.SECONDS).build().newCall(request).execute().use { response ->
            response.body?.string()?.take(20_000).orEmpty()
        }
    } ?: ""

    /** Every online lookup is gated and audited as an opt-in data flow. */
    private suspend fun <T> online(block: () -> T): T? = withContext(Dispatchers.IO) {
        val result = consentGate.observe(ConsentRequests.passive(Capability.THREAT_INTEL)) { block() }
        when (result) {
            is ConsentResult.Allowed -> result.value
            is ConsentResult.Denied -> null
        }
    }
}
