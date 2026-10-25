package com.sentinelnet.engine.capture

import android.content.Context
import android.content.Intent
import com.sentinelnet.core.consent.Capability
import com.sentinelnet.core.consent.ConsentGate
import com.sentinelnet.core.consent.ConsentRequest
import com.sentinelnet.core.consent.ConsentResult
import com.sentinelnet.engine.api.CaptureEngine
import com.sentinelnet.engine.api.EngineStatus
import com.sentinelnet.engine.api.Requirement
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.coroutines.channels.awaitClose
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.callbackFlow
import java.io.File
import javax.inject.Inject
import javax.inject.Singleton

/** Consent-gated facade over SentinelVpnService. Also requests VPN consent via the OS dialog. */
@Singleton
class VpnCaptureEngine @Inject constructor(
    @ApplicationContext private val context: Context,
    private val consentGate: ConsentGate
) : CaptureEngine {

    override val id = "capture"
    override val displayName = "VpnService lab capture"
    override val requiredCapability = Capability.PACKET_CAPTURE

    override fun status(): EngineStatus = if (android.net.VpnService.prepare(context) == null) {
        EngineStatus.ok()
    } else {
        EngineStatus(false, Requirement.CONSENT, "Android VPN consent dialog must be accepted")
    }

    /** Caller must have obtained the OS VPN permission first (see CaptureViewModel). */
    override fun start(consent: ConsentRequest): Flow<String> = callbackFlow {
        val verdict = consentGate.guard(consent) { true }
        if (verdict is ConsentResult.Denied) {
            trySend("Capture denied: ${verdict.reason.name}")
            close()
            return@callbackFlow
        }
        SentinelVpnService.createChannel(context)
        context.startForegroundService(Intent(context, SentinelVpnService::class.java))
        SentinelVpnService.isRunning = true
        trySend("Lab capture started (10.222.222.0/24, metadata only)")
        awaitClose { stop() }
    }

    override fun stop() {
        context.startService(Intent(context, SentinelVpnService::class.java)
            .setAction(SentinelVpnService.ACTION_STOP))
        SentinelVpnService.isRunning = false
    }

    override fun isRunning(): Boolean = SentinelVpnService.isRunning

    override fun exportPcap(): File? = SentinelVpnService.lastPcapPath?.let { File(it).takeIf { f -> f.exists() } }
}
