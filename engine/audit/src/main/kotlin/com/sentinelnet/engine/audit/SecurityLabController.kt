package com.sentinelnet.engine.audit

import com.sentinelnet.core.consent.Capability
import com.sentinelnet.core.consent.ConsentGate
import com.sentinelnet.core.consent.ConsentRequest
import com.sentinelnet.core.consent.ConsentResult
import com.sentinelnet.core.crypto.Bytes
import com.sentinelnet.core.crypto.PassphraseAudit
import com.sentinelnet.core.crypto.WpaPskLab
import javax.inject.Inject
import javax.inject.Singleton

/**
 * Android-facing controller for the offline WPA Security Lab.
 *
 * SAFETY: this controller can ONLY analyse a handshake the user already has
 * (imported from a file they own, or generated locally by the app). It has no
 * path to a live scan result, no BSSID targeting, no deauth and no capture.
 * Every exercise is gated by SECURITY_LAB (biometric + authorization + audit).
 */
@Singleton
class SecurityLabController @Inject constructor(private val consentGate: ConsentGate) {

    fun auditOwnPassphrase(passphrase: String): PassphraseAudit.Verdict = PassphraseAudit.audit(passphrase)

    /** Locally generated teaching vector — the recommended first-run experience. */
    fun syntheticLesson(ssid: String, passphrase: String): WpaPskLab.HandshakeSample =
        WpaPskLab.syntheticHandshake(ssid, passphrase)

    fun verifyOne(sample: WpaPskLab.HandshakeSample, candidate: String): WpaPskLab.LabResult =
        WpaPskLab.verify(sample, candidate)

    fun runExercise(
        sample: WpaPskLab.HandshakeSample,
        wordlist: List<String>,
        consent: ConsentRequest
    ): Result<WpaPskLab.LabExercise> {
        val verdict = consentGate.guard(consent) {
            WpaPskLab.exercise(sample, wordlist.asSequence().take(WpaPskLab.MAX_CANDIDATES))
        }
        return when (verdict) {
            is ConsentResult.Allowed -> Result.success(verdict.value)
            is ConsentResult.Denied -> Result.failure(
                SecurityException("${verdict.reason.name}: ${verdict.detail}")
            )
        }
    }

    /**
     * Imports a handshake from a simple key=value text format (see
     * docs/SECURITY_LAB.md). Fields: ssid, ap, sta, anonce, snonce, eapol, mic, kdv.
     * Hex fields must be even-length hex. Accessing this file requires the user
     * to pick it through the Storage Access Framework — no directory scanning.
     */
    fun importHandshake(text: String): WpaPskLab.HandshakeSample? {
        return try {
            val fields = text.lines()
                .map { it.trim() }
                .filter { it.isNotBlank() && !it.startsWith("#") && '=' in it }
                .associate { it.substringBefore('=').trim().lowercase() to it.substringAfter('=').trim() }
            val ssid = fields["ssid"] ?: return null
            val ap = Bytes.fromMac(fields["ap"] ?: return null)
            val sta = Bytes.fromMac(fields["sta"] ?: return null)
            val anonce = Bytes.fromHex(fields["anonce"] ?: return null)
            val snonce = Bytes.fromHex(fields["snonce"] ?: return null)
            val eapol = Bytes.fromHex(fields["eapol"] ?: return null)
            val mic = Bytes.fromHex(fields["mic"] ?: return null)
            val kdv = fields["kdv"]?.toIntOrNull() ?: 2
            if (anonce.size != 32 || snonce.size != 32 || mic.size != 16 || kdv !in 1..2) return null
            WpaPskLab.HandshakeSample(ssid, ap, sta, anonce, snonce, eapol, mic, kdv, false)
        } catch (t: Throwable) { null }
    }
}
