package com.sentinelnet.core.crypto

/**
 * SentinelNet Security Lab — WPA/WPA2 personal-mode key derivation.
 *
 * !! SCOPE AND SAFETY BOUNDARY !!
 * This is an OFFLINE, EDUCATIONAL implementation of IEEE 802.11i key
 * derivation. It operates ONLY on data the user already possesses and imports
 * explicitly (a handshake from their OWN network or an authorized engagement),
 * or on a synthetic handshake generated locally by [syntheticHandshake].
 *
 * SentinelNet does NOT and WILL NOT:
 *  - put a Wi-Fi radio into monitor mode, inject frames, or send deauth frames;
 *  - capture handshakes from networks around the device;
 *  - target a nearby SSID/BSSID discovered by a scan;
 *  - use cloud/GPU cracking, distributed cracking, or bundled password lists.
 * Stock Android hardware cannot do any of those things anyway. The lab exists
 * so students can SEE why a weak WPA passphrase is recoverable and why WPA3-SAE
 * (Simultaneous Authentication of Equals) fixes it — on their own equipment.
 *
 * Every call from the Android layer must pass through ConsentGate with
 * Capability.SECURITY_LAB (biometric + authorization assertion + audit event).
 */
object WpaPskLab {
    const val WPA_ITERATIONS = 4096
    const val PMK_LENGTH = 32
    const val PTK_LENGTH = 64
    const val KCK_LENGTH = 16
    /** Hard caps keep the lab battery-friendly and prevent it becoming a cracker. */
    const val MAX_CANDIDATES = 200_000
    const val MAX_LAB_MILLIS = 30_000L

    /** PMK = PBKDF2-HMAC-SHA1(passphrase, ssid, 4096, 32). */
    fun derivePmk(ssid: String, passphrase: String): ByteArray =
        Pbkdf2.hmacSha1(
            password = passphrase.toByteArray(Charsets.UTF_8),
            salt = ssid.toByteArray(Charsets.UTF_8),
            iterations = WPA_ITERATIONS,
            derivedKeyLength = PMK_LENGTH
        )

    /**
     * PTK = PRF-512(PMK, "Pairwise key expansion", Min(AA,SPA)||Max(AA,SPA)||
     *        Min(ANonce,SNonce)||Max(ANonce,SNonce)).
     * The 802.11i PRF uses a NUL separator after the label and a 1-byte counter.
     */
    fun derivePtk(
        pmk: ByteArray,
        apMac: ByteArray,
        staMac: ByteArray,
        aNonce: ByteArray,
        sNonce: ByteArray
    ): ByteArray {
        require(pmk.size == PMK_LENGTH) { "PMK must be 32 bytes" }
        require(apMac.size == 6 && staMac.size == 6) { "MACs must be 6 bytes" }
        require(aNonce.size == 32 && sNonce.size == 32) { "Nonces must be 32 bytes" }
        val label = "Pairwise key expansion".toByteArray(Charsets.US_ASCII)
        val prefix = Bytes.concat(
            label, byteArrayOf(0),
            Bytes.min(apMac, staMac), Bytes.max(apMac, staMac),
            Bytes.min(aNonce, sNonce), Bytes.max(aNonce, sNonce)
        )
        val out = ByteArray(80) // 4 x HMAC-SHA1 blocks
        for (i in 0..3) {
            val input = Bytes.concat(prefix, byteArrayOf(i.toByte()))
            Hmac.sha1(pmk, input).copyInto(out, i * 20)
        }
        return out.copyOf(PTK_LENGTH)
    }

    /** EAPOL-Key MIC over the frame with its MIC field zeroed, as specified. */
    fun computeMic(keyDescriptorVersion: Int, kck: ByteArray, eapolFrameWithZeroedMic: ByteArray): ByteArray? =
        when (keyDescriptorVersion) {
            1 -> Hmac.md5(kck, eapolFrameWithZeroedMic)                    // WPA / TKIP
            2 -> Hmac.sha1(kck, eapolFrameWithZeroedMic).copyOf(16)        // WPA2 / CCMP
            // KDV 3 can require AES-128-CMAC; returning null is honest rather than wrong.
            else -> null
        }

    /**
     * A locally generated, deterministic teaching handshake. Nothing is captured
     * from the air: the nonces are fixed constants and the EAPOL frame is a
     * minimal, clearly-labelled synthetic structure.
     */
    fun syntheticHandshake(ssid: String, passphrase: String, keyDescriptorVersion: Int = 2): HandshakeSample {
        val apMac = Bytes.fromMac("00:1A:2B:3C:4D:5E")
        val staMac = Bytes.fromMac("7C:2E:BD:11:22:33")
        val aNonce = ByteArray(32) { (it * 7 + 3).toByte() }
        val sNonce = ByteArray(32) { (it * 13 + 29).toByte() }
        // EAPOL-Key header (protocol version 2, type 3 = Key), key info, replay
        // counter, nonces and a 16-byte MIC field that MUST be zeroed.
        val frame = ByteArray(95)
        frame[0] = 2; frame[3] = 3
        frame[5] = 0x08 // Key MIC bit set (informational for the lab)
        aNonce.copyInto(frame, 17)
        sNonce.copyInto(frame, 49)
        // bytes 81..96 would be the MIC: left at zero.
        return HandshakeSample(
            ssid = ssid,
            apMac = apMac,
            staMac = staMac,
            aNonce = aNonce,
            sNonce = sNonce,
            eapolFrameWithZeroedMic = frame,
            expectedMic = ByteArray(16),
            keyDescriptorVersion = keyDescriptorVersion,
            synthetic = true
        ).withCorrectMic(passphrase)
    }

    /** Verify one candidate passphrase against an already-imported handshake. */
    fun verify(sample: HandshakeSample, candidate: String): LabResult {
        if (sample.keyDescriptorVersion !in 1..2) {
            return LabResult(false, candidate, "unsupported KDV ${sample.keyDescriptorVersion}", "", "", 0)
        }
        val pmk = derivePmk(sample.ssid, candidate)
        val ptk = derivePtk(pmk, sample.apMac, sample.staMac, sample.aNonce, sample.sNonce)
        val kck = ptk.copyOf(KCK_LENGTH)
        val mic = computeMic(sample.keyDescriptorVersion, kck, sample.eapolFrameWithZeroedMic)
            ?: return LabResult(false, candidate, "unsupported MIC algorithm", "", "", 0)
        return LabResult(
            matched = Bytes.constantTimeEquals(mic, sample.expectedMic),
            candidate = candidate,
            computedMicHex = Bytes.toHex(mic, lowerCase = true),
            expectedMicHex = Bytes.toHex(sample.expectedMic, lowerCase = true),
            pmkHex = Bytes.toHex(pmk, lowerCase = true),
            elapsedMs = 0
        )
    }

    /**
     * Offline dictionary exercise over a USER-SUPPLIED list and a USER-SUPPLIED
     * handshake. Capped in count and wall-clock time. Returns the first match
     * or the number tested. Intentionally single-threaded and slow: this is a
     * teaching instrument, not a high-throughput password cracker.
     */
    fun exercise(sample: HandshakeSample, candidates: Sequence<String>, clock: () -> Long = System::currentTimeMillis): LabExercise {
        val start = clock()
        var tested = 0
        for (candidate in candidates) {
            if (tested >= MAX_CANDIDATES || clock() - start > MAX_LAB_MILLIS) break
            tested++
            val result = verify(sample, candidate)
            if (result.matched) {
                return LabExercise(found = candidate, tested = tested, elapsedMs = clock() - start, capped = false)
            }
        }
        val elapsed = clock() - start
        return LabExercise(
            found = null, tested = tested, elapsedMs = elapsed,
            capped = tested >= MAX_CANDIDATES || elapsed > MAX_LAB_MILLIS
        )
    }

    data class HandshakeSample(
        val ssid: String,
        val apMac: ByteArray,
        val staMac: ByteArray,
        val aNonce: ByteArray,
        val sNonce: ByteArray,
        val eapolFrameWithZeroedMic: ByteArray,
        val expectedMic: ByteArray,
        val keyDescriptorVersion: Int,
        val synthetic: Boolean
    ) {
        /** Fills in the expected MIC from the known passphrase (teaching test vector). */
        fun withCorrectMic(passphrase: String): HandshakeSample {
            val pmk = derivePmk(ssid, passphrase)
            val ptk = derivePtk(pmk, apMac, staMac, aNonce, sNonce)
            val mic = computeMic(keyDescriptorVersion, ptk.copyOf(KCK_LENGTH), eapolFrameWithZeroedMic)
                ?: ByteArray(16)
            return copy(expectedMic = mic)
        }
    }

    data class LabResult(
        val matched: Boolean,
        val candidate: String,
        val computedMicHex: String,
        val expectedMicHex: String,
        val pmkHex: String,
        val elapsedMs: Long
    )

    data class LabExercise(
        val found: String?, val tested: Int, val elapsedMs: Long, val capped: Boolean
    )
}
