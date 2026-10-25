package com.sentinelnet.engine.api

import com.sentinelnet.core.consent.Capability

/**
 * Every engine advertises what it needs BEFORE any action runs. The UI shows
 * this in the "Requirements" chip and refuses to launch when unavailable —
 * the root-optional / graceful-degradation rule from the spec.
 */
enum class Requirement { NONE, PERMISSION, BIOMETRIC, ROOT, SHIZUKU, HARDWARE, CONSENT, NOT_IMPLEMENTED }

data class EngineStatus(
    val available: Boolean,
    val requirement: Requirement = Requirement.NONE,
    val detail: String = ""
) {
    companion object {
        fun ok() = EngineStatus(true)
        fun permission(name: String) = EngineStatus(false, Requirement.PERMISSION, "Needs $name")
        fun notImplemented(feature: String) = EngineStatus(false, Requirement.NOT_IMPLEMENTED,
            "$feature is scheduled in a later roadmap phase (see docs/ROADMAP.md)")
    }
}

/** Stable engine contract. UI never touches Android system APIs directly. */
interface SentinelEngine {
    val id: String
    val displayName: String
    /** The capability the ConsentGate checks before any invasive operation. */
    val requiredCapability: Capability
    fun status(): EngineStatus
}
