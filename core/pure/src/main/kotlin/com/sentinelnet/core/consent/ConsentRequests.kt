package com.sentinelnet.core.consent

import java.util.UUID

/** Single place where fresh nonces are minted; never reuse a nonce for two actions. */
object ConsentRequests {
    fun newNonce(): String = UUID.randomUUID().toString()

    fun passive(capability: Capability, actor: String = "local-user", sessionId: String = "default"): ConsentRequest =
        ConsentRequest(capability, newNonce(), "-", actor, sessionId, null)

    fun active(
        capability: Capability,
        target: String,
        decision: ConsentDecision?,
        actor: String = "local-user",
        sessionId: String = "default"
    ): ConsentRequest = ConsentRequest(capability, newNonce(), target, actor, sessionId, decision)
}
