package com.sentinelnet.core.consent

import kotlin.math.max

/** Sliding-window limiter for invasive actions. Protects the device and the network. */
class RateLimiter(private val clock: Clock = SystemClock) {
    private val lock = Any()
    private val stamps = mutableMapOf<String, ArrayDeque<Long>>()

    fun tryAcquire(key: String, maxPerMinute: Int): Boolean {
        if (maxPerMinute <= 0) return false
        val now = clock.nowMillis()
        synchronized(lock) {
            val q = stamps.getOrPut(key) { ArrayDeque() }
            val windowStart = now - 60_000L
            while (q.isNotEmpty() && q.first() < windowStart) q.removeFirst()
            if (q.size >= max(1, maxPerMinute)) return false
            q.addLast(now)
            return true
        }
    }

    fun count(key: String): Int = synchronized(lock) { stamps[key]?.size ?: 0 }
    fun reset() = synchronized(lock) { stamps.clear() }
}
