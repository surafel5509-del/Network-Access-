package com.sentinelnet.core.domain

import com.sentinelnet.core.model.Band
import com.sentinelnet.core.model.ChannelLoad
import com.sentinelnet.core.model.ChannelRecommendation
import com.sentinelnet.core.model.WifiChannels
import com.sentinelnet.core.model.WifiNetwork
import kotlin.math.abs
import kotlin.math.exp

/**
 * Channel congestion + best-channel recommendation.
 *
 * For 2.4 GHz, neighbouring channels overlap: an AP on channel 3 interferes
 * with channels 1 and 6. We model that with a Gaussian kernel over channel
 * distance, weighted by received signal strength. Only 1/6/11 are ever
 * recommended (the non-overlapping set). 5/6 GHz use their own channel grid.
 */
class ChannelAdvisor(private val oui: OuiLookup = OuiLookup()) {

    fun analyze(networks: List<WifiNetwork>): List<ChannelLoad> {
        val observed = networks.filter { it.channel > 0 && it.band != Band.UNKNOWN }
        val channelsByBand = observed.map { it.band }.toSet()
        return channelsByBand.flatMap { band ->
            val candidates = when (band) {
                Band.GHZ_2_4 -> (1..14).toList()
                Band.GHZ_5 -> WifiChannels.COMMON_5
                Band.GHZ_6 -> (1..10).toList()
                Band.UNKNOWN -> emptyList()
            }
            candidates.map { ch ->
                val apCount = observed.count { it.band == band && it.channel == ch }
                val congestion = observed.filter { it.band == band }
                    .sumOf { ap -> interference(ap, ch, band) * signalWeight(ap.rssiDbm) }
                ChannelLoad(ch, band, apCount, congestion)
            }
        }.sortedWith(compareBy({ it.band.ordinal }, { it.channel }))
    }

    fun recommend(band: Band, networks: List<WifiNetwork>): ChannelRecommendation {
        val candidates = when (band) {
            Band.GHZ_2_4 -> WifiChannels.NON_OVERLAPPING_2_4
            Band.GHZ_5 -> WifiChannels.COMMON_5
            Band.GHZ_6 -> (1..10).toList()
            Band.UNKNOWN -> return ChannelRecommendation(
                band, -1, -1, 0.0, "No networks observed; join a network first."
            )
        }
        val observed = networks.filter { it.band == band && it.channel > 0 }
        if (observed.isEmpty()) {
            return ChannelRecommendation(
                band, candidates.first(), WifiChannels.channelToFrequency(candidates.first(), band),
                100.0, "No access points observed in this band; channel is clear."
            )
        }
        val loads = candidates.map { ch ->
            val congestion = observed.sumOf { ap -> interference(ap, ch, band) * signalWeight(ap.rssiDbm) }
            // Wider channels occupy more spectrum, so penalize them slightly.
            val widthPenalty = observed.filter { it.band == band }
                .sumOf { ap -> interference(ap, ch, band) * (ap.channelWidthMhz / 20.0 - 1.0) }
            ch to congestion + widthPenalty * 0.4
        }.sortedBy { it.second }

        val best = loads.first()
        val worst = loads.last().second
        val normalized = if (worst <= 0.0) 100.0 else (1.0 - best.second / (worst + 1e-9)) * 100.0
        val score = normalized.coerceIn(0.0, 100.0)
        val freq = WifiChannels.channelToFrequency(best.first, band)
        val reason = buildString {
            append("Channel ${best.first} has the lowest weighted congestion ")
            append("(%.2f) across ${observed.size} AP(s)".format(best.second))
            if (band == Band.GHZ_2_4) append("; 1/6/11 avoid co-channel overlap")
            if (band == Band.GHZ_6) append("; 6 GHz prefers Wi-Fi 6E/7 clients")
            append(".")
        }
        return ChannelRecommendation(
            band = band, channel = best.first, frequencyMhz = freq, score = score,
            reason = reason, alternatives = loads.drop(1).take(2).map { it.first }
        )
    }

    /** Vendors with unusually strong signals can indicate an attacker nearby. */
    fun suspiciouslyStrong(networks: List<WifiNetwork>, thresholdDbm: Int = -35): List<WifiNetwork> =
        networks.filter { it.rssiDbm > thresholdDbm }

    private fun signalWeight(rssiDbm: Int): Double {
        // -30 dBm (adjacent) is far more disruptive than -85 dBm (edge of range).
        val clamped = rssiDbm.coerceIn(-95, -30)
        return 1.0 + 3.0 * exp((clamped + 95) / 22.0)
    }

    private fun interference(ap: WifiNetwork, channel: Int, band: Band): Double {
        val distance = abs(ap.channel - channel)
        val sigma = when (band) {
            Band.GHZ_2_4 -> 2.2   // ~4-5 channels of overlap at 20 MHz
            Band.GHZ_5 -> 0.9
            Band.GHZ_6 -> 0.9
            Band.UNKNOWN -> 1.0
        }
        val widthFactor = 1.0 + (ap.channelWidthMhz - 20).coerceAtLeast(0) / 40.0
        return exp(-(distance * distance) / (2.0 * sigma * sigma)) * widthFactor
    }

    /** Exposed for UI overlays: vendor name for a network whose BSSID is globally unique. */
    fun annotateVendor(network: WifiNetwork): String? = oui.lookup(network.bssid)
}
