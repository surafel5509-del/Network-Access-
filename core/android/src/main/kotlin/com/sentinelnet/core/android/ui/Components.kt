package com.sentinelnet.core.android.ui

import androidx.compose.foundation.Canvas
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.material3.AssistChip
import androidx.compose.material3.AssistChipDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.unit.dp
import com.sentinelnet.core.model.Severity

@Composable
fun ScoreGauge(score: Int, modifier: Modifier = Modifier.size(140.dp)) {
    val color = when {
        score >= 90 -> SentinelGreen
        score >= 70 -> SentinelBlue
        score >= 50 -> SentinelAmber
        else -> SentinelRed
    }
    val track = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.12f)
    Canvas(modifier = modifier.semantics { contentDescription = "Security score $score out of 100" }) {
        val thickness = 18.dp.toPx()
        drawArc(track, 135f, 270f, false, style = Stroke(thickness, cap = StrokeCap.Round))
        drawArc(color, 135f, 270f * score / 100f, false, style = Stroke(thickness, cap = StrokeCap.Round))
    }
}

@Composable
fun SeverityChip(severity: Severity) {
    val color = when (severity) {
        Severity.CRITICAL -> SentinelRed
        Severity.HIGH -> Color(0xFFFF7A45)
        Severity.MEDIUM -> SentinelAmber
        Severity.LOW -> SentinelBlue
        Severity.INFO -> Color.Gray
    }
    AssistChip(
        onClick = { },
        label = { Text(severity.name, style = MaterialTheme.typography.labelSmall) },
        colors = AssistChipDefaults.assistChipColors(labelColor = color),
        modifier = Modifier.semantics { contentDescription = "Severity: ${severity.name}" }
    )
}

@Composable
fun SectionCard(title: String, subtitle: String? = null, content: @Composable () -> Unit) {
    Card(
        modifier = Modifier.fillMaxWidth().padding(vertical = 6.dp),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface)
    ) {
        Column(Modifier.padding(16.dp)) {
            Text(title, style = MaterialTheme.typography.titleMedium)
            if (subtitle != null) {
                Spacer(Modifier.height(2.dp))
                Text(subtitle, style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.7f))
            }
            Spacer(Modifier.height(10.dp))
            content()
        }
    }
}

@Composable
fun SignalGraph(samples: List<Int>, modifier: Modifier = Modifier.fillMaxWidth().height(96.dp)) {
    if (samples.isEmpty()) return
    val line = SentinelGreen
    val grid = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.12f)
    Canvas(modifier = modifier.semantics { contentDescription = "Signal strength over time" }) {
        val stepX = size.width / (samples.size - 1).coerceAtLeast(1)
        val toY = { dbm: Int ->
            val normalized = ((dbm + 95).coerceIn(0, 65)) / 65f
            size.height - normalized * size.height
        }
        drawLine(grid, androidx.compose.ui.geometry.Offset(0f, size.height / 2),
            androidx.compose.ui.geometry.Offset(size.width, size.height / 2), 1.dp.toPx())
        for (i in 1 until samples.size) {
            drawLine(
                line,
                androidx.compose.ui.geometry.Offset((i - 1) * stepX, toY(samples[i - 1])),
                androidx.compose.ui.geometry.Offset(i * stepX, toY(samples[i])),
                3.dp.toPx(), StrokeCap.Round
            )
        }
    }
}

@Composable
fun KeyValueRow(key: String, value: String) {
    Row(
        Modifier.fillMaxWidth().padding(vertical = 3.dp),
        horizontalArrangement = Arrangement.SpaceBetween,
        verticalAlignment = Alignment.CenterVertically
    ) {
        Text(key, style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.7f))
        Text(value, style = MaterialTheme.typography.bodyMedium)
    }
}
