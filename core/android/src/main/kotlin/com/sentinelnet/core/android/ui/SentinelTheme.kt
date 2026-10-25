package com.sentinelnet.core.android.ui

import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Typography
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalLayoutDirection
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.LayoutDirection
import androidx.compose.ui.unit.sp
import java.util.Locale

val SentinelGreen = Color(0xFF00E5A0)
val SentinelGreenDark = Color(0xFF00B37C)
val SentinelNavy = Color(0xFF0B1220)
val SentinelAmber = Color(0xFFFFB020)
val SentinelRed = Color(0xFFFF4D5E)
val SentinelBlue = Color(0xFF4C8DFF)

private val DarkColors = darkColorScheme(
    primary = SentinelGreen, onPrimary = SentinelNavy,
    secondary = SentinelBlue, background = SentinelNavy,
    surface = Color(0xFF131C2B), onSurface = Color(0xFFE8EEF6),
    error = SentinelRed
)

private val LightColors = lightColorScheme(
    primary = SentinelGreenDark, onPrimary = Color.White,
    secondary = SentinelBlue, background = Color(0xFFF5F7FA),
    surface = Color.White, onSurface = Color(0xFF101828),
    error = SentinelRed
)

/** AMOLED variant: pure black surfaces, high-contrast text. */
private val AmoledColors = DarkColors.copy(
    background = Color.Black, surface = Color(0xFF0A0A0A), onSurface = Color.White
)

private val SentinelTypography = Typography(
    headlineMedium = TextStyle(fontWeight = FontWeight.Bold, fontSize = 26.sp),
    titleMedium = TextStyle(fontWeight = FontWeight.SemiBold, fontSize = 18.sp),
    bodyMedium = TextStyle(fontSize = 14.sp, lineHeight = 20.sp),
    labelSmall = TextStyle(fontSize = 11.sp, fontWeight = FontWeight.Medium)
)

/**
 * Material 3 theme with full RTL support. Amharic/Arabic/Hebrew flip the layout
 * direction at the root, so every screen inherits it — WCAG 2.1 AA friendly.
 */
@Composable
fun SentinelTheme(
    darkTheme: Boolean = isSystemInDarkTheme(),
    amoled: Boolean = false,
    highContrast: Boolean = false,
    content: @Composable () -> Unit
) {
    val colors = when {
        highContrast -> DarkColors.copy(onSurface = Color.White, onBackground = Color.White)
        amoled -> AmoledColors
        darkTheme -> DarkColors
        else -> LightColors
    }
    val rtlLanguages = setOf("am", "ar", "he", "fa", "ur")
    val direction = if (Locale.getDefault().language in rtlLanguages) LayoutDirection.Rtl else LayoutDirection.Ltr
    CompositionLocalProvider(LocalLayoutDirection provides direction) {
        MaterialTheme(colorScheme = colors, typography = SentinelTypography, content = content)
    }
}
