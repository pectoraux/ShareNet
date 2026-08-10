package net.sharenet.demo.ui.theme

import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color

private val LightColors = lightColorScheme(
    primary = Color(0xFF1B6B4A),
    onPrimary = Color.White,
    primaryContainer = Color(0xFFA8F0C6),
    secondary = Color(0xFF4D6357),
    error = Color(0xFFBA1A1A),
    surface = Color(0xFFFBFDF8),
)

private val DarkColors = darkColorScheme(
    primary = Color(0xFF8CD4A5),
    onPrimary = Color(0xFF003823),
    primaryContainer = Color(0xFF00522F),
    secondary = Color(0xFFB5CCBE),
    error = Color(0xFFFFB4AB),
    surface = Color(0xFF191C1A),
)

@Composable
fun ShareNetDemoTheme(
    darkTheme: Boolean = isSystemInDarkTheme(),
    content: @Composable () -> Unit,
) {
    val scheme = if (darkTheme) DarkColors else LightColors
    MaterialTheme(colorScheme = scheme, content = content)
}
