package net.sharenet.wallet.ui.theme

import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color

private val LightColors = lightColorScheme(
    primary = Color(0xFF1B4D6B),
    onPrimary = Color.White,
    primaryContainer = Color(0xFFCCE5FF),
    secondary = Color(0xFF51606F),
    surface = Color(0xFFF7F9FF),
    error = Color(0xFFBA1A1A),
)
private val DarkColors = darkColorScheme(
    primary = Color(0xFF8DCCFF),
    onPrimary = Color(0xFF003351),
    secondary = Color(0xFFB9C8DA),
    surface = Color(0xFF191C1E),
)

@Composable
fun ShareNetWalletTheme(darkTheme: Boolean = isSystemInDarkTheme(), content: @Composable () -> Unit) {
    MaterialTheme(colorScheme = if (darkTheme) DarkColors else LightColors, content = content)
}
