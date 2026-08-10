package net.sharenet.assistant.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Card
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.RadioButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun SettingsScreen(onBack: () -> Unit) {
    var selectedModel by remember { mutableStateOf("auto") }
    var selectedLang by remember { mutableStateOf("en") }

    Scaffold(topBar = {
        TopAppBar(
            title = { Text("Settings") },
            navigationIcon = { androidx.compose.material3.TextButton(onClick = onBack) { Text("‹ Back") } },
        )
    }) { padding ->
        Column(modifier = Modifier.fillMaxSize().padding(padding).padding(16.dp), verticalArrangement = Arrangement.spacedBy(18.dp)) {

            Text("Model", style = MaterialTheme.typography.titleSmall)
            Text("Tiered selection: 1B on <4GB RAM, 3–4B otherwise. Weights via ShareNet catalog MODEL_WEIGHTS.", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.outline)
            listOf("auto" to "Auto (tiered by RAM)", "1b" to "Gemma 1B (low RAM)", "4b" to "Gemma 4B (high RAM)").forEach { (value, label) ->
                Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                    Text(label, style = MaterialTheme.typography.bodyMedium)
                    RadioButton(selected = selectedModel == value, onClick = { selectedModel = value })
                }
            }
            Card(modifier = Modifier.fillMaxWidth()) {
                Text("Model: $selectedModel", modifier = Modifier.padding(12.dp), style = MaterialTheme.typography.bodySmall)
            }

            Text("Language", style = MaterialTheme.typography.titleSmall)
            listOf("en" to "English", "fr" to "Français").forEach { (code, label) ->
                Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                    Text(label, style = MaterialTheme.typography.bodyMedium)
                    RadioButton(selected = selectedLang == code, onClick = { selectedLang = code })
                }
            }
            Text("v1: EN/FR ASR + NLLB translation. Local languages via additional MODEL_WEIGHTS.", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.outline)
        }
    }
}
