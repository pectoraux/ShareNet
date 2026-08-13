package net.sharenet.assistant.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewmodel.compose.viewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import net.sharenet.assistant.contribution.Contribution
import net.sharenet.assistant.contribution.ContributionQueue

class ContributionViewModel(
    val queue: ContributionQueue = ContributionQueue(),
) : ViewModel() {
    val consentGranted: StateFlow<Boolean> = queue.consentGranted
    val pending: StateFlow<List<Contribution>> = queue.queue
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ContributionScreen(
    onBack: () -> Unit,
    viewModel: ContributionViewModel = viewModel { ContributionViewModel() },
) {
    val consent by viewModel.consentGranted.collectAsState()
    val pending by viewModel.pending.collectAsState()
    var correction by remember { mutableStateOf("") }
    var sourceLang by remember { mutableStateOf("en") }
    var targetLang by remember { mutableStateOf("fr") }

    Scaffold(topBar = {
        TopAppBar(
            title = { Text("Contribute") },
            navigationIcon = { androidx.compose.material3.TextButton(onClick = onBack) { Text("‹ Back") } },
        )
    }) { padding ->
        LazyColumn(modifier = Modifier.fillMaxSize().padding(padding).padding(16.dp), verticalArrangement = Arrangement.spacedBy(14.dp)) {

            item {
                Card(modifier = Modifier.fillMaxWidth()) {
                    Column(modifier = Modifier.padding(14.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                        Text("Consent", style = MaterialTheme.typography.titleSmall)
                        Text("Your corrections help improve the model. They are signed with your device key and queued for delivery when online. You can opt out at any time.", style = MaterialTheme.typography.bodySmall)
                        androidx.compose.foundation.layout.Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                            Text(if (consent) "I consent" else "Consent required")
                            Switch(checked = consent, onCheckedChange = { viewModel.queue.setConsent(it) })
                        }
                    }
                }
            }

            item {
                Text("Correction UI", style = MaterialTheme.typography.titleSmall)
                OutlinedTextField(
                    value = correction,
                    onValueChange = { correction = it },
                    label = { Text("Correct the response") },
                    modifier = Modifier.fillMaxWidth(),
                    minLines = 3,
                )
                androidx.compose.foundation.layout.Row(horizontalArrangement = Arrangement.spacedBy(8.dp), modifier = Modifier.padding(top = 8.dp)) {
                    OutlinedTextField(value = sourceLang, onValueChange = { sourceLang = it }, label = { Text("From") }, modifier = Modifier.weight(1f))
                    OutlinedTextField(value = targetLang, onValueChange = { targetLang = it }, label = { Text("To") }, modifier = Modifier.weight(1f))
                }
                Button(
                    onClick = {
                        if (correction.isBlank()) return@Button
                        viewModel.queue.enqueue(
                            Contribution(
                                contributorId = "node-self",
                                sourceLang = sourceLang,
                                targetLang = targetLang,
                                sourceText = "original model output placeholder",
                                correctedText = correction,
                                originalModelOutput = "original model output placeholder",
                                modelVersion = "gemma-1b-v1",
                            ),
                        )
                        correction = ""
                    },
                    enabled = consent && correction.isNotBlank(),
                    modifier = Modifier.fillMaxWidth().padding(top = 8.dp),
                ) { Text("Submit correction") }
                Text("Queued (${pending.size} pending) — signed ✓ when consent granted", style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.outline)
            }

            item {
                Text("Contributor Dashboard", style = MaterialTheme.typography.titleSmall)
                if (pending.isEmpty()) {
                    Text("No contributions yet.", style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.outline)
                }
            }

            items(pending) { c ->
                Card(modifier = Modifier.fillMaxWidth()) {
                    Column(modifier = Modifier.padding(12.dp)) {
                        Text(c.correctedText, style = MaterialTheme.typography.bodyMedium)
                        Text("${c.sourceLang} → ${c.targetLang} · ${if (c.isSigned()) "Signed ✓" else "Unsigned"}", style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.outline)
                    }
                }
            }
        }
    }
}
