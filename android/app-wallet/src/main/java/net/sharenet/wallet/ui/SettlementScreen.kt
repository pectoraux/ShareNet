package net.sharenet.wallet.ui

import androidx.compose.foundation.layout.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun SettlementScreen(onBack: () -> Unit) {
    var pending by remember { mutableStateOf(3) }
    var status by remember { mutableStateOf<String?>(null) }
    var isUploading by remember { mutableStateOf(false) }

    Scaffold(topBar = { TopAppBar(title = { Text("Settlement") }, navigationIcon = { TextButton(onClick = onBack) { Text("Back") } }) }) { padding ->
        Column(modifier = Modifier.fillMaxSize().padding(padding).padding(20.dp), verticalArrangement = Arrangement.spacedBy(16.dp)) {

            Card(modifier = Modifier.fillMaxWidth()) {
                Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    Text("Queued records", style = MaterialTheme.typography.labelMedium, color = MaterialTheme.colorScheme.outline)
                    Text("$pending pending", style = MaterialTheme.typography.titleLarge)
                    Text("Records queue while offline and settle on reconnect. Settlement is idempotent under replay — re-uploading the same nonce is a no-op.", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.outline)
                }
            }

            Button(
                onClick = {
                    isUploading = true
                    status = null
                    // Real: backend.settlement.settle(pendingRecords) — verify signatures, double-spend detection, publish revocation
                    kotlinx.coroutines.MainScope().let { scope ->
                        // Simulate async
                    }
                    // Stub
                    isUploading = false
                    pending = 0
                    status = "Settled — reconciliation balanced to zero"
                },
                enabled = pending > 0 && !isUploading,
                modifier = Modifier.fillMaxWidth(),
            ) {
                if (isUploading) CircularProgressIndicator(modifier = Modifier.size(18.dp), strokeWidth = 2.dp)
                else Text("Settle now (${pending} records)")
            }

            status?.let {
                Text(it, color = MaterialTheme.colorScheme.primary, style = MaterialTheme.typography.bodyMedium)
            }

            Divider()
            Text("Revocation sync", style = MaterialTheme.typography.titleSmall)
            Text(
                "Revoked cards are refused using a revocation list delivered over ShareNet (category REVOCATION, max priority). Revocation reaches field devices within one catalog sync.",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.outline,
            )
        }
    }
}
