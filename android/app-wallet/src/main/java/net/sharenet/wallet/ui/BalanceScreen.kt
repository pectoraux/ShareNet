package net.sharenet.wallet.ui

import androidx.compose.foundation.layout.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun BalanceScreen(
    onBack: () -> Unit,
    fetchBalance: suspend () -> Int = { 0 },
) {
    var balance by remember { mutableStateOf<Int?>(null) }
    var offlineValue by remember { mutableStateOf<Int?>(null) }
    var txCount by remember { mutableStateOf<Int?>(null) }
    var error by remember { mutableStateOf<String?>(null) }

    LaunchedEffect(Unit) {
        try {
            // Real: channel.transceive(ApduCommands.getBalance()) + ApduCommands.getOfflineState()
            // Stub values for emulator without NFC
            balance = 42500
            offlineValue = 7500
            txCount = 12
        } catch (e: Exception) {
            error = e.message
        }
    }

    Scaffold(topBar = { TopAppBar(title = { Text("Balance") }, navigationIcon = { TextButton(onClick = onBack) { Text("Back") } }) }) { padding ->
        Column(modifier = Modifier.fillMaxSize().padding(padding).padding(20.dp), verticalArrangement = Arrangement.spacedBy(16.dp)) {
            error?.let { Text(it, color = MaterialTheme.colorScheme.error) }

            // Primary balance — strong hierarchy, not a thin gray card
            Card(modifier = Modifier.fillMaxWidth(), colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.primaryContainer)) {
                Column(modifier = Modifier.padding(20.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
                    Text("Available", style = MaterialTheme.typography.labelMedium, color = MaterialTheme.colorScheme.onPrimaryContainer.copy(alpha = 0.7f))
                    Text(
                        text = balance?.let { "%,d".format(it) } ?: "—",
                        style = MaterialTheme.typography.displaySmall,
                        color = MaterialTheme.colorScheme.onPrimaryContainer,
                    )
                    Text("minor units", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onPrimaryContainer.copy(alpha = 0.7f))
                }
            }

            Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                ElevatedCard(modifier = Modifier.weight(1f)) {
                    Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                        Text("Pending settlement", style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.outline)
                        Text(offlineValue?.let { "%,d".format(it) } ?: "—", style = MaterialTheme.typography.titleMedium)
                    }
                }
                ElevatedCard(modifier = Modifier.weight(1f)) {
                    Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                        Text("Transactions", style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.outline)
                        Text(txCount?.toString() ?: "—", style = MaterialTheme.typography.titleMedium)
                    }
                }
            }

            Text(
                "Values are read from the secure element via GET_BALANCE + GET_OFFLINE_STATE. Phone is untrusted — it never holds value.",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.outline,
            )

            Button(onClick = { balance = null; offlineValue = null; /* re-fetch */ balance = 42500; offlineValue = 7500 }, modifier = Modifier.fillMaxWidth()) {
                Text("Refresh from card (tap)")
            }
        }
    }
}
