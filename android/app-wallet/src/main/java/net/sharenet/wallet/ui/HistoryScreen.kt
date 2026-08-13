package net.sharenet.wallet.ui

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp

data class UiTx(val counter: Int, val amount: Int, val nonce: String, val settled: Boolean)

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun HistoryScreen(onBack: () -> Unit) {
    // Stub history — real from WalletDatabase TxLogDao
    var txs by remember {
        mutableStateOf(
            listOf(
                UiTx(12, 5000, "a1b2c3d4", false),
                UiTx(11, 2500, "e5f6a7b8", true),
                UiTx(10, 10000, "c9d0e1f2", true),
                UiTx(9, 750, "a3b4c5d6", true),
            )
        )
    }

    Scaffold(topBar = { TopAppBar(title = { Text("History") }, navigationIcon = { TextButton(onClick = onBack) { Text("Back") } }) }) { padding ->
        Column(modifier = Modifier.fillMaxSize().padding(padding)) {
            if (txs.isEmpty()) {
                Box(modifier = Modifier.fillMaxSize().padding(24.dp), contentAlignment = androidx.compose.ui.Alignment.Center) {
                    Text("No transactions yet", style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.outline)
                }
            } else {
                LazyColumn(contentPadding = PaddingValues(12.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    items(txs) { tx ->
                        ElevatedCard(modifier = Modifier.fillMaxWidth()) {
                            Row(modifier = Modifier.fillMaxWidth().padding(14.dp), horizontalArrangement = Arrangement.SpaceBetween) {
                                Column(verticalArrangement = Arrangement.spacedBy(2.dp)) {
                                    Text("#${tx.counter}  •  %,d".format(tx.amount), style = MaterialTheme.typography.titleSmall)
                                    Text("nonce ${tx.nonce}", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.outline)
                                }
                                Badge(containerColor = if (tx.settled) MaterialTheme.colorScheme.secondaryContainer else MaterialTheme.colorScheme.tertiaryContainer) {
                                    Text(if (tx.settled) "settled" else "pending", modifier = Modifier.padding(horizontal = 6.dp, vertical = 2.dp))
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}
