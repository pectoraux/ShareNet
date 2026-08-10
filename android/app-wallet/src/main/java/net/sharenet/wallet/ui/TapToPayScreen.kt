package net.sharenet.wallet.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.launch

/**
 * Two-tap offline payment.
 *
 * Flow: amount → tap payer (DEBIT) → tap payee (CREDIT) → record for settlement.
 * In this scaffold the NFC taps are simulated with buttons; wire to
 * [net.sharenet.wallet.nfc.NfcReaderManager] + [net.sharenet.wallet.nfc.CardChannel]
 * in the real device build.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun TapToPayScreen(
    onNavigateBalance: () -> Unit,
    onNavigateHistory: () -> Unit,
    onNavigateSettlement: () -> Unit,
) {
    var amountText by remember { mutableStateOf("1000") }
    var step by remember { mutableStateOf(Step.ENTER_AMOUNT) }
    var status by remember { mutableStateOf<String?>(null) }
    var isError by remember { mutableStateOf(false) }
    val scope = rememberCoroutineScope()

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("Tap to Pay") },
                actions = {
                    androidx.compose.material3.TextButton(onClick = onNavigateBalance) { Text("Balance") }
                    androidx.compose.material3.TextButton(onClick = onNavigateHistory) { Text("History") }
                    androidx.compose.material3.TextButton(onClick = onNavigateSettlement) { Text("Settle") }
                },
            )
        },
    ) { padding ->
        Column(modifier = Modifier.fillMaxSize().padding(padding).padding(16.dp), verticalArrangement = Arrangement.spacedBy(14.dp)) {

            OutlinedTextField(
                value = amountText,
                onValueChange = { amountText = it.filter { c -> c.isDigit() } },
                label = { Text("Amount (minor units)") },
                modifier = Modifier.fillMaxWidth(),
            )

            when (step) {
                Step.ENTER_AMOUNT -> {
                    Text("Hold card to reader — NFC reader mode (IsoDep, enableReaderMode)", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.outline)
                    Button(
                        onClick = {
                            val amt = amountText.toIntOrNull() ?: 0
                            if (amt <= 0) { status = "Enter a valid amount"; isError = true; return@Button }
                            // Simulate payer tap → DEBIT
                            scope.launch {
                                // Real: channel.transceive(ApduCommands.debit(amt))
                                // Check invariants: no double credit, balance non-negative, offline cap, revocation
                                kotlinx.coroutines.delay(400)
                                // Fake revoked check example: if (revoked) throw
                                status = "Payer debited — now tap payee card"
                                isError = false
                                step = Step.PAYER_DONE
                            }
                        },
                        modifier = Modifier.fillMaxWidth(),
                    ) { Text("Debit payer (tap card)") }
                }
                Step.PAYER_DONE -> {
                    Text("Payer debited — now tap payee card", color = MaterialTheme.colorScheme.primary, style = MaterialTheme.typography.bodyMedium)
                    Button(
                        onClick = {
                            scope.launch {
                                kotlinx.coroutines.delay(400)
                                // Real: channel.transceive(ApduCommands.credit(amt))
                                status = "Payment recorded — pending settlement"
                                isError = false
                                step = Step.DONE
                                // Real: transactionDao.insert(record) → queue+settle on reconnect
                            }
                        },
                        modifier = Modifier.fillMaxWidth(),
                    ) { Text("Credit payee (tap card)") }
                }
                Step.DONE -> {
                    Card(modifier = Modifier.fillMaxWidth()) {
                        Text(status ?: "Done", modifier = Modifier.padding(14.dp), color = if (isError) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.primary)
                    }
                    Button(onClick = { step = Step.ENTER_AMOUNT; status = null }, modifier = Modifier.fillMaxWidth()) { Text("New payment") }
                }
            }

            status?.let {
                if (step != Step.DONE) {
                    Text(it, color = if (isError) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.primary, style = MaterialTheme.typography.bodyMedium)
                }
            }

            // Revoked demo
            Card(modifier = Modifier.fillMaxWidth()) {
                Column(modifier = Modifier.padding(12.dp)) {
                    Text("Revocation: card on the ShareNet revocation list is refused (catalog priority max).", style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.outline)
                }
            }

            Row(horizontalArrangement = Arrangement.spacedBy(8.dp), modifier = Modifier.fillMaxWidth()) {
                Button(onClick = onNavigateBalance, modifier = Modifier.weight(1f)) { Text("Balance") }
                Button(onClick = onNavigateHistory, modifier = Modifier.weight(1f)) { Text("History") }
            }
        }
    }
}

private enum class Step { ENTER_AMOUNT, PAYER_DONE, DONE }
