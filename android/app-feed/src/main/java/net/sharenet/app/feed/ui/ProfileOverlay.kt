package net.sharenet.app.feed.ui

import androidx.compose.foundation.layout.*
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ProfileSheet(viewModel: FeedViewModel, onDismiss: () -> Unit) {
    val userStats by viewModel.userStats.collectAsState()

    ModalBottomSheet(onDismissRequest = onDismiss) {
        Column(modifier = Modifier.padding(24.dp).fillMaxWidth()) {
            Text("User Profile", style = MaterialTheme.typography.headlineMedium)
            Spacer(modifier = Modifier.height(16.dp))
            
            Card(modifier = Modifier.fillMaxWidth()) {
                Column(modifier = Modifier.padding(16.dp)) {
                    Text("Civic Points", style = MaterialTheme.typography.labelMedium)
                    Text("${userStats.civicPoints}", style = MaterialTheme.typography.displaySmall)
                }
            }

            Spacer(modifier = Modifier.height(24.dp))
            
            Row(verticalAlignment = Alignment.CenterVertically) {
                Column(modifier = Modifier.weight(1f)) {
                    Text("Internet Bridging", style = MaterialTheme.typography.titleMedium)
                    Text("Earn points by sharing your internet with the mesh.", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.outline)
                }
                Switch(
                    checked = userStats.bridgingEnabled,
                    onCheckedChange = { viewModel.toggleBridging(it) }
                )
            }

            Spacer(modifier = Modifier.height(32.dp))
            Button(onClick = onDismiss, modifier = Modifier.fillMaxWidth()) {
                Text("Close")
            }
        }
    }
}
