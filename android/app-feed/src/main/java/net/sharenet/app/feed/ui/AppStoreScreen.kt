package net.sharenet.app.feed.ui

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import net.sharenet.feed.domain.AppStoreItem

@Composable
fun AppStoreScreen(viewModel: FeedViewModel) {
    val storeItems by viewModel.storeItems.collectAsState()
    val reviewQueue by viewModel.reviewQueue.collectAsState()
    val userStats by viewModel.userStats.collectAsState()
    
    var showSubmitDialog by remember { mutableStateOf(false) }

    LazyColumn(
        modifier = Modifier.fillMaxSize(),
        contentPadding = PaddingValues(16.dp),
        verticalArrangement = Arrangement.spacedBy(20.dp)
    ) {
        item {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text("App Store", style = MaterialTheme.typography.displaySmall, fontWeight = FontWeight.Bold, modifier = Modifier.weight(1f))
                IconButton(onClick = { /* Profile */ }) { Text("👤") }
            }
        }

        if (userStats.isAdmin && reviewQueue.isNotEmpty()) {
            item { Text("Review Queue (Admin)", style = MaterialTheme.typography.titleLarge) }
            items(reviewQueue) { app ->
                AppStoreRow(app, onAction = { viewModel.approveApp(app.id) }, actionLabel = "Approve")
            }
            item { HorizontalDivider(modifier = Modifier.padding(vertical = 8.dp)) }
        }

        item {
            Text("Categories", style = MaterialTheme.typography.titleLarge)
            Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                listOf("SOCIAL", "GAMES", "FINANCE").forEach { cat ->
                    FilterChip(
                        selected = false,
                        onClick = { },
                        label = { Text(cat) }
                    )
                }
            }
        }

        item { Text("Featured Apps", style = MaterialTheme.typography.titleLarge) }
        
        if (storeItems.isEmpty()) {
            item { Text("No apps approved yet. Be the first developer!", color = MaterialTheme.colorScheme.outline) }
        } else {
            items(storeItems) { app ->
                AppStoreRow(app, onAction = { viewModel.installApp(app.id) }, actionLabel = "GET")
            }
        }

        item {
            Button(onClick = { showSubmitDialog = true }, modifier = Modifier.fillMaxWidth()) {
                Text("Developer Portal: Submit App")
            }
        }
    }

    if (showSubmitDialog) {
        SubmitAppDialog(
            onDismiss = { showSubmitDialog = false },
            onSubmit = { name, desc -> 
                viewModel.submitApp(name, desc)
                showSubmitDialog = false
            }
        )
    }
}

@Composable
fun AppStoreRow(app: AppStoreItem, onAction: () -> Unit, actionLabel: String) {
    Card(modifier = Modifier.fillMaxWidth()) {
        Row(modifier = Modifier.padding(16.dp), verticalAlignment = Alignment.CenterVertically) {
            Surface(modifier = Modifier.size(60.dp), color = MaterialTheme.colorScheme.surfaceVariant, shape = MaterialTheme.shapes.medium) {
                Box(contentAlignment = Alignment.Center) { Text(app.icon, style = MaterialTheme.typography.headlineMedium) }
            }
            Column(modifier = Modifier.padding(start = 16.dp).weight(1f)) {
                Text(app.name, style = MaterialTheme.typography.titleMedium)
                Text(app.developer, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.outline)
                Text(app.description, style = MaterialTheme.typography.bodySmall, maxLines = 1)
            }
            Button(onClick = onAction) { Text(actionLabel) }
        }
    }
}

@Composable
fun SubmitAppDialog(onDismiss: () -> Unit, onSubmit: (String, String) -> Unit) {
    var name by remember { mutableStateOf("") }
    var desc by remember { mutableStateOf("") }
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("Submit App Clone") },
        text = {
            Column {
                OutlinedTextField(value = name, onValueChange = { name = it }, label = { Text("App Name") })
                OutlinedTextField(value = desc, onValueChange = { desc = it }, label = { Text("Description") })
            }
        },
        confirmButton = { TextButton(onClick = { onSubmit(name, desc) }) { Text("Submit") } },
        dismissButton = { TextButton(onClick = onDismiss) { Text("Cancel") } }
    )
}

