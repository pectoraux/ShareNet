package net.sharenet.app.feed.ui

import androidx.compose.foundation.gestures.detectTapGestures
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.grid.GridCells
import androidx.compose.foundation.lazy.grid.LazyVerticalGrid
import androidx.compose.foundation.lazy.grid.items
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.ui.unit.dp
import net.sharenet.feed.domain.AppStoreItem

@Composable
fun LibraryScreen(viewModel: FeedViewModel) {
    val libraryItems by viewModel.libraryItems.collectAsState()
    var selectedAppId by remember { mutableStateOf<String?>(null) }

    Column(modifier = Modifier.fillMaxSize().padding(16.dp)) {
        Text("My Library", style = MaterialTheme.typography.displaySmall)
        Spacer(modifier = Modifier.height(20.dp))

        if (libraryItems.isEmpty()) {
            Box(modifier = Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
                Text("No apps installed. Find them in the Store.", color = MaterialTheme.colorScheme.outline)
            }
        } else {
            LazyVerticalGrid(
                columns = GridCells.Fixed(4),
                horizontalArrangement = Arrangement.spacedBy(16.dp),
                verticalArrangement = Arrangement.spacedBy(24.dp)
            ) {
                items(libraryItems) { app ->
                    AppIcon(
                        app = app,
                        onClick = { viewModel.launchApp(app.id) },
                        onLongClick = { selectedAppId = app.id }
                    )
                }
            }
        }
    }

    if (selectedAppId != null) {
        AlertDialog(
            onDismissRequest = { selectedAppId = null },
            title = { Text("App Actions") },
            text = { Text("Do you want to uninstall this application?") },
            confirmButton = { 
                TextButton(onClick = { 
                    viewModel.uninstallApp(selectedAppId!!)
                    selectedAppId = null 
                }) { Text("Uninstall", color = MaterialTheme.colorScheme.error) }
            },
            dismissButton = { TextButton(onClick = { selectedAppId = null }) { Text("Cancel") } }
        )
    }
}

@Composable
fun AppIcon(app: AppStoreItem, onClick: () -> Unit, onLongClick: () -> Unit) {
    Column(
        horizontalAlignment = Alignment.CenterHorizontally,
        modifier = Modifier.pointerInput(Unit) {
            detectTapGestures(
                onTap = { onClick() },
                onLongPress = { onLongClick() }
            )
        }
    ) {
        Surface(
            modifier = Modifier.size(64.dp),
            color = MaterialTheme.colorScheme.secondaryContainer,
            shape = MaterialTheme.shapes.medium
        ) {
            Box(contentAlignment = Alignment.Center) {
                Text(app.icon, style = MaterialTheme.typography.headlineLarge)
            }
        }
        Text(app.name, style = MaterialTheme.typography.labelSmall, maxLines = 1, modifier = Modifier.padding(top = 4.dp))
    }
}
