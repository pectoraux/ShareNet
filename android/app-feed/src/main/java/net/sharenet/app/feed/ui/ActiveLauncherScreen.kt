package net.sharenet.app.feed.ui

import androidx.compose.foundation.layout.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp

@Composable
fun ActiveLauncherScreen(viewModel: FeedViewModel) {
    val activeApps by viewModel.activeApps.collectAsState()
    
    if (activeApps.isEmpty()) {
        Box(modifier = Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
            Column(horizontalAlignment = Alignment.CenterHorizontally) {
                Text("No apps running.", style = MaterialTheme.typography.titleMedium)
                Text("Launch an app from your Library.", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.outline)
            }
        }
    } else {
        val lastLaunched = activeApps.first()
        
        Column(modifier = Modifier.fillMaxSize()) {
            // Task Switcher / Status Bar
            if (activeApps.size > 1) {
                ScrollableTabRow(
                    selectedTabIndex = 0,
                    edgePadding = 16.dp,
                    divider = {},
                    containerColor = MaterialTheme.colorScheme.surfaceVariant
                ) {
                    activeApps.forEach { app ->
                        Tab(
                            selected = app.appId == lastLaunched.appId,
                            onClick = { viewModel.launchApp(app.appId) }, // Re-launch to move to top
                            text = { Text(app.name) }
                        )
                    }
                }
            }

            // App Container
            Box(modifier = Modifier.weight(1f).fillMaxWidth()) {
                AppInstanceContainer(app = lastLaunched, onClose = { viewModel.closeApp(it) })
            }
        }
    }
}

@Composable
fun AppInstanceContainer(app: net.sharenet.feed.domain.ActiveApp, onClose: (String) -> Unit) {
    Surface(modifier = Modifier.fillMaxSize(), color = MaterialTheme.colorScheme.background) {
        Column(modifier = Modifier.fillMaxSize().padding(16.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text(app.name, style = MaterialTheme.typography.headlineMedium, modifier = Modifier.weight(1f))
                IconButton(onClick = { onClose(app.appId) }) { Text("✕") }
            }
            HorizontalDivider()
            Spacer(modifier = Modifier.height(20.dp))
            
            // Executing App Content via Sandbox
            Card(modifier = Modifier.fillMaxWidth().weight(1f)) {
                AppSandboxContainer(appId = app.appId, appName = app.name)
            }
        }
    }
}
