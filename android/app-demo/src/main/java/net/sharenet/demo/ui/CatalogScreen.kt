package net.sharenet.demo.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.LazyRow
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.AssistChip
import androidx.compose.material3.AssistChipDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilterChip
import androidx.compose.material3.FloatingActionButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
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

// ---------------------------------------------------------------------------
// Domain — mirrors sharenet-sdk CatalogEntry but decoupled for SDK isolation.
// In production these map 1:1 to net.sharenet.sdk.catalog.CatalogEntry.
// ---------------------------------------------------------------------------

enum class Category { EDUCATION, HEALTH, APP_UPDATE, MODEL_WEIGHTS, DATASET }

enum class Priority(val label: String, val level: Int) {
    LOW("Low", 0),
    NORMAL("Normal", 1),
    HIGH("High", 2),
}

data class CatalogItem(
    val blobId: String,
    val category: Category,
    val priority: Priority,
    val displayName: String,
    val sizeBytes: Long,
    val mimeType: String,
)

// ---------------------------------------------------------------------------
// ViewModel — SDK-only: real impl would inject ShareNetSdk catalog repo.
// ---------------------------------------------------------------------------

class CatalogViewModel : ViewModel() {
    private val _items = MutableStateFlow<List<CatalogItem>>(sampleItems)
    val items: StateFlow<List<CatalogItem>> = _items

    private val _selectedCategory = MutableStateFlow<Category?>(null)
    val selectedCategory: StateFlow<Category?> = _selectedCategory

    fun selectCategory(category: Category?) {
        _selectedCategory.value = category
    }

    fun refresh() {
        // Real impl: viewModelScope.launch { _items.value = sdk.catalog.list() }
        _items.value = sampleItems.shuffled()
    }
}

private val sampleItems = listOf(
    CatalogItem("blob-edu-001", Category.EDUCATION, Priority.HIGH, "Primary Math — Grade 4 (EN/FR)", 42_000_000, "application/x-sharenet-blob"),
    CatalogItem("blob-health-002", Category.HEALTH, Priority.HIGH, "Malaria Prevention Guide", 18_000_000, "application/pdf"),
    CatalogItem("blob-app-003", Category.APP_UPDATE, Priority.NORMAL, "ShareNet Assistant v1.2.0", 95_000_000, "application/vnd.android.package-archive"),
    CatalogItem("blob-model-004", Category.MODEL_WEIGHTS, Priority.LOW, "Gemma-3 1B — EN/FR quantized", 850_000_000, "application/octet-stream"),
    CatalogItem("blob-data-005", Category.DATASET, Priority.LOW, "Twi parallel corpus v3", 210_000_000, "application/x-sharenet-dataset"),
    CatalogItem("blob-edu-006", Category.EDUCATION, Priority.NORMAL, "Science Experiments — Offline Lab", 67_000_000, "application/x-sharenet-blob"),
    CatalogItem("blob-health-007", Category.HEALTH, Priority.NORMAL, "Maternal Health Audio (Ewe)", 33_000_000, "audio/ogg"),
)

// ---------------------------------------------------------------------------
// Composables
// ---------------------------------------------------------------------------

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun CatalogScreen(
    onBlobClick: (String) -> Unit,
    onPublishClick: () -> Unit,
    viewModel: CatalogViewModel = viewModel(),
) {
    val items by viewModel.items.collectAsState()
    val selectedCategory by viewModel.selectedCategory.collectAsState()

    val filtered = remember(items, selectedCategory) {
        if (selectedCategory == null) items else items.filter { it.category == selectedCategory }
    }

    Scaffold(
        topBar = { TopAppBar(title = { Text("ShareNet Demo — Catalog") }) },
        floatingActionButton = {
            FloatingActionButton(onClick = onPublishClick) { Text("+") }
        },
    ) { padding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .padding(16.dp),
        ) {
            CategoryFilterRow(
                selected = selectedCategory,
                onSelect = { viewModel.selectCategory(it) },
            )

            if (filtered.isEmpty()) {
                Text(
                    text = "No content available. Pull to sync or wait for nearby peers.",
                    style = MaterialTheme.typography.bodyMedium,
                    modifier = Modifier.padding(top = 32.dp),
                )
            } else {
                LazyColumn(
                    modifier = Modifier.padding(top = 12.dp),
                    verticalArrangement = Arrangement.spacedBy(10.dp),
                ) {
                    items(filtered, key = { it.blobId }) { item ->
                        CatalogCard(item = item, onClick = { onBlobClick(item.blobId) })
                    }
                }
            }
        }
    }
}

@Composable
private fun CategoryFilterRow(
    selected: Category?,
    onSelect: (Category?) -> Unit,
) {
    LazyRow(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
        item {
            FilterChip(
                selected = selected == null,
                onClick = { onSelect(null) },
                label = { Text("All") },
            )
        }
        items(Category.entries) { cat ->
            FilterChip(
                selected = selected == cat,
                onClick = { onSelect(cat) },
                label = { Text(cat.name) },
            )
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun CatalogCard(item: CatalogItem, onClick: () -> Unit) {
    Card(onClick = onClick, modifier = Modifier.fillMaxWidth()) {
        Column(modifier = Modifier.padding(14.dp)) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
            ) {
                Text(item.displayName, style = MaterialTheme.typography.titleSmall)
                PriorityBadge(priority = item.priority)
            }
            Text(
                text = "${item.category.name} · ${humanSize(item.sizeBytes)} · ${item.mimeType}",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.padding(top = 4.dp),
            )
            Text(
                text = "blob: ${item.blobId}",
                style = MaterialTheme.typography.labelSmall,
                color = MaterialTheme.colorScheme.outline,
            )
        }
    }
}

@Composable
private fun PriorityBadge(priority: Priority) {
    val container = when (priority) {
        Priority.HIGH -> MaterialTheme.colorScheme.errorContainer
        Priority.NORMAL -> MaterialTheme.colorScheme.secondaryContainer
        Priority.LOW -> MaterialTheme.colorScheme.surfaceVariant
    }
    val labelColor = when (priority) {
        Priority.HIGH -> MaterialTheme.colorScheme.onErrorContainer
        Priority.NORMAL -> MaterialTheme.colorScheme.onSecondaryContainer
        Priority.LOW -> MaterialTheme.colorScheme.onSurfaceVariant
    }
    AssistChip(
        onClick = {},
        label = { Text(priority.label, color = labelColor, style = MaterialTheme.typography.labelSmall) },
        colors = AssistChipDefaults.assistChipColors(containerColor = container),
        enabled = false,
    )
}

private fun humanSize(bytes: Long): String = when {
    bytes >= 1_000_000_000 -> String.format("%.1f GB", bytes / 1e9)
    bytes >= 1_000_000 -> String.format("%.0f MB", bytes / 1e6)
    bytes >= 1_000 -> String.format("%.0f KB", bytes / 1e3)
    else -> "$bytes B"
}
