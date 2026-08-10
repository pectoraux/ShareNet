package net.sharenet.demo.ui

import android.net.Uri
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Button
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.ExposedDropdownMenuBox
import androidx.compose.material3.ExposedDropdownMenuDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
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
import androidx.lifecycle.viewModelScope
import androidx.lifecycle.viewmodel.compose.viewModel
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.launch

// ---------------------------------------------------------------------------
// Publish — picks a file via SAF, publishes through SDK.
// Real impl: sdk.publish(fileUri, category) → BlobId + Manifest signed with device key.
// ---------------------------------------------------------------------------

class PublishViewModel : ViewModel() {
    private val _pickedUri = MutableStateFlow<Uri?>(null)
    val pickedUri: StateFlow<Uri?> = _pickedUri

    private val _isPublishing = MutableStateFlow(false)
    val isPublishing: StateFlow<Boolean> = _isPublishing

    private val _result = MutableStateFlow<String?>(null)
    val result: StateFlow<String?> = _result

    private val _error = MutableStateFlow<String?>(null)
    val error: StateFlow<String?> = _error

    fun onFilePicked(uri: Uri) {
        _pickedUri.value = uri
        _result.value = null
        _error.value = null
    }

    fun publish(category: Category) {
        val uri = _pickedUri.value ?: run {
            _error.value = "No file selected"
            return
        }
        if (_isPublishing.value) return
        viewModelScope.launch {
            _isPublishing.value = true
            _error.value = null
            try {
                // Real: sdk.content.publish(uri, category)
                delay(1200) // simulate chunking + Merkle + signing
                val fakeBlobId = "blob-${uri.lastPathSegment?.hashCode()?.toString(16) ?: "xxxx"}"
                _result.value = fakeBlobId
            } catch (e: Exception) {
                _error.value = e.message ?: "Unknown error"
            } finally {
                _isPublishing.value = false
            }
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun PublishScreen(
    onBack: () -> Unit,
    onPublished: (String) -> Unit,
    viewModel: PublishViewModel = viewModel(),
) {
    val pickedUri by viewModel.pickedUri.collectAsState()
    val isPublishing by viewModel.isPublishing.collectAsState()
    val result by viewModel.result.collectAsState()
    val error by viewModel.error.collectAsState()

    var selectedCategory by remember { mutableStateOf(Category.EDUCATION) }
    var menuExpanded by remember { mutableStateOf(false) }

    val pickerLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.GetContent(),
    ) { uri: Uri? ->
        if (uri != null) viewModel.onFilePicked(uri)
    }

    // Navigate to detail when publish succeeds
    if (result != null) {
        // Show success inline and let user tap through — alternative is auto-navigate.
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("Publish") },
                navigationIcon = {
                    androidx.compose.material3.TextButton(onClick = onBack) { Text("‹ Back") }
                },
            )
        },
    ) { padding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(14.dp),
        ) {
            Text(
                "Pick a file and publish it to the ShareNet mesh. The file is chunked, Merkle-hashed, and signed with your device key.",
                style = MaterialTheme.typography.bodySmall,
            )

            Button(
                onClick = { pickerLauncher.launch("*/*") },
                modifier = Modifier.fillMaxWidth(),
            ) { Text("Pick File") }

            Text(
                text = pickedUri?.toString() ?: "No file selected",
                style = MaterialTheme.typography.bodySmall,
                color = if (pickedUri != null) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.outline,
            )

            // Category picker
            ExposedDropdownMenuBox(
                expanded = menuExpanded,
                onExpandedChange = { menuExpanded = !menuExpanded },
            ) {
                OutlinedTextField(
                    value = selectedCategory.name,
                    onValueChange = {},
                    readOnly = true,
                    label = { Text("Category") },
                    trailingIcon = { ExposedDropdownMenuDefaults.TrailingIcon(expanded = menuExpanded) },
                    modifier = Modifier
                        .menuAnchor()
                        .fillMaxWidth(),
                )
                ExposedDropdownMenu(expanded = menuExpanded, onDismissRequest = { menuExpanded = false }) {
                    Category.entries.forEach { cat ->
                        DropdownMenuItem(
                            text = { Text(cat.name) },
                            onClick = {
                                selectedCategory = cat
                                menuExpanded = false
                            },
                        )
                    }
                }
            }

            Button(
                onClick = { viewModel.publish(selectedCategory) },
                enabled = pickedUri != null && !isPublishing,
                modifier = Modifier.fillMaxWidth(),
            ) {
                Text(if (isPublishing) "Publishing…" else "Publish to ShareNet")
            }

            if (isPublishing) {
                androidx.compose.material3.LinearProgressIndicator(modifier = Modifier.fillMaxWidth())
            }

            result?.let { blobId ->
                Text("Published — blob $blobId", color = MaterialTheme.colorScheme.primary, style = MaterialTheme.typography.bodyMedium)
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    Button(onClick = { onPublished(blobId) }) { Text("View Blob") }
                }
            }

            error?.let { msg ->
                Text("Publish failed: $msg", color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodyMedium)
            }
        }
    }
}
