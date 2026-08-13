package net.sharenet.demo.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
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
// Fetch + verify state machine — real impl delegates to SDK blob store.
// ---------------------------------------------------------------------------

sealed interface FetchState {
    data object Idle : FetchState
    data class Fetching(val progress: Float) : FetchState // 0..1
    data object Verifying : FetchState
    data object Verified : FetchState
    data class Failed(val reason: String) : FetchState
}

class BlobDetailViewModel : ViewModel() {
    private val _state = MutableStateFlow<FetchState>(FetchState.Idle)
    val state: StateFlow<FetchState> = _state

    private val _renderText = MutableStateFlow<String?>(null)
    val renderText: StateFlow<String?> = _renderText

    fun fetchAndVerify(blobId: String) {
        if (_state.value is FetchState.Fetching || _state.value is FetchState.Verifying) return
        viewModelScope.launch {
            _state.value = FetchState.Fetching(0f)
            // Simulated chunk fetch — real: sdk.blobs.fetch(blobId).collect { progress }
            repeat(10) { i ->
                delay(180)
                _state.value = FetchState.Fetching((i + 1) / 10f)
            }
            _state.value = FetchState.Verifying
            delay(600)
            // Real: sdk.blobs.verify(blobId) — checks Merkle root + Ed25519 signature
            val ok = true // stub: always passes; inject failure for error-path QA
            if (ok) {
                _state.value = FetchState.Verified
                _renderText.value = "Blob $blobId — Merkle root verified. " +
                    "Content would render here (PDF / HTML / media). " +
                    "Truncated preview from blob store."
            } else {
                _state.value = FetchState.Failed("Merkle mismatch — chunk re-fetch required")
            }
        }
    }

    fun reset() {
        _state.value = FetchState.Idle
        _renderText.value = null
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun BlobDetailScreen(
    blobId: String,
    onBack: () -> Unit,
    viewModel: BlobDetailViewModel = viewModel(),
) {
    val state by viewModel.state.collectAsState()
    val renderText by viewModel.renderText.collectAsState()

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("Blob Detail") },
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
            Text("blob: $blobId", style = MaterialTheme.typography.labelMedium)
            Text("Tap Verify to fetch chunks, check Merkle root + signature, and render.", style = MaterialTheme.typography.bodySmall)

            when (val s = state) {
                is FetchState.Idle -> {
                    Button(onClick = { viewModel.fetchAndVerify(blobId) }, modifier = Modifier.fillMaxWidth()) {
                        Text("Fetch + Verify + Render")
                    }
                }
                is FetchState.Fetching -> {
                    Text("Fetching… ${(s.progress * 100).toInt()}%", style = MaterialTheme.typography.bodyMedium)
                    LinearProgressIndicator(progress = { s.progress }, modifier = Modifier.fillMaxWidth())
                    Text("Progress", style = MaterialTheme.typography.labelSmall)
                }
                is FetchState.Verifying -> {
                    LinearProgressIndicator(modifier = Modifier.fillMaxWidth())
                    Text("Verifying Merkle tree & publisher signature…", style = MaterialTheme.typography.bodyMedium)
                }
                is FetchState.Verified -> {
                    Text("Verified ✓", color = MaterialTheme.colorScheme.primary, style = MaterialTheme.typography.titleSmall)
                    Card(modifier = Modifier.fillMaxWidth()) {
                        Text(
                            text = renderText ?: "Rendered content will appear here",
                            modifier = Modifier.padding(14.dp),
                            style = MaterialTheme.typography.bodyMedium,
                        )
                    }
                    Button(onClick = { viewModel.reset() }, modifier = Modifier.fillMaxWidth()) {
                        Text("Fetch Again")
                    }
                }
                is FetchState.Failed -> {
                    Text("Verification failed: ${s.reason}", color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodyMedium)
                    Button(onClick = { viewModel.fetchAndVerify(blobId) }, modifier = Modifier.fillMaxWidth()) {
                        Text("Retry")
                    }
                }
            }
        }
    }
}
