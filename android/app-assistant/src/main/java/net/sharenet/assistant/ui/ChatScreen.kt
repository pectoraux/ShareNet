package net.sharenet.assistant.ui

import androidx.compose.foundation.ExperimentalFoundationApi
import androidx.compose.foundation.combinedClickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import androidx.lifecycle.viewmodel.compose.viewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch

// ---------------------------------------------------------------------------
// ViewModel — wires LanguagePipeline (chat + voice) + Conversation store.
// Simplified for scaffolding; real impl injects AssistantAppContainer.
// ---------------------------------------------------------------------------

data class UiMessage(val role: String, val content: String, val isStreaming: Boolean = false)

class ChatViewModel : ViewModel() {
    private val _messages = MutableStateFlow<List<UiMessage>>(emptyList())
    val messages: StateFlow<List<UiMessage>> = _messages.asStateFlow()

    private val _isStreaming = MutableStateFlow(false)
    val isStreaming: StateFlow<Boolean> = _isStreaming.asStateFlow()

    private val _transcription = MutableStateFlow<String?>(null)
    val transcription: StateFlow<String?> = _transcription.asStateFlow()

    private val _isListening = MutableStateFlow(false)
    val isListening: StateFlow<Boolean> = _isListening.asStateFlow()

    fun sendText(text: String) {
        if (text.isBlank()) return
        _messages.value = _messages.value + UiMessage("user", text)
        // Simulate LLM streaming via pipeline
        viewModelScope.launch {
            _isStreaming.value = true
            val llmResponse = "This is a streamed response for: \"$text\" — produced via LanguagePipeline (ASR→translate→LLM→translate→TTS). TTS audio is a placeholder in v1."
            _messages.value = _messages.value + UiMessage("assistant", "", isStreaming = true)
            var acc = ""
            for (word in llmResponse.split(" ")) {
                kotlinx.coroutines.delay(35)
                acc += "$word "
                _messages.value = _messages.value.dropLast(1) + UiMessage("assistant", acc.trim(), isStreaming = true)
            }
            _messages.value = _messages.value.dropLast(1) + UiMessage("assistant", acc.trim(), isStreaming = false)
            _isStreaming.value = false
        }
    }

    fun startListening() {
        _isListening.value = true
        _transcription.value = ""
        viewModelScope.launch {
            // Simulate streaming transcription
            val fake = "Bonjour, comment ça va"
            for (i in 1..fake.length) {
                kotlinx.coroutines.delay(60)
                _transcription.value = fake.take(i)
            }
        }
    }

    fun stopListening() {
        _isListening.value = false
        val transcript = _transcription.value ?: ""
        _transcription.value = null
        if (transcript.isNotBlank()) sendText(transcript)
    }

    fun newConversation() {
        _messages.value = emptyList()
    }
}

@OptIn(ExperimentalMaterial3Api::class, ExperimentalFoundationApi::class)
@Composable
fun ChatScreen(
    onNavigateSettings: () -> Unit,
    onNavigateContribution: () -> Unit,
    viewModel: ChatViewModel = viewModel(),
) {
    val messages by viewModel.messages.collectAsState()
    val isStreaming by viewModel.isStreaming.collectAsState()
    val transcription by viewModel.transcription.collectAsState()
    val isListening by viewModel.isListening.collectAsState()
    var input by remember { mutableStateOf("") }
    val listState = rememberLazyListState()

    LaunchedEffect(messages.size) {
        if (messages.isNotEmpty()) listState.animateScrollToItem(messages.size - 1)
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("Assistant") },
                actions = {
                    IconButton(onClick = { viewModel.newConversation() }) { Text("＋") }
                    IconButton(onClick = onNavigateContribution) { Text("✎") }
                    IconButton(onClick = onNavigateSettings) { Text("⚙") }
                },
            )
        },
        bottomBar = {
            Column(modifier = Modifier.padding(10.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
                // Streaming transcription overlay
                if (transcription != null) {
                    Card(colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.secondaryContainer)) {
                        Text(
                            text = if (transcription!!.isEmpty()) "Listening…" else transcription!!,
                            modifier = Modifier.padding(10.dp),
                            style = MaterialTheme.typography.bodySmall,
                        )
                    }
                }
                Row(modifier = Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    OutlinedTextField(
                        value = input,
                        onValueChange = { input = it },
                        placeholder = { Text("Ask anything…") },
                        modifier = Modifier.weight(1f),
                        enabled = !isStreaming,
                    )
                    Button(
                        onClick = { viewModel.sendText(input); input = "" },
                        enabled = input.isNotBlank() && !isStreaming,
                    ) { Text("Send") }
                }
                // Hold-to-talk
                Box(modifier = Modifier.fillMaxWidth(), contentAlignment = Alignment.Center) {
                    androidx.compose.material3.FilledTonalButton(
                        onClick = {},
                        modifier = Modifier
                            .fillMaxWidth()
                            .combinedClickable(
                                onClick = {},
                                onLongClick = { viewModel.startListening() },
                            ),
                    ) {
                        Text(if (isListening) "Listening… (release to send)" else "Hold to talk")
                    }
                    // Proper hold-to-talk uses pointerInput; simplified to long-press for scaffold.
                    // Replace with: Modifier.pointerInput { detectTapGestures(onPress = { start; awaitRelease(); stop }) }
                }
                if (isListening) {
                    Button(
                        onClick = { viewModel.stopListening() },
                        modifier = Modifier.fillMaxWidth(),
                    ) { Text("Stop & Send") }
                }
            }
        },
    ) { padding ->
        if (messages.isEmpty() && transcription == null) {
            Box(modifier = Modifier.fillMaxSize().padding(padding), contentAlignment = Alignment.Center) {
                Text("No messages yet. Type or hold to talk.", style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.outline)
            }
        } else {
            LazyColumn(
                state = listState,
                modifier = Modifier.fillMaxSize().padding(padding).padding(horizontal = 12.dp),
                verticalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                items(messages) { msg ->
                    val isUser = msg.role == "user"
                    Card(
                        modifier = Modifier.fillMaxWidth(),
                        colors = CardDefaults.cardColors(
                            containerColor = if (isUser) MaterialTheme.colorScheme.primaryContainer else MaterialTheme.colorScheme.surfaceVariant,
                        ),
                    ) {
                        Column(modifier = Modifier.padding(10.dp)) {
                            Text(msg.content + if (msg.isStreaming) " ▌" else "", style = MaterialTheme.typography.bodyMedium)
                            if (!isUser && !msg.isStreaming && msg.content.isNotBlank()) {
                                Text(
                                    "🔊 Audio response (TTS placeholder)",
                                    style = MaterialTheme.typography.labelSmall,
                                    color = MaterialTheme.colorScheme.outline,
                                    modifier = Modifier.padding(top = 4.dp),
                                )
                            }
                        }
                    }
                }
            }
        }
    }
}
