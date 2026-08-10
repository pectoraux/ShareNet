package net.sharenet.assistant.data

import kotlinx.coroutines.flow.Flow
import java.util.UUID

/**
 * Repository over [AssistantDatabase]. Keeps ViewModels free of Room details.
 */
class ConversationRepository(
    private val conversationDao: ConversationDao,
    private val messageDao: MessageDao,
) {
    fun observeConversations(): Flow<List<Conversation>> = conversationDao.observeAll()

    fun observeMessages(conversationId: String): Flow<List<Message>> =
        messageDao.observeForConversation(conversationId)

    suspend fun createConversation(title: String = "New chat"): Conversation {
        val now = System.currentTimeMillis()
        val conv = Conversation(id = UUID.randomUUID().toString(), title = title, createdAt = now, updatedAt = now)
        conversationDao.upsert(conv)
        return conv
    }

    suspend fun appendMessage(conversationId: String, role: String, content: String, audioPath: String? = null): Message {
        val msg = Message(
            id = UUID.randomUUID().toString(),
            conversationId = conversationId,
            role = role,
            content = content,
            createdAt = System.currentTimeMillis(),
            audioPath = audioPath,
        )
        messageDao.insert(msg)
        // bump conversation updatedAt
        conversationDao.getById(conversationId)?.let { conv ->
            conversationDao.upsert(conv.copy(updatedAt = msg.createdAt))
        }
        return msg
    }

    suspend fun clearConversation(conversationId: String) = messageDao.clearConversation(conversationId)
}
