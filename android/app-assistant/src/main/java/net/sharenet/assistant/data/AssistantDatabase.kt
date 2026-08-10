package net.sharenet.assistant.data

import androidx.room.Database
import androidx.room.RoomDatabase

@Database(entities = [Conversation::class, Message::class], version = 1, exportSchema = false)
abstract class AssistantDatabase : RoomDatabase() {
    abstract fun conversationDao(): ConversationDao
    abstract fun messageDao(): MessageDao
}
