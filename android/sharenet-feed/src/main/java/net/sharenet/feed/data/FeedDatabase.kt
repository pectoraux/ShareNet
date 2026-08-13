package net.sharenet.feed.data

import androidx.room.Database
import androidx.room.RoomDatabase

@Database(
    entities = [
        PostEntity::class,
        ActionEntity::class,
        CursorEntity::class,
        AppEntity::class,
        UserStatsEntity::class,
        ActiveAppEntity::class
    ],
    version = 2
)
abstract class FeedDatabase : RoomDatabase() {
    abstract fun postDao(): PostDao
    abstract fun actionDao(): ActionDao
    abstract fun cursorDao(): CursorDao
    abstract fun appDao(): AppDao
    abstract fun userStatsDao(): UserStatsDao
    abstract fun activeAppDao(): ActiveAppDao
}
