package net.sharenet.feed

import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import net.sharenet.crypto.BlobId
import net.sharenet.feed.domain.FeedItem
import net.sharenet.feed.domain.FeedRepository

class FakeFeedRepository : FeedRepository {
    private val _feed = MutableStateFlow<List<FeedItem>>(emptyList())
    override fun observeFeed(): Flow<List<FeedItem>> = _feed.asStateFlow()

    override fun observeAds(): Flow<List<FeedItem>> = kotlinx.coroutines.flow.flowOf(emptyList())

    override suspend fun like(blobId: BlobId) {
        val list = _feed.value.toMutableList()
        val idx = list.indexOfFirst { it.blobId == blobId }
        if (idx != -1) {
            val item = list[idx]
            val newLiked = !item.isLiked
            list[idx] = item.copy(
                isLiked = newLiked,
                likeCount = item.likeCount + if (newLiked) 1 else -1
            )
            _feed.value = list
        }
    }

    override suspend fun comment(blobId: BlobId, text: String) {
        val list = _feed.value.toMutableList()
        val idx = list.indexOfFirst { it.blobId == blobId }
        if (idx != -1) {
            val item = list[idx]
            list[idx] = item.copy(commentCount = item.commentCount + 1)
            _feed.value = list
        }
    }

    override suspend fun createPost(blobId: BlobId, caption: String, publisherId: String) {
        _feed.value = _feed.value + FeedItem(
            blobId = blobId,
            caption = caption,
            publisherId = publisherId,
            publishedAt = System.currentTimeMillis(),
            likeCount = 0,
            commentCount = 0,
            isLiked = false,
            isPending = true
        )
    }

    fun setFeed(items: List<FeedItem>) {
        _feed.value = items
    }
}
