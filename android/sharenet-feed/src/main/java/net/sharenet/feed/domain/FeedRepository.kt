package net.sharenet.feed.domain

import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.flow.combine
import net.sharenet.crypto.BlobId
import net.sharenet.crypto.Category
import net.sharenet.feed.data.ActionEntity
import net.sharenet.feed.data.ActionDao
import net.sharenet.feed.data.PostDao
import net.sharenet.feed.data.PostEntity

interface FeedRepository {
    fun observeFeed(): Flow<List<FeedItem>>
    suspend fun like(blobId: BlobId)
    suspend fun comment(blobId: BlobId, text: String)
    suspend fun createPost(blobId: BlobId, caption: String, publisherId: String)
}

class RealFeedRepository(
    private val postDao: PostDao,
    private val actionDao: ActionDao,
) : FeedRepository {

    override fun observeFeed(): Flow<List<FeedItem>> {
        return combine(
            postDao.observeAll(),
            observeAds()
        ) { posts, ads ->
            val domainPosts = posts.map { it.toDomain() }
            if (ads.isEmpty()) domainPosts
            else interleaveAds(domainPosts, ads)
        }
    }

    private fun observeAds(): Flow<List<FeedItem>> {
        // Real: catalogStore.observe(Category.AD)
        return kotlinx.coroutines.flow.flowOf(emptyList())
    }

    private fun interleaveAds(posts: List<FeedItem>, ads: List<FeedItem>): List<FeedItem> {
        val result = mutableListOf<FeedItem>()
        posts.forEachIndexed { index, post ->
            result.add(post)
            if ((index + 1) % 5 == 0 && ads.isNotEmpty()) {
                result.add(ads[index % ads.size].copy(caption = "[AD] " + ads[index % ads.size].caption))
            }
        }
        return result
    }

    override suspend fun like(blobId: BlobId) {
        val blobIdHex = blobId.toHex()
        val post = postDao.getById(blobIdHex) ?: return
        
        // Optimistic update
        val newLiked = !post.isLiked
        val delta = if (newLiked) 1 else -1
        postDao.updateLike(blobIdHex, newLiked, delta)
        
        // Queue action
        actionDao.upsert(
            ActionEntity(
                type = ActionType.LIKE.name,
                targetBlobIdHex = blobIdHex,
                payload = null,
                status = "PENDING"
            )
        )
    }

    override suspend fun comment(blobId: BlobId, text: String) {
        val blobIdHex = blobId.toHex()
        // Queue action
        actionDao.upsert(
            ActionEntity(
                type = ActionType.COMMENT.name,
                targetBlobIdHex = blobIdHex,
                payload = text.encodeToByteArray(),
                status = "PENDING"
            )
        )
    }

    override suspend fun createPost(blobId: BlobId, caption: String, publisherId: String) {
        val blobIdHex = blobId.toHex()
        val now = System.currentTimeMillis()
        
        // Optimistic insert
        postDao.upsert(
            PostEntity(
                blobIdHex = blobIdHex,
                caption = caption,
                publisherIdHex = publisherId,
                publishedAt = now,
                mimeType = "video/sharenet-feed-post",
                isLiked = false
            )
        )
        
        // Queue action
        actionDao.upsert(
            ActionEntity(
                type = ActionType.POST.name,
                targetBlobIdHex = blobIdHex,
                payload = caption.encodeToByteArray(),
                status = "PENDING"
            )
        )
    }

    private fun PostEntity.toDomain() = FeedItem(
        blobId = BlobId.fromHex(blobIdHex),
        caption = caption,
        publisherId = publisherIdHex,
        publishedAt = publishedAt,
        likeCount = likeCount,
        commentCount = commentCount,
        isLiked = isLiked
    )
}
